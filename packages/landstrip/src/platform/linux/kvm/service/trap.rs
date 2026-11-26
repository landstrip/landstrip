// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::ErrnoExt;
use super::super::cancel::Client;
use super::super::fds::{BrokerFd, GuestFd};
use super::super::machine::Regs;
use super::super::memory::HostCString;
use super::super::policy::{self, Access, DirBase, Missing, Policy, ResolveFlags};
use super::{AT_EMPTY_PATH, SyscallArgs, WORD_SIZE};
use crate::policy::DenialReason;
use crate::trap::{FilesystemDenial, NetworkOperation, Reply, ReplyAction, Trap, TrapOperation};
use crate::trap_fd::TrapFd;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use syscalls::{Errno, Sysno};

use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
enum QuerySubject {
    FilesystemRead(Vec<u8>),
    FilesystemWrite(Vec<u8>),
    NetworkConnect(String),
    NetworkBind(String),
}

impl QuerySubject {
    fn filesystem(operation: TrapOperation, path: &Path) -> Self {
        let raw = path.as_os_str().as_bytes().to_vec();
        match operation {
            TrapOperation::Read => Self::FilesystemRead(raw),
            TrapOperation::Write => Self::FilesystemWrite(raw),
        }
    }

    fn network(operation: NetworkOperation, target: &str) -> Self {
        match operation {
            NetworkOperation::Connect => Self::NetworkConnect(target.to_owned()),
            NetworkOperation::Bind => Self::NetworkBind(target.to_owned()),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(from = "Vec<(QuerySubject, bool)>", into = "Vec<(QuerySubject, bool)>")]
struct QueryDecisions(HashMap<QuerySubject, bool>);

impl From<Vec<(QuerySubject, bool)>> for QueryDecisions {
    fn from(entries: Vec<(QuerySubject, bool)>) -> Self {
        Self(entries.into_iter().collect())
    }
}

impl From<QueryDecisions> for Vec<(QuerySubject, bool)> {
    fn from(decisions: QueryDecisions) -> Self {
        decisions.0.into_iter().collect()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct QueryState {
    queryable: bool,
    next_query_seq: u32,
    reply_buffer: Vec<u8>,
    decisions: QueryDecisions,
}

impl QueryState {
    fn allocate_query_id(&mut self) -> u64 {
        let seq = self.next_query_seq.max(1);
        self.next_query_seq = seq.saturating_add(1);
        (u64::from(std::process::id()) << 32) | u64::from(seq)
    }
}

#[derive(Clone, Copy)]
pub(super) enum QueryOutcome {
    Allowed,
    Denied,
    Cancelled,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub(super) struct PendingDenials {
    seen: HashSet<String>,
    records: Vec<String>,
}

/// The denial records of one payload run.
///
/// A denial is reported as it happens, except for a read that no root grants:
/// that one is reported when the payload fails, because the failed read is what
/// explains the failure. Only the process the payload started reports those, so
/// a process the payload forks hands its own to it over [`Channel`].
pub(super) struct Denials {
    trap: Option<TrapFd>,
    channel: Channel,
    seen: Mutex<HashSet<String>>,
    pending: Mutex<PendingDenials>,
    query: Mutex<QueryState>,
    /// Whether this process is the one the payload started.
    root: AtomicBool,
    flushed: AtomicBool,
    cancelled: AtomicBool,
}

impl Denials {
    fn read_reply_byte(&self, fd: RawFd) -> io::Result<u8> {
        loop {
            if self.cancelled.load(Ordering::Acquire) {
                return Err(io::Error::from_raw_os_error(libc::ECANCELED));
            }
            let mut byte = 0u8;
            let result = Client::invoke(
                Sysno::read,
                &[
                    i64::from(fd).cast_unsigned(),
                    (&raw mut byte).expose_provenance() as u64,
                    1,
                    0,
                    0,
                    0,
                ],
            );
            match result.cast_signed() {
                1 => return Ok(byte),
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                value if value == -i64::from(libc::EINTR) => {}
                value if value == -i64::from(libc::EAGAIN) => {
                    let mut poll = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let result = Client::invoke(
                        Sysno::ppoll,
                        &[
                            (&raw mut poll).expose_provenance() as u64,
                            1,
                            0,
                            0,
                            WORD_SIZE,
                            0,
                        ],
                    );
                    if result.cast_signed() < 0 && result != Errno::EINTR.negated() {
                        return Err(io::Error::from_raw_os_error(
                            i32::try_from(-result.cast_signed()).unwrap_or(libc::EIO),
                        ));
                    }
                }
                value => {
                    return Err(io::Error::from_raw_os_error(
                        i32::try_from(-value).unwrap_or(libc::EIO),
                    ));
                }
            }
        }
    }
    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(super) fn set_cancelled(&self, value: bool) {
        self.cancelled.store(value, Ordering::Release);
    }

    pub(super) fn keep_channel(
        &self,
        inherit: &mut super::super::handoff::Inherited,
    ) -> Result<[RawFd; 2]> {
        self.channel.keep(inherit)
    }

    pub(super) fn keep_trap(
        &self,
        inherit: &mut super::super::handoff::Inherited,
    ) -> Result<Option<RawFd>> {
        self.trap
            .as_ref()
            .map(|fd| inherit.keep(fd.as_fd()))
            .transpose()
    }

    pub(super) fn seen_snapshot(&self) -> HashSet<String> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(super) fn pending_snapshot(&self) -> PendingDenials {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(super) fn is_root(&self) -> bool {
        self.root.load(Ordering::Relaxed)
    }

    pub(super) fn restore_exec(
        &mut self,
        seen: HashSet<String>,
        pending: PendingDenials,
        query: QueryState,
        root: bool,
    ) {
        *self
            .seen
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = seen;
        *self
            .pending
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = pending;
        *self
            .query
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = query;
        *self.root.get_mut() = root;
    }

    pub(super) fn new(trap: Option<TrapFd>, channel: Channel) -> Self {
        let queryable = trap.as_ref().is_some_and(TrapFd::is_stream_socket);
        Self {
            trap,
            channel,
            seen: Mutex::new(HashSet::new()),
            pending: Mutex::new(PendingDenials::default()),
            query: Mutex::new(QueryState {
                queryable,
                next_query_seq: 1,
                reply_buffer: Vec::new(),
                decisions: QueryDecisions::default(),
            }),
            root: AtomicBool::new(true),
            flushed: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }

    pub(super) fn query_snapshot(&self) -> QueryState {
        self.query
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(super) fn child_clone(&self, query_state: QueryState) -> Result<Self> {
        let trap = self
            .trap
            .as_ref()
            .map(|fd| fd.clone_above(GuestFd::broker_base()))
            .transpose()
            .context("duplicate trap descriptor for child")?;
        let channel = self.channel.clone_above()?;
        let seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Ok(Self {
            trap,
            channel,
            seen: Mutex::new(seen),
            pending: Mutex::new(PendingDenials::default()),
            query: Mutex::new(query_state),
            root: AtomicBool::new(false),
            flushed: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        })
    }

    pub(super) fn can_query(&self) -> bool {
        self.trap.is_some() && self.query_snapshot().queryable
    }

    pub(super) fn release_forked_fds(&self) {
        if let Some(trap) = &self.trap {
            trap.close_for_forked_parent();
        }
        self.channel.release_forked_fds();
    }

    fn emit_unique(&self, record: &str) {
        let inserted = {
            let mut seen = self
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if seen.contains(record) {
                false
            } else {
                seen.insert(record.to_owned())
            }
        };
        if inserted {
            Trap::emit_record(record, self.trap.as_ref());
        }
    }

    fn report(&self, trap: &Trap) {
        self.emit_unique(&trap.to_string());
    }

    /// Hands a refused access to a responder that answers on the trap
    /// descriptor, and reports what happened.
    fn query(&self, denial: &FilesystemDenial) -> QueryOutcome {
        let Some(trap_fd) = self.trap.as_ref() else {
            return QueryOutcome::Denied;
        };
        let subject = QuerySubject::filesystem(denial.operation, &denial.path);
        let mut state = self
            .query
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(&allowed) = state.decisions.0.get(&subject) {
            return if allowed {
                QueryOutcome::Allowed
            } else {
                QueryOutcome::Denied
            };
        }
        if !state.queryable {
            return QueryOutcome::Denied;
        }
        let query_id = state.allocate_query_id();
        let trap = denial.to_trap(Some(query_id));
        self.ask(trap_fd, &mut state, subject, query_id, &trap)
    }

    /// Hands a refused network operation to the responder, and reports what
    /// happened.
    pub(super) fn query_network(
        &self,
        policy: &Policy,
        operation: NetworkOperation,
        target: &str,
    ) -> QueryOutcome {
        let Some(trap_fd) = self.trap.as_ref() else {
            return QueryOutcome::Denied;
        };
        let subject = QuerySubject::network(operation, target);
        let mut state = self
            .query
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(&allowed) = state.decisions.0.get(&subject) {
            return if allowed {
                QueryOutcome::Allowed
            } else {
                QueryOutcome::Denied
            };
        }
        if !state.queryable {
            return QueryOutcome::Denied;
        }
        let query_id = state.allocate_query_id();
        let trap = Trap::network(
            operation,
            target.to_owned(),
            policy.process_context(),
            Some(query_id),
        );
        self.ask(trap_fd, &mut state, subject, query_id, &trap)
    }

    /// Puts a query to the responder and reads the answer that belongs to it.
    fn ask(
        &self,
        trap_fd: &TrapFd,
        state: &mut QueryState,
        subject: QuerySubject,
        query_id: u64,
        trap: &Trap,
    ) -> QueryOutcome {
        // Forked payload processes share the trap descriptor, so the write and
        // the read of one query must not interleave with another process's: a
        // concurrent query can tear a reply line or consume its answer. The
        // record lock is not inherited across `fork`, so a child can never
        // deadlock on a query its parent has in flight.
        let _exclusive = match TrapLock::acquire(trap_fd.as_fd(), &self.cancelled) {
            Ok(guard) => guard,
            Err(error) => {
                if error.raw_os_error() == Some(libc::ECANCELED) {
                    return QueryOutcome::Cancelled;
                }
                log::debug!("kvm: cannot lock the trap descriptor: {error}");
                state.queryable = false;
                return QueryOutcome::Denied;
            }
        };
        if let Err(error) = trap_fd.write(trap) {
            log::debug!("kvm: cannot query the responder: {error}");
            state.queryable = false;
            return QueryOutcome::Denied;
        }
        // A process the payload forked shares the trap descriptor, so answers
        // for its queries arrive here too.
        for _ in 0..MAX_ANSWERS {
            let stanza = match TrapFd::read_stanza(&mut state.reply_buffer, || {
                self.read_reply_byte(trap_fd.as_raw_fd())
            }) {
                Ok(stanza) => stanza,
                Err(error) => {
                    if error.raw_os_error() == Some(libc::ECANCELED) {
                        return QueryOutcome::Cancelled;
                    }
                    log::debug!("kvm: cannot read the responder answer: {error}");
                    state.queryable = false;
                    return QueryOutcome::Denied;
                }
            };
            match stanza.parse::<Reply>() {
                Ok(reply) if reply.query_id == query_id => {
                    let allowed = matches!(reply.action, ReplyAction::Allow);
                    state.decisions.0.insert(subject, allowed);
                    return if allowed {
                        QueryOutcome::Allowed
                    } else {
                        QueryOutcome::Denied
                    };
                }
                Ok(_) => {}
                Err(error) => {
                    log::debug!("kvm: unusable responder answer {stanza:?}: {error}");
                    state.queryable = false;
                    return QueryOutcome::Denied;
                }
            }
        }
        log::debug!("kvm: no answer for query {query_id}");
        state.queryable = false;
        QueryOutcome::Denied
    }

    /// Holds a denial back until the payload's failure can be told.
    fn defer(&self, trap: &Trap) {
        let record = trap.to_string();
        let already_emitted = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&record);
        if already_emitted {
            return;
        }
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending.seen.insert(record.clone()) {
            pending.records.push(record);
        }
    }

    /// Reports the denials the payload's failure leaves unexplained, and drops
    /// them when it succeeded.
    pub(super) fn flush(&self, failed: bool) {
        if self.flushed.swap(true, Ordering::AcqRel) {
            return;
        }
        let passed = self.receive();
        let drained = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.seen.clear();
            if !self.root.load(Ordering::Acquire) {
                if failed {
                    self.channel.send(&pending.records);
                }
                pending.records.clear();
                return;
            }
            if !failed {
                pending.records.clear();
                return;
            }
            std::mem::take(&mut pending.records)
        };
        for record in drained {
            self.emit_unique(&record);
        }
        for record in passed {
            self.emit_unique(&record);
        }
    }

    /// Collects the records the payload's other processes passed on.
    fn receive(&self) -> Vec<String> {
        if !self.root.load(Ordering::Acquire) {
            return Vec::new();
        }
        self.channel.receive()
    }
}

/// Serializes trap queries on a descriptor shared by forked payload
/// processes. An fcntl record lock is held by the process, so fork cannot
/// hand a held lock to a child that would deadlock on it.
struct TrapLock<'fd>(BorrowedFd<'fd>);

#[allow(clippy::cast_possible_truncation)]
impl<'fd> TrapLock<'fd> {
    /// Takes the lock, retrying interruption unless exec retires the worker.
    fn acquire(fd: BorrowedFd<'fd>, cancelled: &AtomicBool) -> io::Result<Self> {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(io::Error::from_raw_os_error(libc::ECANCELED));
            }
            let lock = libc::flock {
                l_type: libc::F_WRLCK as libc::c_short,
                l_whence: libc::SEEK_SET as libc::c_short,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            };
            let locked = Client::invoke(
                Sysno::fcntl,
                &[
                    i64::from(fd.as_raw_fd()).cast_unsigned(),
                    libc::F_SETLKW as u64,
                    (&raw const lock).expose_provenance() as u64,
                    0,
                    0,
                    0,
                ],
            );
            if locked == 0 {
                return Ok(Self(fd));
            }
            let error = io::Error::from_raw_os_error(
                i32::try_from(-locked.cast_signed()).unwrap_or(libc::EIO),
            );
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
impl Drop for TrapLock<'_> {
    fn drop(&mut self) {
        let unlock = libc::flock {
            l_type: libc::F_UNLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        // SAFETY: the descriptor is open while the lock lives; if it were
        // closed, the kernel would have dropped the lock already.
        unsafe { libc::fcntl(self.0.as_raw_fd(), libc::F_SETLK, &unlock) };
    }
}

/// Longest run of answers read while waiting for the one a query names.
const MAX_ANSWERS: u32 = 16;

/// The records a payload's processes hold back for the process it started.
///
/// The broker is shared with the payload, so a forked process inherits the
/// descriptor and passes its records to the process the payload started, which
/// is the one whose failure explains them.
pub(crate) struct Channel {
    reader: BrokerFd,
    writer: BrokerFd,
}

impl Channel {
    pub(crate) fn new() -> Result<Self> {
        let _fd_lock = GuestFd::read_fd_table();
        let (reader, writer) = UnixDatagram::pair().context("create the denial channel")?;
        Ok(Self {
            reader: GuestFd::relocate_above(OwnedFd::from(reader))
                .context("relocate denial channel reader")?,
            writer: GuestFd::relocate_above(OwnedFd::from(writer))
                .context("relocate denial channel writer")?,
        })
    }

    fn release_forked_fds(&self) {
        self.reader.close_for_forked_parent();
        self.writer.close_for_forked_parent();
    }

    pub(super) fn keep(
        &self,
        inherit: &mut super::super::handoff::Inherited,
    ) -> Result<[RawFd; 2]> {
        Ok([
            inherit.keep(self.reader.as_fd())?,
            inherit.keep(self.writer.as_fd())?,
        ])
    }

    pub(super) fn from_exec([reader, writer]: [RawFd; 2], floor: RawFd) -> Result<Self> {
        use super::super::handoff::Inherited;
        Ok(Self {
            reader: Inherited::adopt(reader, floor)?,
            writer: Inherited::adopt(writer, floor)?,
        })
    }

    fn clone_above(&self) -> Result<Self> {
        Ok(Self {
            reader: GuestFd::duplicate_above(self.reader.as_raw_fd())
                .context("duplicate denial channel reader")?,
            writer: GuestFd::duplicate_above(self.writer.as_raw_fd())
                .context("duplicate denial channel writer")?,
        })
    }
    fn send(&self, records: &[String]) {
        for record in records {
            // SAFETY: the descriptor is open, and the record outlives the call.
            let sent = unsafe {
                libc::send(
                    self.writer.as_raw_fd(),
                    record.as_ptr().cast(),
                    record.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 {
                log::debug!(
                    "kvm: cannot pass a denial on: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }

    fn receive(&self) -> Vec<String> {
        let mut records = Vec::new();
        loop {
            // Peek the datagram length so a long denial is not truncated.
            // SAFETY: nothing is read from the null buffer with length 0.
            let length = unsafe {
                libc::recv(
                    self.reader.as_raw_fd(),
                    std::ptr::null_mut(),
                    0,
                    libc::MSG_PEEK | libc::MSG_TRUNC | libc::MSG_DONTWAIT,
                )
            };
            let Ok(length) = usize::try_from(length) else {
                break;
            };
            if length == 0 {
                break;
            }
            let mut buffer = vec![0u8; length];
            // SAFETY: the buffer is writable storage of the length given.
            let received = unsafe {
                libc::recv(
                    self.reader.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            let Ok(count) = usize::try_from(received) else {
                break;
            };
            buffer.truncate(count);
            records.push(String::from_utf8_lossy(&buffer).into_owned());
        }
        records
    }
}

/// What a path argument that names no path refers to.
#[derive(Clone, Copy)]
pub(super) enum Empty {
    /// Nothing the rules can classify: the kernel answers the syscall.
    Nothing,
    /// The directory descriptor once `AT_EMPTY_PATH` is in the flags argument
    /// at `index`.
    Flagged { index: usize },
}

impl Empty {
    fn names_descriptor(self, argument: &[u64; 6], path: &HostCString) -> bool {
        let Self::Flagged { index: flags } = self else {
            return false;
        };
        path.is_empty_non_null() && argument[flags] & AT_EMPTY_PATH != 0
    }
}

/// The object a mediated syscall reaches.
#[derive(Clone, Copy)]
pub(super) enum Target<'a> {
    Path {
        dir: DirBase<'a>,
        path: &'a HostCString,
        follow: bool,
        resolve: ResolveFlags,
        empty: Empty,
        missing: Missing,
    },
    Descriptor(BorrowedFd<'a>),
}

/// One access a syscall needs granted.
pub(super) struct Request<'a> {
    target: Target<'a>,
    access: Access,
    pub(super) flags: Vec<&'static str>,
    /// The flags of an `open`, whose read and write modes are classified
    /// separately.
    open: Option<i32>,
}

impl<'a> Request<'a> {
    pub(super) const fn read(dir: DirBase<'a>, path: &'a HostCString, follow: bool) -> Self {
        Self::path(dir, path, Access::Read, follow).missing(Missing::Kernel)
    }

    pub(super) const fn write_descriptor(fd: BorrowedFd<'a>) -> Self {
        Self::with(Target::Descriptor(fd), Access::Write)
    }

    pub(super) const fn path(
        dir: DirBase<'a>,
        path: &'a HostCString,
        access: Access,
        follow: bool,
    ) -> Self {
        Self::with(
            Target::Path {
                dir,
                path,
                follow,
                resolve: ResolveFlags::empty(),
                empty: Empty::Nothing,
                missing: Missing::Rules,
            },
            access,
        )
    }

    /// Whether the rules classify the entry when it does not exist.
    pub(super) const fn missing(mut self, missing: Missing) -> Self {
        if let Target::Path { missing: slot, .. } = &mut self.target {
            *slot = missing;
        }
        self
    }

    pub(super) const fn resolves(mut self, resolve: ResolveFlags) -> Self {
        if let Target::Path { resolve: slot, .. } = &mut self.target {
            *slot = resolve;
        }
        self
    }

    pub(super) fn open_follows(flags: i32, path: &HostCString, resolve: ResolveFlags) -> bool {
        const CREAT_EXCL: i32 = libc::O_CREAT | libc::O_EXCL;
        if resolve.has_no_symlinks() {
            return false;
        }
        if path.as_bytes().is_some_and(|bytes| bytes.ends_with(b"/")) {
            return true;
        }
        flags & libc::O_NOFOLLOW == 0 && (flags & CREAT_EXCL) != CREAT_EXCL
    }

    /// Describes what a path argument that names no path refers to.
    pub(super) const fn empty(mut self, empty: Empty) -> Self {
        if let Target::Path { empty: slot, .. } = &mut self.target {
            *slot = empty;
        }
        self
    }

    /// Classifies the request as the `open` of `flags` it is.
    pub(super) const fn opens(mut self, flags: i32) -> Self {
        self.open = Some(flags);
        self
    }

    pub(super) const fn with(target: Target<'a>, access: Access) -> Self {
        Self {
            target,
            access,
            flags: Vec::new(),
            open: None,
        }
    }

    pub(super) fn open_flag_names(flags: i32) -> Vec<&'static str> {
        let mut names = vec![match flags & libc::O_ACCMODE {
            libc::O_WRONLY => "O_WRONLY",
            libc::O_RDWR => "O_RDWR",
            _ => "O_RDONLY",
        }];
        for (flag, name) in [
            (libc::O_CREAT, "O_CREAT"),
            (libc::O_EXCL, "O_EXCL"),
            (libc::O_TRUNC, "O_TRUNC"),
            (libc::O_APPEND, "O_APPEND"),
            (libc::O_DIRECTORY, "O_DIRECTORY"),
            (libc::O_NOFOLLOW, "O_NOFOLLOW"),
            (libc::O_PATH, "O_PATH"),
        ] {
            if flags & flag != 0 {
                names.push(name);
            }
        }
        names
    }

    pub(super) fn xattr_access(syscall: Sysno) -> Access {
        if matches!(
            syscall,
            Sysno::getxattr
                | Sysno::lgetxattr
                | Sysno::fgetxattr
                | Sysno::listxattr
                | Sysno::llistxattr
                | Sysno::flistxattr
        ) {
            Access::Read
        } else {
            Access::Write
        }
    }

    pub(super) fn xattr_path(syscall: Sysno, path: &'a HostCString) -> Self {
        let access = Self::xattr_access(syscall);
        let trailing_slash = path.as_bytes().is_some_and(|bytes| bytes.ends_with(b"/"));
        let follow = trailing_slash
            || !matches!(
                syscall,
                Sysno::lsetxattr | Sysno::lgetxattr | Sysno::llistxattr | Sysno::lremovexattr
            );
        let request = Self::path(DirBase::Cwd, path, access, follow);
        match access {
            Access::Read => request.missing(Missing::Kernel),
            Access::Write => request,
        }
    }

    pub(super) fn xattr_fd(syscall: Sysno, fd: BorrowedFd<'a>) -> Self {
        Self::with(Target::Descriptor(fd), Self::xattr_access(syscall))
    }
}

impl Denials {
    /// Refuses an access the policy denied, reporting it when requested.
    ///
    /// Answers with the status to hand back, or `None` when a responder granted
    /// the access and the syscall is to be forwarded.
    pub(super) fn refuse(
        &self,
        policy: &Policy,
        syscall: Sysno,
        denial: policy::Denial,
        flags: Vec<&'static str>,
    ) -> Option<Errno> {
        let record = FilesystemDenial {
            operation: match denial.access {
                Access::Read => TrapOperation::Read,
                Access::Write => TrapOperation::Write,
            },
            path: denial.path,
            requested_path: denial.requested_path,
            syscall: syscall.name(),
            flags,
            reason: denial.reason,
            process: policy.process_context(),
        };
        if denial.queryable {
            match self.query(&record) {
                QueryOutcome::Allowed => return None,
                QueryOutcome::Cancelled => return Some(policy::DENIED),
                QueryOutcome::Denied => {}
            }
        }
        let trap = record.into_trap(None);
        let deferred = matches!(denial.access, Access::Read)
            && matches!(denial.reason, DenialReason::AllowMiss);
        if deferred {
            self.defer(&trap);
        } else {
            self.report(&trap);
        }
        Some(policy::DENIED)
    }

    /// Reports a network operation the policy denied.
    pub(super) fn deny_network(
        &self,
        policy: &Policy,
        operation: NetworkOperation,
        target: String,
    ) {
        let trap = Trap::network(operation, target, policy.process_context(), None);
        self.report(&trap);
    }

    pub(super) fn is_cached_allow(&self, access: Access, path: &std::path::Path) -> bool {
        let operation = match access {
            Access::Read => TrapOperation::Read,
            Access::Write => TrapOperation::Write,
        };
        let subject = QuerySubject::filesystem(operation, path);
        self.query
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .decisions
            .0
            .get(&subject)
            .copied()
            .unwrap_or(false)
    }

    /// Refuses the access `request` names, unless the policy grants it.
    pub(super) fn refuse_target(
        &self,
        policy: &Policy,
        registers: &Regs,
        request: Request<'_>,
    ) -> Option<Errno> {
        let argument = SyscallArgs::raw(registers);
        let denials = match request.target {
            Target::Path {
                dir,
                path,
                follow,
                resolve,
                empty,
                missing,
            } => {
                if empty.names_descriptor(&argument, path) {
                    match request.open {
                        Some(flags) => policy.descriptor_open_denials_at(dir, flags),
                        None => policy
                            .descriptor_denial_at(dir, request.access)
                            .into_iter()
                            .collect(),
                    }
                } else {
                    let path_ref = path.as_path();
                    if path_ref.as_os_str().is_empty() {
                        return None;
                    }
                    match request.open {
                        Some(flags) => {
                            policy.open_denials_at(dir, path_ref, flags, follow, resolve, missing)
                        }
                        None => policy
                            .denial_at(dir, path_ref, request.access, follow, missing)
                            .into_iter()
                            .collect(),
                    }
                }
            }
            Target::Descriptor(fd) => policy
                .borrowed_descriptor_denial(fd, request.access)
                .into_iter()
                .collect(),
        };
        let syscall = registers.syscall()?;
        let mut flags = request.flags;
        let len = denials.len();
        for (idx, denial) in denials.into_iter().enumerate() {
            let item_flags = if idx + 1 == len {
                std::mem::take(&mut flags)
            } else {
                flags.clone()
            };
            if let Some(errno) = self.refuse(policy, syscall, denial, item_flags) {
                return Some(errno);
            }
        }
        None
    }
}
