// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::signals::ForwardSignals;
use super::dbus::DbusProxies;
use super::error::{BrokerError, SysResult};
use super::fs::{FsBroker, MUTATION_SYSCALLS};
use super::grant::Grant;
use super::network::NetBroker;
use super::notify::{NotificationChannel, NotificationResponse, NotificationResult, QueryDecision};
use super::process::TargetProcess;
use crate::error::{Error as LandstripError, Mechanism};
use crate::policy::{AccessPolicy, DenialReason};
use crate::trap::{
    FilesystemDenial, NetworkOperation, ProcessContext, Reply, ReplyAction, Trap, TrapOperation,
};
use crate::trap_fd::TrapFd;
use anyhow::Result;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const POLL_MS: u16 = 100;
const CONTROL_BUFFER_MAX: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) enum QuerySubject {
    FilesystemRead(PathBuf),
    FilesystemWrite(PathBuf),
    NetworkConnect(String),
    NetworkBind(String),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) enum Denial {
    Filesystem(FilesystemDenial),
    Network(NetworkOperation, String, ProcessContext),
}

impl Denial {
    fn subject(&self) -> QuerySubject {
        match self {
            Self::Filesystem(denial) => match denial.operation {
                TrapOperation::Read => QuerySubject::FilesystemRead(denial.path.clone()),
                TrapOperation::Write => QuerySubject::FilesystemWrite(denial.path.clone()),
            },
            Self::Network(NetworkOperation::Connect, target, _) => {
                QuerySubject::NetworkConnect(target.clone())
            }
            Self::Network(NetworkOperation::Bind, target, _) => {
                QuerySubject::NetworkBind(target.clone())
            }
        }
    }

    fn report_on_success(&self) -> bool {
        match self {
            Self::Filesystem(denial) => {
                denial.operation == TrapOperation::Write || denial.reason == DenialReason::DenyMatch
            }
            Self::Network(_, _, _) => true,
        }
    }

    pub(super) fn to_trap(&self, query_id: Option<u64>) -> Trap {
        match self {
            Self::Filesystem(denial) => denial.to_trap(query_id, Mechanism::Seccomp),
            Self::Network(operation, target, process) => Trap::network(
                *operation,
                target.clone(),
                process.clone(),
                query_id,
                Mechanism::Seccomp,
            ),
        }
    }

    pub(super) fn into_trap(self, query_id: Option<u64>) -> Trap {
        match self {
            Self::Filesystem(denial) => denial.into_trap(query_id, Mechanism::Seccomp),
            Self::Network(operation, target, process) => {
                Trap::network(operation, target, process, query_id, Mechanism::Seccomp)
            }
        }
    }
}

impl From<Denial> for Trap {
    fn from(denial: Denial) -> Self {
        denial.into_trap(None)
    }
}

pub(super) struct Denials<'a> {
    trap_fd: Option<&'a TrapFd>,
    query_enabled: bool,
    next_query_id: u64,
    decisions: HashMap<QuerySubject, ReplyAction>,
    seen: HashSet<Denial>,
    pending: Vec<Denial>,
}

impl<'a> Denials<'a> {
    pub(super) fn new(trap_fd: Option<&'a TrapFd>) -> Self {
        Self {
            trap_fd,
            query_enabled: trap_fd.is_some_and(TrapFd::is_stream_socket),
            next_query_id: 1,
            decisions: HashMap::new(),
            seen: HashSet::new(),
            pending: Vec::new(),
        }
    }

    pub(super) fn can_query(&self, allow_query: bool) -> bool {
        self.query_enabled && allow_query
    }

    pub(super) fn control_fd(&self) -> Option<BorrowedFd<'a>> {
        self.trap_fd.filter(|_| self.query_enabled).map(AsFd::as_fd)
    }

    pub(super) fn disable_queries(&mut self) {
        self.query_enabled = false;
    }

    pub(super) fn cache_decision(&mut self, subject: QuerySubject, action: ReplyAction) {
        self.decisions.insert(subject, action);
    }

    pub(super) fn write(&self, trap: &Trap) -> io::Result<()> {
        self.trap_fd.map_or(Ok(()), |trap_fd| trap_fd.write(trap))
    }

    pub(super) fn record(&mut self, denial: Denial) {
        if self.seen.insert(denial.clone()) {
            self.pending.push(denial);
        }
    }

    pub(super) fn deny(
        &mut self,
        denial: Denial,
        allow_query: bool,
        grant: Option<Grant>,
    ) -> SysResult<NotificationResult> {
        self.deny_chain(vec![(denial, allow_query)], grant)
    }

    pub(super) fn deny_chain(
        &mut self,
        items: Vec<(Denial, bool)>,
        grant: Option<Grant>,
    ) -> SysResult<NotificationResult> {
        let mut iter = items.into_iter();
        while let Some((denial, allow_query)) = iter.next() {
            let subject = denial.subject();
            if allow_query {
                match self.decisions.get(&subject).copied() {
                    Some(ReplyAction::Allow) => continue,
                    Some(ReplyAction::Deny) => {
                        self.record(denial);
                        return Err(BrokerError::PolicyDenied);
                    }
                    None if self.query_enabled => {
                        let query_id = self.next_query_id;
                        self.next_query_id = query_id.checked_add(1).ok_or(Errno::EOVERFLOW)?;
                        let trap = denial.to_trap(Some(query_id));
                        return Ok(NotificationResult::Query(Box::new(QueryDecision {
                            query_id,
                            subject,
                            denial,
                            followup: iter.next(),
                            trap,
                            grant,
                        })));
                    }
                    None => {}
                }
            }
            self.record(denial);
            return Err(BrokerError::PolicyDenied);
        }
        Ok(match grant {
            Some(grant) => NotificationResult::Grant(grant),
            None => NotificationResult::Continue,
        })
    }

    pub(super) fn emit(self, status: WaitStatus) -> i32 {
        let code = match status {
            WaitStatus::Exited(_, code) => code,
            WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
            _ => 1,
        };
        let Self {
            trap_fd, pending, ..
        } = self;
        for denial in pending
            .into_iter()
            .filter(|denial| code != 0 || denial.report_on_success())
        {
            Trap::from(denial).emit_with_fd(trap_fd);
        }
        code
    }
}

pub(super) enum HandleResult {
    Respond(libc::seccomp_notif_resp),
    Apply(Grant),
    Pending(Box<QueryDecision>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct NamespaceId {
    device: u64,
    inode: u64,
}

impl TryFrom<&TargetProcess> for NamespaceId {
    type Error = io::Error;

    fn try_from(process: &TargetProcess) -> io::Result<Self> {
        let metadata = fs::metadata(process.proc_path("ns/mnt"))?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl NamespaceId {
    pub(super) fn verify(self, pid: u32) -> SysResult<()> {
        let actual = Self::try_from(&TargetProcess::from_raw(pid))?;
        if actual != self {
            return Err(BrokerError::PolicyDenied);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum SyscallClass {
    Bind,
    Connect,
    Listen,
    Sendto,
    Sendmsg,
    Sendmmsg,
    Open,
    InotifyAddWatch,
    Access,
    Mutation { landlock_backed: bool },
}

impl SyscallClass {
    pub(super) const ACCESS: &[i64] = &[
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_access,
    ];

    pub(super) const FILESYSTEM: &[i64] = &[
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_inotify_add_watch,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_open,
    ];

    pub(super) const DATAGRAM_SEND: &[i64] =
        &[libc::SYS_sendto, libc::SYS_sendmsg, libc::SYS_sendmmsg];

    pub(super) fn notified(
        policy: &AccessPolicy,
        needs_filesystem: bool,
    ) -> impl Iterator<Item = i64> {
        let listen: &[i64] = if policy.network_access.is_unrestricted() {
            &[]
        } else {
            &[libc::SYS_listen]
        };
        let filesystem = if needs_filesystem {
            Self::FILESYSTEM
        } else {
            &[]
        };
        [libc::SYS_bind, libc::SYS_connect]
            .into_iter()
            .chain(listen.iter().copied())
            .chain(Self::ACCESS.iter().copied())
            .chain(Self::DATAGRAM_SEND.iter().copied())
            .chain(filesystem.iter().copied())
            .chain(
                MUTATION_SYSCALLS
                    .iter()
                    .filter(move |spec| needs_filesystem || !spec.landlock_backed)
                    .filter_map(|spec| spec.nr),
            )
    }

    pub(super) fn classify(syscall: i64) -> Option<Self> {
        match syscall {
            libc::SYS_bind => Some(Self::Bind),
            libc::SYS_connect => Some(Self::Connect),
            libc::SYS_listen => Some(Self::Listen),
            libc::SYS_sendto => Some(Self::Sendto),
            libc::SYS_sendmsg => Some(Self::Sendmsg),
            libc::SYS_sendmmsg => Some(Self::Sendmmsg),
            libc::SYS_openat | libc::SYS_openat2 => Some(Self::Open),
            #[cfg(target_arch = "x86_64")]
            libc::SYS_open => Some(Self::Open),
            libc::SYS_inotify_add_watch => Some(Self::InotifyAddWatch),
            libc::SYS_faccessat | libc::SYS_faccessat2 => Some(Self::Access),
            #[cfg(target_arch = "x86_64")]
            libc::SYS_access => Some(Self::Access),
            _ => MUTATION_SYSCALLS
                .iter()
                .find(|spec| spec.nr == Some(syscall))
                .map(|spec| Self::Mutation {
                    landlock_backed: spec.landlock_backed,
                }),
        }
    }
}

struct PendingQuery {
    request: libc::seccomp_notif,
    subject: QuerySubject,
    denial: Denial,
    followup: Option<(Denial, bool)>,
    grant: Option<Grant>,
}

pub(super) struct Supervisor<'a> {
    policy: &'a AccessPolicy,
    child: Pid,
    notify_fd: BorrowedFd<'a>,
    notify: NotificationChannel<'a>,
    notify_filesystem: bool,
    mount_namespace: NamespaceId,
    signals: &'a mut ForwardSignals,
    denials: Denials<'a>,
    pending_queries: HashMap<u64, PendingQuery>,
    read_queue: VecDeque<u8>,
    stanza_buffer: Vec<u8>,
    dbus_proxies: DbusProxies,
    abstract_sockets: HashSet<Vec<u8>>,
}

impl<'a> Supervisor<'a> {
    pub(super) fn new(
        policy: &'a AccessPolicy,
        child: Pid,
        notify_fd: BorrowedFd<'a>,
        notify_filesystem: bool,
        trap_fd: Option<&'a TrapFd>,
        mount_namespace: NamespaceId,
        signals: &'a mut ForwardSignals,
    ) -> Self {
        Self {
            policy,
            child,
            notify_fd,
            notify: NotificationChannel::new(notify_fd),
            notify_filesystem,
            mount_namespace,
            signals,
            denials: Denials::new(trap_fd),
            pending_queries: HashMap::new(),
            read_queue: VecDeque::new(),
            stanza_buffer: Vec::new(),
            dbus_proxies: DbusProxies::new(),
            abstract_sockets: HashSet::new(),
        }
    }

    pub(super) fn run(mut self) -> Result<i32> {
        loop {
            if let Some(status) = self.wait_child(Some(WaitPidFlag::WNOHANG))? {
                return Ok(self.denials.emit(status));
            }

            let control_fd = self.denials.control_fd();
            let revents = self.poll_fds(control_fd)?;
            if revents.iter().all(PollFlags::is_empty) {
                continue;
            }

            if revents[1].intersects(PollFlags::POLLIN) {
                self.signals.process_pending()?;
            }

            if revents[0].intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
            {
                if let Some(status) = self.wait_child(None)? {
                    return Ok(self.denials.emit(status));
                }
                continue;
            }

            if let Some(cfd) = control_fd {
                let dead = if revents[2].intersects(PollFlags::POLLIN) {
                    self.read_control_responses(cfd)
                } else {
                    revents[2]
                        .intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                };
                if dead {
                    self.disconnect_control();
                }
            }

            if !revents[0].intersects(PollFlags::POLLIN) {
                continue;
            }

            let Some((request, handle_result)) = self.receive_notification()? else {
                continue;
            };
            self.finish_request(request, handle_result)?;
        }
    }

    fn finish_request(
        &mut self,
        request: libc::seccomp_notif,
        handle_result: HandleResult,
    ) -> Result<()> {
        match handle_result {
            HandleResult::Respond(response) => {
                if let Err(source) = self.notify.respond(response) {
                    if self.wait_child(Some(WaitPidFlag::WNOHANG))?.is_some() {
                        return Ok(());
                    }
                    return Err(source);
                }
            }
            HandleResult::Pending(decision) => {
                let decision = *decision;
                if let Err(error) = self.denials.write(&decision.trap) {
                    log::debug!("trap query write failed: {error}");
                    self.denials.record(decision.denial);
                    self.disconnect_control();
                    self.notify
                        .respond(NotificationResponse::error(request.id, libc::EACCES))?;
                } else {
                    self.pending_queries.insert(
                        decision.query_id,
                        PendingQuery {
                            request,
                            subject: decision.subject,
                            denial: decision.denial,
                            followup: decision.followup,
                            grant: decision.grant,
                        },
                    );
                }
            }
            HandleResult::Apply(grant) => {
                grant.apply(
                    self.policy,
                    &mut self.dbus_proxies,
                    &mut self.abstract_sockets,
                    self.notify,
                    request.id,
                );
            }
        }
        Ok(())
    }

    fn wait_child(&self, options: Option<WaitPidFlag>) -> Result<Option<WaitStatus>> {
        loop {
            match waitpid(self.child, options) {
                Ok(WaitStatus::StillAlive) => return Ok(None),
                Ok(status) => return Ok(Some(status)),
                Err(Errno::EINTR) => {}
                Err(error) => return Err(LandstripError::supervise_errno(error).into()),
            }
        }
    }

    fn handle_request(&mut self, request: &libc::seccomp_notif) -> HandleResult {
        let syscall = i64::from(request.data.nr);
        let result = match SyscallClass::classify(syscall) {
            Some(SyscallClass::Bind) => {
                NetBroker::handle_bind(self.policy, request, &mut self.denials)
            }
            Some(SyscallClass::Connect) => NetBroker::handle_connect(
                self.policy,
                self.dbus_proxies.is_available(),
                &self.abstract_sockets,
                request,
                &mut self.denials,
            ),
            Some(SyscallClass::Listen) => NetBroker::handle_listen(self.policy, request),
            Some(SyscallClass::Sendto) => NetBroker::handle_sendto(
                self.policy,
                &self.abstract_sockets,
                request,
                &mut self.denials,
            ),
            Some(SyscallClass::Sendmsg) => NetBroker::handle_sendmsg(
                self.policy,
                &self.abstract_sockets,
                request,
                &mut self.denials,
            ),
            Some(SyscallClass::Sendmmsg) => NetBroker::handle_sendmmsg(
                self.policy,
                &self.abstract_sockets,
                request,
                &mut self.denials,
            ),
            Some(SyscallClass::Open) if self.notify_filesystem => {
                FsBroker::handle_openat(self.policy, request, &mut self.denials)
            }
            Some(SyscallClass::InotifyAddWatch) if self.notify_filesystem => {
                FsBroker::handle_inotify_add_watch(self.policy, request, &mut self.denials)
            }
            Some(SyscallClass::Access) => {
                FsBroker::handle_access(self.policy, request, &mut self.denials)
            }
            Some(SyscallClass::Mutation { landlock_backed })
                if self.notify_filesystem || !landlock_backed =>
            {
                FsBroker::handle_mutation(self.policy, request, &mut self.denials)
            }
            Some(
                SyscallClass::Open | SyscallClass::InotifyAddWatch | SyscallClass::Mutation { .. },
            )
            | None => Ok(NotificationResult::Continue),
        };
        Self::result_to_handle(request.id, result)
    }

    fn result_to_handle(id: u64, result: SysResult<NotificationResult>) -> HandleResult {
        match result {
            Ok(NotificationResult::Continue) => {
                HandleResult::Respond(NotificationResponse::continue_syscall(id))
            }
            Ok(NotificationResult::Grant(grant)) => HandleResult::Apply(grant),
            Ok(NotificationResult::Query(decision)) => HandleResult::Pending(decision),
            Err(error) => HandleResult::Respond(NotificationResponse::error(id, error.errno())),
        }
    }

    fn receive_notification(&mut self) -> Result<Option<(libc::seccomp_notif, HandleResult)>> {
        let Some(request) = self.notify.receive()? else {
            return Ok(None);
        };
        if !self.notify.is_id_valid(request.id)? {
            return Ok(None);
        }
        let handle_result = match self.mount_namespace.verify(request.pid) {
            Ok(()) => self.handle_request(&request),
            Err(error) => {
                HandleResult::Respond(NotificationResponse::error(request.id, error.errno()))
            }
        };
        if !self.notify.is_id_valid(request.id)? {
            return Ok(None);
        }
        Ok(Some((request, handle_result)))
    }

    fn poll_fds(&self, control: Option<BorrowedFd<'_>>) -> Result<[PollFlags; 3]> {
        let len = if control.is_some() { 3 } else { 2 };
        let mut poll_fds = [
            PollFd::new(self.notify_fd, PollFlags::POLLIN),
            PollFd::new(self.signals.as_fd(), PollFlags::POLLIN),
            PollFd::new(control.unwrap_or(self.notify_fd), PollFlags::POLLIN),
        ];
        loop {
            match poll(&mut poll_fds[..len], POLL_MS) {
                Ok(0) => return Ok([PollFlags::empty(); 3]),
                Ok(_) => {
                    return Ok([
                        poll_fds[0].revents().unwrap_or_else(PollFlags::empty),
                        poll_fds[1].revents().unwrap_or_else(PollFlags::empty),
                        if control.is_some() {
                            poll_fds[2].revents().unwrap_or_else(PollFlags::empty)
                        } else {
                            PollFlags::empty()
                        },
                    ]);
                }
                Err(Errno::EINTR) => {}
                Err(error) => return Err(LandstripError::supervise_errno(error).into()),
            }
        }
    }

    fn read_control_responses(&mut self, control_fd: BorrowedFd<'_>) -> bool {
        let mut chunk = [0u8; 4096];
        let n = loop {
            let n = unsafe {
                libc::read(
                    control_fd.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break n;
        };
        if n == 0 {
            return true;
        }
        if n < 0 {
            return io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock;
        }
        let Ok(n) = usize::try_from(n) else {
            return true;
        };
        if self.read_queue.len() + self.stanza_buffer.len() + n > CONTROL_BUFFER_MAX {
            self.read_queue.clear();
            self.stanza_buffer.clear();
            return true;
        }
        self.read_queue.extend(&chunk[..n]);

        loop {
            let stanza = TrapFd::read_stanza(&mut self.stanza_buffer, || {
                self.read_queue
                    .pop_front()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
            });
            let stanza = match stanza {
                Ok(stanza) => stanza,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return false,
                Err(_) => return true,
            };
            let Ok(reply) = stanza.parse::<Reply>() else {
                return true;
            };
            let Some(pending) = self.pending_queries.remove(&reply.query_id) else {
                continue;
            };
            self.denials.cache_decision(pending.subject, reply.action);
            let id = pending.request.id;
            if !self.notify.is_id_valid(id).unwrap_or(false) {
                continue;
            }
            match reply.action {
                ReplyAction::Allow => {
                    if let Some((next_denial, next_allow_query)) = pending.followup {
                        let next_result = self
                            .denials
                            .deny_chain(vec![(next_denial, next_allow_query)], pending.grant);
                        let handle = Self::result_to_handle(id, next_result);
                        let _ = self.finish_request(pending.request, handle);
                    } else if let Some(grant) = pending.grant {
                        grant.apply(
                            self.policy,
                            &mut self.dbus_proxies,
                            &mut self.abstract_sockets,
                            self.notify,
                            id,
                        );
                    } else {
                        let _ = self
                            .notify
                            .respond(NotificationResponse::continue_syscall(id));
                    }
                }
                ReplyAction::Deny => {
                    self.denials.record(pending.denial);
                    let _ = self
                        .notify
                        .respond(NotificationResponse::error(id, libc::EACCES));
                }
            }
        }
    }

    fn disconnect_control(&mut self) {
        for (_id, pending) in self.pending_queries.drain() {
            self.denials.record(pending.denial);
            let id = pending.request.id;
            if self.notify.is_id_valid(id).unwrap_or(false) {
                let _ = self
                    .notify
                    .respond(NotificationResponse::error(id, libc::EACCES));
            }
        }
        self.denials.disable_queries();
    }
}
