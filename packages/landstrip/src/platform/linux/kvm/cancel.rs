// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! The outer supervisor interrupts blocked guest syscalls without reserving a
//! signal or unwinding a Rust worker. Exec first attaches every worker, then
//! requests cancellation; each worker detaches before acknowledging retirement.
//! The syscall return label distinguishes guest operations from Rust/libc's own
//! synchronization, which must remain usable until workers return and join.
//!
//! The supervisor also watches the exit of each thread with a robust list,
//! without tracing its syscalls, to release the guest locks of a thread
//! killed by a fatal signal. A retiring worker then keeps its watch.
use super::ErrnoExt;
use super::fds::{BrokerHandle, GuestFd};
use super::robust::NativeHead;
use anyhow::{Context, Result, bail};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::sync::Mutex;
use syscalls::{Errno, Sysno};

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".pushsection .text",
    ".global landstrip_broker_syscall",
    ".hidden landstrip_broker_syscall",
    "landstrip_broker_syscall:",
    "mov rax, rdi",
    "mov r11, rsi",
    "mov rdi, [r11]",
    "mov rsi, [r11 + 8]",
    "mov rdx, [r11 + 16]",
    "mov r10, [r11 + 24]",
    "mov r8, [r11 + 32]",
    "mov r9, [r11 + 40]",
    "syscall",
    ".global landstrip_broker_syscall_return",
    ".hidden landstrip_broker_syscall_return",
    "landstrip_broker_syscall_return:",
    "ret",
    ".popsection",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".pushsection .text",
    ".global landstrip_broker_syscall",
    ".hidden landstrip_broker_syscall",
    "landstrip_broker_syscall:",
    "mov x8, x0",
    "mov x9, x1",
    "ldp x0, x1, [x9]",
    "ldp x2, x3, [x9, #16]",
    "ldp x4, x5, [x9, #32]",
    "svc #0",
    ".global landstrip_broker_syscall_return",
    ".hidden landstrip_broker_syscall_return",
    "landstrip_broker_syscall_return:",
    "ret",
    ".popsection",
);

unsafe extern "C" {
    fn landstrip_broker_syscall(number: libc::c_long, arguments: *const u64) -> u64;
    fn landstrip_broker_syscall_return();
}

pub(super) struct PendingClient {
    request: UnixDatagram,
    response: UnixDatagram,
    reply: UnixDatagram,
}

impl PendingClient {
    pub(super) fn relocate_above(self) -> Result<Client> {
        let relocate = |sock: UnixDatagram| -> io::Result<BrokerHandle<UnixDatagram>> {
            GuestFd::relocate_above(OwnedFd::from(sock))
                .map(|fd| fd.map_same_fd(UnixDatagram::from))
        };
        Ok(Client {
            request: relocate(self.request)?,
            response: Mutex::new(relocate(self.response)?),
            reply: relocate(self.reply)?,
        })
    }
}

pub(super) struct Client {
    request: BrokerHandle<UnixDatagram>,
    response: Mutex<BrokerHandle<UnixDatagram>>,
    reply: BrokerHandle<UnixDatagram>,
}

struct Trace {
    process: i32,
    reply: Option<UnixDatagram>,
    /// Present while exec cancellation traces the syscalls of this thread.
    cancel: Option<Cancel>,
    /// Whether the exit of this thread releases its guest robust list.
    watch: bool,
    /// Set once `PTRACE_EVENT_EXIT` has been observed for this thread.
    exiting: bool,
    /// Set when tracing of this thread is being torn down asynchronously.
    detaching: bool,
}

struct Cancel {
    return_pc: u64,
    cancelling: bool,
    skipped: bool,
}

pub(super) struct Supervisor {
    socket: UnixDatagram,
    traced: BTreeMap<i32, Trace>,
    root: i32,
    exited: Option<i32>,
}

impl Client {
    pub(super) fn pair() -> Result<(UnixDatagram, PendingClient)> {
        let (server, request) = UnixDatagram::pair()?;
        let enabled: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&raw const enabled).cast(),
                libc::socklen_t::try_from(std::mem::size_of_val(&enabled))?,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("enable cancellation credentials");
        }
        let (response, reply) = UnixDatagram::pair()?;
        Ok((
            server,
            PendingClient {
                request,
                response,
                reply,
            },
        ))
    }

    fn socket_pair() -> Result<(BrokerHandle<UnixDatagram>, BrokerHandle<UnixDatagram>)> {
        let _fd_lock = GuestFd::read_fd_table();
        let (left, right) = UnixDatagram::pair()?;
        Ok((
            GuestFd::relocate_above(OwnedFd::from(left))?.map_same_fd(UnixDatagram::from),
            GuestFd::relocate_above(OwnedFd::from(right))?.map_same_fd(UnixDatagram::from),
        ))
    }

    pub(super) fn release_forked_fds(&self) {
        self.request.close_for_forked_parent();
        if let Ok(response) = self.response.try_lock() {
            response.close_for_forked_parent();
        }
        self.reply.close_for_forked_parent();
    }

    pub(super) fn child_clone(&self) -> Result<Self> {
        let request =
            GuestFd::duplicate_above(self.request.as_raw_fd())?.map_same_fd(UnixDatagram::from);
        let (response, reply) = Self::socket_pair()?;
        Ok(Self {
            request,
            response: Mutex::new(response),
            reply,
        })
    }

    pub(super) fn exec_descriptors(
        &self,
        inherited: &mut super::handoff::Inherited,
    ) -> Result<[libc::c_int; 3]> {
        let response = self
            .response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok([
            inherited.keep(self.request.as_fd())?,
            inherited.keep(response.as_fd())?,
            inherited.keep(self.reply.as_fd())?,
        ])
    }

    pub(super) fn from_exec(
        [request, response, reply]: [libc::c_int; 3],
        floor: libc::c_int,
    ) -> Result<Self> {
        use super::handoff::Inherited;
        Ok(Self {
            request: Inherited::adopt(request, floor)?.map_same_fd(UnixDatagram::from),
            response: Mutex::new(
                Inherited::adopt(response, floor)?.map_same_fd(UnixDatagram::from),
            ),
            reply: Inherited::adopt(reply, floor)?.map_same_fd(UnixDatagram::from),
        })
    }

    pub(super) fn invoke(syscall: Sysno, arguments: &[u64; 6]) -> u64 {
        unsafe { landstrip_broker_syscall(libc::c_long::from(syscall.id()), arguments.as_ptr()) }
    }

    pub(super) fn request(&self, request: Request<'_>) -> Result<()> {
        let response = self
            .response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let message = request.encode();
        let descriptors = [self.reply.as_raw_fd()];
        let length = sendmsg::<()>(
            self.request.as_raw_fd(),
            &[IoSlice::new(&message)],
            &[ControlMessage::ScmRights(&descriptors)],
            MsgFlags::empty(),
            None,
        )?;
        if length != message.len() {
            bail!("short cancellation request");
        }
        let mut reply = [0u8; 4];
        loop {
            match response.get().recv(&mut reply) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => {
                    if result? != reply.len() {
                        bail!("short cancellation reply");
                    }
                    break;
                }
            }
        }
        let errno = i32::from_ne_bytes(reply);
        if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno)).context("cancel guest workers");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) enum Request<'a> {
    Attach(&'a [u64]),
    Interrupt,
    Retire(u64),
    WatchRobust(u64),
}

#[derive(Clone, Copy)]
enum Command<'a> {
    Attach { return_pc: u64, tids: &'a [u64] },
    Interrupt,
    Retire(u64),
    WatchRobust(u64),
}

impl Request<'_> {
    const TAG_ATTACH: u8 = 0;
    const TAG_INTERRUPT: u8 = 1;
    const TAG_RETIRE: u8 = 2;
    const TAG_WATCH_ROBUST: u8 = 3;

    fn encode(self) -> Vec<u8> {
        match self {
            Self::Attach(tids) => {
                let mut message = Vec::with_capacity(1 + (1 + tids.len()) * 8);
                message.push(Self::TAG_ATTACH);
                let return_pc = landstrip_broker_syscall_return as *const () as u64;
                message.extend_from_slice(&return_pc.to_ne_bytes());
                for tid in tids {
                    message.extend_from_slice(&tid.to_ne_bytes());
                }
                message
            }
            Self::Interrupt => vec![Self::TAG_INTERRUPT],
            Self::Retire(tid) => {
                let mut message = Vec::with_capacity(9);
                message.push(Self::TAG_RETIRE);
                message.extend_from_slice(&tid.to_ne_bytes());
                message
            }
            Self::WatchRobust(tid) => {
                let mut message = Vec::with_capacity(9);
                message.push(Self::TAG_WATCH_ROBUST);
                message.extend_from_slice(&tid.to_ne_bytes());
                message
            }
        }
    }
}

impl<'a> Command<'a> {
    fn decode(tag: u8, arguments: &'a [u64]) -> Result<Self> {
        match tag {
            Request::TAG_ATTACH => {
                let (&return_pc, tids) = arguments
                    .split_first()
                    .context("missing broker return PC")?;
                Ok(Self::Attach { return_pc, tids })
            }
            Request::TAG_INTERRUPT => {
                if !arguments.is_empty() {
                    bail!("unexpected interrupt arguments");
                }
                Ok(Self::Interrupt)
            }
            Request::TAG_RETIRE => {
                let &[tid] = arguments else {
                    bail!("missing retired TID");
                };
                Ok(Self::Retire(tid))
            }
            Request::TAG_WATCH_ROBUST => {
                let &[tid] = arguments else {
                    bail!("missing robust TID");
                };
                Ok(Self::WatchRobust(tid))
            }
            _ => bail!("unknown cancellation operation"),
        }
    }
}

impl Supervisor {
    pub(super) fn new(socket: UnixDatagram, root: i32) -> Self {
        Self {
            socket,
            root,
            traced: BTreeMap::new(),
            exited: None,
        }
    }
    pub(super) fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.socket.as_fd()
    }

    pub(super) fn take_exit(&mut self) -> Option<i32> {
        self.exited.take()
    }

    fn ptrace(request: impl Into<i64>, tid: i32, data: usize) -> io::Result<()> {
        let request = request.into().try_into().map_err(io::Error::other)?;
        if unsafe { libc::ptrace(request, tid, 0usize, data) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn is_esrch(error: &anyhow::Error) -> bool {
        error
            .downcast_ref::<io::Error>()
            .is_some_and(|io_err| io_err.raw_os_error() == Some(libc::ESRCH))
    }

    fn host_tid(pid: i32, tid: u64) -> Result<i32> {
        let tasks = std::path::Path::new("/proc")
            .join(pid.to_string())
            .join("task");
        let entries = match std::fs::read_dir(tasks) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::from_raw_os_error(libc::ESRCH).into());
            }
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let Ok(status) = std::fs::read(entry.path().join("status")) else {
                continue;
            };
            // Linux truncates comm in bytes, so the Name field need not be UTF-8.
            if status
                .split(|&byte| byte == b'\n')
                .find_map(|line| line.strip_prefix(b"NSpid:"))
                .and_then(|ids| {
                    ids.rsplit(u8::is_ascii_whitespace)
                        .find(|id| !id.is_empty())
                })
                .and_then(|id| std::str::from_utf8(id).ok())
                .and_then(|id| id.parse::<u64>().ok())
                == Some(tid)
            {
                return Ok(entry.file_name().to_string_lossy().parse()?);
            }
        }
        Err(io::Error::from_raw_os_error(libc::ESRCH).into())
    }

    pub(super) fn receive(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; 65536];
        let mut ancillary = nix::cmsg_space!(libc::ucred, [libc::c_int; 1]);
        let mut slices = [IoSliceMut::new(&mut buffer)];
        let msg = recvmsg::<()>(
            self.socket.as_raw_fd(),
            &mut slices,
            Some(&mut ancillary),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )?;
        let length = msg.bytes;
        let truncated = msg
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
        let mut pid = None;
        let mut replies = Vec::new();
        for cmsg in msg.cmsgs()? {
            match cmsg {
                ControlMessageOwned::ScmCredentials(cred) => pid = Some(cred.pid()),
                ControlMessageOwned::ScmRights(fds) => {
                    replies.extend(
                        fds.into_iter()
                            .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
                    );
                }
                _ => {}
            }
        }
        let pid = pid.context("missing cancellation credentials")?;
        if truncated || length == 0 || (length - 1) % 8 != 0 || replies.len() != 1 {
            bail!("invalid cancellation request");
        }
        let reply = UnixDatagram::from(replies.pop().context("missing cancellation reply socket")?);
        let arguments = buffer[1..length]
            .chunks_exact(8)
            .map(|raw| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(raw);
                u64::from_ne_bytes(bytes)
            })
            .collect::<Vec<_>>();
        let result =
            Command::decode(buffer[0], &arguments).and_then(|command| self.command(command, pid));
        match result {
            Ok(Some(host)) => {
                self.traced
                    .get_mut(&host)
                    .context("missing retiring worker")?
                    .reply = Some(reply);
            }
            Ok(None) => Self::respond(&reply, 0)?,
            Err(error) => {
                self.detach_process(pid)?;
                Self::respond(
                    &reply,
                    error
                        .downcast_ref::<io::Error>()
                        .and_then(io::Error::raw_os_error)
                        .unwrap_or(libc::EIO),
                )?;
            }
        }
        Ok(())
    }

    fn respond(socket: &UnixDatagram, errno: i32) -> Result<()> {
        match socket.send(&errno.to_ne_bytes()) {
            Ok(_) => Ok(()),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ECONNREFUSED | libc::EPIPE | libc::ENOTCONN)
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Traces `host`, which may already be traced for the other purpose.
    fn trace(&mut self, pid: i32, host: i32) -> Result<&mut Trace> {
        Ok(match self.traced.entry(host) {
            Entry::Occupied(trace) => trace.into_mut(),
            Entry::Vacant(vacant) => {
                Self::ptrace(
                    libc::PTRACE_SEIZE,
                    host,
                    (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACEEXIT) as usize,
                )?;
                vacant.insert(Trace {
                    process: pid,
                    reply: None,
                    cancel: None,
                    watch: false,
                    exiting: false,
                    detaching: false,
                })
            }
        })
    }

    fn command(&mut self, command: Command<'_>, pid: i32) -> Result<Option<i32>> {
        match command {
            Command::Attach { return_pc, tids } => {
                for tid in tids {
                    let host = match Self::host_tid(pid, *tid) {
                        Ok(host) => host,
                        Err(error) if Self::is_esrch(&error) => continue,
                        Err(error) => return Err(error),
                    };
                    match self.trace(pid, host) {
                        Ok(trace) => {
                            if !trace.exiting && !trace.detaching {
                                trace.cancel.get_or_insert(Cancel {
                                    return_pc,
                                    cancelling: false,
                                    skipped: false,
                                });
                            }
                        }
                        Err(error) if Self::is_esrch(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            Command::Interrupt => {
                for (&tid, trace) in &mut self.traced {
                    if trace.process != pid || trace.exiting || trace.detaching {
                        continue;
                    }
                    let Some(cancel) = trace.cancel.as_mut() else {
                        continue;
                    };
                    cancel.cancelling = true;
                    match Self::ptrace(libc::PTRACE_INTERRUPT, tid, 0) {
                        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
                        result => result?,
                    }
                }
            }
            Command::Retire(tid) => {
                let host = match Self::host_tid(pid, tid) {
                    Ok(host) => host,
                    Err(error) if Self::is_esrch(&error) => return Ok(None),
                    Err(error) => return Err(error),
                };
                if self
                    .traced
                    .get(&host)
                    .is_some_and(|trace| !trace.exiting && !trace.detaching)
                {
                    match Self::ptrace(libc::PTRACE_INTERRUPT, host, 0) {
                        Ok(()) => return Ok(Some(host)),
                        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                            return Ok(None);
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            Command::WatchRobust(tid) => {
                let host = match Self::host_tid(pid, tid) {
                    Ok(host) => host,
                    Err(error) if Self::is_esrch(&error) => return Ok(None),
                    Err(error) => return Err(error),
                };
                match self.trace(pid, host) {
                    Ok(trace) => {
                        if !trace.detaching {
                            trace.watch = true;
                        }
                    }
                    Err(error) if Self::is_esrch(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(None)
    }

    fn detach_process(&mut self, pid: i32) -> Result<()> {
        for (&tid, trace) in &mut self.traced {
            if trace.process != pid {
                continue;
            }
            trace.cancel = None;
            trace.watch = false;
            trace.detaching = true;
            if !trace.exiting {
                match Self::ptrace(libc::PTRACE_INTERRUPT, tid, 0) {
                    Ok(()) => {}
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        self.progress()
    }

    pub(super) fn progress(&mut self) -> Result<()> {
        let tids = self.traced.keys().copied().collect::<Vec<_>>();
        for tid in tids {
            loop {
                let mut status = 0;
                let rc =
                    unsafe { libc::waitpid(tid, &raw mut status, libc::__WALL | libc::WNOHANG) };
                if rc == 0 {
                    break;
                }
                if rc < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        self.traced.remove(&tid);
                        break;
                    }
                    return Err(error.into());
                }
                if !libc::WIFSTOPPED(status) {
                    self.traced.remove(&tid);
                    if tid == self.root {
                        self.exited = Some(status);
                    }
                    break;
                }
                if !self.handle_stopped(tid, status)? {
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_stopped(&mut self, tid: i32, status: i32) -> Result<bool> {
        let event = status >> 16;
        if event == libc::PTRACE_EVENT_EXIT {
            let watch = if let Some(trace) = self.traced.get_mut(&tid) {
                trace.exiting = true;
                if let Some(reply) = trace.reply.take() {
                    Self::respond(&reply, 0)?;
                }
                trace.watch
            } else {
                false
            };
            if watch {
                Self::release_robust_list(tid);
            }
            self.resume_alive(tid, 0)?;
            return Ok(true);
        }
        if self.traced.get(&tid).is_some_and(|trace| trace.detaching) {
            if let Some(reply) = self.traced.get_mut(&tid).and_then(|t| t.reply.take()) {
                Self::respond(&reply, libc::EIO)?;
            }
            return match Self::ptrace(libc::PTRACE_DETACH, tid, 0) {
                Ok(()) => {
                    self.traced.remove(&tid);
                    Ok(false)
                }
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(true),
                Err(error) => Err(error.into()),
            };
        }
        if self.traced[&tid].reply.is_some() {
            return self.complete_retirement(tid);
        }
        let signal = libc::WSTOPSIG(status);
        if event == libc::PTRACE_EVENT_STOP
            && self.traced[&tid].cancel.is_none()
            && matches!(
                signal,
                libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
            )
        {
            // Keep a group-stop until `SIGCONT`.
            match Self::ptrace(libc::PTRACE_LISTEN, tid, 0) {
                Ok(()) => return Ok(true),
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(true),
                Err(error) => return Err(error.into()),
            }
        }
        if signal == (libc::SIGTRAP | 0x80) || event == libc::PTRACE_EVENT_STOP {
            if let Some(cancel) = self
                .traced
                .get_mut(&tid)
                .and_then(|trace| trace.cancel.as_mut())
                .filter(|cancel| cancel.cancelling)
            {
                let phase = match Self::syscall_phase(tid) {
                    Ok(phase) => phase,
                    Err(error) if Self::is_esrch(&error) => return Ok(true),
                    Err(error) => return Err(error),
                };
                match Self::interrupt_syscall(tid, phase, cancel) {
                    Ok(skipped) => cancel.skipped = skipped,
                    Err(error) if Self::is_esrch(&error) => return Ok(true),
                    Err(error) => return Err(error),
                }
            }
            self.resume_alive(tid, 0)?;
        } else {
            self.resume_alive(tid, signal)?;
        }
        Ok(true)
    }

    fn complete_retirement(&mut self, tid: i32) -> Result<bool> {
        let trace = self
            .traced
            .get_mut(&tid)
            .context("missing retiring worker")?;
        let reply = trace.reply.take().context("missing retirement reply")?;
        if trace.watch {
            trace.cancel = None;
            return match Self::ptrace(libc::PTRACE_CONT, tid, 0) {
                Ok(()) => {
                    Self::respond(&reply, 0)?;
                    Ok(true)
                }
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                    Self::respond(&reply, 0)?;
                    Ok(true)
                }
                Err(error) => Err(error.into()),
            };
        }
        match Self::ptrace(libc::PTRACE_DETACH, tid, 0) {
            Ok(()) => {
                self.traced.remove(&tid);
                Self::respond(&reply, 0)?;
                Ok(false)
            }
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                Self::respond(&reply, 0)?;
                Ok(true)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn resume_alive(&self, tid: i32, signal: i32) -> Result<()> {
        match self.resume(tid, signal) {
            Ok(()) => Ok(()),
            Err(error) if Self::is_esrch(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn resume(&self, tid: i32, signal: i32) -> Result<()> {
        let request = if self.traced[&tid].cancel.is_some() {
            libc::PTRACE_SYSCALL
        } else {
            libc::PTRACE_CONT
        };
        Ok(Self::ptrace(request, tid, usize::try_from(signal)?)?)
    }

    /// Mirrors the guest robust list of a thread stopped at exit into its
    /// native list. Like the kernel, it silently gives up on any failure.
    fn release_robust_list(tid: i32) {
        let mut native = 0u64;
        let mut length = 0usize;
        // SAFETY: both outputs are valid local variables.
        let failed = unsafe {
            syscalls::syscall!(
                Sysno::get_robust_list,
                tid.cast_unsigned() as usize,
                (&raw mut native).expose_provenance(),
                (&raw mut length).expose_provenance()
            )
        }
        .is_err();
        let mut head = NativeHead::default();
        if failed
            || native == 0
            || !Self::transfer(
                tid,
                native,
                (&raw mut head).cast(),
                size_of::<NativeHead>(),
                false,
            )
        {
            return;
        }
        let read = |address: u64| {
            let mut word = 0u64;
            Self::transfer(tid, address, (&raw mut word).cast(), 8, false).then_some(word)
        };
        for (address, mut value) in head.exit_writes(native, read) {
            if !Self::transfer(tid, address, (&raw mut value).cast(), 8, true) {
                return;
            }
        }
    }

    /// Copies `length` bytes between `local` and `remote` in thread `tid`.
    fn transfer(
        tid: i32,
        remote: u64,
        local: *mut libc::c_void,
        length: usize,
        write: bool,
    ) -> bool {
        let Ok(address) = usize::try_from(remote) else {
            return false;
        };
        let local = libc::iovec {
            iov_base: local,
            iov_len: length,
        };
        let remote = libc::iovec {
            iov_base: std::ptr::without_provenance_mut(address),
            iov_len: length,
        };
        // SAFETY: `local` is valid for `length` bytes; the kernel checks `remote`.
        let copied = unsafe {
            if write {
                libc::process_vm_writev(tid, &raw const local, 1, &raw const remote, 1, 0)
            } else {
                libc::process_vm_readv(tid, &raw const local, 1, &raw const remote, 1, 0)
            }
        };
        usize::try_from(copied).ok() == Some(length)
    }

    fn syscall_phase(tid: i32) -> Result<u8> {
        let mut info = [0u8; 88];
        let result = unsafe { libc::ptrace(0x420e, tid, info.len(), info.as_mut_ptr()) };
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(info[0])
    }
    #[cfg(target_arch = "x86_64")]
    fn interrupt_syscall(tid: i32, phase: u8, cancel: &Cancel) -> Result<bool> {
        let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        if unsafe { libc::ptrace(libc::PTRACE_GETREGS, tid, 0usize, &raw mut registers) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let broker = registers.rip == cancel.return_pc;
        let kvm = registers.orig_rax == Sysno::ioctl as u64 && registers.rsi == 0xae80;
        let futex_wake = (registers.orig_rax == Sysno::futex as u64
            && registers.rsi & 0x7f == libc::FUTEX_WAKE as u64)
            || registers.orig_rax == Sysno::futex_wake as u64;
        let eligible = (broker && !futex_wake) || kvm;
        let restarting = matches!(
            usize::try_from(registers.rax).map(Errno::from_ret),
            Ok(Err(Errno::ERESTARTSYS
                | Errno::ERESTARTNOINTR
                | Errno::ERESTARTNOHAND
                | Errno::ERESTART_RESTARTBLOCK))
        );
        if phase == 2 && cancel.skipped || eligible && (phase == 1 || restarting) {
            registers.orig_rax = u64::MAX;
            registers.rax = Errno::EINTR.negated();
            if unsafe { libc::ptrace(libc::PTRACE_SETREGS, tid, 0usize, &raw const registers) } < 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(if phase == 0 {
            cancel.skipped
        } else {
            eligible && phase == 1
        })
    }

    #[cfg(target_arch = "aarch64")]
    fn interrupt_syscall(tid: i32, phase: u8, cancel: &Cancel) -> Result<bool> {
        let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: (&raw mut registers).cast(),
            iov_len: std::mem::size_of_val(&registers),
        };
        if unsafe { libc::ptrace(libc::PTRACE_GETREGSET, tid, 1usize, &raw mut vector) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let broker = registers.pc == cancel.return_pc;
        let kvm = registers.regs[8] == Sysno::ioctl as u64 && registers.regs[1] == 0xae80;
        let futex_wake = (registers.regs[8] == Sysno::futex as u64
            && registers.regs[1] & 0x7f == libc::FUTEX_WAKE as u64)
            || registers.regs[8] == Sysno::futex_wake as u64;
        let eligible = (broker && !futex_wake) || kvm;
        let restarting = matches!(
            usize::try_from(registers.regs[0]).map(Errno::from_ret),
            Ok(Err(Errno::ERESTARTSYS
                | Errno::ERESTARTNOINTR
                | Errno::ERESTARTNOHAND
                | Errno::ERESTART_RESTARTBLOCK))
        );
        if phase == 2 && cancel.skipped || eligible && (phase == 1 || restarting) {
            let mut number = -1i32;
            let mut syscall = libc::iovec {
                iov_base: (&raw mut number).cast(),
                iov_len: std::mem::size_of_val(&number),
            };
            if unsafe { libc::ptrace(libc::PTRACE_SETREGSET, tid, 0x404usize, &raw mut syscall) }
                < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            registers.regs[0] = Errno::EINTR.negated();
            vector.iov_base = (&raw mut registers).cast();
            if unsafe { libc::ptrace(libc::PTRACE_SETREGSET, tid, 1usize, &raw mut vector) } < 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(if phase == 0 {
            cancel.skipped
        } else {
            eligible && phase == 1
        })
    }
}
