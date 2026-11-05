// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::signals::ForwardSignals;
use super::error::{BrokerError, SysResult};
use super::fs::{MUTATION_SYSCALLS, handle_access, handle_mutation, handle_openat};
use super::grant::Grant;
use super::network::{handle_bind, handle_connect, handle_sendmmsg, handle_sendmsg, handle_sendto};
use super::notify::{NotificationChannel, NotificationResponse, NotificationResult, QueryDecision};
use super::process::TargetProcess;
use crate::error::Error as LandstripError;
use crate::policy::{AccessPolicy, DenialReason};
use crate::trap::{FilesystemDenial, NetworkOperation, ProcessContext, Trap, TrapOperation};
use crate::trap_fd::TrapFd;
use anyhow::Result;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;

const POLL_MS: u16 = 100;
const CONTROL_BUFFER_MAX: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) enum Denial {
    Filesystem(FilesystemDenial),
    Network(NetworkOperation, String, ProcessContext),
}

impl Denial {
    fn report_on_success(&self) -> bool {
        match self {
            Self::Filesystem(denial) => {
                denial.operation == TrapOperation::Write || denial.reason == DenialReason::DenyMatch
            }
            Self::Network(_, _, _) => true,
        }
    }

    pub(super) fn into_trap(self, query_id: Option<u64>) -> Trap {
        match self {
            Self::Filesystem(denial) => Trap::filesystem(denial, query_id),
            Self::Network(operation, target, process) => {
                Trap::network(operation, target, process, query_id)
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
    seen: HashSet<Denial>,
    pending: Vec<Denial>,
}

impl<'a> Denials<'a> {
    pub(super) fn new(trap_fd: Option<&'a TrapFd>) -> Self {
        Self {
            trap_fd,
            query_enabled: trap_fd.is_some_and(TrapFd::is_stream_socket),
            next_query_id: 1,
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
        self.trap_fd = None;
        self.query_enabled = false;
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
        if self.can_query(allow_query) {
            let query_id = self.next_query_id;
            self.next_query_id += 1;
            return Ok(NotificationResult::query(
                query_id,
                denial.into_trap(Some(query_id)),
                grant,
            ));
        }
        self.record(denial);
        Err(BrokerError::PolicyDenied)
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
    Pending(QueryDecision),
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
    Sendto,
    Sendmsg,
    Sendmmsg,
    Open,
    Access,
    Handle,
    Mutation { landlock_backed: bool },
}

impl SyscallClass {
    pub(super) const ACCESS: &[i64] = &[
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        libc::SYS_access,
    ];

    pub(super) const FILESYSTEM: &[i64] = &[
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        libc::SYS_open,
    ];

    pub(super) const DATAGRAM_SEND: &[i64] =
        &[libc::SYS_sendto, libc::SYS_sendmsg, libc::SYS_sendmmsg];

    pub(super) fn notified(
        policy: &AccessPolicy,
        needs_filesystem: bool,
    ) -> impl Iterator<Item = i64> {
        let restricted = !policy.network_access.is_unrestricted();
        let datagram = if restricted && policy.network_access.allows_local_binding() {
            Self::DATAGRAM_SEND
        } else {
            &[]
        };
        let filesystem = if needs_filesystem {
            Self::FILESYSTEM
        } else {
            &[]
        };
        policy
            .network_access
            .needs_bind_broker()
            .then_some(libc::SYS_bind)
            .into_iter()
            .chain(std::iter::once(libc::SYS_connect))
            .chain(Self::ACCESS.iter().copied())
            .chain(datagram.iter().copied())
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
            libc::SYS_sendto => Some(Self::Sendto),
            libc::SYS_sendmsg => Some(Self::Sendmsg),
            libc::SYS_sendmmsg => Some(Self::Sendmmsg),
            libc::SYS_openat | libc::SYS_openat2 => Some(Self::Open),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            libc::SYS_open => Some(Self::Open),
            libc::SYS_faccessat | libc::SYS_faccessat2 => Some(Self::Access),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            libc::SYS_access => Some(Self::Access),
            libc::SYS_name_to_handle_at | libc::SYS_open_by_handle_at => Some(Self::Handle),
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
    grant: Option<Grant>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ControlAction {
    Allow,
    #[serde(other)]
    Deny,
}

#[derive(Deserialize)]
struct ControlResponse {
    query_id: String,
    action: ControlAction,
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
    control_buffer: Vec<u8>,
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
            control_buffer: Vec::new(),
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
            match handle_result {
                HandleResult::Respond(response) => {
                    if let Err(source) = self.notify.respond(response) {
                        if let Some(status) = self.wait_child(Some(WaitPidFlag::WNOHANG))? {
                            return Ok(self.denials.emit(status));
                        }
                        return Err(source);
                    }
                }
                HandleResult::Pending(decision) => {
                    if let Err(error) = self.denials.write(&decision.trap) {
                        log::debug!("trap query write failed: {error}");
                        self.disconnect_control();
                        self.notify.respond(NotificationResponse::error(
                            request.id,
                            LandstripError::DENIAL_ERRNO,
                        ))?;
                    } else {
                        self.pending_queries.insert(
                            decision.query_id,
                            PendingQuery {
                                request,
                                grant: decision.grant,
                            },
                        );
                    }
                }
                HandleResult::Apply(grant) => {
                    grant.apply(self.policy, self.notify, request.id);
                }
            }
        }
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
            Some(SyscallClass::Bind) => handle_bind(self.policy, request, &mut self.denials),
            Some(SyscallClass::Connect) => handle_connect(self.policy, request, &mut self.denials),
            Some(SyscallClass::Sendto) => handle_sendto(request, &mut self.denials),
            Some(SyscallClass::Sendmsg) => handle_sendmsg(request, &mut self.denials),
            Some(SyscallClass::Sendmmsg) => handle_sendmmsg(request, &mut self.denials),
            Some(SyscallClass::Open) if self.notify_filesystem => {
                handle_openat(self.policy, request, &mut self.denials)
            }
            Some(SyscallClass::Access) => handle_access(self.policy, request, &mut self.denials),
            Some(SyscallClass::Handle) if self.notify_filesystem => Err(BrokerError::PolicyDenied),
            Some(SyscallClass::Mutation { landlock_backed })
                if self.notify_filesystem || !landlock_backed =>
            {
                handle_mutation(self.policy, request, &mut self.denials)
            }
            Some(SyscallClass::Open | SyscallClass::Handle | SyscallClass::Mutation { .. })
            | None => Ok(NotificationResult::Continue),
        };
        match result {
            Ok(NotificationResult::Continue) => {
                HandleResult::Respond(NotificationResponse::continue_syscall(request.id))
            }
            Ok(NotificationResult::Grant(grant)) => HandleResult::Apply(grant),
            Ok(NotificationResult::Query(decision)) => HandleResult::Pending(decision),
            Err(error) => {
                HandleResult::Respond(NotificationResponse::error(request.id, error.errno()))
            }
        }
    }

    fn receive_notification(&mut self) -> Result<Option<(libc::seccomp_notif, HandleResult)>> {
        let request = self.notify.receive()?;
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
        self.control_buffer.extend_from_slice(&chunk[..n]);

        if self.control_buffer.len() > CONTROL_BUFFER_MAX {
            log::warn!(
                "linux: control buffer exceeded {CONTROL_BUFFER_MAX} bytes with no newline; dropping"
            );
            self.control_buffer.clear();
            return true;
        }

        let Some(last_newline) = self.control_buffer.iter().rposition(|b| *b == b'\n') else {
            return false;
        };
        let complete: Vec<u8> = self.control_buffer.drain(..=last_newline).collect();

        for line in complete.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let Ok(response): std::result::Result<ControlResponse, _> =
                serde_json::from_slice(line)
            else {
                return true;
            };
            let Ok(query_id) = response.query_id.parse::<u64>() else {
                return true;
            };
            if let Some(pending) = self.pending_queries.remove(&query_id) {
                let id = pending.request.id;
                if !self.notify.is_id_valid(id).unwrap_or(false) {
                    continue;
                }
                match response.action {
                    ControlAction::Allow => match pending.grant {
                        Some(grant) => grant.apply(self.policy, self.notify, id),
                        None => {
                            let _ = self
                                .notify
                                .respond(NotificationResponse::continue_syscall(id));
                        }
                    },
                    ControlAction::Deny => {
                        let _ = self.notify.respond(NotificationResponse::error(
                            id,
                            LandstripError::DENIAL_ERRNO,
                        ));
                    }
                }
            }
        }
        false
    }

    fn disconnect_control(&mut self) {
        for (_id, pending) in self.pending_queries.drain() {
            let id = pending.request.id;
            if self.notify.is_id_valid(id).unwrap_or(false) {
                let _ = self.notify.respond(NotificationResponse::error(
                    id,
                    LandstripError::DENIAL_ERRNO,
                ));
            }
        }
        self.denials.disable_queries();
    }
}
