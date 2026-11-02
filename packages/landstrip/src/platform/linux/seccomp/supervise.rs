// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::signals::ForwardSignals;
use super::error::{BrokerError, SysResult};
use super::fs::{MUTATION_SYSCALLS, handle_access, handle_mutation, handle_openat, legacy_syscall};
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

pub(super) struct NotificationContext<'a> {
    pub(super) policy: &'a AccessPolicy,
    pub(super) syscalls: &'a NotificationSyscalls,
    pub(super) notify_filesystem: bool,
    pub(super) mount_namespace: NamespaceId,
}

impl NotificationContext<'_> {
    fn handle(&self, request: &libc::seccomp_notif, denials: &mut Denials<'_>) -> HandleResult {
        let syscall = i64::from(request.data.nr);
        let result = if syscall == self.syscalls.bind {
            handle_bind(self.policy, request, denials)
        } else if syscall == self.syscalls.connect {
            handle_connect(self.policy, request, denials)
        } else if syscall == self.syscalls.sendto {
            handle_sendto(request, denials)
        } else if syscall == self.syscalls.sendmsg {
            handle_sendmsg(request, denials)
        } else if syscall == self.syscalls.sendmmsg {
            handle_sendmmsg(request, denials)
        } else if self.notify_filesystem && self.syscalls.is_open(syscall) {
            handle_openat(self.policy, request, denials)
        } else if self.syscalls.is_access(syscall) {
            handle_access(self.policy, request, denials)
        } else if self.notify_filesystem && self.syscalls.is_handle_syscall(syscall) {
            Err(BrokerError::PolicyDenied)
        } else if self.notify_filesystem
            || MUTATION_SYSCALLS
                .iter()
                .any(|spec| !spec.landlock_backed && spec.nr == Some(syscall))
        {
            handle_mutation(self.policy, request, denials)
        } else {
            Ok(NotificationResult::Continue)
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

pub(crate) struct NotificationSyscalls {
    pub(crate) bind: i64,
    pub(crate) connect: i64,
    pub(crate) socket: i64,
    pub(crate) sendto: i64,
    pub(crate) sendmsg: i64,
    pub(crate) sendmmsg: i64,
    pub(crate) io_uring_setup: i64,
    pub(crate) io_uring_enter: i64,
    pub(crate) io_uring_register: i64,
    openat: i64,
    openat2: i64,
    open: Option<i64>,
    access: Option<i64>,
    faccessat: i64,
    faccessat2: i64,
    name_to_handle_at: i64,
    open_by_handle_at: i64,
}

impl NotificationSyscalls {
    pub(crate) fn new() -> Self {
        Self {
            bind: libc::SYS_bind,
            connect: libc::SYS_connect,
            socket: libc::SYS_socket,
            sendto: libc::SYS_sendto,
            sendmsg: libc::SYS_sendmsg,
            sendmmsg: libc::SYS_sendmmsg,
            io_uring_setup: libc::SYS_io_uring_setup,
            io_uring_enter: libc::SYS_io_uring_enter,
            io_uring_register: libc::SYS_io_uring_register,
            openat: libc::SYS_openat,
            openat2: libc::SYS_openat2,
            open: legacy_syscall::OPEN,
            access: legacy_syscall::ACCESS,
            faccessat: libc::SYS_faccessat,
            faccessat2: libc::SYS_faccessat2,
            name_to_handle_at: libc::SYS_name_to_handle_at,
            open_by_handle_at: libc::SYS_open_by_handle_at,
        }
    }

    fn is_open(&self, syscall: i64) -> bool {
        syscall == self.openat
            || syscall == self.openat2
            || self.open.is_some_and(|open| open == syscall)
    }

    fn is_access(&self, syscall: i64) -> bool {
        syscall == self.faccessat
            || syscall == self.faccessat2
            || self.access.is_some_and(|access| access == syscall)
    }

    fn is_handle_syscall(&self, syscall: i64) -> bool {
        syscall == self.name_to_handle_at || syscall == self.open_by_handle_at
    }

    pub(crate) fn access_syscalls(&self) -> Vec<i64> {
        let mut nrs = vec![self.faccessat, self.faccessat2];
        if let Some(access) = self.access {
            nrs.push(access);
        }
        nrs
    }

    pub(crate) fn filesystem_syscalls(&self) -> Vec<i64> {
        let mut nrs = vec![
            self.openat,
            self.openat2,
            self.name_to_handle_at,
            self.open_by_handle_at,
        ];
        if let Some(open) = self.open {
            nrs.push(open);
        }
        nrs
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
    pub(super) policy: &'a AccessPolicy,
    pub(super) child: Pid,
    pub(super) notify_fd: BorrowedFd<'a>,
    pub(super) syscalls: &'a NotificationSyscalls,
    pub(super) notify_filesystem: bool,
    pub(super) trap_fd: Option<&'a TrapFd>,
    pub(super) mount_namespace: NamespaceId,
    pub(super) signals: Option<&'a mut ForwardSignals>,
}

impl Supervisor<'_> {
    #[allow(
        clippy::too_many_lines,
        reason = "query delivery failure handling must update supervisor state atomically"
    )]
    pub(super) fn run(mut self) -> Result<i32> {
        let notify = NotificationChannel::new(self.notify_fd);
        let mut denials = Denials::new(self.trap_fd);
        let mut trap_fd = self
            .trap_fd
            .filter(|trap_fd| trap_fd.is_stream_socket())
            .map(AsFd::as_fd);
        let ctx = NotificationContext {
            policy: self.policy,
            syscalls: self.syscalls,
            notify_filesystem: self.notify_filesystem,
            mount_namespace: self.mount_namespace,
        };
        let mut pending_queries: HashMap<u64, PendingQuery> = HashMap::new();
        let mut control_buffer: Vec<u8> = Vec::new();
        loop {
            loop {
                match waitpid(self.child, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) => break,
                    Ok(status) => return Ok(denials.emit(status)),
                    Err(Errno::EINTR) => {}
                    Err(error) => return Err(LandstripError::supervise_errno(error).into()),
                }
            }

            let signal_fd = self.signals.as_ref().map(|s| s.as_fd());
            let revents = poll_broker_fds(self.notify_fd, trap_fd, signal_fd)?;
            if revents.iter().all(PollFlags::is_empty) {
                continue;
            }

            if let Some(ref mut signals) = self.signals
                && revents[2].intersects(PollFlags::POLLIN)
            {
                signals.process_pending()?;
            }

            if revents[0].intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
            {
                loop {
                    match waitpid(self.child, None) {
                        Ok(status) => return Ok(denials.emit(status)),
                        Err(Errno::EINTR) => {}
                        Err(error) => return Err(LandstripError::supervise_errno(error).into()),
                    }
                }
            }

            if let Some(cfd) = trap_fd {
                let dead = revents[1]
                    .intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                    || (revents[1].intersects(PollFlags::POLLIN)
                        && process_control_responses(
                            self.policy,
                            cfd,
                            &mut control_buffer,
                            &mut pending_queries,
                            notify,
                        ));
                if dead {
                    deny_all_pending(&mut pending_queries, notify);
                    denials.disable_queries();
                    trap_fd = None;
                }
            }

            if !revents[0].intersects(PollFlags::POLLIN) {
                continue;
            }

            let Some((request, handle_result)) =
                receive_handled_notification(notify, &ctx, &mut denials)?
            else {
                continue;
            };
            match handle_result {
                HandleResult::Respond(response) => {
                    if let Err(source) = notify.respond(response) {
                        loop {
                            match waitpid(self.child, Some(WaitPidFlag::WNOHANG)) {
                                Ok(WaitStatus::StillAlive) => break,
                                Ok(status) => return Ok(denials.emit(status)),
                                Err(Errno::EINTR) => {}
                                Err(error) => {
                                    return Err(LandstripError::supervise_errno(error).into());
                                }
                            }
                        }
                        return Err(source);
                    }
                }
                HandleResult::Pending(decision) => {
                    if let Err(error) = denials.write(&decision.trap) {
                        log::debug!("trap query write failed: {error}");
                        deny_all_pending(&mut pending_queries, notify);
                        denials.disable_queries();
                        trap_fd = None;
                        notify.respond(NotificationResponse::error(
                            request.id,
                            LandstripError::DENIAL_ERRNO,
                        ))?;
                    } else {
                        pending_queries.insert(
                            decision.query_id,
                            PendingQuery {
                                request,
                                grant: decision.grant,
                            },
                        );
                    }
                }
                HandleResult::Apply(grant) => {
                    grant.apply(self.policy, notify, request.id);
                }
            }
        }
    }
}

fn receive_handled_notification(
    notify: NotificationChannel<'_>,
    ctx: &NotificationContext,
    denials: &mut Denials<'_>,
) -> Result<Option<(libc::seccomp_notif, HandleResult)>> {
    let request = notify.receive()?;
    if !notify.is_id_valid(request.id)? {
        return Ok(None);
    }
    let handle_result = match ctx.mount_namespace.verify(request.pid) {
        Ok(()) => ctx.handle(&request, denials),
        Err(error) => HandleResult::Respond(NotificationResponse::error(request.id, error.errno())),
    };
    if !notify.is_id_valid(request.id)? {
        return Ok(None);
    }
    Ok(Some((request, handle_result)))
}

fn poll_broker_fds(
    notify: BorrowedFd<'_>,
    control: Option<BorrowedFd<'_>>,
    signals: Option<BorrowedFd<'_>>,
) -> Result<[PollFlags; 3]> {
    let mut len = 1;
    let mut poll_fds = [
        PollFd::new(notify, PollFlags::POLLIN),
        PollFd::new(control.unwrap_or(notify), PollFlags::POLLIN),
        PollFd::new(signals.unwrap_or(notify), PollFlags::POLLIN),
    ];
    if control.is_some() {
        len = 2;
    }
    if signals.is_some() {
        len = 3;
    }
    loop {
        match poll(&mut poll_fds[..len], POLL_MS) {
            Ok(0) => return Ok([PollFlags::empty(); 3]),
            Ok(_) => {
                return Ok([
                    poll_fds[0].revents().unwrap_or_else(PollFlags::empty),
                    poll_fds[1].revents().unwrap_or_else(PollFlags::empty),
                    poll_fds[2].revents().unwrap_or_else(PollFlags::empty),
                ]);
            }
            Err(Errno::EINTR) => {}
            Err(error) => return Err(LandstripError::supervise_errno(error).into()),
        }
    }
}

fn process_control_responses(
    policy: &AccessPolicy,
    control_fd: BorrowedFd<'_>,
    buffer: &mut Vec<u8>,
    pending_queries: &mut HashMap<u64, PendingQuery>,
    notify: NotificationChannel<'_>,
) -> bool {
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
    buffer.extend_from_slice(&chunk[..n]);

    if buffer.len() > CONTROL_BUFFER_MAX {
        log::warn!(
            "linux: control buffer exceeded {CONTROL_BUFFER_MAX} bytes with no newline; dropping"
        );
        buffer.clear();
        return true;
    }

    let Some(last_newline) = buffer.iter().rposition(|b| *b == b'\n') else {
        return false;
    };
    let complete: Vec<u8> = buffer.drain(..=last_newline).collect();

    for line in complete.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(response): std::result::Result<ControlResponse, _> = serde_json::from_slice(line)
        else {
            return true;
        };
        let Ok(query_id) = response.query_id.parse::<u64>() else {
            return true;
        };
        if let Some(pending) = pending_queries.remove(&query_id) {
            let id = pending.request.id;
            if !notify.is_id_valid(id).unwrap_or(false) {
                continue;
            }
            match response.action {
                ControlAction::Allow => match pending.grant {
                    Some(grant) => grant.apply(policy, notify, id),
                    None => {
                        let _ = notify.respond(NotificationResponse::continue_syscall(id));
                    }
                },
                ControlAction::Deny => {
                    let _ = notify.respond(NotificationResponse::error(
                        id,
                        LandstripError::DENIAL_ERRNO,
                    ));
                }
            }
        }
    }
    false
}

fn deny_all_pending(
    pending_queries: &mut HashMap<u64, PendingQuery>,
    notify: NotificationChannel<'_>,
) {
    for (_id, pending) in pending_queries.drain() {
        let id = pending.request.id;
        if notify.is_id_valid(id).unwrap_or(false) {
            let _ = notify.respond(NotificationResponse::error(
                id,
                LandstripError::DENIAL_ERRNO,
            ));
        }
    }
}
