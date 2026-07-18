// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Seccomp filters and user-notification broker for network policy.
//!
//! Direct TCP is denied by default. Configured proxy ports and, when
//! `allowLocalBinding` is enabled, arbitrary loopback ports are allowed. Local
//! TCP bind also requires `allowLocalBinding`. Non-TCP INET, packet, and netlink
//! sockets are blocked.
//!
//! Unix sockets are denied by default. `allowUnixSockets` mediates pathname
//! `connect` and `bind`; abstract sockets, unnamed sockets, and `socketpair` are
//! not path-mediated. `allowAllUnixSockets` permits new Unix sockets without
//! path checks.

use super::fd::close_inherited_fds;
use super::filter::{
    NetworkFilters, build_errno_filter, build_notify_filter, needs_unix_socket_broker,
    setup_failed, unix_socket_filter,
};
use super::landlock::enforce_broker_access_policy;
use crate::engine::error::{Cause, Error as LandstripError};
use crate::engine::paths::{normalize_path, normalize_path_lexically, normalize_path_nofollow};
use crate::engine::policy::{AccessPolicy, ReadAccess, UnixSocketAccess};
use crate::engine::trap::{
    FilesystemDenial, NetworkOperation, ProcessContext, Trap, TrapOperation,
};
use crate::engine::trap_fd::TrapFd;
use anyhow::Result;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, fcntl};
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

const POLL_MS: u16 = 100;
const SECCOMP_IOC_MAGIC: u8 = b'!';
const USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

nix::ioctl_readwrite!(
    seccomp_notif_recv,
    SECCOMP_IOC_MAGIC,
    0,
    libc::seccomp_notif
);
nix::ioctl_readwrite!(
    seccomp_notif_send,
    SECCOMP_IOC_MAGIC,
    1,
    libc::seccomp_notif_resp
);
nix::ioctl_write_ptr!(seccomp_notif_id_valid, SECCOMP_IOC_MAGIC, 2, u64);
nix::ioctl_write_ptr!(
    seccomp_notif_addfd,
    SECCOMP_IOC_MAGIC,
    3,
    libc::seccomp_notif_addfd
);

type SysResult<T> = std::result::Result<T, BrokerError>;
type SocketAddrCall =
    unsafe extern "C" fn(libc::c_int, *const libc::sockaddr, libc::socklen_t) -> libc::c_int;

#[derive(Debug)]
enum BrokerError {
    AddressFamilyNotSupported,
    BadAddress,
    BadFileDescriptor,
    InvalidAddress,
    NameTooLong,
    PolicyDenied,
    SystemCall { errno: i32 },
}

impl BrokerError {
    fn errno(&self) -> i32 {
        match self {
            Self::PolicyDenied => LandstripError::DENIAL_ERRNO,
            Self::AddressFamilyNotSupported => libc::EAFNOSUPPORT,
            Self::InvalidAddress => libc::EINVAL,
            Self::BadFileDescriptor => libc::EBADF,
            Self::BadAddress => libc::EFAULT,
            Self::NameTooLong => libc::ENAMETOOLONG,
            Self::SystemCall { errno } => *errno,
        }
    }
}

/// A syscall that failed while supervising the sandboxed child.
fn supervise_errno(errno: Errno) -> LandstripError {
    supervise_failed(io::Error::from_raw_os_error(errno as i32))
}

fn supervise_failed(source: impl Into<Cause>) -> LandstripError {
    LandstripError::SuperviseFailed {
        source: source.into(),
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn run_broker(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    needs_network: bool,
    needs_filesystem: bool,
    trap_fd: &TrapFd,
) -> Result<i32> {
    let notify_unix_sockets = needs_unix_socket_broker(&policy.network_access.unix_socket_access);
    let notify_bind =
        needs_network && (policy.network_access.local_tcp_bind || notify_unix_sockets);
    let notify_connect = needs_network
        && (policy.network_access.local_tcp_bind
            || !policy.network_access.connect_tcp_ports.is_empty()
            || notify_unix_sockets);
    let notify_filesystem = needs_filesystem;
    let unix_sockets = unix_socket_filter(&policy.network_access.unix_socket_access);
    ensure_notification_supported()?;

    let syscalls = NotificationSyscalls::new();
    let errno = build_errno_filter(&syscalls, needs_network, unix_sockets)?;

    let mut notify_syscalls: Vec<i64> = Vec::new();
    if notify_bind {
        notify_syscalls.push(syscalls.bind);
    }
    if notify_connect {
        notify_syscalls.push(syscalls.connect);
    }
    if notify_filesystem {
        notify_syscalls.extend(syscalls.filesystem_syscalls());
        notify_syscalls.extend(MUTATION_SYSCALLS.iter().filter_map(|spec| spec.nr));
    }
    let notify = if notify_syscalls.is_empty() {
        None
    } else {
        Some(build_notify_filter(&notify_syscalls)?)
    };

    let filters = NetworkFilters::new(errno, notify);
    let (parent, child_sock) = UnixStream::pair().map_err(supervise_failed)?;

    // SAFETY: landstrip forks before spawning threads; the child either execs the tool or exits.
    match unsafe { fork() }.map_err(supervise_errno)? {
        ForkResult::Child => {
            drop(parent);
            let mut child_sock = child_sock;
            let mut handed_off = false;

            let result = (|| -> Result<()> {
                enforce_broker_access_policy(policy)?;

                {
                    let notify = filters.load_with_listener()?;

                    // SAFETY: notify is borrowed only for the duration of fcntl(2).
                    let notify_fd = unsafe { BorrowedFd::borrow_raw(notify.as_raw_fd()) };
                    let notify =
                        fcntl(notify_fd, FcntlArg::F_DUPFD_CLOEXEC(0)).map_err(supervise_errno)?;
                    // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
                    let notify = unsafe { OwnedFd::from_raw_fd(notify) };

                    send_fd(&child_sock, notify.as_raw_fd())?;
                    handed_off = true;
                }

                let mut excluded = vec![child_sock.as_raw_fd()];
                if let Some(fd) = trap_fd.fd() {
                    excluded.push(fd);
                }
                close_inherited_fds(&excluded).map_err(supervise_failed)?;

                let mut child_tool = Command::new(tool);
                child_tool.args(args);

                let error = child_tool.exec();
                Err(LandstripError::LaunchFailed {
                    tool: PathBuf::from(tool),
                    source: error.into(),
                }
                .into())
            })();

            if let Err(error) = result {
                let trap = error
                    .chain()
                    .find_map(<(dyn std::error::Error + 'static)>::downcast_ref::<LandstripError>)
                    .map_or_else(|| Trap::internal(format!("{error:#}")), Trap::from_error);
                if handed_off || send_trap(&mut child_sock, &trap).is_err() {
                    trap_fd.write(&trap);
                    trap.emit();
                }
            }

            // SAFETY: _exit terminates the child without running duplicated parent cleanup.
            unsafe { libc::_exit(127) }
        }
        ForkResult::Parent { child } => {
            drop(child_sock);
            match get_notify_fd(&parent)? {
                NotifyStartup::Ready(notify) => {
                    drop(parent);
                    let notify_fd = notify.as_raw_fd();

                    supervise_child(
                        policy,
                        child,
                        notify_fd,
                        &syscalls,
                        notify_filesystem,
                        trap_fd,
                    )
                }
                NotifyStartup::Trap(trap) => {
                    drop(parent);
                    trap_fd.write_json(&trap);
                    Trap::emit_json(&trap);
                    Ok(1)
                }
            }
        }
    }
}

enum NotifyStartup {
    Ready(OwnedFd),
    Trap(String),
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

#[allow(clippy::too_many_lines)]
fn supervise_child(
    policy: &AccessPolicy,
    child: Pid,
    notify_fd: RawFd,
    syscalls: &NotificationSyscalls,
    notify_filesystem: bool,
    trap_fd: &TrapFd,
) -> Result<i32> {
    let mut denials = Denials::new(trap_fd.clone());
    let query_enabled = trap_fd.is_socket();
    let mut ctx = NotificationContext {
        policy,
        syscalls,
        notify_filesystem,
        query_enabled,
    };
    let mut trap_fd = trap_fd.fd().filter(|_| query_enabled);
    let mut pending_queries: std::collections::HashMap<u64, PendingQuery> =
        std::collections::HashMap::new();
    let mut control_buffer: Vec<u8> = Vec::new();
    let mut next_query_id: u64 = 1;
    // SAFETY: notify_fd is the live seccomp notification fd owned by the parent.
    let notify = unsafe { BorrowedFd::borrow_raw(notify_fd) };
    loop {
        loop {
            match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => break,
                Ok(status) => return Ok(denials.emit(status)),
                Err(Errno::EINTR) => continue,
                Err(error) => {
                    return Err(supervise_errno(error).into());
                }
            }
        }

        let control = trap_fd.map(|cfd| unsafe { BorrowedFd::borrow_raw(cfd) });
        let mut poll_fds = [
            PollFd::new(notify, PollFlags::POLLIN),
            PollFd::new(control.unwrap_or(notify), PollFlags::POLLIN),
        ];
        let len = if control.is_some() { 2 } else { 1 };
        let revents = loop {
            match poll(&mut poll_fds[..len], POLL_MS) {
                Ok(0) => break [PollFlags::empty(); 2],
                Ok(_) => {
                    break [
                        poll_fds[0].revents().unwrap_or_else(PollFlags::empty),
                        poll_fds[1].revents().unwrap_or_else(PollFlags::empty),
                    ];
                }
                Err(Errno::EINTR) => continue,
                Err(error) => {
                    return Err(supervise_errno(error).into());
                }
            }
        };

        if revents.iter().all(PollFlags::is_empty) {
            continue;
        }

        if revents[0].intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            loop {
                match waitpid(child, None) {
                    Ok(status) => return Ok(denials.emit(status)),
                    Err(Errno::EINTR) => continue,
                    Err(error) => {
                        return Err(supervise_errno(error).into());
                    }
                }
            }
        }

        if let Some(cfd) = trap_fd {
            let dead = revents[1]
                .intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                || (revents[1].intersects(PollFlags::POLLIN)
                    && process_control_responses(
                        cfd,
                        &mut control_buffer,
                        &mut pending_queries,
                        notify_fd,
                    ));
            if dead {
                // The launcher closed or errored the trap fd. Any deferred query
                // is unanswerable: deny it with EACCES so the child's syscall
                // resumes instead of hanging, and stop polling the fd so the loop
                // does not spin on a dead socket.
                deny_all_pending(&mut pending_queries, notify_fd);
                trap_fd = None;
                ctx.query_enabled = false;
            }
        }

        if !revents[0].intersects(PollFlags::POLLIN) {
            continue;
        }

        let request = receive_notification(notify_fd)?;
        let handle_result = handle_notification(&ctx, &request, &mut denials, &mut next_query_id);

        if !validate_notification_id(notify_fd, request.id)? {
            continue;
        }
        match handle_result {
            HandleResult::Respond(response) => {
                if let Err(source) = respond_notification(notify_fd, response) {
                    loop {
                        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) => break,
                            Ok(status) => return Ok(denials.emit(status)),
                            Err(Errno::EINTR) => continue,
                            Err(error) => {
                                return Err(supervise_errno(error).into());
                            }
                        }
                    }
                    return Err(source);
                }
            }
            HandleResult::Pending(query_id, grant) => {
                pending_queries.insert(query_id, PendingQuery { request, grant });
            }
            HandleResult::AddFd(grant) => {
                // grant_open opens the path in the broker and completes the
                // notification atomically via SECCOMP_ADDFD_FLAG_SEND; the child
                // receives the broker's fd, eliminating the CONTINUE re-exec
                // window. On failure grant_open responds with an errno itself.
                grant_open(notify_fd, request.id, &grant);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Denial {
    Filesystem(FilesystemDenial),
    Network(NetworkOperation, String, ProcessContext),
}

impl Denial {
    fn report_on_success(&self) -> bool {
        match self {
            Self::Filesystem(denial) => denial.operation == TrapOperation::Write,
            Self::Network(_, _, _) => true,
        }
    }

    fn into_trap(self) -> Trap {
        match self {
            Self::Filesystem(denial) => Trap::filesystem(denial, None),
            Self::Network(operation, target, process) => {
                Trap::network(operation, target, process, None)
            }
        }
    }
}

#[derive(Default)]
struct Denials {
    trap_fd: TrapFd,
    seen: HashSet<Denial>,
    pending: Vec<Denial>,
}

impl Denials {
    fn new(trap_fd: TrapFd) -> Self {
        Self {
            trap_fd,
            ..Self::default()
        }
    }

    fn record(&mut self, denial: Denial) {
        if self.seen.insert(denial.clone()) {
            self.pending.push(denial);
        }
    }

    fn emit(&self, status: WaitStatus) -> i32 {
        let code = exit_code(status);
        for denial in self
            .pending
            .iter()
            .filter(|denial| code != 0 || denial.report_on_success())
        {
            let trap = denial.clone().into_trap();
            self.trap_fd.write(&trap);
            trap.emit();
        }
        code
    }
}

enum HandleResult {
    Respond(libc::seccomp_notif_resp),
    // Broker-mediated open: inject a broker-opened fd via SECCOMP_IOCTL_NOTIF_ADDFD
    // instead of letting the kernel re-run openat in the child. Used for reads,
    // which are not Landlock-backed in the brokered child, so CONTINUE would be
    // TOCTOU-bypassable (a sibling thread could swap the path between the
    // broker's process_vm_readv check and the kernel's re-execution).
    AddFd(OpenGrant),
    Pending(u64, Option<Grant>),
}

/// Immutable context shared across notification handling for a supervised child.
struct NotificationContext<'a> {
    policy: &'a AccessPolicy,
    syscalls: &'a NotificationSyscalls,
    notify_filesystem: bool,
    query_enabled: bool,
}

fn handle_notification(
    ctx: &NotificationContext,
    request: &libc::seccomp_notif,
    denials: &mut Denials,
    next_query_id: &mut u64,
) -> HandleResult {
    let syscall = i64::from(request.data.nr);
    let result = if syscall == ctx.syscalls.bind {
        handle_bind(
            ctx.policy,
            request,
            denials,
            ctx.query_enabled,
            next_query_id,
        )
    } else if syscall == ctx.syscalls.connect {
        handle_connect(
            ctx.policy,
            request,
            denials,
            ctx.query_enabled,
            next_query_id,
        )
    } else if ctx.notify_filesystem
        && (syscall == ctx.syscalls.openat || syscall == ctx.syscalls.openat2)
    {
        handle_openat(
            ctx.policy,
            request,
            denials,
            ctx.query_enabled,
            next_query_id,
        )
    } else if ctx.notify_filesystem {
        handle_mutation(
            ctx.policy,
            request,
            denials,
            ctx.query_enabled,
            next_query_id,
        )
    } else {
        Ok(NotificationResult::Continue)
    };

    match result {
        Ok(NotificationResult::Value(value)) => {
            HandleResult::Respond(notification_value(request.id, value))
        }
        Ok(NotificationResult::Continue) => {
            HandleResult::Respond(notification_continue(request.id))
        }
        Ok(NotificationResult::Open(grant)) => HandleResult::AddFd(grant),
        Ok(NotificationResult::Query(decision)) => {
            denials.trap_fd.write(&decision.trap);
            HandleResult::Pending(decision.query_id, decision.grant)
        }
        Err(error) => {
            let errno = error.errno();
            HandleResult::Respond(notification_error(request.id, -errno.abs()))
        }
    }
}

fn notification_value(id: u64, value: i64) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: value,
        error: 0,
        flags: 0,
    }
}

fn notification_continue(id: u64) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: USER_NOTIF_FLAG_CONTINUE,
    }
}

fn notification_error(id: u64, error: i32) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: 0,
        error,
        flags: 0,
    }
}

fn ensure_notification_supported() -> Result<()> {
    let mut action = libc::SECCOMP_RET_USER_NOTIF;
    seccomp_probe(
        libc::SECCOMP_GET_ACTION_AVAIL,
        ptr::addr_of_mut!(action).cast::<libc::c_void>(),
    )?;

    // SAFETY: zero is a valid initial byte pattern for this plain kernel UAPI struct.
    let mut sizes = unsafe { mem::zeroed::<libc::seccomp_notif_sizes>() };
    seccomp_probe(
        libc::SECCOMP_GET_NOTIF_SIZES,
        ptr::addr_of_mut!(sizes).cast::<libc::c_void>(),
    )
}

fn seccomp_probe(operation: libc::c_uint, data: *mut libc::c_void) -> Result<()> {
    // SAFETY: seccomp(2) copies the operation-specific data pointer before returning.
    let rc = unsafe { libc::syscall(libc::SYS_seccomp, operation, 0, data) };
    if rc < 0 {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }

    Ok(())
}

fn receive_notification(fd: RawFd) -> Result<libc::seccomp_notif> {
    loop {
        // SAFETY: zero is a valid initial byte pattern for this plain kernel UAPI struct.
        let mut request = unsafe { mem::zeroed::<libc::seccomp_notif>() };
        // SAFETY: request points to writable storage for SECCOMP_IOCTL_NOTIF_RECV.
        match unsafe { seccomp_notif_recv(fd, ptr::addr_of_mut!(request)) } {
            Ok(_) => return Ok(request),
            Err(Errno::EINTR) => continue,
            Err(error) => {
                return Err(supervise_errno(error).into());
            }
        }
    }
}

fn respond_notification(fd: RawFd, mut response: libc::seccomp_notif_resp) -> Result<()> {
    loop {
        // SAFETY: response points to initialized storage for SECCOMP_IOCTL_NOTIF_SEND.
        match unsafe { seccomp_notif_send(fd, ptr::addr_of_mut!(response)) } {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(error) => {
                return Err(supervise_errno(error).into());
            }
        }
    }
}

fn validate_notification_id(fd: RawFd, id: u64) -> Result<bool> {
    loop {
        // SAFETY: id points to initialized storage for SECCOMP_IOCTL_NOTIF_ID_VALID.
        match unsafe { seccomp_notif_id_valid(fd, ptr::addr_of!(id)) } {
            Ok(_) => return Ok(true),
            Err(Errno::EINTR) => continue,
            Err(Errno::ENOENT) => return Ok(false),
            Err(error) => {
                return Err(supervise_errno(error).into());
            }
        }
    }
}

fn process_context(pid: u32) -> ProcessContext {
    ProcessContext {
        pid,
        exe: fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned()),
        cwd: fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned()),
    }
}

// Defer a denied network operation to an interactive permission query. The
// duplicated child socket fd is held in the grant so the broker can re-issue the
// connect or bind itself once the launcher approves the query.
fn network_query(
    operation: NetworkOperation,
    target: String,
    pid: u32,
    socket: TargetSocket,
    call: SocketAddrCall,
    next_query_id: &mut u64,
) -> NotificationResult {
    let qid = *next_query_id;
    *next_query_id += 1;
    let trap = Trap::network(operation, target, process_context(pid), Some(qid));
    let grant = Grant::socket(socket.sock, socket.addr, call);
    NotificationResult::query(qid, trap, Some(grant))
}

fn handle_bind(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let mut socket = target_socket(request)?;

    match socket.info.kind() {
        SocketKind::Tcp => {
            if !policy.network_access.local_tcp_bind {
                if let Ok(endpoint) = tcp_endpoint(&socket.addr, socket.info.domain) {
                    if query_enabled {
                        return Ok(network_query(
                            NetworkOperation::Bind,
                            endpoint.addr.to_string(),
                            request.pid,
                            socket,
                            libc::bind,
                            next_query_id,
                        ));
                    }
                    denials.record(Denial::Network(
                        NetworkOperation::Bind,
                        endpoint.addr.to_string(),
                        process_context(request.pid),
                    ));
                }
                return Err(BrokerError::PolicyDenied);
            }
            let endpoint = tcp_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback {
                if query_enabled {
                    return Ok(network_query(
                        NetworkOperation::Bind,
                        endpoint.addr.to_string(),
                        request.pid,
                        socket,
                        libc::bind,
                        next_query_id,
                    ));
                }
                denials.record(Denial::Network(
                    NetworkOperation::Bind,
                    endpoint.addr.to_string(),
                    process_context(request.pid),
                ));
                return Err(BrokerError::PolicyDenied);
            }

            broker_addr_call(socket.sock.as_raw_fd(), &socket.addr, libc::bind)
                .map(NotificationResult::Value)
        }
        SocketKind::Unix => handle_unix_bind(policy, request.pid, &mut socket),
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
        SocketKind::Other => Ok(NotificationResult::Continue),
    }
}

fn handle_connect(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let socket = target_socket(request)?;

    match socket.info.kind() {
        SocketKind::Tcp => {
            let endpoint = tcp_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback
                || (!policy.network_access.local_tcp_bind
                    && !policy
                        .network_access
                        .connect_tcp_ports
                        .contains(&endpoint.port))
            {
                if query_enabled {
                    return Ok(network_query(
                        NetworkOperation::Connect,
                        endpoint.addr.to_string(),
                        request.pid,
                        socket,
                        libc::connect,
                        next_query_id,
                    ));
                }
                denials.record(Denial::Network(
                    NetworkOperation::Connect,
                    endpoint.addr.to_string(),
                    process_context(request.pid),
                ));
                return Err(BrokerError::PolicyDenied);
            }

            broker_addr_call(socket.sock.as_raw_fd(), &socket.addr, libc::connect)
                .map(NotificationResult::Value)
        }
        SocketKind::Unix => handle_unix_connect(policy, request.pid, &socket),
        SocketKind::Other => Ok(NotificationResult::Continue),
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
    }
}

fn handle_unix_connect(
    policy: &AccessPolicy,
    pid: u32,
    socket: &TargetSocket,
) -> SysResult<NotificationResult> {
    let Some((target, relative)) = unix_path_target(pid, &socket.addr)? else {
        return Err(BrokerError::PolicyDenied);
    };
    authorize_unix_path(policy, &target)?;

    let mut addr = socket.addr.clone();
    if relative {
        rewrite_unix_path(&mut addr, &target)?;
    }

    broker_addr_call(socket.sock.as_raw_fd(), &addr, libc::connect).map(NotificationResult::Value)
}

fn handle_unix_bind(
    policy: &AccessPolicy,
    pid: u32,
    socket: &mut TargetSocket,
) -> SysResult<NotificationResult> {
    let Some((target, relative)) = unix_path_target(pid, &socket.addr)? else {
        return Err(BrokerError::PolicyDenied);
    };
    authorize_unix_path(policy, &target)?;

    if !policy
        .write_roots
        .iter()
        .any(|root| target == *root || target.starts_with(root))
    {
        return Err(BrokerError::PolicyDenied);
    }

    if relative {
        rewrite_unix_path(&mut socket.addr, &target)?;
    }

    broker_addr_call(socket.sock.as_raw_fd(), &socket.addr, libc::bind)
        .map(NotificationResult::Value)
}

fn unix_path_target(pid: u32, addr: &[u8]) -> SysResult<Option<(PathBuf, bool)>> {
    let sun_path = mem::size_of::<libc::sa_family_t>();
    if addr.len() <= sun_path || addr[sun_path] == 0 {
        return Ok(None);
    }

    let path = &addr[sun_path..];
    let end = path
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(path.len());
    if end == 0 {
        return Ok(None);
    }

    let path = Path::new(OsStr::from_bytes(&path[..end]));
    if path.is_absolute() {
        Ok(Some((create_path(path), false)))
    } else {
        let pid = i32::try_from(pid).map_err(|_| BrokerError::InvalidAddress)?;
        let cwd =
            fs::read_link(format!("/proc/{pid}/cwd")).map_err(|error| BrokerError::SystemCall {
                errno: error.raw_os_error().unwrap_or(libc::EIO),
            })?;
        Ok(Some((create_path(&cwd.join(path)), true)))
    }
}

fn authorize_unix_path(policy: &AccessPolicy, target: &Path) -> SysResult<()> {
    match &policy.network_access.unix_socket_access {
        UnixSocketAccess::Unrestricted => Ok(()),
        UnixSocketAccess::AllowPaths(paths) => paths
            .iter()
            .any(|path| target == path || target.starts_with(path))
            .then_some(())
            .ok_or(BrokerError::PolicyDenied),
    }
}

fn rewrite_unix_path(addr: &mut Vec<u8>, target: &Path) -> SysResult<()> {
    let sun_path = mem::size_of::<libc::sa_family_t>();
    let path = target.as_os_str().as_bytes();
    let max_path = mem::size_of::<libc::sockaddr_un>() - sun_path;
    if path.len() + 1 > max_path {
        return Err(BrokerError::NameTooLong);
    }

    let mut rewritten = vec![0_u8; sun_path + path.len() + 1];
    rewritten[..sun_path].copy_from_slice(&addr[..sun_path]);
    rewritten[sun_path..sun_path + path.len()].copy_from_slice(path);
    *addr = rewritten;

    Ok(())
}

fn tcp_endpoint(addr: &[u8], domain: i32) -> SysResult<TcpEndpoint> {
    let family = addr
        .get(..mem::size_of::<libc::sa_family_t>())
        .ok_or(BrokerError::InvalidAddress)?;
    let family = <[u8; 2]>::try_from(family).map_err(|_| BrokerError::InvalidAddress)?;

    match (domain, i32::from(libc::sa_family_t::from_ne_bytes(family))) {
        (libc::AF_INET, libc::AF_INET) => {
            if addr.len() < mem::size_of::<libc::sockaddr_in>() {
                return Err(BrokerError::InvalidAddress);
            }

            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
            Ok(TcpEndpoint {
                addr: SocketAddr::from((ip, port)),
                port,
                loopback: ip.is_loopback(),
            })
        }
        (libc::AF_INET6, libc::AF_INET6) => {
            if addr.len() < mem::size_of::<libc::sockaddr_in6>() {
                return Err(BrokerError::InvalidAddress);
            }

            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&addr[8..24]).map_err(|_| BrokerError::InvalidAddress)?,
            );
            Ok(TcpEndpoint {
                addr: SocketAddr::from((ip, port)),
                port,
                loopback: ip.is_loopback()
                    || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
            })
        }
        _ => Err(BrokerError::AddressFamilyNotSupported),
    }
}

fn target_socket(request: &libc::seccomp_notif) -> SysResult<TargetSocket> {
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| BrokerError::BadFileDescriptor)?;
    let target_addr = usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
    let addr_len =
        usize::try_from(request.data.args[2]).map_err(|_| BrokerError::InvalidAddress)?;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);

    if addr_len > mem::size_of::<libc::sockaddr_storage>() {
        return Err(BrokerError::InvalidAddress);
    }

    let addr = read_target_addr(pid, target_addr, addr_len)?;
    let sock = duplicate_target_fd(pid, fd)?;
    let info = SocketInfo::read(sock.as_raw_fd())?;

    Ok(TargetSocket { sock, addr, info })
}

fn read_target_addr(pid: Pid, target_addr: usize, addr_len: usize) -> SysResult<Vec<u8>> {
    if addr_len < mem::size_of::<libc::sa_family_t>() {
        return Err(BrokerError::InvalidAddress);
    }

    let mut addr = vec![0_u8; addr_len];
    let mut local = [IoSliceMut::new(&mut addr)];
    let target = [RemoteIoVec {
        base: target_addr,
        len: addr_len,
    }];
    if process_vm_readv(pid, &mut local, &target).map_err(|error| BrokerError::SystemCall {
        errno: error as i32,
    })? != addr_len
    {
        return Err(BrokerError::BadAddress);
    }

    Ok(addr)
}

fn thread_group_leader(pid: Pid) -> SysResult<Pid> {
    let status_path = Path::new("/proc")
        .join(pid.as_raw().to_string())
        .join("status");
    let status = fs::read_to_string(status_path).map_err(|error| BrokerError::SystemCall {
        errno: error.raw_os_error().unwrap_or(libc::EIO),
    })?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Tgid:"))
        .ok_or(BrokerError::InvalidAddress)?;
    let value = line
        .strip_prefix("Tgid:")
        .ok_or(BrokerError::InvalidAddress)?;
    let tgid = value
        .trim()
        .parse::<i32>()
        .map_err(|_| BrokerError::InvalidAddress)?;
    if tgid <= 0 {
        return Err(BrokerError::InvalidAddress);
    }

    Ok(Pid::from_raw(tgid))
}

fn duplicate_target_fd(pid: Pid, fd: RawFd) -> SysResult<OwnedFd> {
    // Seccomp reports the calling thread ID, but pidfd_open without
    // PIDFD_THREAD accepts only a thread-group leader.
    let process = thread_group_leader(pid)?;
    // SAFETY: pidfd_open copies scalar arguments and returns a new fd on success.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, process.as_raw(), 0) };
    if pidfd < 0 {
        return Err(BrokerError::SystemCall {
            errno: Errno::last() as i32,
        });
    }
    // SAFETY: pidfd_open returned a new owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };

    // SAFETY: pidfd_getfd copies scalar arguments and returns a duplicated fd.
    let sock = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if sock < 0 {
        return Err(BrokerError::SystemCall {
            errno: Errno::last() as i32,
        });
    }

    // SAFETY: pidfd_getfd returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(sock as RawFd) })
}

fn broker_addr_call(sock: RawFd, addr: &[u8], call: SocketAddrCall) -> SysResult<i64> {
    // SAFETY: sockaddr_storage is plain old data and zero is a valid byte pattern.
    let mut storage = unsafe { mem::zeroed::<libc::sockaddr_storage>() };
    // SAFETY: storage is large enough because addr_len is capped before this point.
    unsafe {
        ptr::copy_nonoverlapping(
            addr.as_ptr(),
            ptr::addr_of_mut!(storage).cast::<u8>(),
            addr.len(),
        );
    }
    let addr_len =
        libc::socklen_t::try_from(addr.len()).map_err(|_| BrokerError::InvalidAddress)?;

    // SAFETY: storage contains copied target sockaddr bytes and is aligned.
    let rc = unsafe {
        call(
            sock,
            ptr::addr_of!(storage).cast::<libc::sockaddr>(),
            addr_len,
        )
    };
    if rc < 0 {
        Err(BrokerError::SystemCall {
            errno: Errno::last() as i32,
        })
    } else {
        Ok(i64::from(rc))
    }
}

fn create_path(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("/"));
    let parent = normalize_path(parent);

    match path.file_name() {
        Some(name) => parent.join(name),
        None => parent,
    }
}

fn path_exists(path: &Path) -> SysResult<bool> {
    path.try_exists().map_err(|error| BrokerError::SystemCall {
        errno: error.raw_os_error().unwrap_or(libc::EIO),
    })
}

fn open_flags(flags: i32) -> Vec<&'static str> {
    let mut names = Vec::new();
    match flags & libc::O_ACCMODE {
        libc::O_WRONLY => names.push("O_WRONLY"),
        libc::O_RDWR => names.push("O_RDWR"),
        _ => names.push("O_RDONLY"),
    }
    if flags & libc::O_CREAT != 0 {
        names.push("O_CREAT");
    }
    if flags & libc::O_TRUNC != 0 {
        names.push("O_TRUNC");
    }
    if flags & libc::O_APPEND != 0 {
        names.push("O_APPEND");
    }
    names
}

// The open flags and creation mode an open syscall requested.
struct Open {
    flags: i32,
    mode: u32,
}

impl Open {
    // openat passes flags and mode as scalar arguments.
    #[allow(clippy::cast_possible_truncation)]
    fn from_args(request: &libc::seccomp_notif) -> SysResult<Self> {
        let args = &request.data.args;
        let flags = i32::try_from(args[2]).map_err(|_| BrokerError::InvalidAddress)?;
        Ok(Self {
            flags,
            mode: args[3] as u32,
        })
    }

    // openat2 passes a struct open_how { u64 flags; u64 mode; u64 resolve; } by
    // pointer; only the first two fields matter. The kernel requires size >= 24,
    // but read just the bytes we use.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn from_how(request: &libc::seccomp_notif, pid: Pid) -> SysResult<Self> {
        let args = &request.data.args;
        let addr = usize::try_from(args[2]).map_err(|_| BrokerError::BadAddress)?;
        let size = usize::try_from(args[3]).map_err(|_| BrokerError::InvalidAddress)?;
        if addr == 0 {
            return Err(BrokerError::BadAddress);
        }
        let want = size.min(24);
        let mut buf = [0u8; 24];
        let mut local = [IoSliceMut::new(&mut buf[..want])];
        let target = [RemoteIoVec {
            base: addr,
            len: want,
        }];
        let n = process_vm_readv(pid, &mut local, &target).map_err(|error| {
            BrokerError::SystemCall {
                errno: error as i32,
            }
        })?;
        if n < 16 {
            return Err(BrokerError::BadAddress);
        }
        Ok(Self {
            flags: u64::from_ne_bytes(buf[0..8].try_into().map_err(|_| BrokerError::BadAddress)?)
                as i32,
            mode: u64::from_ne_bytes(buf[8..16].try_into().map_err(|_| BrokerError::BadAddress)?)
                as u32,
        })
    }
}

#[allow(clippy::too_many_lines)]
fn handle_openat(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    // args[0] is dirfd: an i32 (including AT_FDCWD=-100) stored as u64.
    #[allow(clippy::cast_possible_truncation)]
    let dirfd = request.data.args[0] as i32;
    let path_ptr = usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);
    let openat2 = i64::from(request.data.nr) == libc::SYS_openat2;
    let Open { flags, mode } = if openat2 {
        Open::from_how(request, pid)?
    } else {
        Open::from_args(request)?
    };
    let syscall_name = if openat2 { "openat2" } else { "openat" };

    let Some(path) = read_child_path(pid, path_ptr)? else {
        return Ok(NotificationResult::Continue);
    };

    let raw = resolve_child_path(pid, dirfd, &path)?;
    let resolved = normalize_path(&raw);
    let wants_write =
        (flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC)) != 0;
    let reports_write = (flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND)) != 0;
    let wants_read = (flags & libc::O_WRONLY) == 0;

    if wants_write {
        let lexical = normalize_path_lexically(&raw);
        let reason = if policy.is_write_denied(&resolved, &lexical) {
            Some("deny_match")
        } else if policy
            .write_roots
            .iter()
            .any(|root| resolved == *root || resolved.starts_with(root))
        {
            None
        } else {
            Some("allow_miss")
        };
        if let Some(reason) = reason {
            if (flags & libc::O_CREAT) == 0 && !path_exists(&resolved)? {
                return Err(BrokerError::SystemCall {
                    errno: libc::ENOENT,
                });
            }
            if reports_write {
                if query_enabled {
                    let qid = *next_query_id;
                    *next_query_id += 1;
                    let grant = Grant::open(&resolved, flags, mode);
                    return Ok(NotificationResult::query(
                        qid,
                        Trap::filesystem(
                            FilesystemDenial {
                                operation: TrapOperation::Write,
                                path: resolved,
                                requested_path: path,
                                syscall: syscall_name,
                                flags: open_flags(flags),
                                reason,
                                process: process_context(request.pid),
                            },
                            Some(qid),
                        ),
                        grant,
                    ));
                }
                denials.record(Denial::Filesystem(FilesystemDenial {
                    operation: TrapOperation::Write,
                    path: resolved.clone(),
                    requested_path: path.clone(),
                    syscall: syscall_name,
                    flags: open_flags(flags),
                    reason,
                    process: process_context(request.pid),
                }));
            }
            return Err(BrokerError::PolicyDenied);
        }
    }
    if wants_read {
        if let Some(reason) = fs_read_denial_reason(policy, &resolved) {
            if !path_exists(&resolved)? {
                return Err(BrokerError::SystemCall {
                    errno: libc::ENOENT,
                });
            }
            if query_enabled {
                let qid = *next_query_id;
                *next_query_id += 1;
                let grant = Grant::open(&resolved, flags, mode);
                return Ok(NotificationResult::query(
                    qid,
                    Trap::filesystem(
                        FilesystemDenial {
                            operation: TrapOperation::Read,
                            path: resolved,
                            requested_path: path,
                            syscall: syscall_name,
                            flags: open_flags(flags),
                            reason,
                            process: process_context(request.pid),
                        },
                        Some(qid),
                    ),
                    grant,
                ));
            }
            denials.record(Denial::Filesystem(FilesystemDenial {
                operation: TrapOperation::Read,
                path: resolved,
                requested_path: path,
                syscall: syscall_name,
                flags: open_flags(flags),
                reason,
                process: process_context(request.pid),
            }));
            return Err(BrokerError::PolicyDenied);
        }
    }

    // Reads are not Landlock-backed in the brokered child (f3f2105 dropped read
    // handling so execve of denyRead binaries works). Re-running openat in the
    // child via CONTINUE would reopen the classic seccomp-user-notification
    // TOCTOU, so have the broker open the allowed file itself and inject the fd.
    // Pure writes skip this: the brokered child still enforces Landlock write
    // rules, which catch a swapped write target.
    if wants_read {
        if let Some(Grant::Open(grant)) = Grant::open(&resolved, flags, mode) {
            return Ok(NotificationResult::Open(grant));
        }
    }

    Ok(NotificationResult::Continue)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod legacy_syscall {
    pub const RENAME: Option<i64> = Some(libc::SYS_rename);
    pub const LINK: Option<i64> = Some(libc::SYS_link);
    pub const SYMLINK: Option<i64> = Some(libc::SYS_symlink);
    pub const UNLINK: Option<i64> = Some(libc::SYS_unlink);
    pub const RMDIR: Option<i64> = Some(libc::SYS_rmdir);
    pub const MKDIR: Option<i64> = Some(libc::SYS_mkdir);
    pub const MKNOD: Option<i64> = Some(libc::SYS_mknod);
    pub const CREAT: Option<i64> = Some(libc::SYS_creat);
    pub const CHMOD: Option<i64> = Some(libc::SYS_chmod);
    pub const CHOWN: Option<i64> = Some(libc::SYS_chown);
    pub const LCHOWN: Option<i64> = Some(libc::SYS_lchown);
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
mod legacy_syscall {
    pub const RENAME: Option<i64> = None;
    pub const LINK: Option<i64> = None;
    pub const SYMLINK: Option<i64> = None;
    pub const UNLINK: Option<i64> = None;
    pub const RMDIR: Option<i64> = None;
    pub const MKDIR: Option<i64> = None;
    pub const MKNOD: Option<i64> = None;
    pub const CREAT: Option<i64> = None;
    pub const CHMOD: Option<i64> = None;
    pub const CHOWN: Option<i64> = None;
    pub const LCHOWN: Option<i64> = None;
}

struct Syscall {
    nr: Option<i64>,
    name: &'static str,
    paths: &'static [(Option<usize>, usize)],
    landlock_backed: bool,
}

impl Syscall {
    /// Whether this invocation targets the symlink itself rather than what it
    /// resolves to: an inherently no-follow call (`lchown`, `lsetxattr`,
    /// `lremovexattr`) or an `*at` call carrying `AT_SYMLINK_NOFOLLOW`. The policy
    /// check and the broker must then act on the link, not its target.
    fn no_follow(&self, args: &[u64; 6]) -> bool {
        // The flags argument is an int; truncating to i32 recovers it from the
        // u64 register slot the same way the dirfd arguments are read.
        #[allow(clippy::cast_possible_truncation)]
        let flag = |index: usize| args[index] as i32 & libc::AT_SYMLINK_NOFOLLOW != 0;
        #[allow(clippy::cast_possible_truncation)]
        let follow = |index: usize| args[index] as i32 & libc::AT_SYMLINK_FOLLOW != 0;
        match self.name {
            "lchown" | "lsetxattr" | "lremovexattr" | "link" => true,
            "fchownat" => flag(4),
            "fchmodat" | "utimensat" => flag(3),
            // linkat(2) links the symlink itself unless AT_SYMLINK_FOLLOW is set;
            // link(2) has no flags and never dereferences.
            "linkat" => !follow(4),
            _ => false,
        }
    }
}

const MUTATION_SYSCALLS: &[Syscall] = &[
    Syscall {
        nr: Some(libc::SYS_renameat2),
        name: "renameat2",
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_renameat),
        name: "renameat",
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_linkat),
        name: "linkat",
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_symlinkat),
        name: "symlinkat",
        paths: &[(Some(1), 2)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_unlinkat),
        name: "unlinkat",
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_mkdirat),
        name: "mkdirat",
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_mknodat),
        name: "mknodat",
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_truncate),
        name: "truncate",
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_fchmodat),
        name: "fchmodat",
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fchownat),
        name: "fchownat",
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_utimensat),
        name: "utimensat",
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_setxattr),
        name: "setxattr",
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_lsetxattr),
        name: "lsetxattr",
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_removexattr),
        name: "removexattr",
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_lremovexattr),
        name: "lremovexattr",
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::RENAME,
        name: "rename",
        paths: &[(None, 0), (None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::LINK,
        name: "link",
        paths: &[(None, 0), (None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::SYMLINK,
        name: "symlink",
        paths: &[(None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::UNLINK,
        name: "unlink",
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::RMDIR,
        name: "rmdir",
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::MKDIR,
        name: "mkdir",
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::MKNOD,
        name: "mknod",
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::CREAT,
        name: "creat",
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::CHMOD,
        name: "chmod",
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::CHOWN,
        name: "chown",
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::LCHOWN,
        name: "lchown",
        paths: &[(None, 0)],
        landlock_backed: false,
    },
];

fn handle_mutation(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let syscall = i64::from(request.data.nr);
    let Some(spec) = MUTATION_SYSCALLS.iter().find(|s| s.nr == Some(syscall)) else {
        return Ok(NotificationResult::Continue);
    };
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);

    let mut slots: Vec<Option<(PathBuf, PathBuf)>> = Vec::with_capacity(spec.paths.len());
    let mut denial: Option<(usize, &'static str)> = None;
    let no_follow = spec.no_follow(&request.data.args);
    for (index, (dirfd_arg, path_arg)) in spec.paths.iter().enumerate() {
        let dirfd = match dirfd_arg {
            // args[i] is an i32 dirfd (including AT_FDCWD=-100) stored as u64.
            #[allow(clippy::cast_possible_truncation)]
            Some(arg) => request.data.args[*arg] as i32,
            None => libc::AT_FDCWD,
        };
        let path_ptr =
            usize::try_from(request.data.args[*path_arg]).map_err(|_| BrokerError::BadAddress)?;
        let Some(path) = read_child_path(pid, path_ptr)? else {
            slots.push(None);
            continue;
        };
        let raw = resolve_child_path(pid, dirfd, &path)?;
        // No-follow ops act on the link itself: canonicalize the parent but keep
        // the final component so the policy gates the symlink, not its target.
        let resolved = if no_follow {
            normalize_path_nofollow(&raw)
        } else {
            normalize_path(&raw)
        };
        if denial.is_none() {
            let lexical = normalize_path_lexically(&raw);
            let surface_allow_miss = query_enabled || !spec.landlock_backed;
            if let Some(reason) = policy.to_reason(&resolved, &lexical, surface_allow_miss) {
                denial = Some((index, reason));
            }
        }
        slots.push(Some((resolved, path)));
    }

    let Some((index, reason)) = denial else {
        return Ok(NotificationResult::Continue);
    };
    let (resolved, path) = slots[index].clone().ok_or(BrokerError::InvalidAddress)?;

    if !query_enabled {
        denials.record(Denial::Filesystem(FilesystemDenial {
            operation: TrapOperation::Write,
            path: resolved,
            requested_path: path,
            syscall: spec.name,
            flags: Vec::new(),
            reason,
            process: process_context(request.pid),
        }));
        return Err(BrokerError::PolicyDenied);
    }

    let qid = *next_query_id;
    *next_query_id += 1;
    let grant = Grant::mutation(spec, request, pid, &slots)?;
    Ok(NotificationResult::query(
        qid,
        Trap::filesystem(
            FilesystemDenial {
                operation: TrapOperation::Write,
                path: resolved,
                requested_path: path,
                syscall: spec.name,
                flags: Vec::new(),
                reason,
                process: process_context(request.pid),
            },
            Some(qid),
        ),
        grant,
    ))
}

impl Grant {
    fn socket(sock: OwnedFd, addr: Vec<u8>, call: SocketAddrCall) -> Grant {
        Grant::Socket(SocketGrant { sock, addr, call })
    }

    fn open(resolved: &Path, flags: i32, mode: u32) -> Option<Grant> {
        let kind = if let Some(handle) =
            open_path(resolved, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        {
            OpenKind::Reopen(handle)
        } else {
            OpenKind::Create {
                anchor: Anchor::new(resolved)?,
                mode,
            }
        };
        Some(Grant::Open(OpenGrant { flags, kind }))
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn mutation(
        spec: &Syscall,
        request: &libc::seccomp_notif,
        pid: Pid,
        slots: &[Option<(PathBuf, PathBuf)>],
    ) -> SysResult<Option<Grant>> {
        let args = &request.data.args;

        if spec.name == "creat" {
            let Some((resolved, _)) = slots.first().and_then(Option::as_ref) else {
                return Ok(None);
            };
            return Ok(Grant::open(
                resolved,
                libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
                args[1] as u32,
            ));
        }

        let mut anchors = Vec::with_capacity(slots.len());
        for slot in slots {
            let Some((resolved, _)) = slot else {
                return Ok(None);
            };
            match Anchor::new(resolved) {
                Some(anchor) => anchors.push(anchor),
                None => return Ok(None),
            }
        }

        let op = match spec.name {
            "mkdirat" => MutationOp::Mkdir {
                mode: args[2] as u32,
            },
            "mkdir" => MutationOp::Mkdir {
                mode: args[1] as u32,
            },
            "mknodat" => MutationOp::Mknod {
                mode: args[2] as u32,
                dev: args[3],
            },
            "mknod" => MutationOp::Mknod {
                mode: args[1] as u32,
                dev: args[2],
            },
            "unlinkat" => MutationOp::Unlink {
                flags: args[2] as i32,
            },
            "unlink" => MutationOp::Unlink { flags: 0 },
            "rmdir" => MutationOp::Unlink {
                flags: libc::AT_REMOVEDIR,
            },
            "renameat2" => MutationOp::Rename {
                flags: args[4] as u32,
            },
            "renameat" | "rename" => MutationOp::Rename { flags: 0 },
            "linkat" => MutationOp::Link {
                flags: args[4] as i32,
            },
            "link" => MutationOp::Link { flags: 0 },
            "symlinkat" | "symlink" => {
                let Some(target) = read_child_target(pid, args[0])? else {
                    return Ok(None);
                };
                MutationOp::Symlink { target }
            }
            "truncate" => MutationOp::Truncate {
                length: args[1] as i64,
            },
            "fchmodat" => MutationOp::Chmod {
                mode: args[2] as u32,
            },
            "chmod" => MutationOp::Chmod {
                mode: args[1] as u32,
            },
            "fchownat" => MutationOp::Chown {
                uid: args[2] as u32,
                gid: args[3] as u32,
            },
            "chown" | "lchown" => MutationOp::Chown {
                uid: args[1] as u32,
                gid: args[2] as u32,
            },
            "utimensat" => MutationOp::Utimes {
                times: read_child_times(pid, args[2])?,
            },
            "setxattr" | "lsetxattr" => {
                let Some(name) = read_child_target(pid, args[1])? else {
                    return Ok(None);
                };
                MutationOp::SetXattr {
                    name,
                    value: read_child_bytes(pid, args[2], args[3])?,
                    flags: args[4] as i32,
                }
            }
            "removexattr" | "lremovexattr" => {
                let Some(name) = read_child_target(pid, args[1])? else {
                    return Ok(None);
                };
                MutationOp::RemoveXattr { name }
            }
            _ => return Ok(None),
        };

        Ok(Some(Grant::Mutation(MutationGrant {
            op,
            anchors,
            no_follow: spec.no_follow(args),
        })))
    }
}

fn read_child_target(pid: Pid, ptr: u64) -> SysResult<Option<CString>> {
    let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
    if addr == 0 {
        return Ok(None);
    }
    let buf = read_child_string(pid, addr, libc::PATH_MAX as usize)?;
    Ok(CString::new(buf).ok())
}

// Read utimensat's two timespecs from the child; a null pointer means "now".
fn read_child_times(pid: Pid, ptr: u64) -> SysResult<Option<[libc::timespec; 2]>> {
    let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
    if addr == 0 {
        return Ok(None);
    }
    let mut times = [libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }; 2];
    let len = mem::size_of_val(&times);
    // SAFETY: times is a live, suitably aligned array of two POD timespecs that
    // we expose as its raw byte span for the copy from the child.
    let bytes = unsafe { std::slice::from_raw_parts_mut(times.as_mut_ptr().cast::<u8>(), len) };
    let mut local = [IoSliceMut::new(bytes)];
    let target = [RemoteIoVec { base: addr, len }];
    let n =
        process_vm_readv(pid, &mut local, &target).map_err(|error| BrokerError::SystemCall {
            errno: error as i32,
        })?;
    if n < len {
        return Err(BrokerError::BadAddress);
    }
    Ok(Some(times))
}

// Read an extended-attribute value (capped) from the child.
fn read_child_bytes(pid: Pid, ptr: u64, size: u64) -> SysResult<Vec<u8>> {
    const XATTR_MAX: usize = 65536;
    let len = usize::try_from(size)
        .map_err(|_| BrokerError::InvalidAddress)?
        .min(XATTR_MAX);
    let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
    if len == 0 || addr == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len];
    let mut local = [IoSliceMut::new(&mut buf)];
    let target = [RemoteIoVec { base: addr, len }];
    let n =
        process_vm_readv(pid, &mut local, &target).map_err(|error| BrokerError::SystemCall {
            errno: error as i32,
        })?;
    buf.truncate(n);
    Ok(buf)
}

fn read_child_path(pid: Pid, path_ptr: usize) -> SysResult<Option<PathBuf>> {
    if path_ptr == 0 {
        return Ok(None);
    }

    let buf = read_child_string(pid, path_ptr, libc::PATH_MAX as usize)?;
    let path = OsStr::from_bytes(&buf);
    if path.is_empty() {
        return Ok(None);
    }

    Ok(Some(PathBuf::from(path)))
}

fn read_child_string(pid: Pid, addr: usize, max_len: usize) -> SysResult<Vec<u8>> {
    let mut buf = vec![0_u8; max_len];
    let mut local = [IoSliceMut::new(&mut buf)];
    let target = [RemoteIoVec {
        base: addr,
        len: max_len,
    }];
    let n =
        process_vm_readv(pid, &mut local, &target).map_err(|error| BrokerError::SystemCall {
            errno: error as i32,
        })?;

    let null_pos = buf[..n].iter().position(|b| *b == 0).unwrap_or(n);
    buf.truncate(null_pos);
    Ok(buf)
}

/// Upper bound on the trap-fd control buffer. A well-formed launcher sends
/// newline-terminated JSON responses, each far smaller than this; exceeding it
/// without a newline means a broken or hostile peer and the partial run-on
/// data is discarded rather than grown without limit.
const CONTROL_BUFFER_MAX: usize = 64 * 1024;

fn process_control_responses(
    control_fd: i32,
    buffer: &mut Vec<u8>,
    pending_queries: &mut std::collections::HashMap<u64, PendingQuery>,
    notify_fd: RawFd,
) -> bool {
    let mut chunk = [0u8; 4096];
    // SAFETY: read(2) copies bytes from the live buffer.
    let n = loop {
        let n = unsafe { libc::read(control_fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break n;
    };
    if n == 0 {
        // read(2) returning 0 means the launcher closed the trap fd. Signal EOF
        // so the caller denies any pending queries and stops polling.
        return true;
    }
    if n < 0 {
        // Permanent read error; leave the fd alone and let the next poll retry.
        // Fd death is observed via POLLHUP/POLLERR on the control fd.
        return false;
    }
    let Ok(n) = usize::try_from(n) else {
        return false;
    };
    buffer.extend_from_slice(&chunk[..n]);

    // Bound memory against a misbehaving or hostile launcher that never sends a
    // newline: drop a run-on partial response and keep going rather than grow
    // without limit. Well-formed responses are newline-terminated and small.
    if buffer.len() > CONTROL_BUFFER_MAX {
        log::warn!(
            "linux: control buffer exceeded {CONTROL_BUFFER_MAX} bytes with no newline; dropping"
        );
        buffer.clear();
        return false;
    }

    // The trap fd is a stream socket, so a read may split a response across
    // boundaries. Only consume complete newline-terminated lines and keep any
    // trailing partial line for the next read; otherwise a fragmented response
    // would be dropped, leaving the child's syscall suspended forever.
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
            continue;
        };
        let Ok(query_id) = response.query_id.parse::<u64>() else {
            continue;
        };
        if let Some(pending) = pending_queries.remove(&query_id) {
            let id = pending.request.id;
            if !validate_notification_id(notify_fd, id).unwrap_or(false) {
                continue;
            }
            match response.action {
                ControlAction::Allow => match pending.grant {
                    // The broker fulfils the operation itself — it runs outside
                    // the child's Landlock sandbox — so the approval works even
                    // for paths Landlock forbids.
                    Some(Grant::Open(grant)) => grant_open(notify_fd, id, &grant),
                    Some(Grant::Mutation(grant)) => grant_mutation(notify_fd, id, &grant),
                    Some(Grant::Socket(grant)) => grant_socket(notify_fd, id, &grant),
                    // No grant to satisfy: let the kernel run the syscall, still
                    // subject to the child's Landlock.
                    None => {
                        let _ = respond_notification(notify_fd, notification_continue(id));
                    }
                },
                ControlAction::Deny => {
                    let _ = respond_notification(
                        notify_fd,
                        notification_error(id, -LandstripError::DENIAL_ERRNO),
                    );
                }
            }
        }
    }
    false
}

// Deny every deferred query with EACCES and clear the map. Used when the
// control channel is gone (launcher closed or errored the trap fd) so the
// child's suspended syscalls resume instead of hanging forever. Expired
// notification ids are skipped, matching the per-response path.
fn deny_all_pending(
    pending_queries: &mut std::collections::HashMap<u64, PendingQuery>,
    notify_fd: RawFd,
) {
    for (_id, pending) in pending_queries.drain() {
        let id = pending.request.id;
        if validate_notification_id(notify_fd, id).unwrap_or(false) {
            let _ = respond_notification(
                notify_fd,
                notification_error(id, -LandstripError::DENIAL_ERRNO),
            );
        }
    }
}

fn grant_open(notify_fd: RawFd, id: u64, grant: &OpenGrant) {
    let opened = match broker_open(grant) {
        Ok(fd) => fd,
        Err(errno) => {
            let _ = respond_notification(notify_fd, notification_error(id, -errno.abs()));
            return;
        }
    };

    let cloexec = (grant.flags & libc::O_CLOEXEC) != 0;
    let addfd = libc::seccomp_notif_addfd {
        id,
        flags: u32::try_from(libc::SECCOMP_ADDFD_FLAG_SEND).unwrap_or(0),
        srcfd: u32::try_from(opened.as_raw_fd()).unwrap_or(0),
        newfd: 0,
        newfd_flags: if cloexec {
            u32::try_from(libc::O_CLOEXEC).unwrap_or(0)
        } else {
            0
        },
    };

    // SAFETY: addfd points to an initialized struct and opened is a live fd; the
    // SEND flag makes the ioctl complete the notification atomically.
    if unsafe { seccomp_notif_addfd(notify_fd, ptr::addr_of!(addfd)) }.is_err() {
        let _ = respond_notification(
            notify_fd,
            notification_error(id, -LandstripError::DENIAL_ERRNO),
        );
    }
}

fn grant_mutation(notify_fd: RawFd, id: u64, grant: &MutationGrant) {
    let rc = match run_mutation(grant) {
        Ok(()) => notification_value(id, 0),
        Err(errno) => notification_error(id, -errno.abs()),
    };
    let _ = respond_notification(notify_fd, rc);
}

// The broker re-issues the approved connect or bind on the duplicated child
// socket, which shares the child's open file description, so the call takes
// effect on the child's socket while running outside its seccomp filter.
fn grant_socket(notify_fd: RawFd, id: u64, grant: &SocketGrant) {
    let rc = match broker_addr_call(grant.sock.as_raw_fd(), &grant.addr, grant.call) {
        Ok(value) => notification_value(id, value),
        Err(error) => notification_error(id, -error.errno().abs()),
    };
    let _ = respond_notification(notify_fd, rc);
}

fn run_mutation(grant: &MutationGrant) -> std::result::Result<(), i32> {
    let at = grant.anchors.first().ok_or(libc::EINVAL)?;
    let dir = at.dir.as_raw_fd();
    let name = at.name.as_ptr();

    let rc = match &grant.op {
        // Directory-entry operations act on a name within the pinned parent.
        MutationOp::Mkdir { mode } => unsafe { libc::mkdirat(dir, name, *mode) },
        MutationOp::Mknod { mode, dev } => unsafe { libc::mknodat(dir, name, *mode, *dev) },
        MutationOp::Unlink { flags } => unsafe { libc::unlinkat(dir, name, *flags) },
        MutationOp::Symlink { target } => unsafe { libc::symlinkat(target.as_ptr(), dir, name) },
        MutationOp::Truncate { length } => {
            let (file, _path) = pin_target(at)?;
            // SAFETY: ftruncate operates on the freshly opened owned fd.
            return check(unsafe { libc::ftruncate(file.as_raw_fd(), *length) });
        }
        MutationOp::Rename { flags } => {
            let to = grant.anchors.get(1).ok_or(libc::EINVAL)?;
            // libc 0.2 ships no renameat2 wrapper, so invoke the syscall
            // directly to carry RENAME_NOREPLACE/EXCHANGE/WHITEOUT through.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    dir,
                    name,
                    to.dir.as_raw_fd(),
                    to.name.as_ptr(),
                    *flags,
                )
            };
            return if rc < 0 {
                Err(Errno::last() as i32)
            } else {
                Ok(())
            };
        }
        MutationOp::Link { flags } => {
            let to = grant.anchors.get(1).ok_or(libc::EINVAL)?;
            unsafe { libc::linkat(dir, name, to.dir.as_raw_fd(), to.name.as_ptr(), *flags) }
        }
        // Metadata operations have no *at form covering every case, so act on the
        // pinned target through /proc/self/fd, which keeps a symlink swapped into
        // the final component from redirecting them.
        MutationOp::Chmod { mode } => {
            let (_fd, path) = pin_target(at)?;
            unsafe { libc::chmod(path.as_ptr(), *mode) }
        }
        MutationOp::Chown { uid, gid } => {
            if grant.no_follow {
                // Act on the link itself; the parent dir fd is already pinned.
                unsafe { libc::fchownat(dir, name, *uid, *gid, libc::AT_SYMLINK_NOFOLLOW) }
            } else {
                let (_fd, path) = pin_target(at)?;
                unsafe { libc::chown(path.as_ptr(), *uid, *gid) }
            }
        }
        MutationOp::Utimes { times } => {
            let ptr = times.as_ref().map_or(ptr::null(), |t| t.as_ptr());
            if grant.no_follow {
                unsafe { libc::utimensat(dir, name, ptr, libc::AT_SYMLINK_NOFOLLOW) }
            } else {
                let (_fd, path) = pin_target(at)?;
                unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), ptr, 0) }
            }
        }
        MutationOp::SetXattr { name, value, flags } => {
            let (_fd, path) = pin_target(at)?;
            unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    *flags,
                )
            }
        }
        MutationOp::RemoveXattr { name } => {
            let (_fd, path) = pin_target(at)?;
            unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) }
        }
    };
    check(rc)
}

fn check(rc: libc::c_int) -> std::result::Result<(), i32> {
    if rc < 0 {
        return Err(Errno::last() as i32);
    }
    Ok(())
}

// Pin an existing target within the anchor's directory and return both the
// O_PATH handle and a /proc/self/fd path that operates on it.
fn pin_target(at: &Anchor) -> std::result::Result<(OwnedFd, CString), i32> {
    // SAFETY: anchored open of a NUL-terminated name; O_PATH|O_NOFOLLOW pins the
    // final component without following a symlink swapped into it.
    let fd = unsafe {
        libc::openat(
            at.dir.as_raw_fd(),
            at.name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Errno::last() as i32);
    }
    // SAFETY: openat returned a new owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let path =
        CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(|_| libc::EINVAL)?;
    Ok((fd, path))
}

fn open_path(path: &Path, flags: i32) -> Option<OwnedFd> {
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: cpath is NUL-terminated and open copies it.
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        return None;
    }
    // SAFETY: open returned a new owned descriptor.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

impl Anchor {
    fn new(resolved: &Path) -> Option<Self> {
        Some(Self {
            dir: open_path(
                resolved.parent()?,
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )?,
            name: CString::new(resolved.file_name()?.as_bytes()).ok()?,
        })
    }
}

fn broker_open(grant: &OpenGrant) -> std::result::Result<OwnedFd, i32> {
    match &grant.kind {
        // Reopen the pinned inode through procfs; drop creation flags since it
        // already exists, but honour the access mode and O_TRUNC/O_APPEND.
        OpenKind::Reopen(handle) => {
            let proc_path = CString::new(format!("/proc/self/fd/{}", handle.as_raw_fd()))
                .map_err(|_| libc::EINVAL)?;
            let flags = (grant.flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW))
                | libc::O_CLOEXEC;
            // SAFETY: proc_path is NUL-terminated and names the pinned inode.
            let fd = unsafe { libc::open(proc_path.as_ptr(), flags) };
            if fd < 0 {
                return Err(Errno::last() as i32);
            }
            // SAFETY: open returned a new owned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
        // Create within the pinned parent; O_NOFOLLOW blocks a symlink swapped
        // into the final name from redirecting the create.
        OpenKind::Create { anchor, mode } => {
            let flags = grant.flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            // SAFETY: name is NUL-terminated and resolved relative to the pinned parent.
            let fd = unsafe {
                libc::openat(
                    anchor.dir.as_raw_fd(),
                    anchor.name.as_ptr(),
                    flags,
                    *mode as libc::c_uint,
                )
            };
            if fd < 0 {
                return Err(Errno::last() as i32);
            }
            // SAFETY: openat returned a new owned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
}

fn resolve_child_path(pid: Pid, dirfd: i32, path: &Path) -> SysResult<PathBuf> {
    if path.is_absolute() {
        if let Ok(suffix) = path.strip_prefix("/proc/self") {
            return Ok(Path::new("/proc").join(pid.to_string()).join(suffix));
        }
        return Ok(path.to_path_buf());
    }

    if dirfd == libc::AT_FDCWD {
        let cwd =
            fs::read_link(format!("/proc/{pid}/cwd")).map_err(|error| BrokerError::SystemCall {
                errno: error.raw_os_error().unwrap_or(libc::EIO),
            })?;
        return Ok(cwd.join(path));
    }

    // dirfd is a file descriptor; resolve relative to /proc/<pid>/fd/<dirfd>
    let dir_path = fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).map_err(|error| {
        BrokerError::SystemCall {
            errno: error.raw_os_error().unwrap_or(libc::EBADF),
        }
    })?;
    Ok(dir_path.join(path))
}

fn fs_read_denial_reason(policy: &AccessPolicy, path: &Path) -> Option<&'static str> {
    match &policy.read_access {
        ReadAccess::Unrestricted => None,
        ReadAccess::AllowRoots(roots) => {
            if policy
                .read_denied_roots
                .iter()
                .any(|root| path == root || path.starts_with(root))
            {
                return Some("deny_match");
            }
            if roots
                .iter()
                .any(|root| path == root || path.starts_with(root))
            {
                None
            } else {
                Some("allow_miss")
            }
        }
    }
}

fn sockopt(fd: RawFd, level: libc::c_int, name: libc::c_int) -> SysResult<i32> {
    super::fd::getsockopt_int(fd, level, name).map_err(|error| BrokerError::SystemCall {
        errno: error.raw_os_error().unwrap_or(0),
    })
}

fn send_fd(socket: &UnixStream, fd: RawFd) -> Result<()> {
    let byte = [0_u8];
    let iov = [IoSlice::new(&byte)];
    let fds = [fd];
    loop {
        match sendmsg::<()>(
            socket.as_raw_fd(),
            &iov,
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        ) {
            Ok(_) => return Ok(()),
            // A signal during the fd transfer must not abort the broker setup.
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(supervise_errno(error).into()),
        }
    }
}

fn send_trap(socket: &mut UnixStream, trap: &Trap) -> Result<()> {
    let payload = trap.json_line();
    let length =
        u32::try_from(payload.len()).map_err(|_| supervise_failed("notify: trap is too large"))?;

    socket.write_all(&[1_u8]).map_err(supervise_failed)?;
    socket
        .write_all(&length.to_be_bytes())
        .map_err(supervise_failed)?;
    socket
        .write_all(payload.as_bytes())
        .map_err(supervise_failed)?;
    Ok(())
}

fn get_notify_fd(socket: &UnixStream) -> Result<NotifyStartup> {
    let mut byte = [0_u8];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut control = nix::cmsg_space!([RawFd; 1]);
    let (bytes, fd) = loop {
        let message = match recvmsg::<()>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::empty(),
        ) {
            Ok(message) => message,
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(supervise_errno(error).into()),
        };
        let fd = message
            .cmsgs()
            .map_err(supervise_errno)?
            .find_map(|control| match control {
                ControlMessageOwned::ScmRights(fds) => fds.first().copied(),
                _ => None,
            });
        break (message.bytes, fd);
    };

    if bytes == 0 {
        return Err(supervise_failed("notify: unexpected eof").into());
    }

    match byte[0] {
        0 => fd.map_or_else(
            || Err(supervise_failed("notify: missing descriptor").into()),
            |fd| {
                // SAFETY: SCM_RIGHTS transfers ownership of the received descriptor.
                Ok(NotifyStartup::Ready(unsafe { OwnedFd::from_raw_fd(fd) }))
            },
        ),
        1 => {
            let mut length = [0_u8; 4];
            let mut socket = socket;
            socket.read_exact(&mut length).map_err(supervise_failed)?;
            let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
            if length > 1_048_576 {
                return Err(supervise_failed("notify: trap is too large").into());
            }
            let mut payload = vec![0_u8; length];
            socket.read_exact(&mut payload).map_err(supervise_failed)?;
            let trap = String::from_utf8(payload)
                .map_err(|error| supervise_failed(format!("notify: invalid trap: {error}")))?;
            if serde_json::from_str::<serde_json::Value>(&trap).is_err() {
                return Err(supervise_failed("notify: invalid trap").into());
            }
            Ok(NotifyStartup::Trap(trap))
        }
        _ => Err(supervise_failed("notify: invalid marker").into()),
    }
}

#[derive(Debug)]
struct TargetSocket {
    sock: OwnedFd,
    addr: Vec<u8>,
    info: SocketInfo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketInfo {
    domain: i32,
    ty: i32,
    proto: i32,
}

impl SocketInfo {
    fn read(fd: RawFd) -> SysResult<Self> {
        Ok(Self {
            domain: sockopt(fd, libc::SOL_SOCKET, libc::SO_DOMAIN)?,
            ty: sockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE)?,
            proto: sockopt(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL)?,
        })
    }

    fn kind(&self) -> SocketKind {
        if matches!(self.domain, libc::AF_INET | libc::AF_INET6)
            && self.ty == libc::SOCK_STREAM
            && self.proto == libc::IPPROTO_TCP
        {
            SocketKind::Tcp
        } else if self.domain == libc::AF_UNIX {
            SocketKind::Unix
        } else if matches!(self.domain, libc::AF_INET | libc::AF_INET6)
            || matches!(self.domain, libc::AF_PACKET | libc::AF_NETLINK)
        {
            SocketKind::NotSupported
        } else {
            SocketKind::Other
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketKind {
    Tcp,
    Unix,
    NotSupported,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TcpEndpoint {
    addr: SocketAddr,
    port: u16,
    loopback: bool,
}

enum NotificationResult {
    Value(i64),
    Continue,
    Query(QueryDecision),
    Open(OpenGrant),
}

struct QueryDecision {
    query_id: u64,
    trap: Trap,
    grant: Option<Grant>,
}

impl NotificationResult {
    fn query(query_id: u64, trap: Trap, grant: Option<Grant>) -> Self {
        NotificationResult::Query(QueryDecision {
            query_id,
            trap,
            grant,
        })
    }
}

enum Grant {
    Open(OpenGrant),
    Mutation(MutationGrant),
    Socket(SocketGrant),
}

// A duplicated child socket and the resolved target address for a connect or
// bind the broker re-issues itself when a network query is approved.
struct SocketGrant {
    sock: OwnedFd,
    addr: Vec<u8>,
    call: SocketAddrCall,
}

struct Anchor {
    dir: OwnedFd,
    name: CString,
}

struct OpenGrant {
    flags: i32,
    kind: OpenKind,
}

enum OpenKind {
    /// The target already existed at query time; reopen its pinned inode through
    /// `/proc/self/fd` so no path is re-resolved after the prompt.
    Reopen(OwnedFd),
    /// The target did not exist; create it within the pinned parent. `O_NOFOLLOW`
    /// is added so a symlink swapped into the name cannot redirect the create.
    Create { anchor: Anchor, mode: u32 },
}

struct MutationGrant {
    op: MutationOp,
    /// Anchors for each path argument, in the syscall's path order.
    anchors: Vec<Anchor>,
    /// The op targets the link itself (`lchown`, or `*at` with
    /// `AT_SYMLINK_NOFOLLOW`); execute it without following the final symlink.
    no_follow: bool,
}

enum MutationOp {
    Mkdir {
        mode: u32,
    },
    Mknod {
        mode: u32,
        dev: u64,
    },
    Unlink {
        flags: i32,
    },
    Symlink {
        target: CString,
    },
    Truncate {
        length: i64,
    },
    Rename {
        flags: u32,
    },
    Link {
        flags: i32,
    },
    Chmod {
        mode: u32,
    },
    Chown {
        uid: u32,
        gid: u32,
    },
    Utimes {
        times: Option<[libc::timespec; 2]>,
    },
    SetXattr {
        name: CString,
        value: Vec<u8>,
        flags: i32,
    },
    RemoveXattr {
        name: CString,
    },
}

struct PendingQuery {
    request: libc::seccomp_notif,
    grant: Option<Grant>,
}

pub(super) struct NotificationSyscalls {
    pub(super) bind: i64,
    pub(super) connect: i64,
    pub(super) socket: i64,
    openat: i64,
    openat2: i64,
}

impl NotificationSyscalls {
    pub(super) fn new() -> Self {
        Self {
            bind: libc::SYS_bind,
            connect: libc::SYS_connect,
            socket: libc::SYS_socket,
            openat: libc::SYS_openat,
            openat2: libc::SYS_openat2,
        }
    }

    // stat (newfstatat/statx) is intentionally not mediated: blocking metadata
    // reads breaks directory traversal (git, shells, build tools all stat
    // ancestor dirs to canonicalise paths), and denyRead still blocks reading
    // file contents and listing directories via openat.
    pub(super) fn filesystem_syscalls(&self) -> [i64; 2] {
        [self.openat, self.openat2]
    }
}

fn exit_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
        _ => 1,
    }
}
