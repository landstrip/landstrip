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
//! `connect` and `bind`; unnamed sockets and `socketpair` are not path-mediated.
//! `allowAllUnixSockets` permits new Unix sockets without path checks. systemd
//! and D-Bus control sockets stay denied either way: they start processes that
//! would inherit neither Landlock nor seccomp. Host-created abstract Unix sockets
//! are denied by Landlock scope on ABI 6+ (Linux 6.12+); the broker cannot tell
//! those apart from sockets the child created itself.

use super::filter::{NetworkFilters, build_errno_filter, build_notify_filter};
use super::landlock::enforce_broker_access_policy;
use crate::error::{Error as LandstripError, Mechanism};
use crate::paths::{
    PathCoverage, normalize_path, normalize_path_lexically, normalize_path_nofollow,
};
use crate::platform::unix::close_inherited_fds;
use crate::policy::{AccessPolicy, DenialReason, ReadAccess, UnixSocketAccess};
use crate::trap::{FilesystemDenial, NetworkOperation, ProcessContext, Trap, TrapOperation};
use crate::trap_fd::TrapFd;
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
use std::env;
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

const POLL_MS: u16 = 100;
const SECCOMP_IOC_MAGIC: u8 = b'!';
const USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;
// fchmodat2 (Linux 6.6+) is 452 on every landstrip target. libc only exports the
// constant on some arches, so pin the number here for portable mediation.
const SYS_FCHMODAT2: i64 = 452;

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

/// Recover the low 32 bits of a syscall argument register as an unsigned C
/// argument. Seccomp exposes every register as `u64`, including 32-bit values.
fn syscall_u32(value: u64) -> u32 {
    let bytes = value.to_ne_bytes();
    if cfg!(target_endian = "little") {
        u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
    }
}

/// Recover the low 32 bits of a syscall argument register as a signed C
/// argument, preserving values such as `AT_FDCWD` that are sign-extended.
fn syscall_i32(value: u64) -> i32 {
    syscall_u32(value).cast_signed()
}

/// Reinterpret a syscall argument register as its signed 64-bit C type.
fn syscall_i64(value: u64) -> i64 {
    value.cast_signed()
}

/// A syscall that failed while supervising the sandboxed child.
fn supervise_errno(errno: Errno) -> LandstripError {
    LandstripError::supervise(io::Error::from_raw_os_error(errno as i32))
}

pub(super) fn run_broker(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    needs_network: bool,
    needs_filesystem: bool,
    trap_fd: Option<&TrapFd>,
) -> Result<i32> {
    let notify_bind = needs_network && policy.network_access.needs_bind_broker();
    // allowNetwork / allowAllUnixSockets leave unix unrestricted; still trap
    // connect so systemd-run cannot start a process outside Landlock/seccomp.
    let notify_connect = (needs_network && policy.network_access.needs_network_broker())
        || needs_filesystem
        || matches!(
            policy.network_access.unix_socket_access(),
            UnixSocketAccess::Unrestricted
        );
    let notify_filesystem = needs_filesystem;
    let unix_sockets = policy.network_access.unix_socket_access().into();
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
    let (parent, child_sock) = UnixStream::pair().map_err(LandstripError::supervise)?;

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

                    let notify = fcntl(notify.as_fd(), FcntlArg::F_DUPFD_CLOEXEC(0))
                        .map_err(supervise_errno)?;
                    // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
                    let notify = unsafe { OwnedFd::from_raw_fd(notify) };

                    send_fd(&child_sock, notify.as_fd())?;
                    handed_off = true;
                }

                let mut excluded = vec![child_sock.as_raw_fd()];
                if let Some(trap_fd) = trap_fd {
                    excluded.push(trap_fd.as_raw_fd());
                }
                close_inherited_fds(&excluded).map_err(LandstripError::supervise)?;

                let mut child_tool = Command::new(tool);
                child_tool.args(args);

                let error = child_tool.exec();
                Err(LandstripError::launch(tool, error).into())
            })();

            if let Err(error) = result {
                let trap = error
                    .chain()
                    .find_map(<dyn std::error::Error + 'static>::downcast_ref::<LandstripError>)
                    .map_or_else(|| Trap::internal(format!("{error:#}")), Trap::from);
                if handed_off || send_trap(&mut child_sock, &trap).is_err() {
                    if let Some(trap_fd) = trap_fd {
                        trap_fd.write(&trap);
                    }
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

                    supervise_child(
                        policy,
                        child,
                        notify.as_fd(),
                        &syscalls,
                        notify_filesystem,
                        trap_fd,
                    )
                }
                NotifyStartup::Trap(trap) => {
                    drop(parent);
                    if let Some(trap_fd) = trap_fd {
                        trap_fd.write_json(&trap);
                    }
                    let _ = writeln!(io::stderr().lock(), "{trap}");
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

fn supervise_child(
    policy: &AccessPolicy,
    child: Pid,
    notify_fd: BorrowedFd<'_>,
    syscalls: &NotificationSyscalls,
    notify_filesystem: bool,
    trap_fd: Option<&TrapFd>,
) -> Result<i32> {
    let mut denials = Denials::new(trap_fd);
    let query_enabled = trap_fd.is_some_and(TrapFd::is_socket);
    let mount_namespace =
        NamespaceId::try_from(Path::new("/proc/self/ns/mnt")).map_err(LandstripError::supervise)?;
    let mut ctx = NotificationContext {
        policy,
        syscalls,
        notify_filesystem,
        query_enabled,
        mount_namespace,
    };
    let mut trap_fd = trap_fd
        .filter(|trap_fd| trap_fd.is_socket())
        .map(AsFd::as_fd);
    let mut pending_queries: std::collections::HashMap<u64, PendingQuery> =
        std::collections::HashMap::new();
    let mut control_buffer: Vec<u8> = Vec::new();
    let mut next_query_id: u64 = 1;
    loop {
        loop {
            match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => break,
                Ok(status) => return Ok(denials.emit(status)),
                Err(Errno::EINTR) => {}
                Err(error) => {
                    return Err(supervise_errno(error).into());
                }
            }
        }

        let revents = poll_broker_fds(notify_fd, trap_fd)?;

        if revents.iter().all(PollFlags::is_empty) {
            continue;
        }

        if revents[0].intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            loop {
                match waitpid(child, None) {
                    Ok(status) => return Ok(denials.emit(status)),
                    Err(Errno::EINTR) => {}
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

        let Some((request, handle_result)) =
            receive_handled_notification(notify_fd, &ctx, &mut denials, &mut next_query_id)?
        else {
            continue;
        };
        match handle_result {
            HandleResult::Respond(response) => {
                if let Err(source) = respond_notification(notify_fd, response) {
                    loop {
                        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) => break,
                            Ok(status) => return Ok(denials.emit(status)),
                            Err(Errno::EINTR) => {}
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
            HandleResult::RunMutation(grant) => {
                grant_mutation(notify_fd, request.id, &grant);
            }
            HandleResult::RunSocket(grant) => {
                grant_socket(notify_fd, request.id, &grant);
            }
        }
    }
}

fn receive_handled_notification(
    notify_fd: BorrowedFd<'_>,
    ctx: &NotificationContext,
    denials: &mut Denials<'_>,
    next_query_id: &mut u64,
) -> Result<Option<(libc::seccomp_notif, HandleResult)>> {
    let request = receive_notification(notify_fd)?;
    if !validate_notification_id(notify_fd, request.id)? {
        return Ok(None);
    }
    let handle_result = match ctx.mount_namespace.verify(request.pid) {
        Ok(()) => handle_notification(ctx, &request, denials, next_query_id),
        Err(error) => HandleResult::Respond(notification_error(request.id, -error.errno().abs())),
    };
    if !validate_notification_id(notify_fd, request.id)? {
        return Ok(None);
    }
    Ok(Some((request, handle_result)))
}

fn poll_broker_fds(
    notify: BorrowedFd<'_>,
    control: Option<BorrowedFd<'_>>,
) -> Result<[PollFlags; 2]> {
    let len = if control.is_some() { 2 } else { 1 };
    let mut poll_fds = [
        PollFd::new(notify, PollFlags::POLLIN),
        PollFd::new(control.unwrap_or(notify), PollFlags::POLLIN),
    ];
    loop {
        match poll(&mut poll_fds[..len], POLL_MS) {
            Ok(0) => return Ok([PollFlags::empty(); 2]),
            Ok(_) => {
                return Ok([
                    poll_fds[0].revents().unwrap_or_else(PollFlags::empty),
                    poll_fds[1].revents().unwrap_or_else(PollFlags::empty),
                ]);
            }
            Err(Errno::EINTR) => {}
            Err(error) => return Err(supervise_errno(error).into()),
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
struct Denials<'a> {
    trap_fd: Option<&'a TrapFd>,
    seen: HashSet<Denial>,
    pending: Vec<Denial>,
}

impl<'a> Denials<'a> {
    fn new(trap_fd: Option<&'a TrapFd>) -> Self {
        Self {
            trap_fd,
            ..Self::default()
        }
    }

    fn write(&self, trap: &Trap) {
        if let Some(trap_fd) = self.trap_fd {
            trap_fd.write(trap);
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
            self.write(&trap);
            trap.emit();
        }
        code
    }
}

enum HandleResult {
    Respond(libc::seccomp_notif_resp),
    // Broker-mediated open: inject a broker-opened fd via SECCOMP_IOCTL_NOTIF_ADDFD
    // instead of letting the kernel re-run open in the child. Used for every
    // allowed open so CONTINUE cannot TOCTOU-bypass denyRead/denyWrite.
    AddFd(OpenGrant),
    // Broker-mediated side effects are executed only after notification validity
    // is checked immediately before dispatch.
    RunMutation(MutationGrant),
    RunSocket(SocketGrant),
    Pending(u64, Option<Grant>),
}

/// Immutable context shared across notification handling for a supervised child.
struct NotificationContext<'a> {
    policy: &'a AccessPolicy,
    syscalls: &'a NotificationSyscalls,
    notify_filesystem: bool,
    query_enabled: bool,
    mount_namespace: NamespaceId,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct NamespaceId {
    device: u64,
    inode: u64,
}

impl TryFrom<&Path> for NamespaceId {
    type Error = io::Error;

    fn try_from(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl NamespaceId {
    fn verify(self, pid: u32) -> SysResult<()> {
        let path = Path::new("/proc").join(pid.to_string()).join("ns/mnt");
        let actual = Self::try_from(path.as_path()).map_err(|error| BrokerError::SystemCall {
            errno: error.raw_os_error().unwrap_or(libc::EIO),
        })?;
        if actual != self {
            return Err(BrokerError::PolicyDenied);
        }
        Ok(())
    }
}

fn handle_notification(
    ctx: &NotificationContext,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
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
    } else if ctx.notify_filesystem && ctx.syscalls.is_open(syscall) {
        handle_openat(
            ctx.policy,
            request,
            denials,
            ctx.query_enabled,
            next_query_id,
        )
    } else if ctx.notify_filesystem && ctx.syscalls.is_handle_syscall(syscall) {
        // name_to_handle_at / open_by_handle_at bypass path mediation. Deny hard.
        Err(BrokerError::PolicyDenied)
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
        Ok(NotificationResult::Socket(grant)) => HandleResult::RunSocket(grant),
        Ok(NotificationResult::Continue) => {
            HandleResult::Respond(notification_continue(request.id))
        }
        Ok(NotificationResult::Open(grant)) => HandleResult::AddFd(grant),
        Ok(NotificationResult::Mutation(grant)) => HandleResult::RunMutation(grant),
        Ok(NotificationResult::Query(decision)) => {
            denials.write(&decision.trap);
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

pub(super) fn ensure_notification_supported() -> Result<()> {
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
        return Err(
            LandstripError::sandbox_setup(Mechanism::Seccomp, io::Error::last_os_error()).into(),
        );
    }

    Ok(())
}

fn receive_notification(fd: BorrowedFd<'_>) -> Result<libc::seccomp_notif> {
    loop {
        // SAFETY: zero is a valid initial byte pattern for this plain kernel UAPI struct.
        let mut request = unsafe { mem::zeroed::<libc::seccomp_notif>() };
        // SAFETY: request points to writable storage for SECCOMP_IOCTL_NOTIF_RECV.
        match unsafe { seccomp_notif_recv(fd.as_raw_fd(), ptr::addr_of_mut!(request)) } {
            Ok(_) => return Ok(request),
            Err(Errno::EINTR) => {}
            Err(error) => {
                return Err(supervise_errno(error).into());
            }
        }
    }
}

fn respond_notification(fd: BorrowedFd<'_>, mut response: libc::seccomp_notif_resp) -> Result<()> {
    loop {
        // SAFETY: response points to initialized storage for SECCOMP_IOCTL_NOTIF_SEND.
        match unsafe { seccomp_notif_send(fd.as_raw_fd(), ptr::addr_of_mut!(response)) } {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => {}
            Err(error) => {
                return Err(supervise_errno(error).into());
            }
        }
    }
}

fn validate_notification_id(fd: BorrowedFd<'_>, id: u64) -> Result<bool> {
    loop {
        // SAFETY: id points to initialized storage for SECCOMP_IOCTL_NOTIF_ID_VALID.
        match unsafe { seccomp_notif_id_valid(fd.as_raw_fd(), ptr::addr_of!(id)) } {
            Ok(_) => return Ok(true),
            Err(Errno::EINTR) => {}
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
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let socket = target_socket(request)?;

    match socket.info.kind() {
        SocketKind::Tcp => {
            if !policy.network_access.allows_local_tcp_bind() {
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

            Ok(NotificationResult::Socket(SocketGrant::new(
                socket,
                libc::bind,
            )))
        }
        SocketKind::Unix => handle_unix_bind(policy, request.pid, socket),
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
        SocketKind::Other => Ok(NotificationResult::Continue),
    }
}

fn handle_connect(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let socket = target_socket(request)?;

    match socket.info.kind() {
        SocketKind::Tcp => {
            if policy.network_access.is_unrestricted() {
                return Ok(NotificationResult::Continue);
            }
            let endpoint = tcp_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback
                || (!policy.network_access.allows_local_tcp_bind()
                    && !policy
                        .network_access
                        .connect_tcp_ports()
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

            Ok(NotificationResult::Socket(SocketGrant::new(
                socket,
                libc::connect,
            )))
        }
        SocketKind::Unix => handle_unix_connect(policy, request.pid, socket),
        SocketKind::Other => Ok(NotificationResult::Continue),
        SocketKind::NotSupported if policy.network_access.is_unrestricted() => {
            Ok(NotificationResult::Continue)
        }
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
    }
}

fn handle_unix_connect(
    policy: &AccessPolicy,
    pid: u32,
    socket: TargetSocket,
) -> SysResult<NotificationResult> {
    let Some((target, relative)) = unix_path_target(pid, &socket.addr)? else {
        // Abstract / unnamed: path policy cannot see these. Restricted unix
        // policy denies them here. Unrestricted unix continues so Landlock can
        // still refuse host-created abstract sockets (ABI 6+).
        return if matches!(
            policy.network_access.unix_socket_access(),
            UnixSocketAccess::Unrestricted
        ) {
            Ok(NotificationResult::Continue)
        } else {
            Err(BrokerError::PolicyDenied)
        };
    };
    authorize_unix_path(policy, &target)?;

    let mut addr = socket.addr.clone();
    if relative {
        rewrite_unix_path(&mut addr, &target)?;
    }

    Ok(NotificationResult::Socket(SocketGrant {
        sock: socket.sock,
        addr,
        call: libc::connect,
    }))
}

fn handle_unix_bind(
    policy: &AccessPolicy,
    pid: u32,
    mut socket: TargetSocket,
) -> SysResult<NotificationResult> {
    let Some((target, relative)) = unix_path_target(pid, &socket.addr)? else {
        return Err(BrokerError::PolicyDenied);
    };
    authorize_unix_path(policy, &target)?;

    if !target.is_under_any(&policy.write_roots) {
        return Err(BrokerError::PolicyDenied);
    }

    if relative {
        rewrite_unix_path(&mut socket.addr, &target)?;
    }

    Ok(NotificationResult::Socket(SocketGrant::new(
        socket,
        libc::bind,
    )))
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
    if is_supervisor_socket(target) {
        return Err(BrokerError::PolicyDenied);
    }
    match policy.network_access.unix_socket_access() {
        UnixSocketAccess::Unrestricted => Ok(()),
        UnixSocketAccess::AllowPaths(paths) => target
            .is_under_any(paths)
            .then_some(())
            .ok_or(BrokerError::PolicyDenied),
        UnixSocketAccess::Denied => Err(BrokerError::PolicyDenied),
    }
}

/// Sockets a sandboxed child can use to ask an unsandboxed service manager to
/// start a process that inherits neither Landlock nor seccomp.
fn is_supervisor_socket(target: &Path) -> bool {
    let target = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    // SAFETY: getuid(2) is always defined and has no preconditions.
    let uid = unsafe { libc::getuid() };
    let uid_runtime = Path::new("/run/user").join(uid.to_string());
    let runtime = env::var_os("XDG_RUNTIME_DIR").map_or_else(|| uid_runtime.clone(), PathBuf::from);
    let candidates = [
        runtime.join("bus"),
        uid_runtime.join("bus"),
        PathBuf::from("/run/dbus/system_bus_socket"),
    ];
    candidates
        .iter()
        .any(|socket| target == *socket || same_socket_inode(&target, socket))
        || target.is_under("/run/systemd")
        || target.is_under(runtime.join("systemd"))
        || target.is_under(uid_runtime.join("systemd"))
}

fn same_socket_inode(left: &Path, right: &Path) -> bool {
    let Ok(left) = fs::metadata(left) else {
        return false;
    };
    let Ok(right) = fs::metadata(right) else {
        return false;
    };
    left.dev() == right.dev() && left.ino() == right.ino()
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
    // Linux 6.9 added PIDFD_THREAD. Older kernels reject the flag, and pidfd_open
    // without it accepts only a thread-group leader, so use procfs only as the
    // compatibility fallback for obtaining the TGID.
    let pidfd = match open_pidfd(pid, libc::O_EXCL as libc::c_uint) {
        Ok(pidfd) => pidfd,
        Err(Errno::EINVAL | Errno::ENOSYS) => match open_pidfd(pid, 0) {
            Ok(pidfd) => pidfd,
            Err(Errno::EINVAL) => open_pidfd(thread_group_leader(pid)?, 0).map_err(|error| {
                BrokerError::SystemCall {
                    errno: error as i32,
                }
            })?,
            Err(error) => {
                return Err(BrokerError::SystemCall {
                    errno: error as i32,
                });
            }
        },
        Err(error) => {
            return Err(BrokerError::SystemCall {
                errno: error as i32,
            });
        }
    };

    // SAFETY: pidfd_getfd copies scalar arguments and returns a duplicated fd.
    let target = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if target < 0 {
        return Err(BrokerError::SystemCall {
            errno: Errno::last() as i32,
        });
    }

    // SAFETY: pidfd_getfd returned a new owned descriptor.
    let target = RawFd::try_from(target).map_err(|_| BrokerError::BadFileDescriptor)?;
    Ok(unsafe { OwnedFd::from_raw_fd(target) })
}

fn open_pidfd(pid: Pid, flags: libc::c_uint) -> std::result::Result<OwnedFd, Errno> {
    // SAFETY: pidfd_open copies scalar arguments and returns a new fd on success.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), flags) };
    if pidfd < 0 {
        return Err(Errno::last());
    }

    let pidfd = RawFd::try_from(pidfd).map_err(|_| Errno::EBADF)?;
    // SAFETY: pidfd_open returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
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

fn open_flag_names(flags: i32) -> Vec<&'static str> {
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

fn reopen_bits(flags: i32) -> i32 {
    (flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW)) | libc::O_CLOEXEC
}

fn create_bits(flags: i32) -> i32 {
    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

// The open flags and creation mode an open syscall requested.
struct Open {
    flags: i32,
    mode: u32,
}

impl Open {
    // openat passes flags and mode as scalar arguments at args[2]/args[3].
    // legacy open(2) uses the same layout at args[1]/args[2].
    fn from_args(request: &libc::seccomp_notif, legacy_open: bool) -> SysResult<Self> {
        let args = &request.data.args;
        let flags_arg = if legacy_open { 1 } else { 2 };
        let mode_arg = if legacy_open { 2 } else { 3 };
        let flags = i32::try_from(args[flags_arg]).map_err(|_| BrokerError::InvalidAddress)?;
        Ok(Self {
            flags,
            mode: syscall_u32(args[mode_arg]),
        })
    }

    // openat2 passes a struct open_how { u64 flags; u64 mode; u64 resolve; } by
    // pointer; only the first two fields matter. The kernel requires size >= 24,
    // but read just the bytes we use.
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
        let flags = u64::from_ne_bytes(buf[0..8].try_into().map_err(|_| BrokerError::BadAddress)?);
        let mode = u64::from_ne_bytes(buf[8..16].try_into().map_err(|_| BrokerError::BadAddress)?);
        Ok(Self {
            flags: i32::try_from(flags).map_err(|_| BrokerError::InvalidAddress)?,
            mode: u32::try_from(mode).map_err(|_| BrokerError::InvalidAddress)?,
        })
    }
}

struct OpenDenial {
    operation: TrapOperation,
    path: PathBuf,
    requested_path: PathBuf,
    syscall: &'static str,
    flags: i32,
    mode: u32,
    reason: DenialReason,
    pid: u32,
    report: bool,
}

fn deny_open(
    details: OpenDenial,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    if !details.report {
        return Err(BrokerError::PolicyDenied);
    }

    let OpenDenial {
        operation,
        path,
        requested_path,
        syscall,
        flags,
        mode,
        reason,
        pid,
        ..
    } = details;
    if query_enabled {
        let query_id = *next_query_id;
        *next_query_id += 1;
        let grant = Some(Grant::Open(
            OpenGrant::new(&path, flags, mode)
                .map_err(|errno| BrokerError::SystemCall { errno })?,
        ));
        return Ok(NotificationResult::query(
            query_id,
            Trap::filesystem(
                FilesystemDenial {
                    operation,
                    path,
                    requested_path,
                    syscall,
                    flags: open_flag_names(flags),
                    reason,
                    process: process_context(pid),
                },
                Some(query_id),
            ),
            grant,
        ));
    }

    denials.record(Denial::Filesystem(FilesystemDenial {
        operation,
        path,
        requested_path,
        syscall,
        flags: open_flag_names(flags),
        reason,
        process: process_context(pid),
    }));
    Err(BrokerError::PolicyDenied)
}

fn handle_openat(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let nr = i64::from(request.data.nr);
    let openat2 = nr == libc::SYS_openat2;
    let legacy_open = matches!(legacy_syscall::OPEN, Some(open) if open == nr);
    // open(2): path/flags/mode at 0/1/2 with implicit AT_FDCWD.
    // openat(2)/openat2(2): dirfd/path/... at 0/1/...
    let dirfd = if legacy_open {
        libc::AT_FDCWD
    } else {
        syscall_i32(request.data.args[0])
    };
    let path_arg = usize::from(!legacy_open);
    let path_ptr =
        usize::try_from(request.data.args[path_arg]).map_err(|_| BrokerError::BadAddress)?;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);
    let Open { flags, mode } = if openat2 {
        Open::from_how(request, pid)?
    } else {
        Open::from_args(request, legacy_open)?
    };
    let syscall_name = if openat2 {
        "openat2"
    } else if legacy_open {
        "open"
    } else {
        "openat"
    };

    let Some(path) = read_child_path(pid, path_ptr)? else {
        return Ok(NotificationResult::Continue);
    };

    let raw = resolve_child_path(pid, dirfd, &path)?;
    let resolved = normalize_path(&raw);
    let wants_write = flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) != 0;
    let reports_write = flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) != 0;
    let wants_read = flags & libc::O_WRONLY == 0;

    if wants_write {
        let lexical = normalize_path_lexically(&raw);
        let reason = policy.write_reason(&resolved, &lexical, true);
        if let Some(reason) = reason {
            if flags & libc::O_CREAT == 0 && !path_exists(&resolved)? {
                return Err(BrokerError::SystemCall {
                    errno: libc::ENOENT,
                });
            }
            return deny_open(
                OpenDenial {
                    operation: TrapOperation::Write,
                    path: resolved,
                    requested_path: path,
                    syscall: syscall_name,
                    flags,
                    mode,
                    reason,
                    pid: request.pid,
                    report: reports_write,
                },
                denials,
                query_enabled,
                next_query_id,
            );
        }
    }
    if wants_read && let Some(reason) = policy.read_reason(&resolved) {
        if !path_exists(&resolved)? {
            return Err(BrokerError::SystemCall {
                errno: libc::ENOENT,
            });
        }
        return deny_open(
            OpenDenial {
                operation: TrapOperation::Read,
                path: resolved,
                requested_path: path,
                syscall: syscall_name,
                flags,
                mode,
                reason,
                pid: request.pid,
                report: true,
            },
            denials,
            query_enabled,
            next_query_id,
        );
    }

    // fget() rejects FMODE_PATH descriptors (fs/file.c), so
    // SECCOMP_IOCTL_NOTIF_ADDFD fails with EBADF for an O_PATH fd and the
    // child would see a spurious EACCES. An O_PATH handle grants no data
    // access — every dereferencing operation goes through its own brokered
    // syscall — and Landlock does not restrict O_PATH opens, so after the
    // policy checks above let the child's syscall re-execute natively.
    if flags & libc::O_PATH != 0 {
        return Ok(NotificationResult::Continue);
    }

    // Re-running openat in the child via CONTINUE would reopen the classic
    // seccomp-user-notification TOCTOU (a sibling can swap the path after the
    // broker's policy check). Landlock cannot express denyWrite holes under an
    // allowWrite root, so pin every allowed open — read or write — with an
    // OpenGrant and inject the broker's fd via SECCOMP_ADDFD.
    let grant = OpenGrant::new(&resolved, flags, mode)
        .map_err(|errno| BrokerError::SystemCall { errno })?;
    Ok(NotificationResult::Open(grant))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod legacy_syscall {
    pub const OPEN: Option<i64> = Some(libc::SYS_open);
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
    pub const OPEN: Option<i64> = None;
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
enum MutationSyscall {
    Renameat2,
    Renameat,
    Linkat,
    Symlinkat,
    Unlinkat,
    Mkdirat,
    Mknodat,
    Truncate,
    Fchmodat,
    Fchmodat2,
    Fchownat,
    Utimensat,
    Setxattr,
    Lsetxattr,
    Removexattr,
    Lremovexattr,
    Rename,
    Link,
    Symlink,
    Unlink,
    Rmdir,
    Mkdir,
    Mknod,
    Creat,
    Chmod,
    Chown,
    Lchown,
}

impl MutationSyscall {
    /// Whether this invocation targets the symlink itself rather than what it
    /// resolves to: an inherently no-follow call (`unlink`, `unlinkat`,
    /// `rmdir`, `lchown`, `lsetxattr`, `lremovexattr`) or an `*at` call
    /// carrying `AT_SYMLINK_NOFOLLOW`. The policy check and the broker must
    /// then act on the link, not its target.
    fn no_follow(self, args: &[u64; 6]) -> bool {
        // The flags argument is an int; truncating to i32 recovers it from the
        // u64 register slot the same way the dirfd arguments are read.
        let flag = |index: usize| syscall_i32(args[index]) & libc::AT_SYMLINK_NOFOLLOW != 0;
        let follow = |index: usize| syscall_i32(args[index]) & libc::AT_SYMLINK_FOLLOW != 0;
        match self {
            Self::Unlink
            | Self::Unlinkat
            | Self::Rmdir
            | Self::Lchown
            | Self::Lsetxattr
            | Self::Lremovexattr
            | Self::Link => true,
            Self::Fchownat => flag(4),
            Self::Fchmodat | Self::Fchmodat2 | Self::Utimensat => flag(3),
            // linkat(2) links the symlink itself unless AT_SYMLINK_FOLLOW is set;
            // link(2) has no flags and never dereferences.
            Self::Linkat => !follow(4),
            Self::Renameat2
            | Self::Renameat
            | Self::Symlinkat
            | Self::Mkdirat
            | Self::Mknodat
            | Self::Truncate
            | Self::Setxattr
            | Self::Removexattr
            | Self::Rename
            | Self::Symlink
            | Self::Mkdir
            | Self::Mknod
            | Self::Creat
            | Self::Chmod
            | Self::Chown => false,
        }
    }

    fn is_mkdir(self) -> bool {
        matches!(self, Self::Mkdir | Self::Mkdirat)
    }

    fn is_reparent(self) -> bool {
        matches!(
            self,
            Self::Link | Self::Linkat | Self::Rename | Self::Renameat | Self::Renameat2
        )
    }
}

struct Syscall {
    nr: Option<i64>,
    kind: MutationSyscall,
    paths: &'static [(Option<usize>, usize)],
    landlock_backed: bool,
}

const MUTATION_SYSCALLS: &[Syscall] = &[
    Syscall {
        nr: Some(libc::SYS_renameat2),
        kind: MutationSyscall::Renameat2,
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_renameat),
        kind: MutationSyscall::Renameat,
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_linkat),
        kind: MutationSyscall::Linkat,
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_symlinkat),
        kind: MutationSyscall::Symlinkat,
        paths: &[(Some(1), 2)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_unlinkat),
        kind: MutationSyscall::Unlinkat,
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_mkdirat),
        kind: MutationSyscall::Mkdirat,
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_mknodat),
        kind: MutationSyscall::Mknodat,
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_truncate),
        kind: MutationSyscall::Truncate,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_fchmodat),
        kind: MutationSyscall::Fchmodat,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        // fchmodat2 is Linux 6.6+ (nr 452 on all landstrip targets). glibc may
        // implement fchmodat via it; without mediation, mode changes bypass the broker.
        nr: Some(SYS_FCHMODAT2),
        kind: MutationSyscall::Fchmodat2,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fchownat),
        kind: MutationSyscall::Fchownat,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_utimensat),
        kind: MutationSyscall::Utimensat,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_setxattr),
        kind: MutationSyscall::Setxattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_lsetxattr),
        kind: MutationSyscall::Lsetxattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_removexattr),
        kind: MutationSyscall::Removexattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_lremovexattr),
        kind: MutationSyscall::Lremovexattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::RENAME,
        kind: MutationSyscall::Rename,
        paths: &[(None, 0), (None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::LINK,
        kind: MutationSyscall::Link,
        paths: &[(None, 0), (None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::SYMLINK,
        kind: MutationSyscall::Symlink,
        paths: &[(None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::UNLINK,
        kind: MutationSyscall::Unlink,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::RMDIR,
        kind: MutationSyscall::Rmdir,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::MKDIR,
        kind: MutationSyscall::Mkdir,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::MKNOD,
        kind: MutationSyscall::Mknod,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::CREAT,
        kind: MutationSyscall::Creat,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::CHMOD,
        kind: MutationSyscall::Chmod,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::CHOWN,
        kind: MutationSyscall::Chown,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::LCHOWN,
        kind: MutationSyscall::Lchown,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
];

/// Deny link/rename of a `denyRead` source when the new name would be readable.
fn reparent_read_denial(
    policy: &AccessPolicy,
    spec: &Syscall,
    slots: &[Option<(PathBuf, PathBuf)>],
) -> Option<(usize, DenialReason, TrapOperation)> {
    if !spec.kind.is_reparent() {
        return None;
    }
    let (source, _) = slots.first().and_then(Option::as_ref)?;
    let reason = policy.read_reason(source)?;
    let dest_readable = slots
        .get(1)
        .and_then(Option::as_ref)
        .is_none_or(|(dest, _)| policy.read_reason(dest).is_none());
    dest_readable.then_some((0, reason, TrapOperation::Read))
}

fn handle_mutation(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let syscall = i64::from(request.data.nr);
    let Some(spec) = MUTATION_SYSCALLS.iter().find(|s| s.nr == Some(syscall)) else {
        return Ok(NotificationResult::Continue);
    };
    if spec.kind == MutationSyscall::Utimensat && request.data.args[1] == 0 {
        return handle_fd_utimensat(policy, request, denials, query_enabled, next_query_id);
    }

    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);

    let mut slots: Vec<Option<(PathBuf, PathBuf)>> = Vec::with_capacity(spec.paths.len());
    let mut denial: Option<(usize, DenialReason, TrapOperation)> = None;
    let no_follow = spec.kind.no_follow(&request.data.args);
    for (index, (dirfd_arg, path_arg)) in spec.paths.iter().enumerate() {
        let dirfd = match dirfd_arg {
            // args[i] is an i32 dirfd (including AT_FDCWD=-100) stored as u64.
            Some(arg) => syscall_i32(request.data.args[*arg]),
            None => libc::AT_FDCWD,
        };
        let path_ptr =
            usize::try_from(request.data.args[*path_arg]).map_err(|_| BrokerError::BadAddress)?;
        let Some(path) = read_child_path(pid, path_ptr)? else {
            slots.push(None);
            continue;
        };
        let raw = resolve_child_path(pid, dirfd, &path)?;
        // mkdir -p intentionally invokes mkdir for each existing path component.
        // Return the syscall's EEXIST result without prompting instead of treating
        // an operation that cannot mutate the filesystem as a permission request.
        if spec.kind.is_mkdir() && mkdir_target_exists(&raw) {
            return Err(BrokerError::SystemCall {
                errno: libc::EEXIST,
            });
        }
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
            if let Some(reason) = policy.write_reason(&resolved, &lexical, surface_allow_miss) {
                denial = Some((index, reason, TrapOperation::Write));
            }
        }
        slots.push(Some((resolved, path)));
    }

    denial = denial.or_else(|| reparent_read_denial(policy, spec, &slots));

    let Some((index, reason, operation)) = denial else {
        // Allowed mutations still race under CONTINUE when denyWrite sits under
        // an allowWrite root (Landlock cannot express those holes). Fulfill the
        // op in the broker whenever any denyWrite list is present; otherwise
        // landlock-backed ops may CONTINUE under the child's write roots.
        // Reparenting also races when denyRead sits under an allowWrite root:
        // CONTINUE would let link/rename alias a swapped-in secret.
        let must_pin = !policy.write_denied_roots.is_empty()
            || !policy.write_denied_patterns.is_empty()
            || !policy.write_denied_links.is_empty()
            || !spec.landlock_backed
            || (spec.kind.is_reparent() && !matches!(policy.read_access, ReadAccess::Unrestricted));
        if must_pin {
            match Grant::mutation(spec, request, pid, &slots)? {
                Some(Grant::Mutation(grant)) => {
                    return Ok(NotificationResult::Mutation(grant));
                }
                Some(Grant::Open(grant)) => {
                    // creat is modelled as an Open grant.
                    return Ok(NotificationResult::Open(grant));
                }
                Some(Grant::Socket(_)) | None => {
                    // Pin failed (vanished parent, etc.): do not CONTINUE into a race.
                    return Err(BrokerError::SystemCall { errno: libc::EIO });
                }
            }
        }
        return Ok(NotificationResult::Continue);
    };
    let (resolved, path) = slots[index].clone().ok_or(BrokerError::InvalidAddress)?;

    if !query_enabled {
        denials.record(Denial::Filesystem(FilesystemDenial {
            operation,
            path: resolved,
            requested_path: path,
            syscall: spec.kind.into(),
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
                operation,
                path: resolved,
                requested_path: path,
                syscall: spec.kind.into(),
                flags: Vec::new(),
                reason,
                process: process_context(request.pid),
            },
            Some(qid),
        ),
        grant,
    ))
}

/// Mediate the fd-only form used by `futimens(3)`, which glibc issues as
/// `utimensat(fd, NULL, times, 0)`. Pin the child's descriptor before checking
/// policy so another thread cannot swap its fd-table entry between the check
/// and the brokered timestamp update.
fn handle_fd_utimensat(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
    query_enabled: bool,
    next_query_id: &mut u64,
) -> SysResult<NotificationResult> {
    let args = &request.data.args;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);
    if syscall_i32(args[3]) != 0 {
        return Err(BrokerError::SystemCall {
            errno: libc::EINVAL,
        });
    }

    let child_fd = syscall_i32(args[0]);
    if child_fd < 0 {
        return Err(BrokerError::BadFileDescriptor);
    }

    let target = duplicate_target_fd(pid, child_fd)?;
    let requested_path = fs::read_link(
        Path::new("/proc/self/fd").join(target.as_raw_fd().to_string()),
    )
    .map_err(|error| BrokerError::SystemCall {
        errno: error.raw_os_error().unwrap_or(libc::EIO),
    })?;
    let times = read_child_times(pid, args[2])?;
    let resolved = normalize_path(&requested_path);
    let lexical = normalize_path_lexically(&requested_path);
    let reason = policy.write_reason(&resolved, &lexical, true);

    let operation = MutationGrant {
        op: MutationOp::UtimesFd { target, times },
        anchors: Vec::new(),
        no_follow: false,
    };

    let Some(reason) = reason else {
        return Ok(NotificationResult::Mutation(operation));
    };

    let denial = FilesystemDenial {
        operation: TrapOperation::Write,
        path: resolved,
        requested_path,
        syscall: MutationSyscall::Utimensat.into(),
        flags: Vec::new(),
        reason,
        process: process_context(request.pid),
    };
    if !query_enabled {
        denials.record(Denial::Filesystem(denial));
        return Err(BrokerError::PolicyDenied);
    }

    let qid = *next_query_id;
    *next_query_id += 1;
    Ok(NotificationResult::query(
        qid,
        Trap::filesystem(denial, Some(qid)),
        Some(Grant::Mutation(operation)),
    ))
}

impl Grant {
    fn socket(sock: OwnedFd, addr: Vec<u8>, call: SocketAddrCall) -> Grant {
        Grant::Socket(SocketGrant { sock, addr, call })
    }

    fn mutation(
        spec: &Syscall,
        request: &libc::seccomp_notif,
        pid: Pid,
        slots: &[Option<(PathBuf, PathBuf)>],
    ) -> SysResult<Option<Grant>> {
        let args = &request.data.args;

        let op = match spec.kind {
            MutationSyscall::Creat => {
                return creat_grant(slots, syscall_u32(args[1]));
            }
            MutationSyscall::Mkdirat => MutationOp::Mkdir {
                mode: syscall_u32(args[2]),
            },
            MutationSyscall::Mkdir => MutationOp::Mkdir {
                mode: syscall_u32(args[1]),
            },
            MutationSyscall::Mknodat => MutationOp::Mknod {
                mode: syscall_u32(args[2]),
                dev: args[3],
            },
            MutationSyscall::Mknod => MutationOp::Mknod {
                mode: syscall_u32(args[1]),
                dev: args[2],
            },
            MutationSyscall::Unlinkat => MutationOp::Unlink {
                flags: syscall_i32(args[2]),
            },
            MutationSyscall::Unlink => MutationOp::Unlink { flags: 0 },
            MutationSyscall::Rmdir => MutationOp::Unlink {
                flags: libc::AT_REMOVEDIR,
            },
            MutationSyscall::Renameat2 => MutationOp::Rename {
                flags: syscall_u32(args[4]),
            },
            MutationSyscall::Renameat | MutationSyscall::Rename => MutationOp::Rename { flags: 0 },
            MutationSyscall::Linkat => MutationOp::Link {
                flags: syscall_i32(args[4]),
            },
            MutationSyscall::Link => MutationOp::Link { flags: 0 },
            MutationSyscall::Symlinkat | MutationSyscall::Symlink => {
                let Some(target) = read_child_target(pid, args[0])? else {
                    return Ok(None);
                };
                MutationOp::Symlink { target }
            }
            MutationSyscall::Truncate => MutationOp::Truncate {
                length: syscall_i64(args[1]),
            },
            MutationSyscall::Fchmodat | MutationSyscall::Fchmodat2 => MutationOp::Chmod {
                mode: syscall_u32(args[2]),
            },
            MutationSyscall::Chmod => MutationOp::Chmod {
                mode: syscall_u32(args[1]),
            },
            MutationSyscall::Fchownat => MutationOp::Chown {
                uid: syscall_u32(args[2]),
                gid: syscall_u32(args[3]),
            },
            MutationSyscall::Chown | MutationSyscall::Lchown => MutationOp::Chown {
                uid: syscall_u32(args[1]),
                gid: syscall_u32(args[2]),
            },
            MutationSyscall::Utimensat => MutationOp::Utimes {
                times: read_child_times(pid, args[2])?,
            },
            MutationSyscall::Setxattr | MutationSyscall::Lsetxattr => {
                let Some(name) = read_child_target(pid, args[1])? else {
                    return Ok(None);
                };
                MutationOp::SetXattr {
                    name,
                    value: read_child_bytes(pid, args[2], args[3])?,
                    flags: syscall_i32(args[4]),
                }
            }
            MutationSyscall::Removexattr | MutationSyscall::Lremovexattr => {
                let Some(name) = read_child_target(pid, args[1])? else {
                    return Ok(None);
                };
                MutationOp::RemoveXattr { name }
            }
        };

        let mut anchors = Vec::with_capacity(slots.len());
        for slot in slots {
            let Some((resolved, _)) = slot else {
                return Ok(None);
            };
            anchors.push(Anchor::new(resolved).map_err(|errno| BrokerError::SystemCall { errno })?);
        }

        Ok(Some(Grant::Mutation(MutationGrant {
            op,
            anchors,
            no_follow: spec.kind.no_follow(args),
        })))
    }
}

fn creat_grant(slots: &[Option<(PathBuf, PathBuf)>], mode: u32) -> SysResult<Option<Grant>> {
    let Some((resolved, _)) = slots.first().and_then(Option::as_ref) else {
        return Ok(None);
    };
    OpenGrant::new(
        resolved,
        libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
        mode,
    )
    .map(|grant| Some(Grant::Open(grant)))
    .map_err(|errno| BrokerError::SystemCall { errno })
}

fn read_child_target(pid: Pid, ptr: u64) -> SysResult<Option<CString>> {
    let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
    if addr == 0 {
        return Ok(None);
    }
    let buf = read_child_string(pid, addr, libc::PATH_MAX as usize)?;
    CString::new(buf)
        .map(Some)
        .map_err(|_| BrokerError::InvalidAddress)
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

// Read an extended-attribute value from the child. Linux rejects values larger
// than `XATTR_SIZE_MAX`, and the broker must not silently apply a truncated one.
fn read_child_bytes(pid: Pid, ptr: u64, size: u64) -> SysResult<Vec<u8>> {
    const XATTR_MAX: usize = 65536;

    let len = usize::try_from(size).map_err(|_| BrokerError::SystemCall { errno: libc::E2BIG })?;
    if len > XATTR_MAX {
        return Err(BrokerError::SystemCall { errno: libc::E2BIG });
    }
    if len == 0 {
        return Ok(Vec::new());
    }

    let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
    if addr == 0 {
        return Err(BrokerError::BadAddress);
    }

    let mut buf = vec![0_u8; len];
    let mut local = [IoSliceMut::new(&mut buf)];
    let target = [RemoteIoVec { base: addr, len }];
    let n =
        process_vm_readv(pid, &mut local, &target).map_err(|error| BrokerError::SystemCall {
            errno: error as i32,
        })?;
    if n != len {
        return Err(BrokerError::BadAddress);
    }

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
    if n == 0 {
        return Err(BrokerError::BadAddress);
    }
    let Some(null_pos) = buf[..n].iter().position(|byte| *byte == 0) else {
        return Err(BrokerError::NameTooLong);
    };
    buf.truncate(null_pos);
    Ok(buf)
}

/// Upper bound on the trap-fd control buffer. A well-formed launcher sends
/// newline-terminated JSON responses, each far smaller than this; exceeding it
/// without a newline means a broken or hostile peer and the partial run-on
/// data is discarded rather than grown without limit.
const CONTROL_BUFFER_MAX: usize = 64 * 1024;

fn process_control_responses(
    control_fd: BorrowedFd<'_>,
    buffer: &mut Vec<u8>,
    pending_queries: &mut std::collections::HashMap<u64, PendingQuery>,
    notify_fd: BorrowedFd<'_>,
) -> bool {
    let mut chunk = [0u8; 4096];
    // SAFETY: read(2) copies bytes from the live buffer.
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
    notify_fd: BorrowedFd<'_>,
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

fn grant_open(notify_fd: BorrowedFd<'_>, id: u64, grant: &OpenGrant) {
    let opened = match broker_open(grant) {
        Ok(fd) => fd,
        Err(errno) => {
            let _ = respond_notification(notify_fd, notification_error(id, -errno.abs()));
            return;
        }
    };

    let cloexec = grant.flags & libc::O_CLOEXEC != 0;
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
    if unsafe { seccomp_notif_addfd(notify_fd.as_raw_fd(), ptr::addr_of!(addfd)) }.is_err() {
        let _ = respond_notification(
            notify_fd,
            notification_error(id, -LandstripError::DENIAL_ERRNO),
        );
    }
}

fn grant_mutation(notify_fd: BorrowedFd<'_>, id: u64, grant: &MutationGrant) {
    let rc = match run_mutation(grant) {
        Ok(()) => notification_value(id, 0),
        Err(errno) => notification_error(id, -errno.abs()),
    };
    let _ = respond_notification(notify_fd, rc);
}

// The broker re-issues the approved connect or bind on the duplicated child
// socket, which shares the child's open file description, so the call takes
// effect on the child's socket while running outside its seccomp filter.
fn grant_socket(notify_fd: BorrowedFd<'_>, id: u64, grant: &SocketGrant) {
    let rc = match broker_addr_call(grant.sock.as_raw_fd(), &grant.addr, grant.call) {
        Ok(value) => notification_value(id, value),
        Err(error) => notification_error(id, -error.errno().abs()),
    };
    let _ = respond_notification(notify_fd, rc);
}

fn run_mutation(grant: &MutationGrant) -> std::result::Result<(), i32> {
    if let MutationOp::UtimesFd { target, times } = &grant.op {
        let times = times.as_ref().map_or(ptr::null(), |value| value.as_ptr());
        // SAFETY: target is a duplicated descriptor for the blocked task's open
        // file description. A null pathname selects the fd-only utimensat form.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_utimensat,
                target.as_raw_fd(),
                ptr::null::<libc::c_char>(),
                times,
                0,
            )
        };
        return if rc < 0 {
            Err(Errno::last() as i32)
        } else {
            Ok(())
        };
    }

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
            let (_target, path) = pin_target(at)?;
            // Reopen the pinned O_PATH target with write access before ftruncate;
            // ftruncate itself rejects O_PATH descriptors with EBADF.
            // SAFETY: path is NUL-terminated and refers to the live pinned target.
            let writable = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            if writable < 0 {
                return Err(Errno::last() as i32);
            }
            // SAFETY: open returned a new owned descriptor.
            let writable = unsafe { OwnedFd::from_raw_fd(writable) };
            return check(unsafe { libc::ftruncate(writable.as_raw_fd(), *length) });
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
        MutationOp::UtimesFd { .. } => return Err(libc::EINVAL),
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

fn open_path(path: &Path, flags: i32) -> std::result::Result<OwnedFd, i32> {
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    // SAFETY: cpath is NUL-terminated and open copies it.
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        return Err(Errno::last() as i32);
    }
    // SAFETY: open returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// This is deliberately a preflight check: reissuing mkdir could create a path
// after an entry is removed, while a stale EEXIST result cannot mutate it.
fn mkdir_target_exists(path: &Path) -> bool {
    let Ok(anchor) = Anchor::new(&normalize_path_nofollow(path)) else {
        return false;
    };
    // A trailing slash requires the kernel to follow a terminal symlink.
    let flags = if path.as_os_str().as_bytes().ends_with(b"/") {
        0
    } else {
        libc::AT_SYMLINK_NOFOLLOW
    };
    // SAFETY: stat points to initialized storage and anchor owns a valid parent fd.
    let mut stat = unsafe { mem::zeroed::<libc::stat>() };
    // fstatat reports the EEXIST condition without modifying the target.
    unsafe {
        libc::fstatat(
            anchor.dir.as_raw_fd(),
            anchor.name.as_ptr(),
            ptr::addr_of_mut!(stat),
            flags,
        ) == 0
    }
}

impl Anchor {
    fn new(resolved: &Path) -> std::result::Result<Self, i32> {
        let parent = resolved.parent().ok_or(libc::EINVAL)?;
        let name = CString::new(resolved.file_name().ok_or(libc::EINVAL)?.as_bytes())
            .map_err(|_| libc::EINVAL)?;
        Ok(Self {
            dir: open_path(parent, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)?,
            name,
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
            let flags = reopen_bits(grant.flags);
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
            let flags = create_bits(grant.flags);
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

    let dir = duplicate_target_fd(pid, dirfd)?;
    let dir_path = fs::read_link(Path::new("/proc/self/fd").join(dir.as_raw_fd().to_string()))
        .map_err(|error| BrokerError::SystemCall {
            errno: error.raw_os_error().unwrap_or(libc::EBADF),
        })?;
    Ok(dir_path.join(path))
}

fn sockopt(fd: RawFd, level: libc::c_int, name: libc::c_int) -> SysResult<i32> {
    super::getsockopt_int(fd, level, name).map_err(|error| BrokerError::SystemCall {
        errno: error.raw_os_error().unwrap_or(0),
    })
}

fn send_fd(socket: &UnixStream, fd: BorrowedFd<'_>) -> Result<()> {
    let byte = [0_u8];
    let iov = [IoSlice::new(&byte)];
    let fds = [fd.as_raw_fd()];
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
            Err(Errno::EINTR) => {}
            Err(error) => return Err(supervise_errno(error).into()),
        }
    }
}

fn send_trap(socket: &mut UnixStream, trap: &Trap) -> Result<()> {
    let payload = trap.to_string();
    let length = u32::try_from(payload.len())
        .map_err(|_| LandstripError::supervise("notify: trap is too large"))?;

    socket
        .write_all(&[1_u8])
        .map_err(LandstripError::supervise)?;
    socket
        .write_all(&length.to_be_bytes())
        .map_err(LandstripError::supervise)?;
    socket
        .write_all(payload.as_bytes())
        .map_err(LandstripError::supervise)?;
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
        return Err(LandstripError::supervise("notify: unexpected eof").into());
    }

    match byte[0] {
        0 => fd.map_or_else(
            || Err(LandstripError::supervise("notify: missing descriptor").into()),
            |fd| {
                // SAFETY: SCM_RIGHTS transfers ownership of the received descriptor.
                Ok(NotifyStartup::Ready(unsafe { OwnedFd::from_raw_fd(fd) }))
            },
        ),
        1 => {
            let mut length = [0_u8; 4];
            let mut socket = socket;
            socket
                .read_exact(&mut length)
                .map_err(LandstripError::supervise)?;
            let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
            if length > 1_048_576 {
                return Err(LandstripError::supervise("notify: trap is too large").into());
            }
            let mut payload = vec![0_u8; length];
            socket
                .read_exact(&mut payload)
                .map_err(LandstripError::supervise)?;
            let trap = String::from_utf8(payload).map_err(|error| {
                LandstripError::supervise(format!("notify: invalid trap: {error}"))
            })?;
            if serde_json::from_str::<serde_json::Value>(&trap).is_err() {
                return Err(LandstripError::supervise("notify: invalid trap").into());
            }
            Ok(NotifyStartup::Trap(trap))
        }
        _ => Err(LandstripError::supervise("notify: invalid marker").into()),
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
    Socket(SocketGrant),
    Continue,
    Query(QueryDecision),
    Open(OpenGrant),
    Mutation(MutationGrant),
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

impl SocketGrant {
    fn new(socket: TargetSocket, call: SocketAddrCall) -> Self {
        Self {
            sock: socket.sock,
            addr: socket.addr,
            call,
        }
    }
}

struct Anchor {
    dir: OwnedFd,
    name: CString,
}

struct OpenGrant {
    flags: i32,
    kind: OpenKind,
}

impl OpenGrant {
    fn new(resolved: &Path, flags: i32, mode: u32) -> std::result::Result<Self, i32> {
        let kind = match open_path(resolved, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) {
            Ok(handle) => OpenKind::Reopen(handle),
            Err(libc::ENOENT) => OpenKind::Create {
                anchor: Anchor::new(resolved)?,
                mode,
            },
            Err(errno) => return Err(errno),
        };
        Ok(Self { flags, kind })
    }
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
    UtimesFd {
        target: OwnedFd,
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
    open: Option<i64>,
    name_to_handle_at: i64,
    open_by_handle_at: i64,
}

impl NotificationSyscalls {
    pub(super) fn new() -> Self {
        Self {
            bind: libc::SYS_bind,
            connect: libc::SYS_connect,
            socket: libc::SYS_socket,
            openat: libc::SYS_openat,
            openat2: libc::SYS_openat2,
            open: legacy_syscall::OPEN,
            name_to_handle_at: libc::SYS_name_to_handle_at,
            open_by_handle_at: libc::SYS_open_by_handle_at,
        }
    }

    fn is_open(&self, syscall: i64) -> bool {
        syscall == self.openat
            || syscall == self.openat2
            || self.open.is_some_and(|open| open == syscall)
    }

    fn is_handle_syscall(&self, syscall: i64) -> bool {
        syscall == self.name_to_handle_at || syscall == self.open_by_handle_at
    }

    // stat (newfstatat/statx) is intentionally not mediated: blocking metadata
    // reads breaks directory traversal (git, shells, build tools all stat
    // ancestor dirs to canonicalise paths), and denyRead still blocks reading
    // file contents and listing directories via openat. Handle-based open APIs
    // are notified so the broker can hard-deny them.
    pub(super) fn filesystem_syscalls(&self) -> Vec<i64> {
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

fn exit_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
        _ => 1,
    }
}
