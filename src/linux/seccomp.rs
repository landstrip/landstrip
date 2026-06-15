// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Seccomp filters and user-notification broker for network policy.
//!
//! Direct TCP is denied by default. Configured proxy ports are allowed only on
//! loopback, and local TCP bind requires `allowLocalBinding`. Non-TCP INET,
//! packet, and netlink sockets are blocked.
//!
//! Unix sockets are denied by default. `allowUnixSockets` mediates pathname
//! `connect` and `bind`; abstract sockets, unnamed sockets, and `socketpair` are
//! not path-mediated. `allowAllUnixSockets` permits new Unix sockets without
//! path checks.

use super::fd::close_inherited_fds;
use super::landlock::{LandlockFeatures, enforce_access_policy};
use crate::paths::normalize_path;
use crate::policy::{AccessPolicy, ReadAccess, UnixSocketAccess};
use crate::trap::{Result, Trap, TrapOperation};
use crate::trap_fd::TrapFd;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, fcntl};
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{IoSlice, IoSliceMut};
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
const SOCK_TYPE_MASK: u64 = 0x0f;
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

#[repr(C)]
struct SockFilterProg {
    len: libc::c_ushort,
    filter: *const seccompiler::sock_filter,
}

type SysResult<T> = std::result::Result<T, BrokerError>;
type RuleMap = BTreeMap<i64, Vec<SeccompRule>>;
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
            Self::PolicyDenied => libc::EACCES,
            Self::AddressFamilyNotSupported => libc::EAFNOSUPPORT,
            Self::InvalidAddress => libc::EINVAL,
            Self::BadFileDescriptor => libc::EBADF,
            Self::BadAddress => libc::EFAULT,
            Self::NameTooLong => libc::ENAMETOOLONG,
            Self::SystemCall { errno } => *errno,
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn run_broker(
    policy: &AccessPolicy,
    landlock_features: LandlockFeatures,
    tool: &OsStr,
    args: &[OsString],
    needs_network: bool,
    needs_filesystem: bool,
    trap_fd: TrapFd,
) -> Result<i32> {
    let notify_unix_sockets = needs_unix_socket_broker(&policy.network_access.unix_socket_access);
    let notify_bind =
        needs_network && (policy.network_access.local_tcp_bind || notify_unix_sockets);
    let notify_connect = needs_network
        && (!policy.network_access.connect_tcp_ports.is_empty() || notify_unix_sockets);
    let notify_filesystem = needs_filesystem;
    let unix_sockets = unix_socket_filter(&policy.network_access.unix_socket_access);
    ensure_notification_supported()?;

    let syscalls = NotificationSyscalls::new();
    let mut errno_rules = RuleMap::new();
    if needs_network {
        add_socket_family_filter(&mut errno_rules, syscalls.socket)?;
        add_unix_socket_filters(
            &mut errno_rules,
            syscalls.socket,
            syscalls.socketpair,
            unix_sockets,
        )?;
    }

    let eafnosupport = u32::try_from(libc::EAFNOSUPPORT).map_err(|_| Trap::internal())?;
    let errno = if errno_rules.is_empty() {
        None
    } else {
        Some(build_filter(
            errno_rules,
            SeccompAction::Errno(eafnosupport),
        )?)
    };

    let mut notify_syscalls: Vec<i64> = Vec::new();
    if notify_bind {
        notify_syscalls.push(syscalls.bind);
    }
    if notify_connect {
        notify_syscalls.push(syscalls.connect);
    }
    if notify_filesystem {
        notify_syscalls.extend(syscalls.filesystem_syscalls());
    }
    let notify = if notify_syscalls.is_empty() {
        None
    } else {
        Some(build_notify_filter(&notify_syscalls)?)
    };

    let filters = NetworkFilters { errno, notify };
    let (parent, child_sock) = UnixStream::pair()?;

    // SAFETY: landstrip forks before spawning threads; the child either execs the tool or exits.
    match unsafe { fork() }.map_err(|error| system_errno(error as i32))? {
        ForkResult::Child => {
            drop(parent);

            let result = (|| -> Result<()> {
                enforce_access_policy(policy, landlock_features)?;

                {
                    let child_sock = child_sock;
                    let notify = filters.load_with_listener()?;

                    // SAFETY: notify is borrowed only for the duration of fcntl(2).
                    let notify_fd = unsafe { BorrowedFd::borrow_raw(notify.as_raw_fd()) };
                    let notify = fcntl(notify_fd, FcntlArg::F_DUPFD_CLOEXEC(0))
                        .map_err(|error| system_errno(error as i32))?;
                    // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
                    let notify = unsafe { OwnedFd::from_raw_fd(notify) };

                    send_fd(&child_sock, notify.as_raw_fd())?;
                }
                close_inherited_fds();

                let mut child_tool = Command::new(tool);
                child_tool.args(args);

                let error = child_tool.exec();
                Err(Trap::tool_exec(Some(tool.to_os_string()), &error))
            })();

            if let Err(error) = result {
                log::error!("landstrip child setup failed: {error}");
            }

            // SAFETY: _exit terminates the child without running duplicated parent cleanup.
            unsafe { libc::_exit(127) }
        }
        ForkResult::Parent { child } => {
            drop(child_sock);
            let notify = recv_fd(&parent)?;
            drop(parent);
            let notify_fd = notify.as_raw_fd();

            supervise_child(
                policy,
                landlock_features,
                child,
                notify_fd,
                &syscalls,
                notify_filesystem,
                trap_fd,
            )
        }
    }
}

fn supervise_child(
    policy: &AccessPolicy,
    landlock_features: LandlockFeatures,
    child: Pid,
    notify_fd: RawFd,
    syscalls: &NotificationSyscalls,
    notify_filesystem: bool,
    trap_fd: TrapFd,
) -> Result<i32> {
    let mut denials = Denials::new(trap_fd);
    loop {
        loop {
            match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => break,
                Ok(status) => return Ok(denials.emit(status)),
                Err(Errno::EINTR) => continue,
                Err(error) => {
                    return Err(system_errno(error as i32));
                }
            }
        }

        // SAFETY: notify_fd is the live seccomp notification fd owned by the parent.
        let borrowed = unsafe { BorrowedFd::borrow_raw(notify_fd) };
        let mut poll_fd = [PollFd::new(borrowed, PollFlags::POLLIN)];
        let revents = loop {
            match poll(&mut poll_fd, POLL_MS) {
                Ok(0) => break PollFlags::empty(),
                Ok(_) => break poll_fd[0].revents().unwrap_or_else(PollFlags::empty),
                Err(Errno::EINTR) => continue,
                Err(error) => {
                    return Err(system_errno(error as i32));
                }
            }
        };

        if revents.is_empty() {
            continue;
        }

        if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            loop {
                match waitpid(child, None) {
                    Ok(status) => return Ok(denials.emit(status)),
                    Err(Errno::EINTR) => continue,
                    Err(error) => {
                        return Err(system_errno(error as i32));
                    }
                }
            }
        }

        let request = receive_notification(notify_fd)?;
        let response = handle_notification(
            policy,
            landlock_features,
            &request,
            syscalls,
            notify_filesystem,
            &mut denials,
        );

        validate_notification_id(notify_fd, request.id)?;
        if let Err(source) = respond_notification(notify_fd, response) {
            loop {
                match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) => break,
                    Ok(status) => return Ok(denials.emit(status)),
                    Err(Errno::EINTR) => continue,
                    Err(error) => {
                        return Err(system_errno(error as i32));
                    }
                }
            }

            return Err(Trap::policy_stdin_source(source));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum NetworkOperation {
    Connect,
    Bind,
}

impl NetworkOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Bind => "bind",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Denial {
    Filesystem(TrapOperation, PathBuf),
    Network(NetworkOperation, String),
}

impl Denial {
    fn report_on_success(&self) -> bool {
        match self {
            Self::Filesystem(operation, _) => *operation == TrapOperation::Write,
            Self::Network(_, _) => true,
        }
    }

    fn into_trap(self) -> Trap {
        match self {
            Self::Filesystem(operation, path) => {
                Trap::Filesystem(operation, path, "seccomp".to_owned())
            }
            Self::Network(operation, target) => {
                Trap::Network(operation.as_str().to_owned(), target, "seccomp".to_owned())
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

fn handle_notification(
    policy: &AccessPolicy,
    landlock_features: LandlockFeatures,
    request: &libc::seccomp_notif,
    syscalls: &NotificationSyscalls,
    notify_filesystem: bool,
    denials: &mut Denials,
) -> libc::seccomp_notif_resp {
    let syscall = i64::from(request.data.nr);
    let result = if syscall == syscalls.bind {
        handle_bind(policy, request, denials)
    } else if syscall == syscalls.connect {
        handle_connect(policy, landlock_features, request, denials)
    } else if notify_filesystem && syscall == syscalls.openat {
        handle_openat(policy, request, denials)
    } else if notify_filesystem && syscall == syscalls.fstatat {
        handle_fstatat(policy, request)
    } else {
        Ok(NotificationResult::Continue)
    };

    match result {
        Ok(NotificationResult::Value(value)) => notification_value(request.id, value),
        Ok(NotificationResult::Continue) => notification_continue(request.id),
        Err(error) => {
            let errno = error.errno();
            notification_error(request.id, -errno.abs())
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
        return Err(Trap::internal()
            .with_detail("mechanism", "seccomp")
            .with_detail("errno", format!("{}", Errno::last())));
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
                return Err(system_errno(error as i32));
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
                return Err(system_errno(error as i32));
            }
        }
    }
}

fn validate_notification_id(fd: RawFd, id: u64) -> Result<()> {
    loop {
        // SAFETY: id points to initialized storage for SECCOMP_IOCTL_NOTIF_ID_VALID.
        match unsafe { seccomp_notif_id_valid(fd, ptr::addr_of!(id)) } {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(error) => {
                return Err(system_errno(error as i32));
            }
        }
    }
}

fn system_errno(errno: i32) -> Trap {
    Trap::internal().with_detail("errno", errno.to_string())
}

fn handle_bind(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials,
) -> SysResult<NotificationResult> {
    let mut socket = target_socket(request)?;

    match socket.info.kind() {
        SocketKind::Tcp => {
            if !policy.network_access.local_tcp_bind {
                if let Ok(endpoint) = tcp_endpoint(&socket.addr, socket.info.domain) {
                    denials.record(Denial::Network(
                        NetworkOperation::Bind,
                        endpoint.addr.to_string(),
                    ));
                }
                return Err(BrokerError::PolicyDenied);
            }
            let endpoint = tcp_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback {
                denials.record(Denial::Network(
                    NetworkOperation::Bind,
                    endpoint.addr.to_string(),
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
    landlock_features: LandlockFeatures,
    request: &libc::seccomp_notif,
    denials: &mut Denials,
) -> SysResult<NotificationResult> {
    let socket = target_socket(request)?;

    match socket.info.kind() {
        SocketKind::Tcp => {
            let endpoint = tcp_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback
                || !policy
                    .network_access
                    .connect_tcp_ports
                    .contains(&endpoint.port)
            {
                denials.record(Denial::Network(
                    NetworkOperation::Connect,
                    endpoint.addr.to_string(),
                ));
                return Err(BrokerError::PolicyDenied);
            }

            broker_addr_call(socket.sock.as_raw_fd(), &socket.addr, libc::connect)
                .map(NotificationResult::Value)
        }
        SocketKind::Unix => handle_unix_connect(policy, landlock_features, request.pid, &socket),
        SocketKind::Other => Ok(NotificationResult::Continue),
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
    }
}

fn handle_unix_connect(
    policy: &AccessPolicy,
    landlock_features: LandlockFeatures,
    pid: u32,
    socket: &TargetSocket,
) -> SysResult<NotificationResult> {
    let Some((target, relative)) = unix_path_target(pid, &socket.addr)? else {
        return Err(BrokerError::PolicyDenied);
    };
    authorize_unix_path(policy, &target)?;

    if landlock_features.resolve_unix {
        return Ok(NotificationResult::Continue);
    }

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

fn duplicate_target_fd(pid: Pid, fd: RawFd) -> SysResult<OwnedFd> {
    // SAFETY: pidfd_open copies scalar arguments and returns a new fd on success.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
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

pub(super) fn network_filter(config: NetworkFilter, needs_network: bool) -> Result<NetworkFilters> {
    let syscalls = NotificationSyscalls::new();
    let mut errno_rules = RuleMap::new();

    if needs_network {
        add_socket_family_filter(&mut errno_rules, syscalls.socket)?;
        add_unix_socket_filters(
            &mut errno_rules,
            syscalls.socket,
            syscalls.socketpair,
            config.unix_sockets,
        )?;
    }

    let eafnosupport = u32::try_from(libc::EAFNOSUPPORT).map_err(|_| Trap::internal())?;
    let errno = if errno_rules.is_empty() {
        None
    } else {
        Some(build_filter(
            errno_rules,
            SeccompAction::Errno(eafnosupport),
        )?)
    };
    let notify = if config.notify_bind || config.notify_connect || config.notify_filesystem {
        let mut notify_syscalls = Vec::new();
        if config.notify_bind {
            notify_syscalls.push(syscalls.bind);
        }
        if config.notify_connect {
            notify_syscalls.push(syscalls.connect);
        }
        if config.notify_filesystem {
            notify_syscalls.extend(syscalls.filesystem_syscalls());
        }
        Some(build_notify_filter(&notify_syscalls)?)
    } else {
        None
    };

    Ok(NetworkFilters { errno, notify })
}

pub(super) struct NetworkFilters {
    errno: Option<BpfProgram>,
    notify: Option<BpfProgram>,
}

impl NetworkFilters {
    pub(super) fn load(&self) -> Result<()> {
        if let Some(errno) = &self.errno {
            load_program(errno, 0)?;
        }
        if let Some(notify) = &self.notify {
            load_program(notify, 0)?;
        }

        Ok(())
    }

    fn load_with_listener(&self) -> Result<OwnedFd> {
        if let Some(errno) = &self.errno {
            load_program(errno, 0)?;
        }
        let notify = self.notify.as_ref().ok_or_else(Trap::internal)?;

        load_program(notify, libc::SECCOMP_FILTER_FLAG_NEW_LISTENER)?.ok_or_else(Trap::internal)
    }
}

fn build_filter(rules: RuleMap, match_action: SeccompAction) -> Result<BpfProgram> {
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, match_action, target_arch()?)
        .map_err(Trap::policy_stdin_source)?;
    let program = <BpfProgram as TryFrom<SeccompFilter>>::try_from(filter)
        .map_err(Trap::policy_stdin_source)?;

    Ok(program)
}

fn build_notify_filter(syscalls: &[i64]) -> Result<BpfProgram> {
    let mut program = BpfProgram::with_capacity(syscalls.len() * 2 + 2);
    let load_syscall = bpf_code(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS)?;
    let jump_eq = bpf_code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K)?;
    let ret = bpf_code(libc::BPF_RET | libc::BPF_K)?;

    program.push(bpf_stmt(load_syscall, 0));
    for syscall in syscalls {
        program.push(bpf_jump(
            jump_eq,
            u32::try_from(*syscall).map_err(|_| Trap::internal())?,
            0,
            1,
        ));
        program.push(bpf_stmt(ret, libc::SECCOMP_RET_USER_NOTIF));
    }
    program.push(bpf_stmt(ret, libc::SECCOMP_RET_ALLOW));

    Ok(program)
}

fn bpf_code(code: u32) -> Result<u16> {
    u16::try_from(code).map_err(|_| Trap::internal())
}

fn bpf_stmt(code: u16, k: u32) -> seccompiler::sock_filter {
    seccompiler::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> seccompiler::sock_filter {
    seccompiler::sock_filter { code, jt, jf, k }
}

fn target_arch() -> Result<TargetArch> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(TargetArch::x86_64),
        "aarch64" => Ok(TargetArch::aarch64),
        "riscv64" => Ok(TargetArch::riscv64),
        arch => Err(Trap::internal().with_detail("arch", arch)),
    }
}

fn load_program(program: &BpfProgram, flags: libc::c_ulong) -> Result<Option<OwnedFd>> {
    if program.is_empty() {
        return Err(Trap::internal());
    }

    // SAFETY: prctl(2) copies scalar arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(system_errno(Errno::last() as i32));
    }

    let len = libc::c_ushort::try_from(program.len()).map_err(|_| Trap::internal())?;
    let filter = SockFilterProg {
        len,
        filter: program.as_ptr(),
    };

    // SAFETY: filter points to a live seccomp BPF program for the duration of the syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            ptr::addr_of!(filter),
        )
    };
    if rc < 0 {
        return Err(system_errno(Errno::last() as i32));
    }

    if flags & libc::SECCOMP_FILTER_FLAG_NEW_LISTENER == 0 {
        return Ok(None);
    }

    let fd = RawFd::try_from(rc).map_err(|_| Trap::internal())?;
    // SAFETY: seccomp returned a new listener fd when NEW_LISTENER was set.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn seccomp_condition(
    arg_index: u8,
    operator: SeccompCmpOp,
    value: u64,
) -> Result<SeccompCondition> {
    SeccompCondition::new(arg_index, SeccompCmpArgLen::Dword, operator, value)
        .map_err(Trap::policy_stdin_source)
}

fn add_conditional_rule(
    rules: &mut RuleMap,
    syscall: i64,
    conditions: Vec<SeccompCondition>,
) -> Result<()> {
    let rule = SeccompRule::new(conditions).map_err(Trap::policy_stdin_source)?;
    rules.entry(syscall).or_default().push(rule);

    Ok(())
}

fn add_unix_socket_filters(
    rules: &mut RuleMap,
    socket: i64,
    socketpair: i64,
    policy: UnixSocketFilter,
) -> Result<()> {
    match policy {
        UnixSocketFilter::Unrestricted => {}
        UnixSocketFilter::PathMediated => {
            add_socket_domain_filter(rules, socketpair, libc::AF_UNIX)?;
        }
        UnixSocketFilter::DenyAll => {
            add_socket_domain_filter(rules, socket, libc::AF_UNIX)?;
            add_socket_domain_filter(rules, socketpair, libc::AF_UNIX)?;
        }
    }

    Ok(())
}

pub(super) fn needs_unix_socket_broker(access: &UnixSocketAccess) -> bool {
    matches!(access, UnixSocketAccess::AllowPaths(paths) if !paths.is_empty())
}

pub(super) fn needs_filesystem_broker(policy: &AccessPolicy) -> bool {
    !policy.write_roots.is_empty() || !matches!(policy.read_access, ReadAccess::Unrestricted)
}

pub(super) fn unix_socket_filter(access: &UnixSocketAccess) -> UnixSocketFilter {
    match access {
        UnixSocketAccess::Unrestricted => UnixSocketFilter::Unrestricted,
        UnixSocketAccess::AllowPaths(paths) if paths.is_empty() => UnixSocketFilter::DenyAll,
        UnixSocketAccess::AllowPaths(_) => UnixSocketFilter::PathMediated,
    }
}

#[derive(Clone, Copy)]
pub(super) struct NetworkFilter {
    pub(super) notify_bind: bool,
    pub(super) notify_connect: bool,
    pub(super) notify_filesystem: bool,
    pub(super) unix_sockets: UnixSocketFilter,
}

#[derive(Clone, Copy)]
pub(super) enum UnixSocketFilter {
    Unrestricted,
    PathMediated,
    DenyAll,
}

fn add_socket_family_filter(rules: &mut RuleMap, socket: i64) -> Result<()> {
    let stream = u64::try_from(libc::SOCK_STREAM).map_err(|_| Trap::internal())?;
    let tcp = u64::try_from(libc::IPPROTO_TCP).map_err(|_| Trap::internal())?;

    for domain in [libc::AF_INET, libc::AF_INET6] {
        let domain = u64::try_from(domain).map_err(|_| Trap::internal())?;

        for ty in 0..=SOCK_TYPE_MASK {
            if ty == stream {
                continue;
            }

            add_conditional_rule(
                rules,
                socket,
                vec![
                    seccomp_condition(0, SeccompCmpOp::Eq, domain)?,
                    seccomp_condition(1, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), ty)?,
                ],
            )?;
        }

        for proto in 1..tcp {
            add_conditional_rule(
                rules,
                socket,
                vec![
                    seccomp_condition(0, SeccompCmpOp::Eq, domain)?,
                    seccomp_condition(1, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), stream)?,
                    seccomp_condition(2, SeccompCmpOp::Eq, proto)?,
                ],
            )?;
        }

        add_conditional_rule(
            rules,
            socket,
            vec![
                seccomp_condition(0, SeccompCmpOp::Eq, domain)?,
                seccomp_condition(1, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), stream)?,
                seccomp_condition(2, SeccompCmpOp::Gt, tcp)?,
            ],
        )?;
    }

    for domain in [libc::AF_PACKET, libc::AF_NETLINK] {
        add_socket_domain_filter(rules, socket, domain)?;
    }

    Ok(())
}

fn add_socket_domain_filter(rules: &mut RuleMap, socket: i64, domain: i32) -> Result<()> {
    let domain = u64::try_from(domain).map_err(|_| Trap::internal())?;

    add_conditional_rule(
        rules,
        socket,
        vec![seccomp_condition(0, SeccompCmpOp::Eq, domain)?],
    )
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

fn handle_openat(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials,
) -> SysResult<NotificationResult> {
    // args[0] is dirfd: an i32 (including AT_FDCWD=-100) stored as u64.
    #[allow(clippy::cast_possible_truncation)]
    let dirfd = request.data.args[0] as i32;
    let path_ptr = usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
    let flags = i32::try_from(request.data.args[2]).map_err(|_| BrokerError::InvalidAddress)?;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);

    let Some(path) = read_child_path(pid, path_ptr)? else {
        return Ok(NotificationResult::Continue);
    };

    let resolved = resolve_child_path(pid, dirfd, &path)?;
    let wants_write =
        (flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC)) != 0;
    let reports_write = (flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND)) != 0;
    let wants_read = (flags & libc::O_WRONLY) == 0;

    if wants_write && check_fs_write(policy, &resolved).is_err() {
        if (flags & libc::O_CREAT) == 0 && !path_exists(&resolved)? {
            return Err(BrokerError::SystemCall {
                errno: libc::ENOENT,
            });
        }
        if reports_write {
            denials.record(Denial::Filesystem(TrapOperation::Write, resolved.clone()));
        }
        return Err(BrokerError::PolicyDenied);
    }
    if wants_read && check_fs_read(policy, &resolved).is_err() {
        if !path_exists(&resolved)? {
            return Err(BrokerError::SystemCall {
                errno: libc::ENOENT,
            });
        }
        denials.record(Denial::Filesystem(TrapOperation::Read, resolved));
        return Err(BrokerError::PolicyDenied);
    }

    Ok(NotificationResult::Continue)
}

fn handle_fstatat(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
) -> SysResult<NotificationResult> {
    // args[0] is dirfd: an i32 (including AT_FDCWD=-100) stored as u64.
    #[allow(clippy::cast_possible_truncation)]
    let dirfd = request.data.args[0] as i32;
    let path_ptr = usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| BrokerError::InvalidAddress)?);

    let Some(path) = read_child_path(pid, path_ptr)? else {
        return Ok(NotificationResult::Continue);
    };

    let resolved = resolve_child_path(pid, dirfd, &path)?;
    if check_fs_read(policy, &resolved).is_err() {
        if !path_exists(&resolved)? {
            return Err(BrokerError::SystemCall {
                errno: libc::ENOENT,
            });
        }
        return Err(BrokerError::PolicyDenied);
    }

    Ok(NotificationResult::Continue)
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

fn resolve_child_path(pid: Pid, dirfd: i32, path: &Path) -> SysResult<PathBuf> {
    if path.is_absolute() {
        return Ok(normalize_path(path));
    }

    if dirfd == libc::AT_FDCWD {
        let cwd =
            fs::read_link(format!("/proc/{pid}/cwd")).map_err(|error| BrokerError::SystemCall {
                errno: error.raw_os_error().unwrap_or(libc::EIO),
            })?;
        return Ok(normalize_path(&cwd.join(path)));
    }

    // dirfd is a file descriptor; resolve relative to /proc/<pid>/fd/<dirfd>
    let dir_path = fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).map_err(|error| {
        BrokerError::SystemCall {
            errno: error.raw_os_error().unwrap_or(libc::EBADF),
        }
    })?;
    Ok(normalize_path(&dir_path.join(path)))
}

fn check_fs_read(policy: &AccessPolicy, path: &Path) -> SysResult<()> {
    match &policy.read_access {
        ReadAccess::Unrestricted => Ok(()),
        ReadAccess::AllowRoots(roots) => {
            if roots
                .iter()
                .any(|root| path == root || path.starts_with(root))
            {
                return Ok(());
            }
            Err(BrokerError::PolicyDenied)
        }
    }
}

fn check_fs_write(policy: &AccessPolicy, path: &Path) -> SysResult<()> {
    if policy.write_roots.is_empty() {
        return Err(BrokerError::PolicyDenied);
    }

    if policy
        .write_roots
        .iter()
        .any(|root| path == root || path.starts_with(root))
    {
        return Ok(());
    }

    Err(BrokerError::PolicyDenied)
}

fn sockopt(fd: RawFd, level: libc::c_int, name: libc::c_int) -> SysResult<i32> {
    let mut value = 0;
    let mut len = libc::socklen_t::try_from(mem::size_of_val(&value))
        .map_err(|_| BrokerError::InvalidAddress)?;

    // SAFETY: value and len point to initialized storage for getsockopt(2) to update.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            ptr::addr_of_mut!(value).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc < 0 {
        Err(BrokerError::SystemCall {
            errno: Errno::last() as i32,
        })
    } else {
        Ok(value)
    }
}

fn send_fd(socket: &UnixStream, fd: RawFd) -> Result<()> {
    let byte = [0_u8];
    let iov = [IoSlice::new(&byte)];
    let fds = [fd];

    sendmsg::<()>(
        socket.as_raw_fd(),
        &iov,
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )
    .map(|_| ())
    .map_err(|error| system_errno(error as i32))
}

fn recv_fd(socket: &UnixStream) -> Result<OwnedFd> {
    let mut byte = [0_u8];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut control = nix::cmsg_space!([RawFd; 1]);
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::empty(),
    )
    .map_err(|error| system_errno(error as i32))?;

    if message.bytes == 0 {
        return Err(Trap::internal());
    }

    for control in message
        .cmsgs()
        .map_err(|error| system_errno(error as i32))?
    {
        if let ControlMessageOwned::ScmRights(fds) = control {
            let Some(fd) = fds.first().copied() else {
                continue;
            };
            // SAFETY: SCM_RIGHTS transfers ownership of the received descriptor.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }

    Err(Trap::internal())
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
}

struct NotificationSyscalls {
    bind: i64,
    connect: i64,
    socket: i64,
    socketpair: i64,
    openat: i64,
    fstatat: i64,
}

impl NotificationSyscalls {
    fn new() -> Self {
        Self {
            bind: libc::SYS_bind,
            connect: libc::SYS_connect,
            socket: libc::SYS_socket,
            socketpair: libc::SYS_socketpair,
            openat: libc::SYS_openat,
            fstatat: libc::SYS_newfstatat,
        }
    }

    fn filesystem_syscalls(&self) -> [i64; 2] {
        [self.openat, self.fstatat]
    }
}

fn exit_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
        _ => 1,
    }
}
