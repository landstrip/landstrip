// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use crate::fd::close_inherited_fds;
use crate::landlock::enforce_access_policy;
use crate::paths::normalize_path;
use crate::policy::{AccessPolicy, UnixSocketAccess};
use libseccomp::{
    ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpNotifReq, ScmpNotifResp,
    ScmpNotifRespFlags, ScmpSyscall, ScmpVersion, get_api as seccomp_api_level, notify_id_valid,
};
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, fcntl};
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{IoSlice, IoSliceMut};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

const NOTIFY_API: u32 = 6;
const POLL_MS: u16 = 100;
const SOCK_TYPE_MASK: u64 = 0x0f;

type SysResult<T> = std::result::Result<T, Error>;
type SocketAddrCall =
    unsafe extern "C" fn(libc::c_int, *const libc::sockaddr, libc::socklen_t) -> libc::c_int;

#[allow(clippy::too_many_lines)]
pub(crate) fn run_network_broker(
    policy: &AccessPolicy,
    command: &OsStr,
    args: &[OsString],
) -> Result<i32> {
    let api_level = seccomp_api_level();
    let version = ScmpVersion::current()?;

    if api_level < NOTIFY_API {
        return Err(Error::NotSupportedNotifyApi {
            required: NOTIFY_API,
            current: api_level,
            version: version.to_string(),
        });
    }

    let notify_unix_sockets = needs_unix_socket_broker(&policy.network_access.unix_socket_access);
    let notify_bind = policy.network_access.local_tcp_bind || notify_unix_sockets;
    let notify_connect = !policy.network_access.connect_tcp_ports.is_empty() || notify_unix_sockets;
    let unix_sockets = unix_socket_filter(&policy.network_access.unix_socket_access);
    let _filter = network_filter(NetworkFilter {
        notify_bind,
        notify_connect,
        unix_sockets,
    })?;
    let syscalls = NotificationSyscalls::new()?;
    let (parent, child_sock) = UnixStream::pair()?;

    // SAFETY: landstrip forks before spawning threads; the child either execs the target or exits.
    match unsafe { fork() }? {
        ForkResult::Child => {
            drop(parent);

            let result = (|| -> Result<()> {
                enforce_access_policy(policy)?;

                let filter = network_filter(NetworkFilter {
                    notify_bind,
                    notify_connect,
                    unix_sockets,
                })?;
                filter.load()?;
                let notify = filter.get_notify_fd()?;

                // SAFETY: notify is borrowed only for the duration of fcntl(2).
                let notify_fd = unsafe { BorrowedFd::borrow_raw(notify) };
                let notify = fcntl(notify_fd, FcntlArg::F_DUPFD_CLOEXEC(0))?;
                // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
                let notify = unsafe { OwnedFd::from_raw_fd(notify) };

                send_fd(&child_sock, notify.as_raw_fd())?;
                drop(notify);
                drop(child_sock);
                drop(filter);
                close_inherited_fds();

                let mut child_command = Command::new(command);
                child_command.args(args);

                let error = child_command.exec();
                Err(Error::Exec {
                    command: command.to_os_string(),
                    source: error,
                })
            })();

            if let Err(error) = result {
                eprintln!("landstrip child setup failed: {error:?}");
            }

            // SAFETY: _exit terminates the child without running duplicated parent cleanup.
            unsafe { libc::_exit(127) }
        }
        ForkResult::Parent { child } => {
            drop(child_sock);
            let notify = recv_fd(&parent)?;
            drop(parent);
            let notify_fd = notify.as_raw_fd();

            supervise_child(policy, child, notify_fd, &syscalls)
        }
    }
}

fn supervise_child(
    policy: &AccessPolicy,
    child: Pid,
    notify_fd: RawFd,
    syscalls: &NotificationSyscalls,
) -> Result<i32> {
    loop {
        loop {
            match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => break,
                Ok(status) => return Ok(ExitCode::from(status).into()),
                Err(Errno::EINTR) => continue,
                Err(source) => return Err(Error::Nix(source)),
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
                Err(source) => return Err(Error::Nix(source)),
            }
        };

        if revents.is_empty() {
            continue;
        }

        if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            loop {
                match waitpid(child, None) {
                    Ok(status) => return Ok(ExitCode::from(status).into()),
                    Err(Errno::EINTR) => continue,
                    Err(source) => return Err(Error::Nix(source)),
                }
            }
        }

        let request = ScmpNotifReq::receive(notify_fd)?;
        let response = handle_notification(policy, &request, syscalls);

        notify_id_valid(notify_fd, request.id)?;
        if let Err(source) = response.respond(notify_fd) {
            loop {
                match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) => break,
                    Ok(status) => return Ok(ExitCode::from(status).into()),
                    Err(Errno::EINTR) => continue,
                    Err(wait_error) => return Err(Error::Nix(wait_error)),
                }
            }

            return Err(Error::Seccomp(source));
        }
    }
}

fn handle_notification(
    policy: &AccessPolicy,
    request: &ScmpNotifReq,
    syscalls: &NotificationSyscalls,
) -> ScmpNotifResp {
    let result = if request.data.syscall == syscalls.bind {
        handle_bind(policy, request)
    } else if request.data.syscall == syscalls.connect {
        handle_connect(policy, request)
    } else {
        Ok(NotificationResult::Continue)
    };

    match result {
        Ok(NotificationResult::Value(value)) => {
            ScmpNotifResp::new_val(request.id, value, ScmpNotifRespFlags::empty())
        }
        Ok(NotificationResult::Continue) => {
            ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty())
        }
        Err(error) => {
            let errno = notification_errno(&error);
            ScmpNotifResp::new_error(request.id, -errno.abs(), ScmpNotifRespFlags::empty())
        }
    }
}

fn notification_errno(error: &Error) -> i32 {
    match error {
        Error::PolicyDenied => libc::EACCES,
        Error::AddressFamilyNotSupported => libc::EAFNOSUPPORT,
        Error::InvalidAddress => libc::EINVAL,
        Error::BadFileDescriptor => libc::EBADF,
        Error::BadAddress => libc::EFAULT,
        Error::NameTooLong => libc::ENAMETOOLONG,
        Error::Nix(errno) => *errno as i32,
        Error::PeerClosed => libc::ECONNRESET,
        Error::MissingFileDescriptor => libc::EBADMSG,
        _ => libc::EIO,
    }
}

fn handle_bind(policy: &AccessPolicy, request: &ScmpNotifReq) -> SysResult<NotificationResult> {
    let mut socket = target_socket(request)?;

    match socket.kind() {
        SocketKind::Tcp => {
            if !policy.network_access.local_tcp_bind {
                return Err(Error::PolicyDenied);
            }
            let endpoint = tcp_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback {
                return Err(Error::PolicyDenied);
            }

            broker_addr_call(socket.sock.as_raw_fd(), &socket.addr, libc::bind)
                .map(NotificationResult::Value)
        }
        SocketKind::Unix => handle_unix_bind(policy, request.pid, &mut socket),
        SocketKind::NotSupported => Err(Error::AddressFamilyNotSupported),
        SocketKind::Other => Ok(NotificationResult::Continue),
    }
}

fn handle_connect(policy: &AccessPolicy, request: &ScmpNotifReq) -> SysResult<NotificationResult> {
    let socket = target_socket(request)?;

    match socket.kind() {
        SocketKind::Tcp => {
            let endpoint = tcp_endpoint(&socket.addr, socket.info.domain)?;
            authorize_proxy_endpoint(&policy.network_access.connect_tcp_ports, endpoint)?;
            broker_addr_call(socket.sock.as_raw_fd(), &socket.addr, libc::connect)
                .map(NotificationResult::Value)
        }
        SocketKind::Unix => handle_unix_connect(policy, request.pid, &socket),
        SocketKind::Other => Ok(NotificationResult::Continue),
        SocketKind::NotSupported => Err(Error::AddressFamilyNotSupported),
    }
}

fn handle_unix_connect(
    policy: &AccessPolicy,
    pid: u32,
    socket: &TargetSocket,
) -> SysResult<NotificationResult> {
    let Some((target, relative)) = unix_path_target(pid, &socket.addr)? else {
        return Err(Error::PolicyDenied);
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
        return Err(Error::PolicyDenied);
    };
    authorize_unix_path(policy, &target)?;

    if !policy
        .write_roots
        .iter()
        .any(|root| target == *root || target.starts_with(root))
    {
        return Err(Error::PolicyDenied);
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
        let pid = i32::try_from(pid).map_err(|_| Error::InvalidAddress)?;
        let cwd = fs::read_link(format!("/proc/{pid}/cwd")).map_err(Error::Io)?;
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
            .ok_or(Error::PolicyDenied),
    }
}

fn rewrite_unix_path(addr: &mut Vec<u8>, target: &Path) -> SysResult<()> {
    let sun_path = mem::size_of::<libc::sa_family_t>();
    let path = target.as_os_str().as_bytes();
    let max_path = mem::size_of::<libc::sockaddr_un>() - sun_path;
    if path.len() + 1 > max_path {
        return Err(Error::NameTooLong);
    }

    let mut rewritten = vec![0_u8; sun_path + path.len() + 1];
    rewritten[..sun_path].copy_from_slice(&addr[..sun_path]);
    rewritten[sun_path..sun_path + path.len()].copy_from_slice(path);
    *addr = rewritten;

    Ok(())
}

fn authorize_proxy_endpoint(ports: &[u16], endpoint: TcpEndpoint) -> SysResult<()> {
    if !endpoint.loopback || !ports.contains(&endpoint.port) {
        return Err(Error::PolicyDenied);
    }

    Ok(())
}

fn tcp_endpoint(addr: &[u8], domain: i32) -> SysResult<TcpEndpoint> {
    match (domain, sockaddr_family(addr)?) {
        (libc::AF_INET, libc::AF_INET) => {
            if addr.len() < mem::size_of::<libc::sockaddr_in>() {
                return Err(Error::InvalidAddress);
            }

            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
            Ok(TcpEndpoint {
                port,
                loopback: ip.is_loopback(),
            })
        }
        (libc::AF_INET6, libc::AF_INET6) => {
            if addr.len() < mem::size_of::<libc::sockaddr_in6>() {
                return Err(Error::InvalidAddress);
            }

            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&addr[8..24]).map_err(|_| Error::InvalidAddress)?,
            );
            Ok(TcpEndpoint {
                port,
                loopback: ip.is_loopback(),
            })
        }
        _ => Err(Error::AddressFamilyNotSupported),
    }
}

fn sockaddr_family(addr: &[u8]) -> SysResult<i32> {
    let family = addr
        .get(..mem::size_of::<libc::sa_family_t>())
        .ok_or(Error::InvalidAddress)?;
    let family = <[u8; 2]>::try_from(family).map_err(|_| Error::InvalidAddress)?;

    Ok(i32::from(libc::sa_family_t::from_ne_bytes(family)))
}

fn target_socket(request: &ScmpNotifReq) -> SysResult<TargetSocket> {
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| Error::BadFileDescriptor)?;
    let target_addr = usize::try_from(request.data.args[1]).map_err(|_| Error::BadAddress)?;
    let addr_len = usize::try_from(request.data.args[2]).map_err(|_| Error::InvalidAddress)?;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| Error::InvalidAddress)?);

    if addr_len > mem::size_of::<libc::sockaddr_storage>() {
        return Err(Error::InvalidAddress);
    }

    let addr = read_target_addr(pid, target_addr, addr_len)?;
    let sock = duplicate_target_fd(pid, fd)?;
    let info = SocketInfo::read(sock.as_raw_fd())?;

    Ok(TargetSocket { sock, addr, info })
}

fn read_target_addr(pid: Pid, target_addr: usize, addr_len: usize) -> SysResult<Vec<u8>> {
    if addr_len < mem::size_of::<libc::sa_family_t>() {
        return Err(Error::InvalidAddress);
    }

    let mut addr = vec![0_u8; addr_len];
    let mut local = [IoSliceMut::new(&mut addr)];
    let target = [RemoteIoVec {
        base: target_addr,
        len: addr_len,
    }];
    if process_vm_readv(pid, &mut local, &target).map_err(Error::Nix)? != addr_len {
        return Err(Error::BadAddress);
    }

    Ok(addr)
}

fn duplicate_target_fd(pid: Pid, fd: RawFd) -> SysResult<OwnedFd> {
    // SAFETY: pidfd_open copies scalar arguments and returns a new fd on success.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
    if pidfd < 0 {
        return Err(Error::Nix(Errno::last()));
    }
    // SAFETY: pidfd_open returned a new owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };

    // SAFETY: pidfd_getfd copies scalar arguments and returns a duplicated fd.
    let sock = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if sock < 0 {
        return Err(Error::Nix(Errno::last()));
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
    let addr_len = libc::socklen_t::try_from(addr.len()).map_err(|_| Error::InvalidAddress)?;

    // SAFETY: storage contains copied target sockaddr bytes and is aligned.
    let rc = unsafe {
        call(
            sock,
            ptr::addr_of!(storage).cast::<libc::sockaddr>(),
            addr_len,
        )
    };
    if rc < 0 {
        Err(Error::Nix(Errno::last()))
    } else {
        Ok(i64::from(rc))
    }
}

pub(crate) fn network_filter(config: NetworkFilter) -> Result<ScmpFilterContext> {
    let syscalls = NotificationSyscalls::new()?;
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow).map_err(Error::Seccomp)?;

    add_socket_family_filter(&mut filter, syscalls.socket)?;
    add_unix_socket_filters(
        &mut filter,
        syscalls.socket,
        syscalls.socketpair,
        config.unix_sockets,
    )?;

    if config.notify_bind {
        filter
            .add_rule(ScmpAction::Notify, syscalls.bind)
            .map_err(Error::Seccomp)?;
    }

    if config.notify_connect {
        filter
            .add_rule(ScmpAction::Notify, syscalls.connect)
            .map_err(Error::Seccomp)?;
    }

    Ok(filter)
}

fn add_unix_socket_filters(
    filter: &mut ScmpFilterContext,
    socket: ScmpSyscall,
    socketpair: ScmpSyscall,
    policy: UnixSocketFilter,
) -> Result<()> {
    match policy {
        UnixSocketFilter::Unrestricted => {}
        UnixSocketFilter::PathMediated => {
            add_socket_domain_filter(filter, socketpair, libc::AF_UNIX)?;
        }
        UnixSocketFilter::DenyAll => {
            add_socket_domain_filter(filter, socket, libc::AF_UNIX)?;
            add_socket_domain_filter(filter, socketpair, libc::AF_UNIX)?;
        }
    }

    Ok(())
}

fn needs_unix_socket_broker(access: &UnixSocketAccess) -> bool {
    matches!(access, UnixSocketAccess::AllowPaths(paths) if !paths.is_empty())
}

fn unix_socket_filter(access: &UnixSocketAccess) -> UnixSocketFilter {
    match access {
        UnixSocketAccess::Unrestricted => UnixSocketFilter::Unrestricted,
        UnixSocketAccess::AllowPaths(paths) if paths.is_empty() => UnixSocketFilter::DenyAll,
        UnixSocketAccess::AllowPaths(_) => UnixSocketFilter::PathMediated,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct NetworkFilter {
    pub(crate) notify_bind: bool,
    pub(crate) notify_connect: bool,
    pub(crate) unix_sockets: UnixSocketFilter,
}

#[derive(Clone, Copy)]
pub(crate) enum UnixSocketFilter {
    Unrestricted,
    PathMediated,
    DenyAll,
}

fn add_socket_family_filter(filter: &mut ScmpFilterContext, socket: ScmpSyscall) -> Result<()> {
    let stream = u64::try_from(libc::SOCK_STREAM).map_err(|_| Error::InvalidAddress)?;
    let tcp = u64::try_from(libc::IPPROTO_TCP).map_err(|_| Error::InvalidAddress)?;

    for domain in [libc::AF_INET, libc::AF_INET6] {
        let domain = u64::try_from(domain).map_err(|_| Error::InvalidAddress)?;

        for ty in 0..=SOCK_TYPE_MASK {
            if ty == stream {
                continue;
            }

            filter
                .add_rule_conditional(
                    ScmpAction::Errno(libc::EAFNOSUPPORT),
                    socket,
                    &[
                        ScmpArgCompare::new(0, ScmpCompareOp::Equal, domain),
                        ScmpArgCompare::new(1, ScmpCompareOp::MaskedEqual(SOCK_TYPE_MASK), ty),
                    ],
                )
                .map_err(Error::Seccomp)?;
        }

        for proto in 1..tcp {
            filter
                .add_rule_conditional(
                    ScmpAction::Errno(libc::EAFNOSUPPORT),
                    socket,
                    &[
                        ScmpArgCompare::new(0, ScmpCompareOp::Equal, domain),
                        ScmpArgCompare::new(1, ScmpCompareOp::MaskedEqual(SOCK_TYPE_MASK), stream),
                        ScmpArgCompare::new(2, ScmpCompareOp::Equal, proto),
                    ],
                )
                .map_err(Error::Seccomp)?;
        }

        filter
            .add_rule_conditional(
                ScmpAction::Errno(libc::EAFNOSUPPORT),
                socket,
                &[
                    ScmpArgCompare::new(0, ScmpCompareOp::Equal, domain),
                    ScmpArgCompare::new(1, ScmpCompareOp::MaskedEqual(SOCK_TYPE_MASK), stream),
                    ScmpArgCompare::new(2, ScmpCompareOp::Greater, tcp),
                ],
            )
            .map_err(Error::Seccomp)?;
    }

    for domain in [libc::AF_PACKET, libc::AF_NETLINK] {
        add_socket_domain_filter(filter, socket, domain)?;
    }

    Ok(())
}

fn add_socket_domain_filter(
    filter: &mut ScmpFilterContext,
    socket: ScmpSyscall,
    domain: i32,
) -> Result<()> {
    let domain = u64::try_from(domain).map_err(|_| Error::InvalidAddress)?;

    filter
        .add_rule_conditional(
            ScmpAction::Errno(libc::EAFNOSUPPORT),
            socket,
            &[ScmpArgCompare::new(0, ScmpCompareOp::Equal, domain)],
        )
        .map(|_| ())
        .map_err(Error::Seccomp)
}

fn create_path(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("/"));
    let parent = normalize_path(parent);

    path.file_name()
        .map_or(parent.clone(), |name| parent.join(name))
}

fn sockopt(fd: RawFd, level: libc::c_int, name: libc::c_int) -> SysResult<i32> {
    let mut value = 0;
    let mut len =
        libc::socklen_t::try_from(mem::size_of_val(&value)).map_err(|_| Error::InvalidAddress)?;

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
        Err(Error::Nix(Errno::last()))
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
    .map_err(Error::Nix)
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
    .map_err(Error::Nix)?;

    if message.bytes == 0 {
        return Err(Error::PeerClosed);
    }

    for control in message.cmsgs().map_err(Error::Nix)? {
        if let ControlMessageOwned::ScmRights(fds) = control {
            let Some(fd) = fds.first().copied() else {
                continue;
            };
            // SAFETY: SCM_RIGHTS transfers ownership of the received descriptor.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }

    Err(Error::MissingFileDescriptor)
}

#[derive(Debug)]
struct TargetSocket {
    sock: OwnedFd,
    addr: Vec<u8>,
    info: SocketInfo,
}

impl TargetSocket {
    fn kind(&self) -> SocketKind {
        self.info.kind()
    }
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
    port: u16,
    loopback: bool,
}

enum NotificationResult {
    Value(i64),
    Continue,
}

struct NotificationSyscalls {
    bind: ScmpSyscall,
    connect: ScmpSyscall,
    socket: ScmpSyscall,
    socketpair: ScmpSyscall,
}

impl NotificationSyscalls {
    fn new() -> Result<Self> {
        Ok(Self {
            bind: ScmpSyscall::from_name("bind").map_err(Error::Seccomp)?,
            connect: ScmpSyscall::from_name("connect").map_err(Error::Seccomp)?,
            socket: ScmpSyscall::from_name("socket").map_err(Error::Seccomp)?,
            socketpair: ScmpSyscall::from_name("socketpair").map_err(Error::Seccomp)?,
        })
    }
}

struct ExitCode(i32);

impl From<WaitStatus> for ExitCode {
    fn from(status: WaitStatus) -> Self {
        Self(match status {
            WaitStatus::Exited(_, code) => code,
            WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
            _ => 1,
        })
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code.0
    }
}
