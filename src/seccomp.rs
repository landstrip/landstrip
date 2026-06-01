// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use crate::landlock::enforce_access_policy;
use crate::paths::normalize_path;
use crate::policy::AccessPolicy;
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
use std::io::{self, IoSlice, IoSliceMut};
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

type SysResult<T> = std::result::Result<T, i32>;
type SocketAddrCall =
    unsafe extern "C" fn(libc::c_int, *const libc::sockaddr, libc::socklen_t) -> libc::c_int;

#[allow(clippy::too_many_lines)]
pub(crate) fn run_network_broker(
    policy: &AccessPolicy,
    command: &OsStr,
    args: &[OsString],
) -> Result<i32> {
    let api_level = seccomp_api_level();
    let version =
        ScmpVersion::current().map_err(|source| Error::with_source("seccomp: version", source))?;

    if api_level < NOTIFY_API {
        return Err(Error::message(format!(
            "seccomp: user notification requires libseccomp API level \
             {NOTIFY_API} or newer; current level is {api_level} \
             with libseccomp {version}"
        )));
    }

    let notify_bind = policy.network_access.local_tcp_bind;
    let notify_connect = !policy.network_access.connect_tcp_ports.is_empty();
    let _filter = network_filter(notify_bind, notify_connect)?;
    let syscalls = NotificationSyscalls::new()?;
    let (parent, child_sock) =
        UnixStream::pair().map_err(|source| Error::with_source("seccomp: socketpair", source))?;

    // SAFETY: landstrip forks before spawning threads; the child either execs the target or exits.
    match unsafe { fork() }.map_err(|source| Error::with_source("seccomp: fork", source))? {
        ForkResult::Child => {
            drop(parent);

            let result = (|| -> Result<()> {
                enforce_access_policy(policy)?;

                let filter = network_filter(notify_bind, notify_connect)?;
                filter
                    .load()
                    .map_err(|source| Error::with_source("seccomp: load", source))?;
                let notify = filter
                    .get_notify_fd()
                    .map_err(|source| Error::with_source("seccomp: notify fd", source))?;

                // SAFETY: notify is borrowed only for the duration of fcntl(2).
                let notify_fd = unsafe { BorrowedFd::borrow_raw(notify) };
                let notify = fcntl(notify_fd, FcntlArg::F_DUPFD_CLOEXEC(0))
                    .map_err(|source| Error::with_source("seccomp: duplicate notify fd", source))?;
                // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
                let notify = unsafe { OwnedFd::from_raw_fd(notify) };

                send_fd(&child_sock, notify.as_raw_fd())
                    .map_err(|source| Error::with_source("seccomp: send notify fd", source))?;
                drop(child_sock);

                let error = Command::new(command).args(args).exec();
                Err(Error::with_source(
                    format!("exec: {}", command.to_string_lossy()),
                    error,
                ))
            })();

            if let Err(error) = result {
                eprintln!("landstrip child setup failed: {error:?}");
            }

            // SAFETY: _exit terminates the child without running duplicated parent cleanup.
            unsafe { libc::_exit(127) }
        }
        ForkResult::Parent { child } => {
            drop(child_sock);
            let notify = recv_fd(&parent)
                .map_err(|source| Error::with_source("seccomp: receive notify fd", source))?;
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
                Err(source) => return Err(Error::with_source("seccomp: wait", source)),
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
                Err(source) => return Err(Error::with_source("seccomp: poll", source)),
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
                    Err(source) => return Err(Error::with_source("seccomp: wait", source)),
                }
            }
        }

        let request = ScmpNotifReq::receive(notify_fd)
            .map_err(|source| Error::with_source("seccomp: receive notification", source))?;
        let response = handle_notification(policy, &request, syscalls);

        notify_id_valid(notify_fd, request.id)
            .map_err(|source| Error::with_source("seccomp: stale notification", source))?;
        if let Err(source) = response.respond(notify_fd) {
            loop {
                match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) => break,
                    Ok(status) => return Ok(ExitCode::from(status).into()),
                    Err(Errno::EINTR) => continue,
                    Err(wait_error) => return Err(Error::with_source("seccomp: wait", wait_error)),
                }
            }

            return Err(Error::with_source("seccomp: respond", source));
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
        Err(errno) => {
            ScmpNotifResp::new_error(request.id, -errno.abs(), ScmpNotifRespFlags::empty())
        }
    }
}

fn handle_bind(policy: &AccessPolicy, request: &ScmpNotifReq) -> SysResult<NotificationResult> {
    let mut socket = remote_socket(request)?;

    match socket.kind() {
        SocketKind::Tcp => {
            let endpoint = tcp_endpoint(&socket.addr, socket.info.domain)?;
            if !endpoint.loopback {
                return Err(libc::EACCES);
            }

            broker_addr_call(socket.sock.as_raw_fd(), &socket.addr, libc::bind)
                .map(NotificationResult::Value)
        }
        SocketKind::Unix => handle_unix_bind(policy, request.pid, &mut socket),
        SocketKind::Unsupported => Err(libc::EAFNOSUPPORT),
        SocketKind::Other => Ok(NotificationResult::Continue),
    }
}

fn handle_connect(policy: &AccessPolicy, request: &ScmpNotifReq) -> SysResult<NotificationResult> {
    let socket = remote_socket(request)?;

    match socket.kind() {
        SocketKind::Tcp => {
            let endpoint = tcp_endpoint(&socket.addr, socket.info.domain)?;
            authorize_proxy_endpoint(&policy.network_access.connect_tcp_ports, endpoint)?;
            broker_addr_call(socket.sock.as_raw_fd(), &socket.addr, libc::connect)
                .map(NotificationResult::Value)
        }
        SocketKind::Unix | SocketKind::Other => Ok(NotificationResult::Continue),
        SocketKind::Unsupported => Err(libc::EAFNOSUPPORT),
    }
}

fn handle_unix_bind(
    policy: &AccessPolicy,
    pid: u32,
    socket: &mut RemoteSocket,
) -> SysResult<NotificationResult> {
    let sun_path = mem::size_of::<libc::sa_family_t>();
    if socket.addr.len() > sun_path && socket.addr[sun_path] != 0 {
        let path = &socket.addr[sun_path..];
        let end = path
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(path.len());
        if end > 0 {
            let path = Path::new(OsStr::from_bytes(&path[..end]));
            let target = if path.is_absolute() {
                create_path(path)
            } else {
                let pid = i32::try_from(pid).map_err(|_| libc::EINVAL)?;
                let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
                    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
                create_path(&cwd.join(path))
            };

            if !policy
                .write_roots
                .iter()
                .any(|root| target == *root || target.starts_with(root))
            {
                return Err(libc::EACCES);
            }

            if !path.is_absolute() {
                rewrite_unix_path(&mut socket.addr, &target)?;
            }
        }
    }

    broker_addr_call(socket.sock.as_raw_fd(), &socket.addr, libc::bind)
        .map(NotificationResult::Value)
}

fn rewrite_unix_path(addr: &mut Vec<u8>, target: &Path) -> SysResult<()> {
    let sun_path = mem::size_of::<libc::sa_family_t>();
    let path = target.as_os_str().as_bytes();
    let max_path = mem::size_of::<libc::sockaddr_un>() - sun_path;
    if path.len() + 1 > max_path {
        return Err(libc::ENAMETOOLONG);
    }

    let mut rewritten = vec![0_u8; sun_path + path.len() + 1];
    rewritten[..sun_path].copy_from_slice(&addr[..sun_path]);
    rewritten[sun_path..sun_path + path.len()].copy_from_slice(path);
    *addr = rewritten;

    Ok(())
}

fn authorize_proxy_endpoint(ports: &[u16], endpoint: TcpEndpoint) -> SysResult<()> {
    if !endpoint.loopback || !ports.contains(&endpoint.port) {
        return Err(libc::EACCES);
    }

    Ok(())
}

fn tcp_endpoint(addr: &[u8], domain: i32) -> SysResult<TcpEndpoint> {
    match (domain, sockaddr_family(addr)?) {
        (libc::AF_INET, libc::AF_INET) => {
            if addr.len() < mem::size_of::<libc::sockaddr_in>() {
                return Err(libc::EINVAL);
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
                return Err(libc::EINVAL);
            }

            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&addr[8..24]).map_err(|_| libc::EINVAL)?);
            Ok(TcpEndpoint {
                port,
                loopback: ip.is_loopback(),
            })
        }
        _ => Err(libc::EAFNOSUPPORT),
    }
}

fn sockaddr_family(addr: &[u8]) -> SysResult<i32> {
    let family = addr
        .get(..mem::size_of::<libc::sa_family_t>())
        .ok_or(libc::EINVAL)?;
    let family = <[u8; 2]>::try_from(family).map_err(|_| libc::EINVAL)?;

    Ok(i32::from(libc::sa_family_t::from_ne_bytes(family)))
}

fn remote_socket(request: &ScmpNotifReq) -> SysResult<RemoteSocket> {
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| libc::EBADF)?;
    let remote_addr = usize::try_from(request.data.args[1]).map_err(|_| libc::EFAULT)?;
    let addr_len = usize::try_from(request.data.args[2]).map_err(|_| libc::EINVAL)?;
    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| libc::EINVAL)?);

    if addr_len > mem::size_of::<libc::sockaddr_storage>() {
        return Err(libc::EINVAL);
    }

    let addr = read_remote_addr(pid, remote_addr, addr_len)?;
    let sock = duplicate_remote_fd(pid, fd)?;
    let info = SocketInfo::read(sock.as_raw_fd())?;

    Ok(RemoteSocket { sock, addr, info })
}

fn read_remote_addr(pid: Pid, remote_addr: usize, addr_len: usize) -> SysResult<Vec<u8>> {
    if addr_len < mem::size_of::<libc::sa_family_t>() {
        return Err(libc::EINVAL);
    }

    let mut addr = vec![0_u8; addr_len];
    let mut local = [IoSliceMut::new(&mut addr)];
    let remote = [RemoteIoVec {
        base: remote_addr,
        len: addr_len,
    }];
    if process_vm_readv(pid, &mut local, &remote).map_err(|error| error as i32)? != addr_len {
        return Err(libc::EFAULT);
    }

    Ok(addr)
}

fn duplicate_remote_fd(pid: Pid, fd: RawFd) -> SysResult<OwnedFd> {
    // SAFETY: pidfd_open copies scalar arguments and returns a new fd on success.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
    if pidfd < 0 {
        return Err(Errno::last_raw());
    }
    // SAFETY: pidfd_open returned a new owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };

    // SAFETY: pidfd_getfd copies scalar arguments and returns a duplicated fd.
    let sock = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if sock < 0 {
        return Err(Errno::last_raw());
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
    let addr_len = libc::socklen_t::try_from(addr.len()).map_err(|_| libc::EINVAL)?;

    // SAFETY: storage contains copied target sockaddr bytes and is aligned.
    let rc = unsafe {
        call(
            sock,
            ptr::addr_of!(storage).cast::<libc::sockaddr>(),
            addr_len,
        )
    };
    if rc < 0 {
        Err(Errno::last_raw())
    } else {
        Ok(i64::from(rc))
    }
}

pub(crate) fn network_filter(notify_bind: bool, notify_connect: bool) -> Result<ScmpFilterContext> {
    let syscalls = NotificationSyscalls::new()?;
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow)
        .map_err(|source| Error::with_source("seccomp: filter", source))?;

    add_socket_family_filter(&mut filter, syscalls.socket)?;

    if notify_bind {
        filter
            .add_rule(ScmpAction::Notify, syscalls.bind)
            .map_err(|source| Error::with_source("seccomp: rule bind", source))?;
    }

    if notify_connect {
        filter
            .add_rule(ScmpAction::Notify, syscalls.connect)
            .map_err(|source| Error::with_source("seccomp: rule connect", source))?;
    }

    Ok(filter)
}

fn add_socket_family_filter(filter: &mut ScmpFilterContext, socket: ScmpSyscall) -> Result<()> {
    for domain in [libc::AF_INET, libc::AF_INET6] {
        add_socket_type_filter(filter, socket, domain, libc::SOCK_DGRAM)?;
        add_socket_type_filter(filter, socket, domain, libc::SOCK_RAW)?;
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
    let domain = u64::try_from(domain)
        .map_err(|source| Error::with_source("seccomp: socket domain", source))?;

    filter
        .add_rule_conditional(
            ScmpAction::Errno(libc::EAFNOSUPPORT),
            socket,
            &[ScmpArgCompare::new(0, ScmpCompareOp::Equal, domain)],
        )
        .map(|_| ())
        .map_err(|source| Error::with_source("seccomp: rule socket domain", source))
}

fn add_socket_type_filter(
    filter: &mut ScmpFilterContext,
    socket: ScmpSyscall,
    domain: i32,
    ty: i32,
) -> Result<()> {
    let domain = u64::try_from(domain)
        .map_err(|source| Error::with_source("seccomp: socket domain", source))?;
    let ty =
        u64::try_from(ty).map_err(|source| Error::with_source("seccomp: socket type", source))?;

    filter
        .add_rule_conditional(
            ScmpAction::Errno(libc::EAFNOSUPPORT),
            socket,
            &[
                ScmpArgCompare::new(0, ScmpCompareOp::Equal, domain),
                ScmpArgCompare::new(1, ScmpCompareOp::MaskedEqual(SOCK_TYPE_MASK), ty),
            ],
        )
        .map(|_| ())
        .map_err(|source| Error::with_source("seccomp: rule socket type", source))
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
    let mut len = libc::socklen_t::try_from(mem::size_of_val(&value)).map_err(|_| libc::EINVAL)?;

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
        Err(Errno::last_raw())
    } else {
        Ok(value)
    }
}

fn send_fd(socket: &UnixStream, fd: RawFd) -> io::Result<()> {
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
    .map_err(|error| io::Error::from_raw_os_error(error as i32))
}

fn recv_fd(socket: &UnixStream) -> io::Result<OwnedFd> {
    let mut byte = [0_u8];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut control = nix::cmsg_space!([RawFd; 1]);
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::empty(),
    )
    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;

    if message.bytes == 0 {
        return Err(io::Error::from_raw_os_error(libc::ECONNRESET));
    }

    for control in message
        .cmsgs()
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?
    {
        if let ControlMessageOwned::ScmRights(fds) = control {
            let Some(fd) = fds.first().copied() else {
                continue;
            };
            // SAFETY: SCM_RIGHTS transfers ownership of the received descriptor.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }

    Err(io::Error::from_raw_os_error(libc::EBADMSG))
}

#[derive(Debug)]
struct RemoteSocket {
    sock: OwnedFd,
    addr: Vec<u8>,
    info: SocketInfo,
}

impl RemoteSocket {
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
            SocketKind::Unsupported
        } else {
            SocketKind::Other
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketKind {
    Tcp,
    Unix,
    Unsupported,
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
}

impl NotificationSyscalls {
    fn new() -> Result<Self> {
        Ok(Self {
            bind: ScmpSyscall::from_name("bind")
                .map_err(|source| Error::with_source("seccomp: syscall bind", source))?,
            connect: ScmpSyscall::from_name("connect")
                .map_err(|source| Error::with_source("seccomp: syscall connect", source))?,
            socket: ScmpSyscall::from_name("socket")
                .map_err(|source| Error::with_source("seccomp: syscall socket", source))?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_connect_allows_loopback_ipv4_port() {
        let endpoint = tcp_endpoint(&sockaddr_in(Ipv4Addr::LOCALHOST, 8080), libc::AF_INET)
            .expect("IPv4 loopback endpoint");

        assert_eq!(authorize_proxy_endpoint(&[8080], endpoint), Ok(()));
    }

    #[test]
    fn proxy_connect_allows_loopback_ipv6_port() {
        let endpoint = tcp_endpoint(&sockaddr_in6(Ipv6Addr::LOCALHOST, 8080), libc::AF_INET6)
            .expect("IPv6 loopback endpoint");

        assert_eq!(authorize_proxy_endpoint(&[8080], endpoint), Ok(()));
    }

    #[test]
    fn proxy_connect_denies_remote_same_port() {
        let endpoint = tcp_endpoint(
            &sockaddr_in(Ipv4Addr::new(203, 0, 113, 7), 8080),
            libc::AF_INET,
        )
        .expect("remote IPv4 endpoint");

        assert_eq!(
            authorize_proxy_endpoint(&[8080], endpoint),
            Err(libc::EACCES)
        );
    }

    #[test]
    fn proxy_connect_denies_unlisted_loopback_port() {
        let endpoint = tcp_endpoint(&sockaddr_in(Ipv4Addr::LOCALHOST, 8081), libc::AF_INET)
            .expect("IPv4 loopback endpoint");

        assert_eq!(
            authorize_proxy_endpoint(&[8080], endpoint),
            Err(libc::EACCES)
        );
    }

    #[test]
    fn unsupported_socket_kinds_are_filtered() {
        for info in [
            SocketInfo {
                domain: libc::AF_INET,
                ty: libc::SOCK_DGRAM,
                proto: libc::IPPROTO_UDP,
            },
            SocketInfo {
                domain: libc::AF_INET6,
                ty: libc::SOCK_DGRAM,
                proto: libc::IPPROTO_UDP,
            },
            SocketInfo {
                domain: libc::AF_INET,
                ty: libc::SOCK_RAW,
                proto: libc::IPPROTO_RAW,
            },
            SocketInfo {
                domain: libc::AF_PACKET,
                ty: libc::SOCK_RAW,
                proto: 0,
            },
            SocketInfo {
                domain: libc::AF_NETLINK,
                ty: libc::SOCK_RAW,
                proto: 0,
            },
        ] {
            assert_eq!(info.kind(), SocketKind::Unsupported);
        }
    }

    fn sockaddr_in(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut addr = vec![0_u8; mem::size_of::<libc::sockaddr_in>()];
        let family = libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET fits");
        addr[..2].copy_from_slice(&family.to_ne_bytes());
        addr[2..4].copy_from_slice(&port.to_be_bytes());
        addr[4..8].copy_from_slice(&ip.octets());
        addr
    }

    fn sockaddr_in6(ip: Ipv6Addr, port: u16) -> Vec<u8> {
        let mut addr = vec![0_u8; mem::size_of::<libc::sockaddr_in6>()];
        let family = libc::sa_family_t::try_from(libc::AF_INET6).expect("AF_INET6 fits");
        addr[..2].copy_from_slice(&family.to_ne_bytes());
        addr[2..4].copy_from_slice(&port.to_be_bytes());
        addr[8..24].copy_from_slice(&ip.octets());
        addr
    }
}
