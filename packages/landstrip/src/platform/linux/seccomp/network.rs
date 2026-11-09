// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use super::grant::{Grant, SessionBusGrant, SocketAddrCall, SocketGrant};
use super::notify::NotificationResult;
use super::process::{MissingTarget, TargetProcess};
use super::procfs::ProcFd;
use super::supervise::{Denial, Denials};
use crate::policy::{AccessPolicy, UnixPathAccess, UnixSocketAccess};
use crate::trap::NetworkOperation;
use socket2::SockRef;
use std::ffi::OsStr;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
#[derive(Debug)]
pub(super) struct TargetSocket {
    pub(super) sock: OwnedFd,
    pub(super) addr: Vec<u8>,
    pub(super) info: SocketInfo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SocketInfo {
    pub(super) domain: i32,
    pub(super) ty: i32,
    pub(super) proto: i32,
}

impl TryFrom<BorrowedFd<'_>> for SocketInfo {
    type Error = BrokerError;

    fn try_from(fd: BorrowedFd<'_>) -> SysResult<Self> {
        let socket = SockRef::from(&fd);
        Ok(Self {
            domain: socket.domain()?.into(),
            ty: socket.r#type()?.into(),
            proto: socket.protocol()?.map_or(0, i32::from),
        })
    }
}

impl SocketInfo {
    pub(super) fn kind(&self) -> SocketKind {
        if matches!(self.domain, libc::AF_INET | libc::AF_INET6)
            && self.ty == libc::SOCK_STREAM
            && (self.proto == libc::IPPROTO_TCP || self.proto == 0)
        {
            SocketKind::Tcp
        } else if matches!(self.domain, libc::AF_INET | libc::AF_INET6)
            && self.ty == libc::SOCK_DGRAM
            && (self.proto == libc::IPPROTO_UDP || self.proto == 0)
        {
            SocketKind::Udp
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
pub(super) enum SocketKind {
    Tcp,
    Udp,
    Unix,
    NotSupported,
    Other,
}

/// Address family decoded from the leading field of a raw socket address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SockAddrFamily(libc::sa_family_t);

impl TryFrom<&[u8]> for SockAddrFamily {
    type Error = BrokerError;

    fn try_from(addr: &[u8]) -> SysResult<Self> {
        let bytes = addr
            .get(..mem::size_of::<libc::sa_family_t>())
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or(BrokerError::InvalidAddress)?;
        Ok(Self(libc::sa_family_t::from_ne_bytes(bytes)))
    }
}

impl From<SockAddrFamily> for i32 {
    fn from(family: SockAddrFamily) -> Self {
        i32::from(family.0)
    }
}

impl TargetSocket {
    fn ip_endpoint(&self) -> SysResult<SocketAddr> {
        SockAddrFamily::parse_ip(&self.addr, self.info.domain)
    }

    fn family(&self) -> SysResult<i32> {
        Ok(i32::from(SockAddrFamily::try_from(self.addr.as_slice())?))
    }

    fn unix_path(&self) -> Option<PathBuf> {
        let sun_path = mem::size_of::<libc::sa_family_t>();
        if self.addr.len() <= sun_path || self.addr[sun_path] == 0 {
            return None;
        }

        let path = &self.addr[sun_path..];
        let end = path
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(path.len());
        if end == 0 {
            return None;
        }

        Some(PathBuf::from(OsStr::from_bytes(&path[..end])))
    }

    fn rewrite_unix_path(&mut self, target: &Path) -> SysResult<()> {
        let sun_path = mem::size_of::<libc::sa_family_t>();
        let path = target.as_os_str().as_bytes();
        let max_path = mem::size_of::<libc::sockaddr_un>() - sun_path;
        if path.len() + 1 > max_path {
            return Err(BrokerError::NameTooLong);
        }

        let mut rewritten = vec![0_u8; sun_path + path.len() + 1];
        rewritten[..sun_path].copy_from_slice(&self.addr[..sun_path]);
        rewritten[sun_path..sun_path + path.len()].copy_from_slice(path);
        self.addr = rewritten;

        Ok(())
    }

    fn deny(
        self,
        operation: NetworkOperation,
        endpoint: SocketAddr,
        pid: u32,
        call: SocketAddrCall,
        denials: &mut Denials<'_>,
    ) -> SysResult<NotificationResult> {
        let target = endpoint.to_string();
        let process = TargetProcess::from_raw(pid).context();
        denials.deny(
            Denial::Network(operation, target, process),
            true,
            Some(Grant::from(self.into_grant(call))),
        )
    }

    fn into_grant(self, call: SocketAddrCall) -> SocketGrant {
        SocketGrant::new(self.sock, self.addr, call, None)
    }
}

pub(super) fn handle_bind(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let socket = TargetSocket::try_from(request)?;

    match socket.info.kind() {
        SocketKind::Tcp | SocketKind::Udp => {
            if policy.network_access.is_unrestricted() {
                return Ok(NotificationResult::grant(socket.into_grant(libc::bind)));
            }
            if !policy.network_access.allows_local_binding() {
                if let Ok(endpoint) = socket.ip_endpoint() {
                    return socket.deny(
                        NetworkOperation::Bind,
                        endpoint,
                        request.pid,
                        libc::bind,
                        denials,
                    );
                }
                return Err(BrokerError::PolicyDenied);
            }
            let endpoint = socket.ip_endpoint()?;
            if !endpoint.ip().to_canonical().is_loopback() {
                return socket.deny(
                    NetworkOperation::Bind,
                    endpoint,
                    request.pid,
                    libc::bind,
                    denials,
                );
            }

            Ok(NotificationResult::grant(socket.into_grant(libc::bind)))
        }
        SocketKind::Unix => UnixSocketOp::Bind.handle(policy, request.pid, socket, denials),
        SocketKind::NotSupported if policy.network_access.is_unrestricted() => {
            Ok(NotificationResult::grant(socket.into_grant(libc::bind)))
        }
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
        SocketKind::Other => Ok(NotificationResult::grant(socket.into_grant(libc::bind))),
    }
}

pub(super) fn handle_connect(
    policy: &AccessPolicy,
    proxy_available: bool,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let socket = TargetSocket::try_from(request)?;

    match socket.info.kind() {
        SocketKind::Tcp => {
            if policy.network_access.is_unrestricted() {
                return Ok(NotificationResult::Continue);
            }
            let endpoint = socket.ip_endpoint()?;
            if !endpoint.ip().to_canonical().is_loopback()
                || (!policy.network_access.allows_local_binding()
                    && !policy
                        .network_access
                        .connect_tcp_ports()
                        .contains(&endpoint.port()))
            {
                return socket.deny(
                    NetworkOperation::Connect,
                    endpoint,
                    request.pid,
                    libc::connect,
                    denials,
                );
            }

            Ok(NotificationResult::grant(socket.into_grant(libc::connect)))
        }
        SocketKind::Udp => {
            if policy.network_access.is_unrestricted() {
                return Ok(NotificationResult::Continue);
            }
            if socket.family()? == libc::AF_UNSPEC {
                return Ok(NotificationResult::grant(socket.into_grant(libc::connect)));
            }
            let endpoint = socket.ip_endpoint()?;
            if !endpoint.ip().to_canonical().is_loopback()
                || !policy.network_access.allows_local_binding()
            {
                return socket.deny(
                    NetworkOperation::Connect,
                    endpoint,
                    request.pid,
                    libc::connect,
                    denials,
                );
            }

            Ok(NotificationResult::grant(socket.into_grant(libc::connect)))
        }
        SocketKind::Unix => {
            UnixSocketOp::Connect { proxy_available }.handle(policy, request.pid, socket, denials)
        }
        SocketKind::Other => Ok(NotificationResult::Continue),
        SocketKind::NotSupported if policy.network_access.is_unrestricted() => {
            Ok(NotificationResult::Continue)
        }
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
    }
}

fn check_target_datagram_addr(
    target: &TargetProcess,
    fd: RawFd,
    target_addr: usize,
    addr_len: usize,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    if target_addr == 0 {
        return Ok(NotificationResult::Continue);
    }
    if addr_len > mem::size_of::<libc::sockaddr_storage>() {
        return Err(BrokerError::InvalidAddress);
    }
    let addr = target.read_sockaddr(target_addr, addr_len)?;
    let sock = target.duplicate_fd(fd)?;
    let info = SocketInfo::try_from(sock.as_fd())?;
    match info.kind() {
        SocketKind::Tcp | SocketKind::Udp => {
            let endpoint = SockAddrFamily::parse_ip(&addr, info.domain)?;
            if endpoint.ip().to_canonical().is_loopback() {
                Ok(NotificationResult::Continue)
            } else {
                denials.record(Denial::Network(
                    NetworkOperation::Connect,
                    endpoint.to_string(),
                    target.context(),
                ));
                Err(BrokerError::PolicyDenied)
            }
        }
        SocketKind::Unix | SocketKind::Other => Ok(NotificationResult::Continue),
        SocketKind::NotSupported => Err(BrokerError::AddressFamilyNotSupported),
    }
}

pub(super) fn handle_sendto(
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let target_addr = usize::try_from(request.data.args[4]).map_err(|_| BrokerError::BadAddress)?;
    let addr_len =
        usize::try_from(request.data.args[5]).map_err(|_| BrokerError::InvalidAddress)?;
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| BrokerError::BadFileDescriptor)?;
    let target = TargetProcess::from_raw(request.pid);
    check_target_datagram_addr(&target, fd, target_addr, addr_len, denials)
}

pub(super) fn handle_sendmsg(
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let target_msg = usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
    let target = TargetProcess::from_raw(request.pid);
    let mut msghdr = mem::MaybeUninit::<libc::msghdr>::uninit();
    let len = mem::size_of::<libc::msghdr>();
    // SAFETY: msghdr is suitably aligned writable storage of size `len`.
    let bytes = unsafe { std::slice::from_raw_parts_mut(msghdr.as_mut_ptr().cast::<u8>(), len) };
    target.read_exact(target_msg, bytes)?;
    let msghdr = unsafe { msghdr.assume_init() };
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| BrokerError::BadFileDescriptor)?;
    check_target_datagram_addr(
        &target,
        fd,
        msghdr.msg_name as usize,
        usize::try_from(msghdr.msg_namelen).unwrap_or(0),
        denials,
    )
}

pub(super) fn handle_sendmmsg(
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let target_msgvec =
        usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
    let vlen = usize::try_from(request.data.args[2]).map_err(|_| BrokerError::InvalidAddress)?;
    if target_msgvec == 0 || vlen == 0 {
        return Ok(NotificationResult::Continue);
    }
    let vlen = vlen.min(1024);
    let target = TargetProcess::from_raw(request.pid);
    let mut mmsgvec = vec![mem::MaybeUninit::<libc::mmsghdr>::uninit(); vlen];
    let total_len = vlen * mem::size_of::<libc::mmsghdr>();
    // SAFETY: mmsgvec has `vlen` elements (`total_len` bytes) of writable storage.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(mmsgvec.as_mut_ptr().cast::<u8>(), total_len) };
    target.read_exact(target_msgvec, bytes)?;
    let fd = RawFd::try_from(request.data.args[0]).map_err(|_| BrokerError::BadFileDescriptor)?;
    for mmsg in mmsgvec {
        let mmsg = unsafe { mmsg.assume_init() };
        let result = check_target_datagram_addr(
            &target,
            fd,
            mmsg.msg_hdr.msg_name as usize,
            usize::try_from(mmsg.msg_hdr.msg_namelen).unwrap_or(0),
            denials,
        )?;
        if !matches!(result, NotificationResult::Continue) {
            return Ok(result);
        }
    }
    Ok(NotificationResult::Continue)
}

#[derive(Clone, Copy)]
enum UnixSocketOp {
    Connect { proxy_available: bool },
    Bind,
}

impl UnixSocketOp {
    fn operation(self) -> NetworkOperation {
        match self {
            Self::Connect { .. } => NetworkOperation::Connect,
            Self::Bind => NetworkOperation::Bind,
        }
    }

    fn call(self) -> SocketAddrCall {
        match self {
            Self::Connect { .. } => libc::connect,
            Self::Bind => libc::bind,
        }
    }

    fn handle(
        self,
        policy: &AccessPolicy,
        pid: u32,
        mut socket: TargetSocket,
        denials: &mut Denials<'_>,
    ) -> SysResult<NotificationResult> {
        let process = TargetProcess::from_raw(pid);
        let operation = self.operation();
        let Some(path) = socket.unix_path() else {
            if matches!(
                policy.network_access.unix_socket_access(),
                UnixSocketAccess::Unrestricted
            ) {
                return Ok(match self {
                    Self::Connect { .. } => NotificationResult::Continue,
                    Self::Bind => NotificationResult::grant(socket.into_grant(libc::bind)),
                });
            }
            return denials.deny(
                Denial::Network(operation, "abstract".to_owned(), process.context()),
                false,
                None,
            );
        };
        let filesystem = process.filesystem()?;
        let (follow, missing) = match self {
            Self::Connect { .. } => (true, MissingTarget::Disallow),
            Self::Bind => (false, MissingTarget::File),
        };
        let target = filesystem.resolve(libc::AT_FDCWD, &path, follow, missing, 0)?;
        let anchor = target.anchor.ok_or(BrokerError::SystemCall {
            errno: libc::ENOENT,
        })?;
        let access = policy.unix_path_access(
            &target.label,
            anchor.target.as_ref().map(AsFd::as_fd),
            matches!(self, Self::Connect { .. }),
        );
        match access {
            UnixPathAccess::Supervisor => {
                log::debug!(
                    "service manager socket {operation:?} denied: {}",
                    target.label.display()
                );
                return Err(BrokerError::PolicyDenied);
            }
            UnixPathAccess::SessionBus { label, allowed } => {
                let Some(upstream) = anchor.target else {
                    return Err(BrokerError::PolicyDenied);
                };
                return self.handle_session_bus(
                    socket.sock,
                    upstream,
                    label,
                    allowed,
                    &process,
                    denials,
                );
            }
            UnixPathAccess::Allowed | UnixPathAccess::Denied => {}
        }
        if matches!(self, Self::Bind)
            && (policy.write_reason(&target.label, true).is_some()
                || policy
                    .write_denials
                    .is_denied_pair(&target.label, &target.lexical))
        {
            return denials.deny(
                Denial::Network(
                    operation,
                    target.label.to_string_lossy().into_owned(),
                    process.context(),
                ),
                false,
                None,
            );
        }
        match self {
            Self::Connect { .. } => {
                let object = anchor.target.as_ref().ok_or(BrokerError::InvalidAddress)?;
                socket.rewrite_unix_path(&ProcFd::new(object.as_fd()).proc_path())?;
            }
            Self::Bind => {
                let broker_path = anchor.path()?;
                socket.rewrite_unix_path(Path::new(OsStr::from_bytes(broker_path.as_bytes())))?;
            }
        }
        let grant = SocketGrant::new(socket.sock, socket.addr, self.call(), Some(anchor));
        if let UnixPathAccess::Denied = access {
            return denials.deny(
                Denial::Network(
                    operation,
                    target.label.to_string_lossy().into_owned(),
                    process.context(),
                ),
                true,
                Some(Grant::from(grant)),
            );
        }

        Ok(NotificationResult::grant(grant))
    }

    fn handle_session_bus(
        self,
        sock: OwnedFd,
        upstream: OwnedFd,
        label: &Path,
        allowed: bool,
        process: &TargetProcess,
        denials: &mut Denials<'_>,
    ) -> SysResult<NotificationResult> {
        if !matches!(
            self,
            Self::Connect {
                proxy_available: true
            }
        ) {
            log::warn!(
                "session bus connect denied (install xdg-dbus-proxy for keyring access): {}",
                label.display()
            );
            return Err(BrokerError::PolicyDenied);
        }
        let grant = SessionBusGrant::new(sock, upstream);
        if allowed {
            return Ok(NotificationResult::grant(grant));
        }
        if denials.can_query(true) {
            return denials.deny(
                Denial::Network(
                    self.operation(),
                    label.to_string_lossy().into_owned(),
                    process.context(),
                ),
                true,
                Some(Grant::from(grant)),
            );
        }
        log::debug!(
            "session bus connect denied without interactive broker: {}",
            label.display()
        );
        Err(BrokerError::PolicyDenied)
    }
}

impl SockAddrFamily {
    fn parse_ip(addr: &[u8], domain: i32) -> SysResult<SocketAddr> {
        match (domain, i32::from(Self::try_from(addr)?)) {
            (libc::AF_INET, libc::AF_INET) => {
                if addr.len() < mem::size_of::<libc::sockaddr_in>() {
                    return Err(BrokerError::InvalidAddress);
                }

                let port = u16::from_be_bytes([addr[2], addr[3]]);
                let ip = Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
                Ok(SocketAddr::from((ip, port)))
            }
            (libc::AF_INET6, libc::AF_INET6) => {
                if addr.len() < mem::size_of::<libc::sockaddr_in6>() {
                    return Err(BrokerError::InvalidAddress);
                }

                let port = u16::from_be_bytes([addr[2], addr[3]]);
                let ip = Ipv6Addr::from(
                    <[u8; 16]>::try_from(&addr[8..24]).map_err(|_| BrokerError::InvalidAddress)?,
                );
                Ok(SocketAddr::from((ip, port)))
            }
            _ => Err(BrokerError::AddressFamilyNotSupported),
        }
    }
}

impl TryFrom<&libc::seccomp_notif> for TargetSocket {
    type Error = BrokerError;

    fn try_from(request: &libc::seccomp_notif) -> SysResult<Self> {
        let fd =
            RawFd::try_from(request.data.args[0]).map_err(|_| BrokerError::BadFileDescriptor)?;
        let target_addr =
            usize::try_from(request.data.args[1]).map_err(|_| BrokerError::BadAddress)?;
        let addr_len =
            usize::try_from(request.data.args[2]).map_err(|_| BrokerError::InvalidAddress)?;

        if addr_len > mem::size_of::<libc::sockaddr_storage>() {
            return Err(BrokerError::InvalidAddress);
        }

        let target = TargetProcess::from_raw(request.pid);
        let addr = target.read_sockaddr(target_addr, addr_len)?;
        let sock = target.duplicate_fd(fd)?;
        let info = SocketInfo::try_from(sock.as_fd())?;

        Ok(Self { sock, addr, info })
    }
}
