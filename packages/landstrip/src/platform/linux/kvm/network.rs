// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Network policy mediation for the syscall broker.
//!
//! Endpoints are decoded from the guest socket address and checked against the
//! policy before the broker forwards `bind` or `connect`. Unix socket paths are
//! resolved through the filesystem policy, so a bind also needs a write grant.

use super::policy::Policy;
use crate::policy::{UnixPathAccess, UnixSocketAccess};
use crate::trap::NetworkOperation;
use socket2::{SockAddr, SockRef};
use std::ffi::{CString, OsStr};
use std::mem;
use std::net::SocketAddr;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const SOCK_TYPE_MASK: i32 = 0xf;

pub(crate) struct NetworkDenial {
    pub(crate) operation: NetworkOperation,
    pub(crate) target: String,
    pub(crate) queryable: bool,
}

/// What the broker does with a socket operation.
pub(crate) enum Verdict {
    /// The policy grants the operation; `pinned` holds an `O_PATH` descriptor
    /// for Unix `connect` so the target inode cannot change across queries.
    Allow {
        pinned: Option<super::fds::BrokerFd>,
    },
    /// User D-Bus session socket filtered through `xdg-dbus-proxy`.
    SessionBus {
        upstream: super::fds::BrokerFd,
        target: String,
        allowed: bool,
    },
    /// The operation fails with `errno`, reported when `denial` is set.
    Refuse {
        errno: i32,
        denial: Option<NetworkDenial>,
        pinned: Option<super::fds::BrokerFd>,
    },
}

/// A socket address family decoded from the leading field.
#[derive(Clone, Copy)]
struct Family(libc::sa_family_t);

/// The socket a guest descriptor refers to.
#[derive(Clone, Copy)]
pub(crate) struct Info {
    domain: i32,
    ty: i32,
    proto: i32,
}

/// Sockets the policy has something to say about.
#[derive(Clone, Copy)]
enum Kind {
    Tcp,
    Udp,
    Unix,
    Unsupported,
}

impl Info {
    pub(crate) fn new(domain: i32, ty: i32, proto: i32) -> Self {
        Self {
            domain,
            ty: ty & SOCK_TYPE_MASK,
            proto,
        }
    }

    /// Refuses a socket the network policy cannot mediate with `EAFNOSUPPORT`.
    pub(crate) fn admit(self, policy: &Policy) -> std::result::Result<(), i32> {
        let network = &policy.rules().network_access;
        match self.kind() {
            _ if network.is_unrestricted() => Ok(()),
            Kind::Udp if !network.allows_local_binding() => Err(libc::EAFNOSUPPORT),
            Kind::Unsupported => Err(libc::EAFNOSUPPORT),
            Kind::Tcp | Kind::Udp | Kind::Unix => Ok(()),
        }
    }
    fn from_fd(descriptor: RawFd) -> Option<Self> {
        let borrowed = unsafe { BorrowedFd::borrow_raw(descriptor) };
        let socket = SockRef::from(&borrowed);
        Some(Self {
            domain: socket.domain().ok()?.into(),
            ty: socket.r#type().ok()?.into(),
            proto: socket.protocol().ok()?.map_or(0, i32::from),
        })
    }

    fn kind(self) -> Kind {
        let ip = matches!(self.domain, libc::AF_INET | libc::AF_INET6);
        let tcp = self.proto == libc::IPPROTO_TCP || self.proto == 0;
        let udp = self.proto == libc::IPPROTO_UDP || self.proto == 0;
        if ip && self.ty == libc::SOCK_STREAM && tcp {
            Kind::Tcp
        } else if ip && self.ty == libc::SOCK_DGRAM && udp {
            Kind::Udp
        } else if self.domain == libc::AF_UNIX {
            Kind::Unix
        } else {
            Kind::Unsupported
        }
    }
}

impl Kind {
    fn endpoint(self, address: &[u8]) -> std::result::Result<Option<SocketAddr>, i32> {
        let family = Family::try_from(address)?;
        if matches!(self, Self::Udp) && i32::from(family.0) == libc::AF_UNSPEC {
            return Ok(None);
        }
        let min_len = match (i32::from(family.0), self) {
            (libc::AF_INET, Self::Tcp | Self::Udp) => mem::size_of::<libc::sockaddr_in>(),
            (libc::AF_INET6, Self::Tcp | Self::Udp) => mem::size_of::<libc::sockaddr_in6>(),
            _ => return Err(libc::EAFNOSUPPORT),
        };
        if address.len() < min_len {
            return Err(libc::EINVAL);
        }
        let copy_len = address.len().min(mem::size_of::<libc::sockaddr_storage>());
        let ((), sockaddr) = unsafe {
            SockAddr::try_init(|storage, len| {
                std::ptr::copy_nonoverlapping(address.as_ptr(), storage.cast::<u8>(), copy_len);
                *len = libc::socklen_t::try_from(copy_len).unwrap_or(0);
                Ok(())
            })
        }
        .map_err(|_| libc::EINVAL)?;
        sockaddr.as_socket().map(Some).ok_or(libc::EINVAL)
    }
}

impl Verdict {
    const fn allow() -> Self {
        Self::Allow { pinned: None }
    }

    pub(crate) fn mediate(
        policy: &Policy,
        descriptor: RawFd,
        operation: NetworkOperation,
        address: &[u8],
    ) -> Self {
        let Some(info) = Info::from_fd(descriptor) else {
            return Self::Refuse {
                errno: libc::EBADF,
                denial: None,
                pinned: None,
            };
        };
        let rules = policy.rules();
        let network = &rules.network_access;
        match info.kind() {
            Kind::Unsupported if network.is_unrestricted() => Self::allow(),
            Kind::Unsupported => Self::Refuse {
                errno: libc::EAFNOSUPPORT,
                denial: None,
                pinned: None,
            },
            Kind::Unix => Self::unix(policy, operation, address),
            Kind::Tcp | Kind::Udp => Self::internet(policy, info.kind(), operation, address),
        }
    }

    pub(crate) fn mediate_datagram(policy: &Policy, descriptor: RawFd, address: &[u8]) -> Self {
        if address.is_empty() {
            return Self::allow();
        }
        let Some(info) = Info::from_fd(descriptor) else {
            return Self::Refuse {
                errno: libc::EBADF,
                denial: None,
                pinned: None,
            };
        };
        match info.kind() {
            kind @ (Kind::Tcp | Kind::Udp) => {
                Self::internet(policy, kind, NetworkOperation::Connect, address)
            }
            Kind::Unix => Self::unix(policy, NetworkOperation::Connect, address),
            Kind::Unsupported if policy.rules().network_access.is_unrestricted() => Self::allow(),
            Kind::Unsupported => {
                Self::refuse(libc::EAFNOSUPPORT, NetworkOperation::Connect, None, false)
            }
        }
    }

    fn internet(policy: &Policy, kind: Kind, operation: NetworkOperation, address: &[u8]) -> Self {
        let network = &policy.rules().network_access;
        if network.is_unrestricted() {
            return Self::allow();
        }
        let endpoint = match kind.endpoint(address) {
            Ok(Some(endpoint)) => endpoint,
            Ok(None) => return Self::allow(),
            Err(errno) => return Self::refuse(errno, operation, None, false),
        };
        let loopback = endpoint.ip().to_canonical().is_loopback();
        let local = network.allows_local_binding();
        let allowed = match (operation, kind) {
            (NetworkOperation::Connect, Kind::Tcp) => {
                loopback && (local || network.connect_tcp_ports().contains(&endpoint.port()))
            }
            (NetworkOperation::Bind | NetworkOperation::Connect, _) => local && loopback,
        };
        if allowed {
            Self::allow()
        } else {
            Self::refuse(libc::EACCES, operation, Some(endpoint.to_string()), true)
        }
    }

    fn unix(policy: &Policy, operation: NetworkOperation, address: &[u8]) -> Self {
        let family = match Family::try_from(address) {
            Ok(family) => i32::from(family.0),
            Err(errno) => {
                return Self::Refuse {
                    errno,
                    denial: None,
                    pinned: None,
                };
            }
        };
        if family == libc::AF_UNSPEC && matches!(operation, NetworkOperation::Connect) {
            return Self::allow();
        }
        if family != libc::AF_UNIX {
            return Self::Refuse {
                errno: libc::EINVAL,
                denial: None,
                pinned: None,
            };
        }
        let unrestricted = matches!(
            policy.rules().network_access.unix_socket_access(),
            UnixSocketAccess::Unrestricted
        );
        match UnixTarget::from(address) {
            UnixTarget::Path(path) => Self::unix_path(policy, operation, &path),
            UnixTarget::Unnamed => {
                if unrestricted && matches!(operation, NetworkOperation::Bind) {
                    Self::allow()
                } else if matches!(operation, NetworkOperation::Connect) {
                    Self::Refuse {
                        errno: libc::EINVAL,
                        denial: None,
                        pinned: None,
                    }
                } else {
                    Self::refuse(libc::EACCES, operation, Some("abstract".to_owned()), false)
                }
            }
            UnixTarget::Abstract(name) => {
                if !unrestricted {
                    return Self::refuse(
                        libc::EACCES,
                        operation,
                        Some("abstract".to_owned()),
                        false,
                    );
                }
                match operation {
                    NetworkOperation::Bind => {
                        policy.record_abstract_socket(name);
                        Self::allow()
                    }
                    NetworkOperation::Connect if policy.owns_abstract_socket(name) => Self::allow(),
                    NetworkOperation::Connect => {
                        Self::refuse(libc::EACCES, operation, Some("abstract".to_owned()), false)
                    }
                }
            }
        }
    }

    fn unix_path(policy: &Policy, operation: NetworkOperation, path: &Path) -> Self {
        let connect = matches!(operation, NetworkOperation::Connect);
        let Some(resolved) = policy.resolved(i64::from(libc::AT_FDCWD), path, connect) else {
            return Self::refuse(
                libc::EACCES,
                operation,
                Some(path.to_string_lossy().into_owned()),
                false,
            );
        };
        let label = resolved.label;
        let lexical = resolved.lexical;
        let target_fd = match Self::open_path_fd(&label) {
            Ok(fd) => Some(fd),
            Err(errno) if connect => {
                return Self::Refuse {
                    errno,
                    denial: None,
                    pinned: None,
                };
            }
            Err(_) => None,
        };
        let access =
            policy
                .rules()
                .unix_path_access(&label, target_fd.as_ref().map(AsFd::as_fd), connect);
        match access {
            UnixPathAccess::Allowed | UnixPathAccess::Denied => {}
            UnixPathAccess::SessionBus {
                label: bus_label,
                allowed,
            } if connect => {
                let target = bus_label.to_string_lossy().into_owned();
                return match target_fd {
                    Some(upstream) => Self::SessionBus {
                        upstream,
                        target,
                        allowed,
                    },
                    None => Self::Refuse {
                        errno: libc::EACCES,
                        denial: None,
                        pinned: None,
                    },
                };
            }
            UnixPathAccess::Supervisor | UnixPathAccess::SessionBus { .. } => {
                return Self::Refuse {
                    errno: libc::EACCES,
                    denial: None,
                    pinned: None,
                };
            }
        }
        if !connect {
            let rules = policy.rules();
            if rules.write_reason(&label, true).is_some()
                || rules.write_denials.is_denied_pair(&label, &lexical)
            {
                return Self::refuse(
                    libc::EACCES,
                    operation,
                    Some(label.to_string_lossy().into_owned()),
                    false,
                );
            }
        }
        if matches!(access, UnixPathAccess::Denied) {
            return Self::Refuse {
                errno: libc::EACCES,
                denial: Some(NetworkDenial {
                    operation,
                    target: label.to_string_lossy().into_owned(),
                    queryable: true,
                }),
                pinned: connect.then_some(target_fd).flatten(),
            };
        }
        Self::Allow {
            pinned: connect.then_some(target_fd).flatten(),
        }
    }

    fn refuse(
        errno: i32,
        operation: NetworkOperation,
        target: Option<String>,
        queryable: bool,
    ) -> Self {
        Self::Refuse {
            errno,
            denial: target.map(|target| NetworkDenial {
                operation,
                target,
                queryable,
            }),
            pinned: None,
        }
    }

    fn open_path_fd(path: &Path) -> std::result::Result<super::fds::BrokerFd, i32> {
        let cpath = CString::new(OsStr::as_bytes(path.as_os_str())).map_err(|_| libc::EINVAL)?;
        let _fd_lock = super::fds::GuestFd::read_fd_table();
        let raw = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ENOENT));
        }
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        super::fds::GuestFd::relocate_above(owned)
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EMFILE))
    }
}

impl TryFrom<&[u8]> for Family {
    type Error = i32;

    fn try_from(address: &[u8]) -> std::result::Result<Self, i32> {
        let bytes = address
            .get(..mem::size_of::<libc::sa_family_t>())
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or(libc::EINVAL)?;
        Ok(Self(libc::sa_family_t::from_ne_bytes(bytes)))
    }
}

enum UnixTarget<'a> {
    Path(PathBuf),
    Abstract(&'a [u8]),
    Unnamed,
}

impl<'a> From<&'a [u8]> for UnixTarget<'a> {
    fn from(address: &'a [u8]) -> Self {
        let offset = mem::size_of::<libc::sa_family_t>();
        let Some(path) = address.get(offset..) else {
            return Self::Unnamed;
        };
        let Some(&first) = path.first() else {
            return Self::Unnamed;
        };
        if first == 0 {
            return Self::Abstract(&path[1..]);
        }
        let end = path
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(path.len());
        if end == 0 {
            return Self::Unnamed;
        }
        Self::Path(PathBuf::from(OsStr::from_bytes(&path[..end])))
    }
}
