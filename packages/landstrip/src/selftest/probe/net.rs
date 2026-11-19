// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::{OsResult, ProbeError, ProbeResult};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetProbe {
    TcpBind,
    TcpConnect {
        addr: SocketAddr,
    },
    #[cfg(target_os = "linux")]
    TcpFastOpen {
        addr: SocketAddr,
    },
    UdpBind,
    #[cfg(target_os = "linux")]
    Netlink,
    UdpLoopbackEcho,
    UdpSend {
        addr: SocketAddrV4,
    },
    UdpMsghdr,
    UnixBind {
        path: PathBuf,
    },
    UnixConnect {
        path: PathBuf,
    },
    UnixSendTo {
        path: PathBuf,
    },
    #[cfg(target_os = "linux")]
    AbstractConnect {
        name: String,
    },
}

impl NetProbe {
    const LOOPBACK: &str = "127.0.0.1:0";

    pub fn run(&self) -> ProbeResult {
        match self {
            Self::TcpBind => {
                TcpListener::bind(Self::LOOPBACK).map_err(ProbeError::Denied)?;
                Ok(())
            }
            Self::TcpConnect { addr } => {
                TcpStream::connect_timeout(addr, Duration::from_secs(3))
                    .map_err(ProbeError::Denied)?
                    .write_all(b"ping")?;
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::TcpFastOpen { addr } => {
                use socket2::{Domain, Socket, Type};
                Socket::new(Domain::for_address(*addr), Type::STREAM, None)?
                    .send_to_with_flags(b"ping", &(*addr).into(), libc::MSG_FASTOPEN)
                    .map_err(ProbeError::denied_on(&[libc::EACCES, libc::EPERM]))?;
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::Netlink => {
                use std::os::fd::{FromRawFd, OwnedFd};
                let fd = unsafe {
                    libc::socket(
                        libc::AF_NETLINK,
                        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                        libc::NETLINK_ROUTE,
                    )
                }
                .os_result()
                .map_err(ProbeError::denied_on(&[libc::EAFNOSUPPORT]))?;
                drop(unsafe { OwnedFd::from_raw_fd(fd) });
                Ok(())
            }
            Self::UdpBind => {
                UdpSocket::bind(Self::LOOPBACK).map_err(ProbeError::denied_on(&[
                    libc::EACCES,
                    libc::EPERM,
                    libc::EAFNOSUPPORT,
                ]))?;
                Ok(())
            }
            Self::UdpLoopbackEcho => Self::udp_loopback_echo(),
            Self::UdpSend { addr } => Self::udp_send(*addr),
            Self::UdpMsghdr => Self::udp_msghdr(),
            Self::UnixBind { path } => Self::unix_bind(path),
            Self::UnixConnect { path } => {
                UnixStream::connect(path)
                    .map_err(ProbeError::Denied)?
                    .write_all(b"unix-hi")?;
                Ok(())
            }
            Self::UnixSendTo { path } => {
                UnixDatagram::unbound()?
                    .send_to(b"unix-dg", path)
                    .map_err(ProbeError::denied_on(&[libc::EACCES, libc::EPERM]))?;
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::AbstractConnect { name } => {
                use std::os::linux::net::SocketAddrExt;
                let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
                UnixStream::connect_addr(&addr).map_err(ProbeError::denied_on(&[
                    libc::ECONNREFUSED,
                    libc::EACCES,
                    libc::EPERM,
                    libc::EAFNOSUPPORT,
                ]))?;
                Ok(())
            }
        }
    }

    fn udp_loopback_echo() -> ProbeResult {
        let rx = UdpSocket::bind(Self::LOOPBACK).map_err(ProbeError::Denied)?;
        let tx = UdpSocket::bind(Self::LOOPBACK).map_err(ProbeError::Denied)?;
        rx.set_read_timeout(Some(Duration::from_secs(2)))?;
        tx.send_to(b"udp-ok", rx.local_addr()?)
            .map_err(ProbeError::Denied)?;
        let mut buf = [0_u8; 16];
        let (len, _) = rx.recv_from(&mut buf).map_err(ProbeError::Denied)?;
        if buf.get(..len) != Some(b"udp-ok".as_slice()) {
            return Err(ProbeError::broken("loopback UDP payload mismatch"));
        }
        Ok(())
    }

    fn sockaddr_in(addr: SocketAddrV4) -> io::Result<libc::sockaddr_in> {
        let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        raw.sin_family = libc::sa_family_t::try_from(libc::AF_INET).map_err(io::Error::other)?;
        raw.sin_port = addr.port().to_be();
        raw.sin_addr.s_addr = u32::from_ne_bytes(addr.ip().octets());
        Ok(raw)
    }

    fn udp_send(addr: SocketAddrV4) -> ProbeResult {
        use std::os::fd::{FromRawFd, OwnedFd};
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) }.os_result()?;
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let dst = Self::sockaddr_in(addr)?;
        let payload = b"probe";
        unsafe {
            libc::sendto(
                std::os::fd::AsRawFd::as_raw_fd(&socket),
                payload.as_ptr().cast(),
                payload.len(),
                0,
                (&raw const dst).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>())
                    .map_err(io::Error::other)?,
            )
        }
        .os_result()
        .map_err(ProbeError::denied_on(&[libc::EACCES, libc::EPERM]))?;
        Ok(())
    }

    fn unix_bind(path: &Path) -> ProbeResult {
        let _ = std::fs::remove_file(path);
        let bound = UnixListener::bind(path);
        let _ = std::fs::remove_file(path);
        bound.map_err(ProbeError::Denied)?;
        Ok(())
    }

    fn udp_msghdr() -> ProbeResult {
        use std::os::fd::AsRawFd;
        const PEEK_FLAGS: i32 = 0x55;
        const SEND_FLAGS: i32 = 0x40;

        let rx = UdpSocket::bind(Self::LOOPBACK)?;
        let tx = UdpSocket::bind(Self::LOOPBACK)?;
        rx.set_nonblocking(true)?;
        let SocketAddr::V4(dst) = rx.local_addr()? else {
            return Err(ProbeError::broken("loopback socket is not IPv4"));
        };
        let raw_dst = Self::sockaddr_in(dst)?;
        let (head, tail) = (*b"abc", *b"defgh");
        let mut send_iov = [
            libc::iovec {
                iov_base: head.as_ptr().cast_mut().cast(),
                iov_len: head.len(),
            },
            libc::iovec {
                iov_base: tail.as_ptr().cast_mut().cast(),
                iov_len: tail.len(),
            },
        ];
        let mut send_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        send_hdr.msg_name = (&raw const raw_dst).cast_mut().cast();
        send_hdr.msg_namelen = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>())
            .map_err(io::Error::other)?;
        send_hdr.msg_iov = send_iov.as_mut_ptr();
        send_hdr.msg_iovlen = 2;
        send_hdr.msg_flags = SEND_FLAGS;

        let mut empty_buf = [0_u8; 4];
        let mut empty_iov = [libc::iovec {
            iov_base: empty_buf.as_mut_ptr().cast(),
            iov_len: empty_buf.len(),
        }];
        let mut empty_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        empty_hdr.msg_iov = empty_iov.as_mut_ptr();
        empty_hdr.msg_iovlen = 1;
        empty_hdr.msg_flags = PEEK_FLAGS;
        let empty =
            unsafe { libc::recvmsg(rx.as_raw_fd(), &raw mut empty_hdr, libc::MSG_DONTWAIT) };
        if empty != -1 || empty_hdr.msg_flags != PEEK_FLAGS {
            return Err(ProbeError::broken(
                "empty recvmsg did not fail or clobbered msg_flags",
            ));
        }

        let sent = unsafe { libc::sendmsg(tx.as_raw_fd(), &raw const send_hdr, 0) }.os_result()?;
        if sent != 8 || send_hdr.msg_flags != SEND_FLAGS {
            return Err(ProbeError::broken(
                "sendmsg short write or clobbered msg_flags",
            ));
        }

        rx.set_nonblocking(false)?;
        rx.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut short_buf = [0_u8; 4];
        let mut recv_iov = [libc::iovec {
            iov_base: short_buf.as_mut_ptr().cast(),
            iov_len: short_buf.len(),
        }];
        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut recv_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        recv_hdr.msg_name = (&raw mut peer).cast();
        recv_hdr.msg_namelen =
            libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
                .map_err(io::Error::other)?;
        recv_hdr.msg_iov = recv_iov.as_mut_ptr();
        recv_hdr.msg_iovlen = 1;
        let got = unsafe { libc::recvmsg(rx.as_raw_fd(), &raw mut recv_hdr, libc::MSG_TRUNC) }
            .os_result()?;
        if got != 8
            || &short_buf != b"abcd"
            || (recv_hdr.msg_flags & libc::MSG_TRUNC) == 0
            || recv_hdr.msg_namelen == 0
        {
            return Err(ProbeError::broken(
                "truncated recvmsg returned wrong length, data, flags or peer",
            ));
        }
        Ok(())
    }
}
