// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::Probe;

/// Re-exec probe: connect to a host-created abstract Unix socket. Exit 0 when
/// Landlock denies the connect (EPERM/EACCES), 1 when it unexpectedly succeeds.
pub struct AbstractConnect;

impl Probe for AbstractConnect {
    #[cfg(target_os = "linux")]
    fn run(&self, args: &mut std::env::ArgsOs) -> i32 {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::{SocketAddr, UnixStream};

        let Some(name) = args.next() else {
            return 2;
        };
        let Ok(addr) = SocketAddr::from_abstract_name(name.as_bytes()) else {
            return 2;
        };
        match UnixStream::connect_addr(&addr) {
            Ok(_) => 1,
            Err(error) => match error.raw_os_error() {
                Some(libc::EACCES | libc::EPERM) => 0,
                _ => 2,
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

pub struct UnixConnect;

impl Probe for UnixConnect {
    #[cfg(unix)]
    fn run(&self, args: &mut std::env::ArgsOs) -> i32 {
        use std::os::unix::net::UnixStream;

        let Some(path) = args.next() else {
            return 2;
        };
        match UnixStream::connect(path) {
            Ok(_) => 1,
            Err(error) => match error.raw_os_error() {
                Some(libc::EACCES) => 0,
                #[cfg(target_os = "macos")]
                Some(libc::EPERM) => 0,
                _ => 2,
            },
        }
    }

    #[cfg(not(unix))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

/// Re-exec probe: bind a Unix socket. Exit 0 when the sandbox denies the bind,
/// 1 when it unexpectedly succeeds.
pub struct UnixBind;

impl Probe for UnixBind {
    #[cfg(unix)]
    fn run(&self, args: &mut std::env::ArgsOs) -> i32 {
        use std::os::unix::net::UnixListener;

        let Some(path) = args.next() else {
            return 2;
        };
        match UnixListener::bind(path) {
            Ok(_) => 1,
            Err(error) => match error.raw_os_error() {
                Some(libc::EACCES | libc::EPERM) => 0,
                _ => 2,
            },
        }
    }

    #[cfg(not(unix))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

pub struct RouteSocket;

impl Probe for RouteSocket {
    #[cfg(target_os = "macos")]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        let fd = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return 1;
        }
        unsafe { libc::close(fd) };
        0
    }

    #[cfg(not(target_os = "macos"))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

pub struct UdpBind;

impl Probe for UdpBind {
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(_) => 0,
            Err(_) => 1,
        }
    }
}

pub struct UdpLocal;

impl Probe for UdpLocal {
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        let server = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => return 1,
        };
        let addr = match server.local_addr() {
            Ok(a) => a,
            Err(_) => return 2,
        };
        let client = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => return 3,
        };
        if client.connect(addr).is_err() {
            return 4;
        }
        if client.send(b"ping").is_err() {
            return 5;
        }
        let mut buf = [0u8; 16];
        match server.recv_from(&mut buf) {
            Ok((len, _)) if &buf[..len] == b"ping" => {}
            _ => return 6,
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let unspec = libc::sockaddr {
                sa_family: libc::AF_UNSPEC as libc::sa_family_t,
                sa_data: [0; 14],
            };
            let res = unsafe {
                libc::connect(
                    client.as_raw_fd(),
                    &unspec as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
                )
            };
            if res != 0 {
                return 7;
            }
        }
        0
    }
}

pub struct UdpRemote;

impl Probe for UdpRemote {
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        let socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => return 0,
        };
        match socket.send_to(b"test", "8.8.8.8:53") {
            Ok(_) => 1,
            Err(_) => 0,
        }
    }
}
