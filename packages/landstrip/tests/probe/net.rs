// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Jarkko Sakkinen

/// Re-exec probe: connect to a host-created abstract Unix socket. Exit 0 when
/// Landlock denies the connect (EPERM/EACCES), 1 when it unexpectedly succeeds.
#[cfg(target_os = "linux")]
pub fn abstract_connect_probe(name: Option<std::ffi::OsString>) -> i32 {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};

    let Some(name) = name else {
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
pub fn abstract_connect_probe(_name: Option<std::ffi::OsString>) -> i32 {
    2
}

#[cfg(target_os = "macos")]
pub fn route_socket_probe() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return 1;
    }
    unsafe { libc::close(fd) };
    0
}

#[cfg(not(target_os = "macos"))]
pub fn route_socket_probe() -> i32 {
    2
}

pub fn udp_bind_probe() -> i32 {
    match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

pub fn udp_local_probe() -> i32 {
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

pub fn udp_remote_probe() -> i32 {
    let socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    match socket.send_to(b"test", "8.8.8.8:53") {
        Ok(_) => 1,
        Err(_) => 0,
    }
}
