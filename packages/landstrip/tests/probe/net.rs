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
