// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! File descriptor cleanup before executing the sandboxed tool.
//!
//! Descriptors above stdio are closed so ambient inherited handles do not bypass
//! the sandbox.

use std::io;
use std::os::fd::RawFd;

const FIRST_INHERITED_FD_U32: u32 = 3;

pub(super) fn close_inherited_fds(excluded: &[RawFd]) -> io::Result<()> {
    for &fd in excluded {
        set_cloexec(fd)?;
    }

    close_inherited_ranges(excluded)
}

fn close_inherited_ranges(excluded: &[RawFd]) -> io::Result<()> {
    let mut excluded: Vec<u32> = excluded
        .iter()
        .filter_map(|fd| u32::try_from(*fd).ok())
        .filter(|fd| *fd >= FIRST_INHERITED_FD_U32)
        .collect();
    excluded.sort_unstable();
    excluded.dedup();

    let mut first = Some(FIRST_INHERITED_FD_U32);
    for fd in excluded {
        let Some(start) = first else {
            break;
        };
        if start < fd {
            close_range(start, fd - 1)?;
        }
        first = fd.checked_add(1);
    }

    if let Some(start) = first {
        close_range(start, u32::MAX)?;
    }
    Ok(())
}

fn close_range(first: u32, last: u32) -> io::Result<()> {
    // SAFETY: close_range(2) copies scalar arguments only and closes descriptors
    // in this process.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0_u32) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl(2) copies scalar arguments only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: fcntl(2) copies scalar arguments only.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reads an integer-valued socket option via `getsockopt(2)`.
pub(crate) fn getsockopt_int(fd: i32, level: i32, name: i32) -> std::io::Result<i32> {
    // SAFETY: getsockopt writes a scalar into value; len bounds the storage.
    let mut value: i32 = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of_val(&value)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket option size exceeds socklen_t",
        )
    })?;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(value)
    }
}
