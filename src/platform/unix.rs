// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Shared Unix helpers.

use std::io;
use std::os::fd::RawFd;

/// Mark a descriptor close-on-exec.
pub(crate) fn set_cloexec(fd: RawFd) -> io::Result<()> {
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
