// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Shared Unix helpers.

use std::io;
use std::os::fd::RawFd;

#[cfg(target_os = "macos")]
const FIRST_INHERITED_FD: RawFd = 3;

/// Close every descriptor the launcher left open so the tool cannot reach them.
///
/// An inherited descriptor is writable regardless of the sandbox profile.
/// Excluded descriptors are marked close-on-exec instead: they survive long
/// enough to report an `exec` that never happened, and the kernel drops them
/// the instant the tool starts.
pub(crate) fn close_inherited_fds(excluded: &[RawFd]) -> io::Result<()> {
    for &fd in excluded {
        set_cloexec(fd)?;
    }

    close_inherited_except(excluded)
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

#[cfg(target_os = "linux")]
fn close_inherited_except(excluded: &[RawFd]) -> io::Result<()> {
    const FIRST: u32 = 3;

    let mut excluded: Vec<u32> = excluded
        .iter()
        .filter_map(|fd| u32::try_from(*fd).ok())
        .filter(|fd| *fd >= FIRST)
        .collect();
    excluded.sort_unstable();
    excluded.dedup();

    let mut first = Some(FIRST);
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
fn close_inherited_except(excluded: &[RawFd]) -> io::Result<()> {
    const FALLBACK_FD_LIMIT: RawFd = 1_048_576;

    if let Ok(entries) = std::fs::read_dir("/dev/fd") {
        let mut fds: Vec<RawFd> = entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse::<RawFd>().ok())
            .filter(|&fd| fd >= FIRST_INHERITED_FD)
            .collect();

        fds.sort_unstable();
        for fd in fds {
            close_fd(fd, excluded);
        }
        return Ok(());
    }

    for fd in FIRST_INHERITED_FD..open_fd_limit(FALLBACK_FD_LIMIT) {
        close_fd(fd, excluded);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn open_fd_limit(fallback: RawFd) -> RawFd {
    let limit = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if limit < i64::from(FIRST_INHERITED_FD) {
        return fallback;
    }
    RawFd::try_from(limit).map_or(fallback, |limit| limit.min(fallback))
}

#[cfg(target_os = "macos")]
fn close_fd(fd: RawFd, excluded: &[RawFd]) {
    if fd >= FIRST_INHERITED_FD && !excluded.contains(&fd) {
        unsafe { libc::close(fd) };
    }
}
