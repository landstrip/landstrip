// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! File descriptor cleanup before executing the sandboxed tool.
//!
//! Descriptors above stdio are closed so ambient inherited handles do not bypass
//! the sandbox.

use nix::errno::Errno;
use std::fs;
use std::io;
use std::os::fd::RawFd;

const FIRST_INHERITED_FD: RawFd = 3;
const FIRST_INHERITED_FD_U32: u32 = 3;
const FALLBACK_FD_LIMIT: RawFd = 1_048_576;

pub(super) fn close_inherited_fds(excluded: &[RawFd]) -> io::Result<()> {
    for &fd in excluded {
        set_cloexec(fd)?;
    }

    if excluded.is_empty() {
        // SAFETY: close_range(2) copies scalar arguments only and closes
        // descriptors in this process.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                FIRST_INHERITED_FD_U32,
                u32::MAX,
                0_u32,
            )
        };
        if rc == 0 {
            return Ok(());
        }

        match Errno::last() {
            Errno::ENOSYS | Errno::EINVAL => {}
            error => log::debug!("fd: close_range errno={}", error as i32),
        }
    }

    match fs::read_dir("/proc/self/fd") {
        Ok(entries) => {
            let mut entries = entries;
            let mut fds = Vec::new();

            for entry in &mut entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        log::debug!("fd: proc entry: {error}");
                        fds.clear();
                        break;
                    }
                };

                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                let Ok(fd) = name.parse::<RawFd>() else {
                    continue;
                };

                if fd >= FIRST_INHERITED_FD && !excluded.contains(&fd) {
                    fds.push(fd);
                }
            }

            drop(entries);

            if !fds.is_empty() {
                fds.sort_unstable();
                fds.dedup();
                for fd in fds {
                    close_fd(fd);
                }
                return Ok(());
            }
        }
        Err(error) => log::debug!("fd: open /proc/self/fd: {error}"),
    }

    let mut rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let mut limit = FALLBACK_FD_LIMIT;

    // SAFETY: rlimit points to initialized writable storage for getrlimit(2).
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlimit) };
    if rc == 0 {
        if let Ok(fallback) = libc::rlim_t::try_from(FALLBACK_FD_LIMIT) {
            if let Ok(capped) = RawFd::try_from(rlimit.rlim_cur.min(fallback)) {
                limit = capped;
            }
        }
    }

    for fd in FIRST_INHERITED_FD..limit {
        if !excluded.contains(&fd) {
            close_fd(fd);
        }
    }
    Ok(())
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
    #[allow(clippy::cast_possible_truncation)]
    let mut len: libc::socklen_t = std::mem::size_of_val(&value) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&raw mut value).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

fn close_fd(fd: RawFd) {
    if fd < FIRST_INHERITED_FD {
        return;
    }

    // SAFETY: close(2) copies the scalar file descriptor argument.
    let rc = unsafe { libc::close(fd) };
    if rc == 0 {
        return;
    }

    let error = Errno::last();
    if error != Errno::EBADF {
        log::debug!("fd: close fd={fd} errno={}", error as i32);
    }
}
