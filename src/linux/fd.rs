// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! File descriptor cleanup before executing the sandboxed tool.
//!
//! Descriptors above stdio are closed so ambient inherited handles do not bypass
//! the sandbox.

use nix::errno::Errno;
use std::fs;
use std::os::fd::RawFd;

const FIRST_INHERITED_FD: RawFd = 3;
const FIRST_INHERITED_FD_U32: u32 = 3;
const FALLBACK_FD_LIMIT: RawFd = 1_048_576;

pub(super) fn close_inherited_fds() {
    // SAFETY: close_range(2) copies scalar arguments and closes descriptors in this process.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            FIRST_INHERITED_FD_U32,
            u32::MAX,
            0_u32,
        )
    };
    if rc == 0 {
        return;
    }

    match Errno::last() {
        Errno::ENOSYS | Errno::EINVAL => {}
        error => log::debug!("fd cleanup: close_range errno={}", error as i32),
    }

    match fs::read_dir("/proc/self/fd") {
        Ok(entries) => {
            let mut entries = entries;
            let mut fds = Vec::new();

            for entry in &mut entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        log::debug!("fd cleanup: proc entry: {error}");
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

                if fd >= FIRST_INHERITED_FD {
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

                return;
            }
        }
        Err(error) => log::debug!("fd cleanup: open /proc/self/fd: {error}"),
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
        close_fd(fd);
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
        log::debug!("fd cleanup: close({fd}) errno={}", error as i32);
    }
}
