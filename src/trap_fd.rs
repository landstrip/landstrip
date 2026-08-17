// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Separate file descriptor for landstrip trap response blocks.

use crate::trap::Trap;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

#[derive(Debug)]
pub(crate) struct TrapFd(OwnedFd);

impl From<OwnedFd> for TrapFd {
    fn from(fd: OwnedFd) -> Self {
        Self(fd)
    }
}

impl AsFd for TrapFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for TrapFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl TrapFd {
    #[cfg(target_os = "linux")]
    pub(crate) fn is_socket(&self) -> bool {
        crate::platform::fd::getsockopt_int(self.as_raw_fd(), libc::SOL_SOCKET, libc::SO_TYPE)
            .is_ok()
    }

    pub(crate) fn write(&self, trap: &Trap) {
        self.write_json(&trap.to_string());
    }

    pub(crate) fn write_json(&self, json: &str) {
        let mut line = json.to_owned();
        line.push('\n');

        #[cfg(target_os = "linux")]
        if self.is_socket() {
            write_socket_trap_fd(self.as_raw_fd(), line.as_bytes());
            return;
        }

        write_nonblocking_trap_fd(self.as_raw_fd(), line.as_bytes());
    }
}

#[cfg(target_os = "linux")]
fn write_socket_trap_fd(fd: i32, line: &[u8]) {
    // SAFETY: send(2) reads the live slice pointer and does not retain it.
    let written = unsafe {
        libc::send(
            fd,
            line.as_ptr().cast(),
            line.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    log_short_write(fd, line.len(), written);
}

fn write_nonblocking_trap_fd(fd: i32, line: &[u8]) {
    if line.len() > libc::PIPE_BUF {
        log::debug!("trap: dropping fd={fd} record larger than PIPE_BUF");
        return;
    }

    // SAFETY: fcntl(2) only reads the scalar file descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        log_fd_error("get flags", fd);
        return;
    }

    let restore_flags = flags & libc::O_NONBLOCK == 0;
    if restore_flags {
        // SAFETY: fcntl(2) only reads scalar arguments.
        let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if result < 0 {
            log_fd_error("set nonblocking", fd);
            return;
        }
    }

    // SAFETY: write(2) reads the live slice pointer and does not retain it.
    let written = write_without_sigpipe(fd, line);
    log_short_write(fd, line.len(), written);

    if restore_flags {
        // SAFETY: fcntl(2) only reads scalar arguments.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
            log_fd_error("restore flags", fd);
        }
    }
}

fn write_without_sigpipe(fd: i32, line: &[u8]) -> isize {
    // SAFETY: the signal set pointers point to initialized local storage.
    unsafe {
        let mut sigpipe = std::mem::zeroed::<libc::sigset_t>();
        if libc::sigemptyset(&raw mut sigpipe) != 0
            || libc::sigaddset(&raw mut sigpipe, libc::SIGPIPE) != 0
        {
            return -1;
        }

        let mut pending = std::mem::zeroed::<libc::sigset_t>();
        let was_pending = libc::sigpending(&raw mut pending) == 0
            && libc::sigismember(&raw const pending, libc::SIGPIPE) == 1;
        let mut old_mask = std::mem::zeroed::<libc::sigset_t>();
        if libc::pthread_sigmask(libc::SIG_BLOCK, &raw const sigpipe, &raw mut old_mask) != 0 {
            return -1;
        }

        // SAFETY: write(2) reads the live slice pointer and does not retain it.
        let written = libc::write(fd, line.as_ptr().cast(), line.len());
        let broken_pipe =
            written < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPIPE);
        if broken_pipe && !was_pending {
            let mut pending = std::mem::zeroed::<libc::sigset_t>();
            if libc::sigpending(&raw mut pending) == 0
                && libc::sigismember(&raw const pending, libc::SIGPIPE) == 1
            {
                let mut signal = 0;
                libc::sigwait(&raw const sigpipe, &raw mut signal);
            }
        }

        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old_mask, std::ptr::null_mut());
        written
    }
}

fn log_short_write(fd: i32, expected: usize, written: isize) {
    if written == isize::try_from(expected).unwrap_or(-1) {
        return;
    }

    let error = std::io::Error::last_os_error();
    log::debug!(
        "trap: write fd={fd} bytes={written} errno={}",
        error.raw_os_error().unwrap_or(0)
    );
}

fn log_fd_error(operation: &str, fd: i32) {
    let error = std::io::Error::last_os_error();
    log::debug!(
        "trap: {operation} fd={fd} errno={}",
        error.raw_os_error().unwrap_or(0)
    );
}
