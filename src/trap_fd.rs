// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Separate file descriptor for landstrip trap response blocks.

use crate::trap::Trap;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TrapFd {
    fd: Option<i32>,
}

impl TrapFd {
    pub(crate) fn from_fd(fd: Option<i32>) -> Self {
        Self { fd }
    }

    pub(crate) fn is_enabled(self) -> bool {
        self.fd.is_some()
    }

    pub(crate) fn close(self) {
        let Some(fd) = self.fd else {
            return;
        };
        close_trap_fd(fd);
    }

    pub(crate) fn write(self, trap: &Trap) {
        let Some(fd) = self.fd else {
            return;
        };
        let Ok(line) = serde_json::to_string(trap) else {
            return;
        };
        write_trap_line(fd, format!("{line}\n").as_bytes());
    }
}

#[cfg(unix)]
fn write_trap_line(fd: i32, line: &[u8]) {
    let mut remaining = line;
    while !remaining.is_empty() {
        // SAFETY: write(2) copies bytes from the live slice pointer.
        let written = unsafe { libc::write(fd, remaining.as_ptr().cast(), remaining.len()) };
        if written == 0 {
            return;
        }
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            log::debug!(
                "trap fd write fd={fd} errno={}",
                error.raw_os_error().unwrap_or(0)
            );
            return;
        }

        let Ok(written) = usize::try_from(written) else {
            return;
        };
        remaining = &remaining[written..];
    }
}

#[cfg(unix)]
fn close_trap_fd(fd: i32) {
    // SAFETY: close(2) copies the scalar file descriptor argument.
    let rc = unsafe { libc::close(fd) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        log::debug!(
            "trap fd close fd={fd} errno={}",
            error.raw_os_error().unwrap_or(0)
        );
    }
}

#[cfg(not(unix))]
fn write_trap_line(_fd: i32, _line: &[u8]) {}

#[cfg(not(unix))]
fn close_trap_fd(_fd: i32) {}
