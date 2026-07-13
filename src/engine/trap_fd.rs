// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Separate file descriptor for landstrip trap response blocks.

use crate::engine::trap::Trap;

#[derive(Clone, Debug, Default)]
pub(crate) struct TrapFd {
    // Denial traps are a `--trap-fd` concept only the Linux broker produces;
    // Windows accepts the flag but has no descriptor to write to.
    #[cfg_attr(not(unix), allow(dead_code))]
    fd: Option<i32>,
}

impl TrapFd {
    pub(crate) fn from_fd(fd: Option<i32>) -> Self {
        Self { fd }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn is_enabled(&self) -> bool {
        self.fd.is_some()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn is_socket(&self) -> bool {
        self.fd.is_some_and(|fd| {
            crate::platform::fd::getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_TYPE).is_ok()
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn close(&self) {
        if let Some(fd) = self.fd {
            close_trap_fd(fd);
        }
    }

    #[cfg(unix)]
    pub(crate) fn fd(&self) -> Option<i32> {
        self.fd
    }

    #[cfg(unix)]
    pub(crate) fn write(&self, trap: &Trap) {
        self.write_json(&trap.json_line());
    }

    #[cfg(unix)]
    pub(crate) fn write_json(&self, json: &str) {
        let mut line = json.to_owned();
        line.push('\n');

        if let Some(fd) = self.fd {
            write_trap_fd(fd, line.as_bytes());
        }
    }

    /// Windows has no inherited landstrip descriptor: traps reach the launcher
    /// on stderr only.
    #[cfg(not(unix))]
    #[allow(clippy::unused_self)]
    pub(crate) fn write(&self, _trap: &Trap) {}
}

#[cfg(unix)]
fn write_trap_fd(fd: i32, line: &[u8]) {
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
                "trap: write fd={fd} errno={}",
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

#[cfg(target_os = "linux")]
fn close_trap_fd(fd: i32) {
    // SAFETY: close(2) copies the scalar file descriptor argument.
    let rc = unsafe { libc::close(fd) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        log::debug!(
            "trap: close fd={fd} errno={}",
            error.raw_os_error().unwrap_or(0)
        );
    }
}
