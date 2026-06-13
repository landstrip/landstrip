// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Separate file descriptor for landstrip error response blocks.

use std::path::Path;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ErrorFd {
    fd: Option<i32>,
}

impl ErrorFd {
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
        close_error_fd(fd);
    }

    pub(crate) fn emit_filesystem_denial(self, operation: &str, path: &Path, mechanism: &str) {
        let Some(fd) = self.fd else {
            return;
        };

        let response = format!(
            "reason: AccessDenied\ntype: filesystem\nfile: {}\noperation: {operation}\nmechanism: {mechanism}\n\n",
            path.display()
        );
        write_error_line(fd, response.as_bytes());
    }
}

#[cfg(unix)]
fn write_error_line(fd: i32, line: &[u8]) {
    use nix::errno::Errno;
    use nix::unistd::write;
    use std::os::fd::BorrowedFd;

    let mut remaining = line;
    while !remaining.is_empty() {
        // SAFETY: fd is supplied by the caller and borrowed only for this write call.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        match write(borrowed, remaining) {
            Ok(0) => return,
            Ok(written) => remaining = &remaining[written..],
            Err(Errno::EINTR) => continue,
            Err(error) => {
                log::debug!("error fd write fd={fd} errno={}", error as i32);
                return;
            }
        }
    }
}

#[cfg(unix)]
fn close_error_fd(fd: i32) {
    // SAFETY: close(2) copies the scalar file descriptor argument.
    let rc = unsafe { libc::close(fd) };
    if rc != 0 {
        log::debug!(
            "error fd close fd={fd} errno={}",
            nix::errno::Errno::last() as i32
        );
    }
}

#[cfg(not(unix))]
fn write_error_line(_fd: i32, _line: &[u8]) {}

#[cfg(not(unix))]
fn close_error_fd(_fd: i32) {}
