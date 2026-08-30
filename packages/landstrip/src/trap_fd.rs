// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Separate file descriptor for landstrip trap response blocks.

use crate::trap::Trap;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_millis(100);

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
    pub(crate) fn is_stream_socket(&self) -> bool {
        loop {
            let mut socket_type = 0;
            let Ok(mut len) = libc::socklen_t::try_from(std::mem::size_of_val(&socket_type)) else {
                return false;
            };
            let result = unsafe {
                libc::getsockopt(
                    self.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&raw mut socket_type).cast(),
                    &raw mut len,
                )
            };
            if result == 0 {
                return socket_type == libc::SOCK_STREAM;
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return false;
            }
        }
    }

    pub(crate) fn write(&self, trap: &Trap) -> io::Result<()> {
        let mut line = trap.to_string();
        line.push('\n');
        self.write_all(line.as_bytes())
    }

    pub(crate) fn write_json(&self, json: &str) -> io::Result<()> {
        let mut line = String::with_capacity(json.len() + 1);
        line.push_str(json);
        line.push('\n');
        self.write_all(line.as_bytes())
    }

    fn write_all(&self, line: &[u8]) -> io::Result<()> {
        if self.is_stream_socket() {
            let result = write_socket_trap_fd(self.as_raw_fd(), line);
            if result.is_err() {
                unsafe { libc::shutdown(self.as_raw_fd(), libc::SHUT_RDWR) };
            }
            return result;
        }

        write_nonblocking_trap_fd(self.as_raw_fd(), line)
    }
}

fn write_socket_trap_fd(fd: RawFd, mut line: &[u8]) -> io::Result<()> {
    let started = Instant::now();
    while !line.is_empty() {
        if started.elapsed() >= SOCKET_WRITE_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "trap socket write timed out",
            ));
        }
        let written = unsafe {
            libc::send(
                fd,
                line.as_ptr().cast(),
                line.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if written > 0 {
            let written = usize::try_from(written).map_err(io::Error::other)?;
            line = &line[written..];
            continue;
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "trap socket accepted no data",
            ));
        }

        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::WouldBlock => wait_socket_writable(fd, started)?,
            _ => return Err(error),
        }
    }
    Ok(())
}

fn wait_socket_writable(fd: RawFd, started: Instant) -> io::Result<()> {
    loop {
        let Some(remaining) = SOCKET_WRITE_TIMEOUT.checked_sub(started.elapsed()) else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "trap socket write timed out",
            ));
        };
        let timeout = i32::try_from(remaining.as_millis()).map_or(i32::MAX, |value| value.max(1));
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&raw mut poll_fd, 1, timeout) };
        if ready > 0 {
            if poll_fd.revents & libc::POLLOUT != 0 {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "trap socket closed while writing",
            ));
        }
        if ready == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "trap socket write timed out",
            ));
        }

        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn write_nonblocking_trap_fd(fd: RawFd, line: &[u8]) -> io::Result<()> {
    if line.len() > libc::PIPE_BUF {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "trap record exceeds PIPE_BUF",
        ));
    }

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }

    let restore_flags = flags & libc::O_NONBLOCK == 0;
    if restore_flags && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let write_result = write_without_sigpipe(fd, line).and_then(|written| {
        if written == line.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("trap fd wrote {written} of {} bytes", line.len()),
            ))
        }
    });

    let restore_result = if restore_flags && unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };

    write_result.and(restore_result)
}

fn write_without_sigpipe(fd: RawFd, line: &[u8]) -> io::Result<usize> {
    unsafe {
        let mut sigpipe = std::mem::zeroed::<libc::sigset_t>();
        if libc::sigemptyset(&raw mut sigpipe) != 0
            || libc::sigaddset(&raw mut sigpipe, libc::SIGPIPE) != 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut old_mask = std::mem::zeroed::<libc::sigset_t>();
        let mask_result =
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const sigpipe, &raw mut old_mask);
        if mask_result != 0 {
            return Err(io::Error::from_raw_os_error(mask_result));
        }

        let write_result = (|| {
            let mut pending = std::mem::zeroed::<libc::sigset_t>();
            if libc::sigpending(&raw mut pending) != 0 {
                return Err(io::Error::last_os_error());
            }
            let was_pending = libc::sigismember(&raw const pending, libc::SIGPIPE) == 1;
            let result = loop {
                let written = libc::write(fd, line.as_ptr().cast(), line.len());
                if written >= 0 {
                    break usize::try_from(written).map_err(io::Error::other);
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    break Err(error);
                }
            };
            if matches!(&result, Err(error) if error.raw_os_error() == Some(libc::EPIPE))
                && !was_pending
            {
                let mut pending = std::mem::zeroed::<libc::sigset_t>();
                if libc::sigpending(&raw mut pending) == 0
                    && libc::sigismember(&raw const pending, libc::SIGPIPE) == 1
                {
                    let mut signal = 0;
                    libc::sigwait(&raw const sigpipe, &raw mut signal);
                }
            }
            result
        })();

        let restore_result =
            libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old_mask, std::ptr::null_mut());
        if restore_result != 0 && write_result.is_ok() {
            return Err(io::Error::from_raw_os_error(restore_result));
        }
        write_result
    }
}

