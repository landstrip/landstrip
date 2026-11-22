// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Separate file descriptor for landstrip trap response blocks.

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::trap::Trap;
use std::io;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::os::fd::FromRawFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_millis(100);

/// Longest answer a responder may write back.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const MAX_REPLY_BYTES: usize = 4096;

#[derive(Debug)]
pub(crate) struct TrapFd {
    fd: std::mem::ManuallyDrop<OwnedFd>,
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    broker_registered: bool,
}

impl From<OwnedFd> for TrapFd {
    fn from(fd: OwnedFd) -> Self {
        Self {
            fd: std::mem::ManuallyDrop::new(fd),
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            broker_registered: false,
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl From<crate::platform::linux::kvm::fds::BrokerFd> for TrapFd {
    fn from(fd: crate::platform::linux::kvm::fds::BrokerFd) -> Self {
        Self {
            fd: std::mem::ManuallyDrop::new(fd.into_unregistered_owned()),
            broker_registered: true,
        }
    }
}

impl Drop for TrapFd {
    fn drop(&mut self) {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        let raw = self.fd.as_raw_fd();
        // SAFETY: `self.fd` is dropped once here before unregistering any
        // broker ownership bit.
        unsafe { std::mem::ManuallyDrop::drop(&mut self.fd) };
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if self.broker_registered {
            crate::platform::linux::kvm::fds::GuestFd::unregister_broker(raw);
        }
    }
}

impl AsFd for TrapFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for TrapFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl TrapFd {
    /// Moves the descriptor above `base`, out of the numbers a payload
    /// allocates.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) fn hide(&mut self, base: RawFd) -> io::Result<()> {
        let old = self.as_raw_fd();
        let was_registered = self.broker_registered;
        // SAFETY: the descriptor is open, and the returned descriptor is owned
        // here.
        let moved = unsafe { libc::fcntl(old, libc::F_DUPFD_CLOEXEC, base) };
        if moved < 0 {
            return Err(io::Error::last_os_error());
        }
        crate::platform::linux::kvm::fds::GuestFd::register_broker(moved);
        // SAFETY: `self.fd` is replaced immediately below with `moved`.
        unsafe { std::mem::ManuallyDrop::drop(&mut self.fd) };
        if was_registered {
            crate::platform::linux::kvm::fds::GuestFd::unregister_broker(old);
        }
        // SAFETY: `fcntl` returned a new descriptor this process owns.
        self.fd = std::mem::ManuallyDrop::new(unsafe { OwnedFd::from_raw_fd(moved) });
        self.broker_registered = true;
        Ok(())
    }

    /// Duplicates this descriptor above `base` for a broker state that owns its
    /// own handle.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) fn clone_above(&self, base: RawFd) -> io::Result<Self> {
        // SAFETY: the descriptor is open, and the returned descriptor is owned
        // here.
        let moved = unsafe { libc::fcntl(self.as_raw_fd(), libc::F_DUPFD_CLOEXEC, base) };
        if moved < 0 {
            return Err(io::Error::last_os_error());
        }
        crate::platform::linux::kvm::fds::GuestFd::register_broker(moved);
        // SAFETY: `fcntl` returned a new descriptor this process owns.
        Ok(Self {
            fd: std::mem::ManuallyDrop::new(unsafe { OwnedFd::from_raw_fd(moved) }),
            broker_registered: true,
        })
    }

    pub(crate) fn connect(path: &Path) -> io::Result<Self> {
        UnixStream::connect(path).map(|stream| Self::from(OwnedFd::from(stream)))
    }

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

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) fn write(&self, trap: &Trap) -> io::Result<()> {
        self.write_stanza(&trap.to_string())
    }

    pub(crate) fn write_stanza(&self, stanza: &str) -> io::Result<()> {
        self.write_all(stanza.as_bytes())
    }

    /// Reads the answer stanza a responder writes back, up to the blank line.
    ///
    /// Only the bytes of one stanza are taken, so answers that arrive together
    /// stay in the socket for the next query.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) fn read_stanza(
        stanza: &mut Vec<u8>,
        mut read_byte: impl FnMut() -> io::Result<u8>,
    ) -> io::Result<String> {
        for _ in stanza.len()..MAX_REPLY_BYTES {
            let byte = read_byte()?;
            if byte == b'\n' {
                if stanza.last() == Some(&b'\r') {
                    stanza.pop();
                }
                if stanza.is_empty() {
                    continue;
                }
                if stanza.last() == Some(&b'\n') {
                    return String::from_utf8(std::mem::take(stanza)).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "reply is not UTF-8")
                    });
                }
            }
            stanza.push(byte);
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reply has no stanza break",
        ))
    }

    fn write_all(&self, line: &[u8]) -> io::Result<()> {
        if self.is_stream_socket() {
            let result = self.write_socket(line);
            if result.is_err() {
                unsafe { libc::shutdown(self.as_raw_fd(), libc::SHUT_RDWR) };
            }
            return result;
        }

        self.write_nonblocking(line)
    }

    fn write_socket(&self, mut line: &[u8]) -> io::Result<()> {
        let fd = self.as_raw_fd();
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
                io::ErrorKind::WouldBlock => self.wait_socket_writable(started)?,
                _ => return Err(error),
            }
        }
        Ok(())
    }

    fn wait_socket_writable(&self, started: Instant) -> io::Result<()> {
        let fd = self.as_raw_fd();
        loop {
            let Some(remaining) = SOCKET_WRITE_TIMEOUT.checked_sub(started.elapsed()) else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "trap socket write timed out",
                ));
            };
            let timeout =
                i32::try_from(remaining.as_millis()).map_or(i32::MAX, |value| value.max(1));
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

    fn write_nonblocking(&self, line: &[u8]) -> io::Result<()> {
        let fd = self.as_raw_fd();
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
        if restore_flags && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }

        let write_result = self.write_without_sigpipe(line).and_then(|written| {
            if written == line.len() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("trap fd wrote {written} of {} bytes", line.len()),
                ))
            }
        });

        let restore_result =
            if restore_flags && unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            };

        write_result.and(restore_result)
    }

    fn write_without_sigpipe(&self, line: &[u8]) -> io::Result<usize> {
        let fd = self.as_raw_fd();
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
}
