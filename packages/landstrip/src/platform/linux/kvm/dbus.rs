// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Lazy `xdg-dbus-proxy` broker for filtering user D-Bus session sockets to
//! `org.freedesktop.secrets` without exposing `org.freedesktop.systemd1` or
//! other unsandboxed session services.

use super::fds::{BrokerFd, GuestFd};
use super::policy::ResolveFlags;
use linux_raw_sys::general::open_how;
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{self, SigSet, SigmaskHow};
use nix::sys::stat::fstat;
use nix::unistd::{UnlinkatFlags, mkdtemp, pipe2, read, unlinkat};
use serde::{Deserialize, Serialize};
use socket2::{SockAddr, SockRef};
use std::collections::{HashMap, hash_map::Entry};
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

const STARTUP_TIMEOUT_MS: u16 = 5_000;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct InodeKey {
    dev: u64,
    ino: u64,
}

impl InodeKey {
    fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, i32> {
        let stat = fstat(fd).map_err(|errno| errno as i32)?;
        Ok(Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
        })
    }
}

pub(crate) struct DbusProxies {
    binary: Option<PathBuf>,
    instances: Mutex<HashMap<InodeKey, Proxy>>,
}

#[derive(Deserialize, Serialize)]
pub(super) struct ExecProxies {
    binary: Option<std::ffi::OsString>,
    instances: Vec<(u64, u64, RawFd, RawFd)>,
}

impl ExecProxies {
    pub(super) fn restore(self, floor: RawFd) -> anyhow::Result<DbusProxies> {
        let instances = self
            .instances
            .into_iter()
            .map(|(dev, ino, socket, keepalive)| {
                Ok((
                    InodeKey { dev, ino },
                    Proxy {
                        socket: super::handoff::Inherited::adopt(socket, floor)?,
                        keepalive: super::handoff::Inherited::adopt(keepalive, floor)?,
                    },
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(DbusProxies {
            binary: self.binary.map(PathBuf::from),
            instances: Mutex::new(instances),
        })
    }
}

impl DbusProxies {
    pub(crate) fn new() -> Self {
        Self {
            binary: which::which("xdg-dbus-proxy").ok(),
            instances: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn fresh(&self) -> Self {
        Self {
            binary: self.binary.clone(),
            instances: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn release_forked_fds(&self) {
        if let Ok(instances) = self.instances.try_lock() {
            for proxy in instances.values() {
                proxy.socket.close_for_forked_parent();
                proxy.keepalive.close_for_forked_parent();
            }
        }
    }

    pub(super) fn exec_state(
        &self,
        inherited: &mut super::handoff::Inherited,
    ) -> anyhow::Result<ExecProxies> {
        let instances = self
            .instances
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let instances = instances
            .iter()
            .map(|(key, proxy)| {
                Ok((
                    key.dev,
                    key.ino,
                    inherited.keep(proxy.socket.as_fd())?,
                    inherited.keep(proxy.keepalive.as_fd())?,
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(ExecProxies {
            binary: self.binary.as_ref().map(|path| path.as_os_str().to_owned()),
            instances,
        })
    }

    pub(crate) fn is_available(&self) -> bool {
        self.binary.is_some()
    }

    pub(crate) fn connect(&self, guest_sock: RawFd, upstream: BorrowedFd<'_>) -> Result<(), i32> {
        let binary = self.binary.as_deref().ok_or(libc::EACCES)?;
        let key = InodeKey::from_fd(upstream)?;

        for attempt in 0..2 {
            let proc_path = {
                let mut instances = self
                    .instances
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if instances.get(&key).is_some_and(|proxy| !proxy.is_alive()) {
                    instances.remove(&key);
                }
                let proxy = match instances.entry(key) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => entry.insert(Proxy::start(binary, upstream)?),
                };
                PathBuf::from(format!("/proc/self/fd/{}", proxy.socket.as_raw_fd()))
            };

            let addr = SockAddr::unix(proc_path).map_err(|_| libc::EINVAL)?;
            let scope = NonblockScope::enter(guest_sock)?;
            let mut retry_dead_proxy = false;
            for step in 0..200 {
                let borrowed = unsafe { BorrowedFd::borrow_raw(scope.fd) };
                let sock = SockRef::from(&borrowed);
                match sock.connect(&addr) {
                    Ok(()) => return Ok(()),
                    Err(error) => {
                        let errno = error.raw_os_error().unwrap_or(libc::EIO);
                        if errno == libc::EAGAIN && !scope.was_nonblocking && step < 199 {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        if errno == libc::ECONNREFUSED && attempt == 0 {
                            retry_dead_proxy = true;
                            break;
                        }
                        return Err(errno);
                    }
                }
            }
            drop(scope);
            if retry_dead_proxy {
                let mut instances = self
                    .instances
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if instances.remove(&key).is_some() {
                    continue;
                }
            }
            return Err(libc::ECONNREFUSED);
        }
        Err(libc::ECONNREFUSED)
    }
}

struct NonblockScope {
    fd: RawFd,
    original_flags: i32,
    was_nonblocking: bool,
}

impl NonblockScope {
    fn enter(fd: RawFd) -> Result<Self, i32> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(libc::EBADF);
        }
        let was_nonblocking = (flags & libc::O_NONBLOCK) != 0;
        if !was_nonblocking
            && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(libc::EBADF);
        }
        Ok(Self {
            fd,
            original_flags: flags,
            was_nonblocking,
        })
    }
}

impl Drop for NonblockScope {
    fn drop(&mut self) {
        if !self.was_nonblocking {
            let _ = unsafe { libc::fcntl(self.fd, libc::F_SETFL, self.original_flags) };
        }
    }
}

struct Proxy {
    socket: BrokerFd,
    keepalive: BrokerFd,
}

impl Proxy {
    fn start(binary: &Path, upstream: BorrowedFd<'_>) -> Result<Self, i32> {
        let dir = TempDir::new()?;
        let (keepalive, sync_fd) = {
            let _fd_lock = GuestFd::read_fd_table();
            let (read_fd, write_fd) = pipe2(OFlag::O_CLOEXEC).map_err(|_| libc::EACCES)?;
            let keepalive = GuestFd::relocate_above(read_fd).map_err(|_| libc::EACCES)?;
            let sync_fd = GuestFd::relocate_above(write_fd).map_err(|_| libc::EACCES)?;
            (keepalive, sync_fd)
        };
        let upstream_fd =
            GuestFd::duplicate_above(upstream.as_raw_fd()).map_err(|_| libc::EACCES)?;

        let binary_c = TempDir::c_path(binary)?;
        let upstream_arg = CString::new(format!(
            "unix:path=/proc/self/fd/{}",
            upstream_fd.as_raw_fd()
        ))
        .map_err(|_| libc::EACCES)?;
        let bus_arg = CString::new(format!("/proc/self/fd/{}/bus", dir.fd.as_raw_fd()))
            .map_err(|_| libc::EACCES)?;
        let fd_arg =
            CString::new(format!("--fd={}", sync_fd.as_raw_fd())).map_err(|_| libc::EACCES)?;
        let filter_arg = c"--filter";
        let talk_arg = c"--talk=org.freedesktop.secrets";

        let retained = [
            upstream_fd.as_raw_fd(),
            dir.fd.as_raw_fd(),
            sync_fd.as_raw_fd(),
        ];

        Self::spawn_detached(
            &binary_c,
            &[
                binary_c.as_c_str(),
                upstream_arg.as_c_str(),
                bus_arg.as_c_str(),
                fd_arg.as_c_str(),
                filter_arg,
                talk_arg,
            ],
            &retained,
        )?;

        drop(sync_fd);
        drop(upstream_fd);

        Self::wait_ready(keepalive.as_fd())?;
        let socket = dir.open_and_unlink_bus()?;
        Ok(Self { socket, keepalive })
    }

    fn is_alive(&self) -> bool {
        let mut poll_fds = [PollFd::new(
            self.keepalive.as_fd(),
            PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
        )];
        match poll(&mut poll_fds, PollTimeout::ZERO) {
            Ok(0) => true,
            Ok(_) => poll_fds[0]
                .revents()
                .is_none_or(|revents| !revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR)),
            Err(_) => false,
        }
    }

    fn spawn_detached(
        binary: &CString,
        args: &[&std::ffi::CStr],
        retained: &[RawFd; 3],
    ) -> Result<(), i32> {
        let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
        ptrs.push(std::ptr::null());

        let middle = unsafe { libc::fork() };
        if middle < 0 {
            return Err(libc::EACCES);
        }
        if middle == 0 {
            let grandchild = unsafe { libc::fork() };
            if grandchild < 0 {
                unsafe { libc::_exit(1) };
            }
            if grandchild > 0 {
                unsafe { libc::_exit(0) };
            }
            let _ = unsafe { libc::setsid() };
            let _ = signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None);
            if let Ok(null) = CString::new("/dev/null") {
                let fd = unsafe { libc::open(null.as_ptr(), libc::O_RDWR) };
                if fd >= 0 {
                    for stdio in 0..=2 {
                        let _ = unsafe { libc::dup2(fd, stdio) };
                    }
                    if fd > 2 {
                        let _ = unsafe { libc::close(fd) };
                    }
                }
            }
            let _ = unsafe {
                syscalls::syscall!(
                    syscalls::Sysno::close_range,
                    3_usize,
                    u32::MAX as usize,
                    libc::CLOSE_RANGE_CLOEXEC as usize
                )
            };
            for &fd in retained {
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if flags < 0
                    || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
                {
                    unsafe { libc::_exit(1) };
                }
            }
            unsafe {
                libc::execv(binary.as_ptr(), ptrs.as_ptr());
                libc::_exit(127);
            }
        }

        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(middle, &raw mut status, 0) };
            if waited == middle {
                break;
            }
            if waited < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(libc::EACCES);
            }
        }
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            Ok(())
        } else {
            Err(libc::EACCES)
        }
    }

    fn wait_ready(fd: BorrowedFd<'_>) -> Result<(), i32> {
        let mut poll_fds = [PollFd::new(fd, PollFlags::POLLIN)];
        loop {
            match poll(&mut poll_fds, STARTUP_TIMEOUT_MS) {
                Ok(0) => {
                    log::warn!("xdg-dbus-proxy startup timed out");
                    return Err(libc::EACCES);
                }
                Ok(_) => break,
                Err(Errno::EINTR) => {}
                Err(errno) => return Err(errno as i32),
            }
        }
        let mut ready = [0_u8; 1];
        loop {
            match read(fd, &mut ready) {
                Ok(1) => return Ok(()),
                Ok(_) => {
                    log::warn!("xdg-dbus-proxy exited before signaling readiness");
                    return Err(libc::EACCES);
                }
                Err(Errno::EINTR) => {}
                Err(errno) => return Err(errno as i32),
            }
        }
    }
}

struct TempDir {
    path: Option<PathBuf>,
    fd: BrokerFd,
}

impl TempDir {
    fn c_path(path: &Path) -> Result<CString, i32> {
        CString::new(OsStr::as_bytes(path.as_os_str())).map_err(|_| libc::EINVAL)
    }

    fn new() -> Result<Self, i32> {
        let path = mkdtemp("/tmp/landstrip-dbus-XXXXXX").map_err(|_| libc::EACCES)?;
        let cpath = match Self::c_path(&path) {
            Ok(cpath) => cpath,
            Err(errno) => {
                let _ = fs::remove_dir_all(&path);
                return Err(errno);
            }
        };
        let fd = {
            let _fd_lock = GuestFd::read_fd_table();
            let raw = unsafe {
                libc::open(
                    cpath.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                let _ = fs::remove_dir_all(&path);
                return Err(libc::EACCES);
            }
            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
            let Ok(fd) = GuestFd::relocate_above(owned) else {
                let _ = fs::remove_dir_all(&path);
                return Err(libc::EACCES);
            };
            fd
        };
        let guard = Self {
            path: Some(path),
            fd,
        };
        let stat = fstat(guard.fd.as_fd()).map_err(|_| libc::EACCES)?;
        let euid = unsafe { libc::geteuid() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
            || stat.st_uid != euid
            || (stat.st_mode & 0o777) != 0o700
        {
            return Err(libc::EACCES);
        }
        Ok(guard)
    }

    fn open_and_unlink_bus(mut self) -> Result<BrokerFd, i32> {
        let how = open_how {
            flags: u64::from((libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC).cast_unsigned()),
            mode: 0,
            resolve: (ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV)
                .bits(),
        };
        let name = c"bus";
        let socket = {
            let _fd_lock = GuestFd::read_fd_table();
            let raw = unsafe {
                syscalls::syscall!(
                    syscalls::Sysno::openat2,
                    self.fd.as_raw_fd().cast_unsigned() as usize,
                    name.as_ptr().expose_provenance(),
                    (&raw const how).expose_provenance(),
                    std::mem::size_of::<open_how>()
                )
            }
            .ok()
            .and_then(|fd| RawFd::try_from(fd).ok())
            .ok_or(libc::EACCES)?;
            let socket = unsafe { OwnedFd::from_raw_fd(raw) };
            GuestFd::relocate_above(socket).map_err(|_| libc::EACCES)?
        };
        let stat = fstat(socket.as_fd()).map_err(|_| libc::EACCES)?;
        let euid = unsafe { libc::geteuid() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK
            || stat.st_uid != euid
            || stat.st_nlink != 1
        {
            return Err(libc::EACCES);
        }
        let _ = unlinkat(self.fd.as_fd(), "bus", UnlinkatFlags::NoRemoveDir);
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir(&path);
        }
        Ok(socket)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(&path);
        }
    }
}
