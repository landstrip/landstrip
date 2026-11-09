// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Lazy `xdg-dbus-proxy` broker for filtering the user D-Bus session socket to
//! `org.freedesktop.secrets` without exposing `org.freedesktop.systemd1` or
//! other unsandboxed session services.

use super::error::{BrokerError, SysResult};
use super::procfs::{OpenHow, ProcFd};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::prctl;
use nix::sys::signal::{self, SigSet, SigmaskHow, Signal};
use nix::sys::stat::fstat;
use nix::unistd::{UnlinkatFlags, mkdtemp, pipe2, read, unlinkat};
use std::collections::{HashMap, hash_map::Entry};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const STARTUP_TIMEOUT_MS: u16 = 5_000;
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
const RESOLVE_NO_XDEV: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct InodeKey {
    dev: u64,
    ino: u64,
}

impl TryFrom<BorrowedFd<'_>> for InodeKey {
    type Error = BrokerError;

    fn try_from(fd: BorrowedFd<'_>) -> SysResult<Self> {
        let stat = fstat(fd)?;
        Ok(Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
        })
    }
}

pub(super) struct DbusProxies {
    binary: Option<PathBuf>,
    instances: HashMap<InodeKey, DbusProxy>,
}

impl DbusProxies {
    pub(super) fn new() -> Self {
        Self {
            binary: which::which("xdg-dbus-proxy").ok(),
            instances: HashMap::new(),
        }
    }

    pub(super) fn is_available(&self) -> bool {
        self.binary.is_some()
    }

    pub(super) fn socket_for(
        &mut self,
        key: InodeKey,
        upstream: BorrowedFd<'_>,
    ) -> SysResult<BorrowedFd<'_>> {
        let binary = self.binary.as_deref().ok_or(BrokerError::PolicyDenied)?;
        if self
            .instances
            .get_mut(&key)
            .is_some_and(|proxy| !proxy.is_alive())
        {
            self.instances.remove(&key);
        }
        let proxy = match self.instances.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(DbusProxy::start(binary, upstream)?),
        };
        Ok(proxy.socket.as_fd())
    }

    pub(super) fn evict(&mut self, key: InodeKey) -> bool {
        self.instances.remove(&key).is_some()
    }
}

struct DbusProxy {
    socket: OwnedFd,
    running: RunningProxy,
}

impl DbusProxy {
    fn start(binary: &Path, upstream: BorrowedFd<'_>) -> SysResult<Self> {
        let dir = TempDir::new()?;
        let (read_fd, write_fd) = pipe2(OFlag::O_CLOEXEC)?;
        let child_fds = ProxyFds::new(upstream, dir.fd.as_fd(), write_fd.as_fd())?;
        drop(write_fd);

        let retained = child_fds.raw();
        let [_, _, raw_sync] = retained;
        let mut upstream_arg = OsString::from("unix:path=");
        upstream_arg.push(ProcFd::new(child_fds.upstream.as_fd()).proc_path());
        let bus_path = ProcFd::new(child_fds.dir.as_fd()).proc_path().join("bus");
        // SAFETY: getpid(2) has no preconditions.
        let broker_pid = unsafe { libc::getpid() };

        let mut command = Command::new(binary);
        command
            .arg(upstream_arg)
            .arg(bus_path)
            .arg(format!("--fd={raw_sync}"))
            .arg("--filter")
            .arg("--talk=org.freedesktop.secrets")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // SAFETY: pre_exec runs in the forked child before exec using async-signal-safe syscalls.
        unsafe {
            command.pre_exec(move || {
                prctl::set_pdeathsig(Signal::SIGKILL)
                    .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
                if libc::getppid() != broker_pid {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
                    .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
                ProxyFds::retain_only(&retained)
            });
        }

        let child = command.spawn().map_err(|error| {
            log::warn!("spawn xdg-dbus-proxy failed: {error}");
            BrokerError::PolicyDenied
        })?;
        drop(child_fds);

        let running = RunningProxy {
            keepalive: Some(read_fd),
            child,
        };
        running.wait_ready()?;
        let socket = dir.open_and_unlink_bus()?;

        Ok(Self { socket, running })
    }

    fn is_alive(&mut self) -> bool {
        matches!(self.running.child.try_wait(), Ok(None))
    }
}

struct ProxyFds {
    upstream: OwnedFd,
    dir: OwnedFd,
    sync: OwnedFd,
}

impl ProxyFds {
    fn new(upstream: BorrowedFd<'_>, dir: BorrowedFd<'_>, sync: BorrowedFd<'_>) -> SysResult<Self> {
        Ok(Self {
            upstream: ProcFd::new(upstream).dup_above_stdio()?,
            dir: ProcFd::new(dir).dup_above_stdio()?,
            sync: ProcFd::new(sync).dup_above_stdio()?,
        })
    }

    fn raw(&self) -> [RawFd; 3] {
        [
            self.upstream.as_raw_fd(),
            self.dir.as_raw_fd(),
            self.sync.as_raw_fd(),
        ]
    }

    fn retain_only(retained: &[RawFd; 3]) -> io::Result<()> {
        let rc =
            unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        for &fd in retained {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

struct RunningProxy {
    keepalive: Option<OwnedFd>,
    child: Child,
}

impl RunningProxy {
    fn wait_ready(&self) -> SysResult<()> {
        let fd = self
            .keepalive
            .as_ref()
            .ok_or(BrokerError::BadFileDescriptor)?
            .as_fd();
        let mut poll_fds = [PollFd::new(fd, PollFlags::POLLIN)];
        loop {
            match poll(&mut poll_fds, STARTUP_TIMEOUT_MS) {
                Ok(0) => {
                    log::warn!("xdg-dbus-proxy startup timed out");
                    return Err(BrokerError::PolicyDenied);
                }
                Ok(_) => break,
                Err(Errno::EINTR) => {}
                Err(errno) => return Err(errno.into()),
            }
        }

        let mut ready = [0_u8; 1];
        loop {
            match read(fd, &mut ready) {
                Ok(1) => return Ok(()),
                Ok(_) => {
                    log::warn!("xdg-dbus-proxy exited before signaling readiness");
                    return Err(BrokerError::PolicyDenied);
                }
                Err(Errno::EINTR) => {}
                Err(errno) => return Err(errno.into()),
            }
        }
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        self.keepalive.take();
        let mut reaped = false;
        for _ in 0..50 {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => {
                    reaped = true;
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(2)),
            }
        }
        if !reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct TempDir {
    path: Option<PathBuf>,
    fd: OwnedFd,
}

impl TempDir {
    fn new() -> SysResult<Self> {
        let path = mkdtemp("/tmp/landstrip-dbus-XXXXXX")?;
        let open_result = ProcFd::open_path(
            &path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        );
        let fd = match open_result {
            Ok(fd) => fd,
            Err(error) => {
                let _ = fs::remove_dir_all(&path);
                return Err(error);
            }
        };
        let guard = Self {
            path: Some(path),
            fd,
        };
        let stat = fstat(guard.fd.as_fd())?;
        // SAFETY: geteuid(2) is always safe and has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
            || stat.st_uid != euid
            || (stat.st_mode & 0o777) != 0o700
        {
            return Err(BrokerError::PolicyDenied);
        }
        Ok(guard)
    }

    fn open_and_unlink_bus(mut self) -> SysResult<OwnedFd> {
        let how = OpenHow {
            flags: u64::try_from(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)?,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
        };
        let socket = how.openat2(self.fd.as_raw_fd(), c"bus")?;
        let stat = fstat(socket.as_fd())?;
        // SAFETY: geteuid(2) is always safe and has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK
            || stat.st_uid != euid
            || stat.st_nlink != 1
        {
            return Err(BrokerError::PolicyDenied);
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
