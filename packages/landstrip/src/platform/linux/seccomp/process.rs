// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use crate::error::Error as LandstripError;
use crate::paths::PathExt;
use crate::trap::ProcessContext;
use anyhow::Result;
use nix::errno::Errno;
use nix::sys::prctl;
use nix::sys::stat::fstat;
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::collections::VecDeque;
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{self, IoSliceMut};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub(super) struct Subreaper {
    restore_needed: bool,
    cleanup_pending: bool,
    listener: Option<OwnedFd>,
}

impl Subreaper {
    pub(super) fn acquire() -> Result<Self> {
        let was_subreaper = prctl::get_child_subreaper().map_err(LandstripError::from)?;
        if !was_subreaper {
            prctl::set_child_subreaper(true).map_err(LandstripError::from)?;
        }
        Ok(Self {
            restore_needed: !was_subreaper,
            cleanup_pending: false,
            listener: None,
        })
    }

    pub(super) fn track_descendants(&mut self) {
        self.cleanup_pending = true;
    }

    pub(super) fn retain_listener(&mut self, listener: OwnedFd) -> BorrowedFd<'_> {
        let listener: &OwnedFd = self.listener.insert(listener);
        listener.as_fd()
    }

    pub(super) fn finish(mut self) -> Result<()> {
        self.teardown()
    }

    fn teardown(&mut self) -> Result<()> {
        let cleanup = if mem::take(&mut self.cleanup_pending) {
            Self::cleanup_descendants()
        } else {
            Ok(())
        };
        let restore = if mem::take(&mut self.restore_needed) {
            prctl::set_child_subreaper(false)
                .map_err(LandstripError::from)
                .map_err(Into::into)
        } else {
            Ok(())
        };
        if cleanup.is_err()
            && let Err(error) = &restore
        {
            log::error!("restore subreaper: {error:#}");
        }
        cleanup.and(restore)
    }

    fn child_pids() -> Result<Vec<Pid>> {
        let children =
            fs::read_to_string("/proc/thread-self/children").map_err(LandstripError::supervise)?;
        children
            .split_whitespace()
            .map(|pid| {
                pid.parse::<i32>().map(Pid::from_raw).map_err(|error| {
                    LandstripError::supervise(io::Error::new(io::ErrorKind::InvalidData, error))
                        .into()
                })
            })
            .collect()
    }

    fn cleanup_descendants() -> Result<()> {
        loop {
            let children = Self::child_pids()?;
            if children.is_empty() {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Err(Errno::ECHILD) => return Ok(()),
                    Ok(_) | Err(Errno::EINTR) => continue,
                    Err(error) => return Err(LandstripError::from(error).into()),
                }
            }

            let mut kill_error = None;
            for child in children {
                // SAFETY: child came from the kernel's direct-child list.
                if unsafe { libc::kill(child.as_raw(), libc::SIGKILL) } == -1 {
                    let error = Errno::last();
                    if error != Errno::ESRCH && kill_error.is_none() {
                        kill_error = Some(error);
                    }
                }
            }
            if let Some(error) = kill_error {
                return Err(LandstripError::from(error).into());
            }

            loop {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => break,
                    Ok(_) | Err(Errno::EINTR) => {}
                    Err(error) => return Err(LandstripError::from(error).into()),
                }
            }
            std::thread::yield_now();
        }
    }
}

impl Drop for Subreaper {
    fn drop(&mut self) {
        if let Err(error) = self.teardown() {
            log::error!("subreaper teardown: {error:#}");
        }
    }
}

pub(super) struct TargetProcess {
    pub(super) pid: Pid,
}

impl TargetProcess {
    pub(super) fn new(pid: Pid) -> Self {
        Self { pid }
    }

    pub(super) fn from_raw(pid: u32) -> Self {
        Self::new(Pid::from_raw(pid.cast_signed()))
    }

    pub(super) fn proc_path(&self, entry: &str) -> PathBuf {
        Path::new("/proc").join(self.pid.to_string()).join(entry)
    }

    pub(super) fn context(&self) -> ProcessContext {
        let pid = self.pid.as_raw().cast_unsigned();
        ProcessContext {
            pid,
            exe: fs::read_link(self.proc_path("exe"))
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
            cwd: fs::read_link(self.proc_path("cwd"))
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
        }
    }

    pub(super) fn read_exact(&self, addr: usize, buf: &mut [u8]) -> SysResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if addr == 0 {
            return Err(BrokerError::BadAddress);
        }
        let len = buf.len();
        let mut local = [IoSliceMut::new(buf)];
        let target = [RemoteIoVec { base: addr, len }];
        if process_vm_readv(self.pid, &mut local, &target)? != len {
            return Err(BrokerError::BadAddress);
        }
        Ok(())
    }

    pub(super) fn read_vec(&self, addr: usize, len: usize) -> SysResult<Vec<u8>> {
        let mut buf = vec![0_u8; len];
        self.read_exact(addr, &mut buf)?;
        Ok(buf)
    }

    pub(super) fn read_string(&self, addr: usize, max_len: usize) -> SysResult<Vec<u8>> {
        let mut buf = vec![0_u8; max_len];
        let mut local = [IoSliceMut::new(&mut buf)];
        let target = [RemoteIoVec {
            base: addr,
            len: max_len,
        }];
        let n = process_vm_readv(self.pid, &mut local, &target)?;
        if n == 0 {
            return Err(BrokerError::BadAddress);
        }
        let slice = &buf[..n];
        let end = slice
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(BrokerError::NameTooLong)?;
        buf.truncate(end);
        Ok(buf)
    }

    pub(super) fn read_path(&self, path_ptr: usize) -> SysResult<PathBuf> {
        if path_ptr == 0 {
            return Err(BrokerError::BadAddress);
        }
        let buf = self.read_string(path_ptr, libc::PATH_MAX as usize)?;
        Ok(PathBuf::from(OsStr::from_bytes(&buf)))
    }

    pub(super) fn read_nonempty_path(&self, path_ptr: usize) -> SysResult<PathBuf> {
        let path = self.read_path(path_ptr)?;
        if path.as_os_str().is_empty() {
            return Err(BrokerError::SystemCall {
                errno: libc::ENOENT,
            });
        }
        Ok(path)
    }

    pub(super) fn read_bytes(&self, ptr: u64, size: u64) -> SysResult<Vec<u8>> {
        const XATTR_MAX: usize = 65536;

        let len =
            usize::try_from(size).map_err(|_| BrokerError::SystemCall { errno: libc::E2BIG })?;
        if len > XATTR_MAX {
            return Err(BrokerError::SystemCall { errno: libc::E2BIG });
        }
        if len == 0 {
            return Ok(Vec::new());
        }

        let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
        self.read_vec(addr, len)
    }

    pub(super) fn read_times(&self, ptr: u64) -> SysResult<Option<[libc::timespec; 2]>> {
        let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
        if addr == 0 {
            return Ok(None);
        }
        let mut times = [libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }; 2];
        let len = mem::size_of_val(&times);
        // SAFETY: times is a live, suitably aligned array of two POD timespecs that
        // we expose as its raw byte span for the copy from the child.
        let bytes = unsafe { std::slice::from_raw_parts_mut(times.as_mut_ptr().cast::<u8>(), len) };
        self.read_exact(addr, bytes)?;
        Ok(Some(times))
    }

    pub(super) fn read_xattr_name(&self, ptr: u64) -> SysResult<CString> {
        const XATTR_NAME_MAX: usize = 255;

        let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
        if addr == 0 {
            return Err(BrokerError::BadAddress);
        }
        let buf = match self.read_string(addr, XATTR_NAME_MAX + 1) {
            Err(BrokerError::NameTooLong) => {
                return Err(BrokerError::SystemCall {
                    errno: libc::ERANGE,
                });
            }
            result => result?,
        };
        CString::new(buf).map_err(|_| BrokerError::BadAddress)
    }

    pub(super) fn read_target(&self, ptr: u64) -> SysResult<CString> {
        let addr = usize::try_from(ptr).map_err(|_| BrokerError::BadAddress)?;
        if addr == 0 {
            return Err(BrokerError::BadAddress);
        }
        let buf = self.read_string(addr, libc::PATH_MAX as usize)?;
        CString::new(buf).map_err(|_| BrokerError::InvalidAddress)
    }

    pub(super) fn read_sockaddr(&self, target_addr: usize, addr_len: usize) -> SysResult<Vec<u8>> {
        if addr_len < mem::size_of::<libc::sa_family_t>() {
            return Err(BrokerError::InvalidAddress);
        }
        self.read_vec(target_addr, addr_len)
    }

    pub(super) fn thread_group_leader(&self) -> SysResult<Pid> {
        let status = fs::read_to_string(self.proc_path("status"))?;
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix("Tgid:"))
            .ok_or(BrokerError::InvalidAddress)?;
        let tgid = value
            .trim()
            .parse::<i32>()
            .map_err(|_| BrokerError::InvalidAddress)?;
        if tgid <= 0 {
            return Err(BrokerError::InvalidAddress);
        }

        Ok(Pid::from_raw(tgid))
    }

    pub(super) fn duplicate_fd(&self, fd: RawFd) -> SysResult<OwnedFd> {
        let pidfd = match self.open_pidfd(libc::O_EXCL as libc::c_uint) {
            Ok(pidfd) => pidfd,
            Err(Errno::EINVAL | Errno::ENOSYS) => match self.open_pidfd(0) {
                Ok(pidfd) => pidfd,
                Err(Errno::EINVAL) => {
                    let leader = TargetProcess::new(self.thread_group_leader()?);
                    leader.open_pidfd(0)?
                }
                Err(error) => return Err(error.into()),
            },
            Err(error) => return Err(error.into()),
        };

        // SAFETY: pidfd_getfd copies scalar arguments and returns a duplicated fd.
        let target = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
        if target < 0 {
            return Err(Errno::last().into());
        }

        let target = RawFd::try_from(target).map_err(|_| BrokerError::BadFileDescriptor)?;
        // SAFETY: pidfd_getfd returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(target) })
    }

    pub(super) fn open_pidfd(&self, flags: libc::c_uint) -> std::result::Result<OwnedFd, Errno> {
        // SAFETY: pidfd_open copies scalar arguments and returns a new fd on success.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid.as_raw(), flags) };
        if pidfd < 0 {
            return Err(Errno::last());
        }
        let pidfd = RawFd::try_from(pidfd).map_err(|_| Errno::EMFILE)?;
        // SAFETY: pidfd_open returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
    }

    pub(super) fn filesystem(&self) -> SysResult<TargetFilesystem<'_>> {
        let root = super::grant::open_path(
            &self.proc_path("root"),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let root_label = super::grant::open_fd_path(root.as_fd())?;
        Ok(TargetFilesystem {
            process: self,
            root,
            root_label,
        })
    }

    pub(super) fn open_dirfd(&self, dirfd: RawFd) -> SysResult<OwnedFd> {
        if dirfd == libc::AT_FDCWD {
            return super::grant::open_path(
                &self.proc_path("cwd"),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            );
        }
        self.duplicate_fd(dirfd)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MissingTarget {
    Disallow,
    File,
    Directory,
}

pub(super) struct ResolvedPath {
    pub(super) lexical: PathBuf,
    pub(super) label: PathBuf,
    pub(super) trailing_slash: bool,
    pub(super) anonymous: bool,
    pub(super) anchor: Option<super::grant::Anchor>,
    pub(super) root: OwnedFd,
}

impl ResolvedPath {
    pub(super) fn is_directory(&self) -> bool {
        self.anchor
            .as_ref()
            .and_then(|anchor| anchor.target.as_ref())
            .and_then(|fd| fstat(fd).ok())
            .is_some_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFDIR)
    }
}

pub(super) struct TargetFilesystem<'a> {
    process: &'a TargetProcess,
    pub(super) root: OwnedFd,
    pub(super) root_label: PathBuf,
}

impl TargetFilesystem<'_> {
    pub(super) fn label(&self, fd: BorrowedFd<'_>) -> SysResult<PathBuf> {
        label_under_root(&self.root_label, fd)
    }

    fn proc_alias(&self, name: &[u8]) -> SysResult<Vec<u8>> {
        let status = fs::read_to_string(self.process.proc_path("status"))?;
        let id = |field: &str| -> SysResult<&str> {
            let value = status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .and_then(|values| values.split_whitespace().last())
                .ok_or_else(|| BrokerError::syscall(libc::EIO))?;
            if value
                .parse::<u32>()
                .map_err(|_| BrokerError::syscall(libc::EIO))?
                == 0
            {
                return Err(BrokerError::syscall(libc::EIO));
            }
            Ok(value)
        };
        let group_id = id("NStgid:")?;
        if name == b"self" {
            return Ok(group_id.as_bytes().to_vec());
        }
        let thread_id = id("NSpid:")?;
        Ok(format!("{group_id}/task/{thread_id}").into_bytes())
    }

    fn directory_stack(&self, base: BorrowedFd<'_>) -> SysResult<Vec<OwnedFd>> {
        let mut dirs = vec![self.root.try_clone()?];
        for component in self.label(base)?.components().skip(1) {
            let name = CString::new(component.as_os_str().as_bytes())?;
            let how = super::grant::OpenHow {
                flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                mode: 0,
                resolve: 0x04 | 0x02 | 0x08,
            };
            dirs.push(
                how.openat2(
                    dirs.last()
                        .ok_or_else(|| BrokerError::syscall(libc::EIO))?
                        .as_raw_fd(),
                    &name,
                )?,
            );
        }
        if !same_object(
            dirs.last()
                .ok_or_else(|| BrokerError::syscall(libc::EIO))?
                .as_fd(),
            base,
        )? {
            return Err(BrokerError::syscall(libc::ESTALE));
        }
        // Keep the actual descriptor, not a pathname substitute from another mount.
        *dirs
            .last_mut()
            .ok_or_else(|| BrokerError::syscall(libc::EIO))? = base.try_clone_to_owned()?;
        Ok(dirs)
    }

    fn proc_root(&self) -> SysResult<OwnedFd> {
        super::grant::OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: 0x04 | 0x02 | 0x08,
        }
        .openat2(self.root.as_raw_fd(), c"proc")
    }

    fn proc_magic(&self, parent: BorrowedFd<'_>, component: &[u8]) -> SysResult<Option<OwnedFd>> {
        let how = super::grant::OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: 0x04 | 0x02 | 0x08,
        };
        let proc = self.proc_root()?;
        for alias in [b"self".as_slice(), b"thread-self".as_slice()] {
            let task = self.proc_alias(alias)?;
            let task = CString::new(task)?;
            let task = how.openat2(proc.as_raw_fd(), &task)?;
            if same_object(parent, task.as_fd())? {
                return match component {
                    b"root" => Ok(Some(self.root.try_clone()?)),
                    b"cwd" => Ok(Some(self.process.open_dirfd(libc::AT_FDCWD)?)),
                    b"exe" => Ok(Some(super::grant::open_path(
                        &self.process.proc_path("exe"),
                        libc::O_PATH | libc::O_CLOEXEC,
                    )?)),
                    _ => Ok(None),
                };
            }
            let fds = how.openat2(task.as_raw_fd(), c"fd")?;
            if same_object(parent, fds.as_fd())? {
                let fd = std::str::from_utf8(component)
                    .ok()
                    .and_then(|value| value.parse::<RawFd>().ok())
                    .filter(|fd| *fd >= 0)
                    .ok_or_else(|| BrokerError::syscall(libc::ELOOP))?;
                return Ok(Some(self.process.duplicate_fd(fd)?));
            }
        }
        Ok(None)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "path resolution keeps one component walk with TOCTOU-safe state"
    )]
    pub(super) fn resolve(
        &self,
        dirfd: RawFd,
        path: &Path,
        follow: bool,
        missing: MissingTarget,
        resolve: u64,
    ) -> SysResult<ResolvedPath> {
        const BENEATH: u64 = 0x08;
        const IN_ROOT: u64 = 0x10;
        const NO_SYMLINKS: u64 = 0x04;
        if resolve & !0x3f != 0 || resolve & (BENEATH | IN_ROOT) == (BENEATH | IN_ROOT) {
            return Err(BrokerError::syscall(libc::EINVAL));
        }
        if resolve & 0x01 != 0 {
            return Err(BrokerError::syscall(libc::EOPNOTSUPP));
        }
        if resolve & 0x20 != 0 {
            return Err(BrokerError::syscall(libc::EAGAIN));
        }
        if path.as_os_str().is_empty() {
            return Err(BrokerError::syscall(libc::ENOENT));
        }
        if path.is_absolute() && resolve & BENEATH != 0 {
            return Err(BrokerError::syscall(libc::EXDEV));
        }
        let scoped = resolve & (IN_ROOT | BENEATH) != 0;
        let base = if !path.is_absolute() || scoped {
            self.process.open_dirfd(dirfd)?
        } else {
            self.root.try_clone()?
        };
        let base_label = self.label(base.as_fd())?;
        let lexical = if path.is_absolute() && !scoped {
            path.to_path_buf()
        } else {
            base_label.join(path.strip_prefix("/").unwrap_or(path))
        }
        .clean_lexically();
        let mut dirs = self.directory_stack(base.as_fd())?;
        let floor = if scoped { dirs.len() } else { 1 };
        let mut pending = path_components(path.as_os_str().as_bytes());
        let trailing_slash = path.as_os_str().as_bytes().ends_with(b"/");
        let mut links = 0;
        loop {
            let component = pending.pop_front().unwrap_or_else(|| b".".to_vec());
            if component == b".." {
                if dirs.len() > floor {
                    dirs.pop();
                } else if resolve & BENEATH != 0 {
                    return Err(BrokerError::syscall(libc::EXDEV));
                }
                if !pending.is_empty() {
                    continue;
                }
            } else if component == b"." && !pending.is_empty() {
                continue;
            }
            let name = CString::new(if component == b".." {
                b".".as_slice()
            } else {
                &component
            })?;
            let parent = dirs.last().ok_or_else(|| BrokerError::syscall(libc::EIO))?;
            let how = super::grant::OpenHow {
                flags: (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
                mode: 0,
                resolve: 0x02 | 0x08,
            };
            let mut object = match how.openat2(parent.as_raw_fd(), &name) {
                Ok(fd) => Some(fd),
                Err(BrokerError::SystemCall {
                    errno: libc::ENOENT,
                }) if missing != MissingTarget::Disallow => {
                    if !pending.is_empty()
                        || (trailing_slash && missing != MissingTarget::Directory)
                    {
                        let mut label = self
                            .label(parent.as_fd())?
                            .join(OsStr::from_bytes(&component));
                        for part in pending {
                            label.push(OsStr::from_bytes(&part));
                        }
                        return Ok(ResolvedPath {
                            lexical,
                            label: label.clean_lexically(),
                            trailing_slash,
                            anonymous: false,
                            anchor: None,
                            root: self.root.try_clone()?,
                        });
                    }
                    None
                }
                Err(errno) => return Err(errno),
            };
            if let Some(fd) = &object {
                let stat = fstat(fd)?;
                if stat.st_mode & libc::S_IFMT == libc::S_IFLNK
                    && (!pending.is_empty()
                        || follow
                        || (trailing_slash && missing != MissingTarget::Directory))
                {
                    if resolve & NO_SYMLINKS != 0 || links == 40 {
                        return Err(BrokerError::syscall(libc::ELOOP));
                    }
                    links += 1;
                    let mut filesystem = unsafe { mem::zeroed::<libc::statfs>() };
                    let rc = unsafe { libc::fstatfs(parent.as_raw_fd(), &raw mut filesystem) };
                    Errno::result(rc)?;
                    let procfs = filesystem.f_type == 0x9fa0;
                    let target = if procfs && (component == b"self" || component == b"thread-self")
                    {
                        if !same_object(parent.as_fd(), self.proc_root()?.as_fd())? {
                            return Err(BrokerError::syscall(libc::ELOOP));
                        }
                        self.proc_alias(&component)?
                    } else {
                        if procfs {
                            if resolve & (0x02 | BENEATH | IN_ROOT) != 0 {
                                return Err(BrokerError::syscall(libc::ELOOP));
                            }
                            if let Some(target) = self.proc_magic(parent.as_fd(), &component)? {
                                if !pending.is_empty() {
                                    if fstat(&target)?.st_mode & libc::S_IFMT != libc::S_IFDIR {
                                        return Err(BrokerError::syscall(libc::ENOTDIR));
                                    }
                                    dirs = self.directory_stack(target.as_fd())?;
                                    continue;
                                }
                                if trailing_slash
                                    && missing != MissingTarget::Directory
                                    && fstat(&target)?.st_mode & libc::S_IFMT != libc::S_IFDIR
                                {
                                    return Err(BrokerError::syscall(libc::ENOTDIR));
                                }
                                let (label, anonymous) =
                                    match fd_label_under_root(&self.root_label, target.as_fd())? {
                                        Some(label) => (label, false),
                                        None => (
                                            self.label(parent.as_fd())?
                                                .join(OsStr::from_bytes(name.as_bytes())),
                                            true,
                                        ),
                                    };
                                return Ok(ResolvedPath {
                                    lexical,
                                    label,
                                    trailing_slash,
                                    anonymous,
                                    anchor: Some(super::grant::Anchor {
                                        dir: parent.try_clone()?,
                                        name,
                                        target: Some(target),
                                    }),
                                    root: self.root.try_clone()?,
                                });
                            }
                        }
                        let mut bytes = vec![0; libc::PATH_MAX as usize];
                        let length = unsafe {
                            libc::readlinkat(
                                fd.as_raw_fd(),
                                c"".as_ptr(),
                                bytes.as_mut_ptr().cast(),
                                bytes.len(),
                            )
                        };
                        let length = Errno::result(length)?;
                        let length = usize::try_from(length)?;
                        if length == bytes.len() {
                            return Err(BrokerError::syscall(libc::ENAMETOOLONG));
                        }
                        bytes.truncate(length);
                        bytes
                    };
                    if target.starts_with(b"/") {
                        if resolve & BENEATH != 0 {
                            return Err(BrokerError::syscall(libc::EXDEV));
                        }
                        dirs.truncate(floor);
                    }
                    let mut expanded = path_components(&target);
                    if target.ends_with(b"/") && pending.is_empty() {
                        expanded.push_back(b".".to_vec());
                    }
                    expanded.append(&mut pending);
                    pending = expanded;
                    continue;
                }
                if !pending.is_empty() {
                    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
                        return Err(BrokerError::syscall(libc::ENOTDIR));
                    }
                    dirs.push(object.ok_or_else(|| BrokerError::syscall(libc::EIO))?);
                    continue;
                }
                if trailing_slash
                    && missing != MissingTarget::Directory
                    && stat.st_mode & libc::S_IFMT != libc::S_IFDIR
                {
                    return Err(BrokerError::syscall(libc::ENOTDIR));
                }
            }
            let label = match &object {
                Some(fd) => self.label(fd.as_fd())?,
                None => self
                    .label(parent.as_fd())?
                    .join(OsStr::from_bytes(name.as_bytes())),
            };
            return Ok(ResolvedPath {
                lexical,
                label,
                trailing_slash,
                anonymous: false,
                anchor: Some(super::grant::Anchor {
                    dir: parent.try_clone()?,
                    name,
                    target: object.take(),
                }),
                root: self.root.try_clone()?,
            });
        }
    }
}

fn path_components(path: &[u8]) -> VecDeque<Vec<u8>> {
    path.split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn same_object(left: BorrowedFd<'_>, right: BorrowedFd<'_>) -> SysResult<bool> {
    fn identity(fd: BorrowedFd<'_>) -> SysResult<(u64, u64)> {
        let mut stat = unsafe { mem::zeroed::<libc::statx>() };
        let rc = unsafe {
            libc::statx(
                fd.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                libc::STATX_INO | libc::STATX_MNT_ID,
                &raw mut stat,
            )
        };
        Errno::result(rc)?;
        if stat.stx_mask & libc::STATX_MNT_ID == 0 {
            return Err(BrokerError::syscall(libc::EOPNOTSUPP));
        }
        Ok((stat.stx_mnt_id, stat.stx_ino))
    }
    Ok(identity(left)? == identity(right)?)
}

pub(super) fn fd_label_under_root(root: &Path, fd: BorrowedFd<'_>) -> SysResult<Option<PathBuf>> {
    let label = super::grant::open_fd_path(fd)?;
    if !label.is_absolute() {
        return Ok(None);
    }
    let label = if let Some(label) = label.as_os_str().as_bytes().strip_suffix(b" (deleted)") {
        // An unlinked file still has the path it was opened through in procfs.
        // Check that path instead of rejecting every deleted descriptor, but
        // keep denying deleted entries that remain reachable through a link.
        if fstat(fd)?.st_nlink != 0 {
            return Err(BrokerError::syscall(libc::EACCES));
        }
        PathBuf::from(OsStr::from_bytes(label))
    } else {
        label
    };
    let relative = label
        .strip_prefix(root)
        .map_err(|_| BrokerError::syscall(libc::EXDEV))?;
    Ok(Some(Path::new("/").join(relative)))
}

pub(super) fn label_under_root(root: &Path, fd: BorrowedFd<'_>) -> SysResult<PathBuf> {
    fd_label_under_root(root, fd)?.ok_or_else(|| BrokerError::syscall(libc::EACCES))
}
