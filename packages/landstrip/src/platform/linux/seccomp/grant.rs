// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use super::fs::SYS_FCHMODAT2;
use super::network::{SocketAddrCall, TargetSocket};
use super::notify::{NotificationChannel, NotificationResponse};
use super::process::{ResolvedPath, fd_label_under_root, label_under_root};
use crate::error::Error as LandstripError;
use crate::policy::AccessPolicy;
use nix::errno::Errno;
use nix::sys::stat::fstat;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

pub(super) const OPEN_HOW_SIZE: usize = 24;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct OpenHow {
    pub(super) flags: u64,
    pub(super) mode: u64,
    pub(super) resolve: u64,
}

impl OpenHow {
    pub(super) fn openat2(&self, dirfd: RawFd, path: &CStr) -> SysResult<OwnedFd> {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                ptr::addr_of!(*self),
                OPEN_HOW_SIZE,
            )
        };
        let fd = Errno::result(rc)?;
        let fd = RawFd::try_from(fd).map_err(|_| BrokerError::syscall(libc::EMFILE))?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn validate(&self) -> SysResult<()> {
        match self.openat2(libc::AT_FDCWD, c"") {
            Err(BrokerError::SystemCall {
                errno: libc::ENOENT,
            }) => Ok(()),
            Err(err) => Err(err),
            Ok(_) => Err(BrokerError::syscall(libc::EIO)),
        }
    }
}

impl TryFrom<&[u8]> for OpenHow {
    type Error = BrokerError;

    fn try_from(buf: &[u8]) -> SysResult<Self> {
        if buf.len() < OPEN_HOW_SIZE {
            return Err(BrokerError::InvalidAddress);
        }
        if buf[OPEN_HOW_SIZE..].iter().any(|byte| *byte != 0) {
            return Err(BrokerError::SystemCall { errno: libc::E2BIG });
        }

        let how = Self {
            flags: u64::from_ne_bytes(buf[0..8].try_into().map_err(|_| BrokerError::BadAddress)?),
            mode: u64::from_ne_bytes(buf[8..16].try_into().map_err(|_| BrokerError::BadAddress)?),
            resolve: u64::from_ne_bytes(
                buf[16..24]
                    .try_into()
                    .map_err(|_| BrokerError::BadAddress)?,
            ),
        };
        how.validate()?;
        Ok(how)
    }
}

pub(super) enum Grant {
    Open(OpenGrant),
    // Preparation failures still await the policy decision before being returned.
    Mutation(SysResult<MutationGrant>),
    Socket(SocketGrant),
}

impl Grant {
    pub(super) fn apply(&self, policy: &AccessPolicy, notify: NotificationChannel<'_>, id: u64) {
        match self {
            Self::Open(grant) => grant.apply(policy, notify, id),
            Self::Mutation(Ok(grant)) => grant.apply(notify, id),
            Self::Mutation(Err(error)) => {
                let _ = notify.respond(NotificationResponse::error(id, error.errno()));
            }
            Self::Socket(grant) => grant.apply(notify, id),
        }
    }
}

impl From<OpenGrant> for Grant {
    fn from(grant: OpenGrant) -> Self {
        Self::Open(grant)
    }
}

impl From<MutationGrant> for Grant {
    fn from(grant: MutationGrant) -> Self {
        Self::Mutation(Ok(grant))
    }
}

impl From<SocketGrant> for Grant {
    fn from(grant: SocketGrant) -> Self {
        Self::Socket(grant)
    }
}

pub(super) struct SocketGrant {
    pub(super) sock: OwnedFd,
    pub(super) addr: Vec<u8>,
    pub(super) call: SocketAddrCall,
    pub(super) _path: Option<Anchor>,
}

impl SocketGrant {
    pub(super) fn new(socket: TargetSocket, call: SocketAddrCall) -> Self {
        Self {
            sock: socket.sock,
            addr: socket.addr,
            call,
            _path: None,
        }
    }

    pub(super) fn apply(&self, notify: NotificationChannel<'_>, id: u64) {
        let rc = match broker_addr_call(self.sock.as_raw_fd(), &self.addr, self.call) {
            Ok(value) => NotificationResponse::success(id, value),
            Err(error) => NotificationResponse::error(id, error.errno()),
        };
        let _ = notify.respond(rc);
    }
}

fn broker_addr_call(sock: RawFd, addr: &[u8], call: SocketAddrCall) -> Result<i64, BrokerError> {
    let len = libc::socklen_t::try_from(addr.len()).map_err(|_| BrokerError::InvalidAddress)?;
    let rc = unsafe { call(sock, addr.as_ptr().cast(), len) };
    if rc < 0 {
        return Err(Errno::last().into());
    }
    Ok(i64::from(rc))
}

pub(super) struct Anchor {
    pub(super) dir: OwnedFd,
    pub(super) name: CString,
    pub(super) target: Option<OwnedFd>,
}

impl Anchor {
    pub(super) fn into_target(self) -> SysResult<OwnedFd> {
        let fd = self
            .target
            .ok_or_else(|| BrokerError::syscall(libc::ENOENT))?;
        validate_nofollow_target(fd.as_fd(), libc::O_NOFOLLOW)?;
        Ok(fd)
    }

    pub(super) fn path(&self) -> SysResult<CString> {
        let mut path = format!("/proc/self/fd/{}/", self.dir.as_raw_fd()).into_bytes();
        path.extend_from_slice(self.name.as_bytes());
        Ok(CString::new(path)?)
    }
}

pub(super) struct OpenGrant {
    pub(super) flags: i32,
    pub(super) kind: OpenKind,
    label: PathBuf,
    root: OwnedFd,
}

impl OpenGrant {
    pub(super) fn new(
        mut resolved: ResolvedPath,
        flags: i32,
        mode: u32,
        resolve: u64,
    ) -> SysResult<Self> {
        if flags & libc::O_TMPFILE == libc::O_TMPFILE {
            return Err(BrokerError::syscall(libc::EOPNOTSUPP));
        }
        let mut anchor = resolved.anchor.take().ok_or_else(|| {
            if resolved.trailing_slash && flags & libc::O_CREAT != 0 {
                BrokerError::syscall(libc::EISDIR)
            } else {
                BrokerError::syscall(libc::ENOENT)
            }
        })?;
        let kind = match anchor.target.take() {
            Some(handle) => {
                if flags & libc::O_CREAT != 0 && flags & libc::O_EXCL != 0 {
                    return Err(BrokerError::syscall(libc::EEXIST));
                }
                validate_nofollow_target(handle.as_fd(), flags)?;
                if flags & libc::O_DIRECTORY != 0 {
                    let stat = fstat(&handle)?;
                    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
                        return Err(BrokerError::syscall(libc::ENOTDIR));
                    }
                }
                OpenKind::Reopen(handle)
            }
            None if flags & libc::O_CREAT != 0 => OpenKind::Create {
                anchor,
                mode,
                resolve,
            },
            None => return Err(BrokerError::syscall(libc::ENOENT)),
        };
        Ok(Self {
            flags,
            kind,
            label: resolved.label,
            root: resolved.root,
        })
    }

    pub(super) fn open(&self) -> SysResult<OwnedFd> {
        match &self.kind {
            OpenKind::Reopen(handle) => {
                if self.flags & libc::O_PATH != 0 {
                    return handle.try_clone().map_err(BrokerError::from);
                }
                let flags = (self.flags
                    & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_TRUNC))
                    | libc::O_CLOEXEC;
                reopen_fd(handle.as_fd(), flags)
            }
            OpenKind::Create {
                anchor,
                mode,
                resolve,
            } => {
                let flags = (self.flags & !libc::O_TRUNC) | libc::O_NOFOLLOW | libc::O_CLOEXEC;
                if *resolve != 0 {
                    let how = OpenHow {
                        flags: u64::try_from(flags)?,
                        mode: u64::from(*mode),
                        resolve: *resolve,
                    };
                    return how.openat2(anchor.dir.as_raw_fd(), &anchor.name);
                }
                let fd = unsafe {
                    libc::openat(
                        anchor.dir.as_raw_fd(),
                        anchor.name.as_ptr(),
                        flags,
                        *mode as libc::c_uint,
                    )
                };
                let fd = Errno::result(fd)?;
                let fd = RawFd::try_from(fd).map_err(|_| BrokerError::syscall(libc::EMFILE))?;
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        }
    }

    fn check_policy(&self, policy: &AccessPolicy, fd: BorrowedFd<'_>) -> SysResult<()> {
        let root = open_fd_path(self.root.as_fd())?;
        if let Some(label) = fd_label_under_root(&root, fd)? {
            self.check_label(policy, &label)?;
        }
        Ok(())
    }

    fn check_label(&self, policy: &AccessPolicy, label: &Path) -> SysResult<()> {
        let moved = label != self.label;
        if self.flags & libc::O_WRONLY == 0
            && (policy.read_denials.is_denied_always(label, label)
                || (moved && policy.read_reason(label).is_some()))
        {
            return Err(BrokerError::syscall(libc::EACCES));
        }
        if self.flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) != 0
            && (policy.write_denials.is_denied_always(label, label)
                || (moved && policy.write_reason(label, true).is_some()))
        {
            return Err(BrokerError::syscall(libc::EACCES));
        }
        Ok(())
    }

    pub(super) fn apply(&self, policy: &AccessPolicy, notify: NotificationChannel<'_>, id: u64) {
        let opened: SysResult<OwnedFd> = (|| {
            // Approval does not authorize a later rename into a denied subtree.
            // Recheck before opening and after opening, before any truncation.
            match &self.kind {
                OpenKind::Reopen(handle) => self.check_policy(policy, handle.as_fd())?,
                OpenKind::Create { anchor, .. } => {
                    let root = open_fd_path(self.root.as_fd())?;
                    let label = label_under_root(&root, anchor.dir.as_fd())?
                        .join(std::ffi::OsStr::from_bytes(anchor.name.as_bytes()));
                    self.check_label(policy, &label)?;
                }
            }
            let fd = self.open()?;
            self.check_policy(policy, fd.as_fd())?;
            if self.flags & libc::O_TRUNC != 0 {
                let stat = fstat(&fd)?;
                if stat.st_mode & libc::S_IFMT == libc::S_IFREG {
                    if self.flags & libc::O_ACCMODE == libc::O_RDONLY {
                        // Linux also permits O_RDONLY|O_TRUNC; do not give the
                        // target a writable descriptor just to truncate it.
                        let writable = reopen_fd(fd.as_fd(), libc::O_WRONLY | libc::O_CLOEXEC)?;
                        self.check_policy(policy, writable.as_fd())?;
                        let rc = unsafe { libc::ftruncate(writable.as_raw_fd(), 0) };
                        Errno::result(rc)?;
                    } else {
                        let rc = unsafe { libc::ftruncate(fd.as_raw_fd(), 0) };
                        Errno::result(rc)?;
                    }
                }
            }
            Ok(fd)
        })();
        let opened = match opened {
            Ok(fd) => fd,
            Err(err) => {
                let _ = notify.respond(NotificationResponse::error(id, err.errno()));
                return;
            }
        };

        let cloexec = self.flags & libc::O_CLOEXEC != 0;
        let addfd = libc::seccomp_notif_addfd {
            id,
            flags: u32::try_from(libc::SECCOMP_ADDFD_FLAG_SEND).unwrap_or(0),
            srcfd: u32::try_from(opened.as_raw_fd()).unwrap_or(0),
            newfd: 0,
            newfd_flags: if cloexec {
                u32::try_from(libc::O_CLOEXEC).unwrap_or(0)
            } else {
                0
            },
        };

        if notify.add_fd(&addfd).is_err() {
            let _ = notify.respond(NotificationResponse::error(
                id,
                LandstripError::DENIAL_ERRNO,
            ));
        }
    }
}

pub(super) enum OpenKind {
    Reopen(OwnedFd),
    Create {
        anchor: Anchor,
        mode: u32,
        resolve: u64,
    },
}

pub(super) enum MutationGrant {
    Mkdir {
        at: Anchor,
        mode: u32,
    },
    Mknod {
        at: Anchor,
        mode: u32,
        dev: u64,
    },
    Unlink {
        at: Anchor,
        flags: i32,
    },
    Symlink {
        at: Anchor,
        target: CString,
    },
    Truncate {
        target: OwnedFd,
        length: i64,
    },
    Rename {
        from: Anchor,
        to: Anchor,
        flags: u32,
    },
    Link {
        from: MutationTarget,
        to: Anchor,
        flags: i32,
    },
    Chmod {
        target: OwnedFd,
        mode: u32,
    },
    Metadata {
        target: MutationTarget,
        mutation: PathMutation,
    },
    Fd {
        target: OwnedFd,
        mutation: FdMutation,
    },
}

impl MutationGrant {
    pub(super) fn run(&self) -> SysResult<()> {
        match self {
            Self::Mkdir { at, mode } => {
                Errno::result(unsafe {
                    libc::mkdirat(at.dir.as_raw_fd(), at.name.as_ptr(), *mode)
                })?;
            }
            Self::Mknod { at, mode, dev } => {
                Errno::result(unsafe {
                    libc::mknodat(at.dir.as_raw_fd(), at.name.as_ptr(), *mode, *dev)
                })?;
            }
            Self::Unlink { at, flags } => {
                Errno::result(unsafe {
                    libc::unlinkat(at.dir.as_raw_fd(), at.name.as_ptr(), *flags)
                })?;
            }
            Self::Symlink { at, target } => {
                Errno::result(unsafe {
                    libc::symlinkat(target.as_ptr(), at.dir.as_raw_fd(), at.name.as_ptr())
                })?;
            }
            Self::Truncate { target, length } => {
                let writable = reopen_fd(target.as_fd(), libc::O_WRONLY | libc::O_CLOEXEC)?;
                Errno::result(unsafe { libc::ftruncate(writable.as_raw_fd(), *length) })?;
            }
            Self::Rename { from, to, flags } => {
                Errno::result(unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        from.dir.as_raw_fd(),
                        from.name.as_ptr(),
                        to.dir.as_raw_fd(),
                        to.name.as_ptr(),
                        *flags,
                    )
                })?;
            }
            Self::Link { from, to, flags } => {
                let rc = match from {
                    MutationTarget::Entry(at) => unsafe {
                        libc::linkat(
                            at.dir.as_raw_fd(),
                            at.name.as_ptr(),
                            to.dir.as_raw_fd(),
                            to.name.as_ptr(),
                            flags & !libc::AT_SYMLINK_FOLLOW,
                        )
                    },
                    MutationTarget::Pinned(_) => {
                        let path = from.path()?;
                        unsafe {
                            libc::linkat(
                                libc::AT_FDCWD,
                                path.as_ptr(),
                                to.dir.as_raw_fd(),
                                to.name.as_ptr(),
                                libc::AT_SYMLINK_FOLLOW,
                            )
                        }
                    }
                };
                Errno::result(rc)?;
            }
            Self::Chmod { target, mode } => {
                let path = CString::new(format!("/proc/self/fd/{}", target.as_raw_fd()))?;
                Errno::result(unsafe { libc::chmod(path.as_ptr(), *mode) })?;
            }
            Self::Metadata { target, mutation } => mutation.run(target)?,
            Self::Fd { target, mutation } => mutation.run(target.as_raw_fd())?,
        }
        Ok(())
    }

    pub(super) fn apply(&self, notify: NotificationChannel<'_>, id: u64) {
        let rc = match self.run() {
            Ok(()) => NotificationResponse::success(id, 0),
            Err(err) => NotificationResponse::error(id, err.errno()),
        };
        let _ = notify.respond(rc);
    }
}

pub(super) enum MutationTarget {
    Entry(Anchor),
    Pinned(OwnedFd),
}

impl MutationTarget {
    pub(super) fn new(anchor: Anchor, no_follow: bool) -> SysResult<Self> {
        if no_follow {
            Ok(Self::Entry(anchor))
        } else {
            anchor.into_target().map(Self::Pinned)
        }
    }

    fn path(&self) -> SysResult<CString> {
        match self {
            Self::Entry(at) => at.path(),
            Self::Pinned(fd) => Ok(CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))?),
        }
    }

    fn at_path(&self) -> (BorrowedFd<'_>, &CStr, i32) {
        match self {
            Self::Entry(at) => (at.dir.as_fd(), &at.name, libc::AT_SYMLINK_NOFOLLOW),
            Self::Pinned(fd) => (fd.as_fd(), c"", libc::AT_EMPTY_PATH),
        }
    }
}

pub(super) enum PathMutation {
    ChmodAt {
        mode: u32,
    },
    Chown {
        uid: u32,
        gid: u32,
    },
    ChownAt {
        uid: u32,
        gid: u32,
    },
    Utimes {
        times: Option<[libc::timespec; 2]>,
    },
    SetXattr {
        name: CString,
        value: Vec<u8>,
        flags: i32,
    },
    RemoveXattr {
        name: CString,
    },
}

impl PathMutation {
    fn run(&self, target: &MutationTarget) -> SysResult<()> {
        match self {
            Self::ChmodAt { mode } => {
                let (dir, name, target_flags) = target.at_path();
                Errno::result(unsafe {
                    libc::syscall(
                        SYS_FCHMODAT2,
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        *mode,
                        target_flags,
                    )
                })?;
            }
            Self::Chown { uid, gid } => {
                let rc = match target {
                    MutationTarget::Entry(at) => unsafe {
                        libc::fchownat(
                            at.dir.as_raw_fd(),
                            at.name.as_ptr(),
                            *uid,
                            *gid,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    },
                    MutationTarget::Pinned(_) => {
                        let path = target.path()?;
                        unsafe { libc::chown(path.as_ptr(), *uid, *gid) }
                    }
                };
                Errno::result(rc)?;
            }
            Self::ChownAt { uid, gid } => {
                let (dir, name, target_flags) = target.at_path();
                Errno::result(unsafe {
                    libc::fchownat(dir.as_raw_fd(), name.as_ptr(), *uid, *gid, target_flags)
                })?;
            }
            Self::Utimes { times } => {
                let times = times.as_ref().map_or(ptr::null(), |t| t.as_ptr());
                let rc = match target {
                    MutationTarget::Entry(at) => unsafe {
                        libc::utimensat(
                            at.dir.as_raw_fd(),
                            at.name.as_ptr(),
                            times,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    },
                    MutationTarget::Pinned(_) => {
                        let path = target.path()?;
                        unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times, 0) }
                    }
                };
                Errno::result(rc)?;
            }
            Self::SetXattr { name, value, flags } => {
                let path = target.path()?;
                let call = match target {
                    MutationTarget::Entry(_) => libc::lsetxattr,
                    MutationTarget::Pinned(_) => libc::setxattr,
                };
                Errno::result(unsafe {
                    call(
                        path.as_ptr(),
                        name.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        *flags,
                    )
                })?;
            }
            Self::RemoveXattr { name } => {
                let path = target.path()?;
                let call = match target {
                    MutationTarget::Entry(_) => libc::lremovexattr,
                    MutationTarget::Pinned(_) => libc::removexattr,
                };
                Errno::result(unsafe { call(path.as_ptr(), name.as_ptr()) })?;
            }
        }
        Ok(())
    }
}

pub(super) enum FdMutation {
    Chmod {
        mode: u32,
    },
    ChmodAt {
        mode: u32,
        flags: i32,
    },
    Chown {
        uid: u32,
        gid: u32,
    },
    ChownAt {
        uid: u32,
        gid: u32,
        flags: i32,
    },
    Utimes {
        times: Option<[libc::timespec; 2]>,
    },
    SetXattr {
        name: CString,
        value: Vec<u8>,
        flags: i32,
    },
    RemoveXattr {
        name: CString,
    },
}

impl FdMutation {
    pub(super) fn run(&self, target: RawFd) -> SysResult<()> {
        let rc = match self {
            Self::Chmod { mode } => unsafe { libc::fchmod(target, *mode) },
            Self::Chown { uid, gid } => unsafe { libc::fchown(target, *uid, *gid) },
            Self::ChmodAt { mode, flags } => unsafe {
                let rc = libc::syscall(SYS_FCHMODAT2, target, c"".as_ptr(), *mode, *flags);
                if rc < 0 { -1 } else { 0 }
            },
            Self::ChownAt { uid, gid, flags } => unsafe {
                libc::fchownat(target, c"".as_ptr(), *uid, *gid, *flags)
            },
            Self::Utimes { times } => {
                let times = times.as_ref().map_or(ptr::null(), |value| value.as_ptr());
                unsafe { libc::futimens(target, times) }
            }
            Self::SetXattr { name, value, flags } => unsafe {
                libc::fsetxattr(
                    target,
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    *flags,
                )
            },
            Self::RemoveXattr { name } => unsafe { libc::fremovexattr(target, name.as_ptr()) },
        };
        Errno::result(rc)?;
        Ok(())
    }
}

pub(super) fn open_path(path: &Path, flags: i32) -> SysResult<OwnedFd> {
    let cpath = CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    let fd = Errno::result(fd)?;
    let fd = RawFd::try_from(fd).map_err(|_| BrokerError::syscall(libc::EMFILE))?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn reopen_fd(fd: BorrowedFd<'_>, flags: i32) -> SysResult<OwnedFd> {
    open_path(
        &Path::new("/proc/self/fd").join(fd.as_raw_fd().to_string()),
        flags,
    )
}

pub(super) fn open_fd_path(fd: BorrowedFd<'_>) -> SysResult<PathBuf> {
    fs::read_link(Path::new("/proc/self/fd").join(fd.as_raw_fd().to_string()))
        .map_err(BrokerError::from)
}

pub(super) fn validate_nofollow_target(handle: BorrowedFd<'_>, flags: i32) -> SysResult<()> {
    if flags & libc::O_NOFOLLOW == 0 || flags & libc::O_PATH != 0 {
        return Ok(());
    }
    let stat = fstat(handle)?;
    if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(BrokerError::syscall(libc::ELOOP));
    }
    Ok(())
}
