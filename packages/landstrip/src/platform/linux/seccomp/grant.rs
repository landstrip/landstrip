// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use super::notify::{NotificationChannel, NotificationResponse};
use super::process::ResolvedPath;
use super::procfs::{Anchor, OpenHow, ProcFd};
use crate::policy::AccessPolicy;
use nix::errno::Errno;
use nix::sys::stat::fstat;
use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

pub(super) const SYS_FCHMODAT2: i64 = 452;

pub(super) type SocketAddrCall =
    unsafe extern "C" fn(libc::c_int, *const libc::sockaddr, libc::socklen_t) -> libc::c_int;

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
    sock: OwnedFd,
    addr: Vec<u8>,
    call: SocketAddrCall,
    _path: Option<Anchor>,
}

impl SocketGrant {
    pub(super) fn new(
        sock: OwnedFd,
        addr: Vec<u8>,
        call: SocketAddrCall,
        path: Option<Anchor>,
    ) -> Self {
        Self {
            sock,
            addr,
            call,
            _path: path,
        }
    }

    fn call_addr(&self) -> SysResult<i64> {
        let len =
            libc::socklen_t::try_from(self.addr.len()).map_err(|_| BrokerError::InvalidAddress)?;
        let rc = unsafe { (self.call)(self.sock.as_raw_fd(), self.addr.as_ptr().cast(), len) };
        if rc < 0 {
            return Err(Errno::last().into());
        }
        Ok(i64::from(rc))
    }

    pub(super) fn apply(&self, notify: NotificationChannel<'_>, id: u64) {
        let rc = match self.call_addr() {
            Ok(value) => NotificationResponse::success(id, value),
            Err(error) => NotificationResponse::error(id, error.errno()),
        };
        let _ = notify.respond(rc);
    }
}

pub(super) struct OpenGrant {
    pub(super) flags: i32,
    pub(super) kind: OpenKind,
    label: PathBuf,
    root_label: PathBuf,
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
                ProcFd::new(handle.as_fd()).validate_nofollow(flags)?;
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
            root_label: resolved.root_label,
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
                ProcFd::new(handle.as_fd()).reopen(flags)
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
        if let Some(label) = ProcFd::new(fd).label_under_root_opt(&self.root_label)? {
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
                    let label = ProcFd::new(anchor.dir.as_fd())
                        .label_under_root(&self.root_label)?
                        .join(OsStr::from_bytes(anchor.name.as_bytes()));
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
                        let writable =
                            ProcFd::new(fd.as_fd()).reopen(libc::O_WRONLY | libc::O_CLOEXEC)?;
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
            let _ = notify.respond(NotificationResponse::error(id, libc::EACCES));
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
        from: MetadataTarget,
        to: Anchor,
        flags: i32,
    },
    Metadata {
        target: MetadataTarget,
        op: MetadataOp,
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
                let writable =
                    ProcFd::new(target.as_fd()).reopen(libc::O_WRONLY | libc::O_CLOEXEC)?;
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
                    MetadataTarget::Entry(at) => unsafe {
                        libc::linkat(
                            at.dir.as_raw_fd(),
                            at.name.as_ptr(),
                            to.dir.as_raw_fd(),
                            to.name.as_ptr(),
                            flags & !libc::AT_SYMLINK_FOLLOW,
                        )
                    },
                    MetadataTarget::Pinned(fd) | MetadataTarget::Descriptor(fd) => {
                        let path = ProcFd::new(fd.as_fd()).c_path()?;
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
            Self::Metadata { target, op } => op.run(target)?,
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

pub(super) enum MetadataTarget {
    Entry(Anchor),
    Pinned(OwnedFd),
    Descriptor(OwnedFd),
}

impl MetadataTarget {
    pub(super) fn from_anchor(anchor: Anchor, no_follow: bool) -> SysResult<Self> {
        if no_follow {
            Ok(Self::Entry(anchor))
        } else {
            anchor.into_target().map(Self::Pinned)
        }
    }

    fn at_args(&self, fd_flags: i32) -> (BorrowedFd<'_>, &CStr, i32) {
        match self {
            Self::Entry(at) => (at.dir.as_fd(), &at.name, libc::AT_SYMLINK_NOFOLLOW),
            Self::Pinned(fd) => (fd.as_fd(), c"", libc::AT_EMPTY_PATH),
            Self::Descriptor(fd) => (fd.as_fd(), c"", fd_flags),
        }
    }

    fn set_xattr(&self, name: &CStr, value: &[u8], flags: i32) -> SysResult<()> {
        let rc = match self {
            Self::Entry(at) => {
                let path = at.path()?;
                unsafe {
                    libc::lsetxattr(
                        path.as_ptr(),
                        name.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        flags,
                    )
                }
            }
            Self::Pinned(fd) => {
                let path = ProcFd::new(fd.as_fd()).c_path()?;
                unsafe {
                    libc::setxattr(
                        path.as_ptr(),
                        name.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        flags,
                    )
                }
            }
            Self::Descriptor(fd) => unsafe {
                libc::fsetxattr(
                    fd.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    flags,
                )
            },
        };
        Errno::result(rc)?;
        Ok(())
    }

    fn remove_xattr(&self, name: &CStr) -> SysResult<()> {
        let rc = match self {
            Self::Entry(at) => {
                let path = at.path()?;
                unsafe { libc::lremovexattr(path.as_ptr(), name.as_ptr()) }
            }
            Self::Pinned(fd) => {
                let path = ProcFd::new(fd.as_fd()).c_path()?;
                unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) }
            }
            Self::Descriptor(fd) => unsafe { libc::fremovexattr(fd.as_raw_fd(), name.as_ptr()) },
        };
        Errno::result(rc)?;
        Ok(())
    }
}

pub(super) enum MetadataOp {
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

impl MetadataOp {
    fn run(&self, target: &MetadataTarget) -> SysResult<()> {
        match self {
            Self::Chmod { mode } => match target {
                MetadataTarget::Entry(at) => {
                    Errno::result(unsafe {
                        libc::syscall(
                            SYS_FCHMODAT2,
                            at.dir.as_raw_fd(),
                            at.name.as_ptr(),
                            *mode,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    })?;
                }
                MetadataTarget::Pinned(fd) => {
                    let path = ProcFd::new(fd.as_fd()).c_path()?;
                    Errno::result(unsafe { libc::chmod(path.as_ptr(), *mode) })?;
                }
                MetadataTarget::Descriptor(fd) => {
                    Errno::result(unsafe { libc::fchmod(fd.as_raw_fd(), *mode) })?;
                }
            },
            Self::ChmodAt { mode, flags } => {
                let (dir, name, target_flags) = target.at_args(*flags);
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
                    MetadataTarget::Entry(at) => unsafe {
                        libc::fchownat(
                            at.dir.as_raw_fd(),
                            at.name.as_ptr(),
                            *uid,
                            *gid,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    },
                    MetadataTarget::Pinned(fd) => {
                        let path = ProcFd::new(fd.as_fd()).c_path()?;
                        unsafe { libc::chown(path.as_ptr(), *uid, *gid) }
                    }
                    MetadataTarget::Descriptor(fd) => unsafe {
                        libc::fchown(fd.as_raw_fd(), *uid, *gid)
                    },
                };
                Errno::result(rc)?;
            }
            Self::ChownAt { uid, gid, flags } => {
                let (dir, name, target_flags) = target.at_args(*flags);
                Errno::result(unsafe {
                    libc::fchownat(dir.as_raw_fd(), name.as_ptr(), *uid, *gid, target_flags)
                })?;
            }
            Self::Utimes { times } => {
                let times = times.as_ref().map_or(ptr::null(), |value| value.as_ptr());
                let rc = match target {
                    MetadataTarget::Entry(at) => unsafe {
                        libc::utimensat(
                            at.dir.as_raw_fd(),
                            at.name.as_ptr(),
                            times,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    },
                    MetadataTarget::Pinned(fd) => {
                        let path = ProcFd::new(fd.as_fd()).c_path()?;
                        unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times, 0) }
                    }
                    MetadataTarget::Descriptor(fd) => unsafe {
                        libc::futimens(fd.as_raw_fd(), times)
                    },
                };
                Errno::result(rc)?;
            }
            Self::SetXattr { name, value, flags } => target.set_xattr(name, value, *flags)?,
            Self::RemoveXattr { name } => target.remove_xattr(name)?,
        }
        Ok(())
    }
}
