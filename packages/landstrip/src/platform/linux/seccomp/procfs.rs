// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use nix::errno::Errno;
use nix::fcntl::AtFlags;
use nix::sys::stat::{fstat, fstatat};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;

#[derive(Clone, Copy)]
pub(super) struct ProcFd<'a>(BorrowedFd<'a>);

impl<'a> ProcFd<'a> {
    pub(super) fn new(fd: BorrowedFd<'a>) -> Self {
        Self(fd)
    }

    pub(super) fn open_path(path: &Path, flags: i32) -> SysResult<OwnedFd> {
        let cpath = CString::new(path.as_os_str().as_bytes())?;
        let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
        let fd = Errno::result(fd)?;
        let fd = RawFd::try_from(fd).map_err(|_| BrokerError::syscall(libc::EMFILE))?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub(super) fn proc_path(self) -> PathBuf {
        Path::new("/proc/self/fd").join(self.0.as_raw_fd().to_string())
    }

    pub(super) fn c_path(self) -> SysResult<CString> {
        Ok(CString::new(self.proc_path().into_os_string().into_vec())?)
    }

    pub(super) fn child_c_path(self, name: &CStr) -> SysResult<CString> {
        let mut path = self.proc_path().into_os_string().into_vec();
        path.push(b'/');
        path.extend_from_slice(name.to_bytes());
        Ok(CString::new(path)?)
    }

    pub(super) fn reopen(self, flags: i32) -> SysResult<OwnedFd> {
        Self::open_path(&self.proc_path(), flags)
    }

    pub(super) fn dup_above_stdio(self) -> SysResult<OwnedFd> {
        let dup = unsafe { libc::fcntl(self.0.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        let dup = Errno::result(dup)?;
        Ok(unsafe { OwnedFd::from_raw_fd(dup) })
    }

    pub(super) fn read_link(self) -> SysResult<PathBuf> {
        fs::read_link(self.proc_path()).map_err(BrokerError::from)
    }

    pub(super) fn validate_nofollow(self, flags: i32) -> SysResult<()> {
        if flags & libc::O_NOFOLLOW == 0 || flags & libc::O_PATH != 0 {
            return Ok(());
        }
        let stat = fstat(self.0)?;
        if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(BrokerError::syscall(libc::ELOOP));
        }
        Ok(())
    }

    pub(super) fn label_under_root_opt(self, root: &Path) -> SysResult<Option<PathBuf>> {
        let Some(label) = FdLabel::try_from(self)?.into_path()? else {
            return Ok(None);
        };
        let relative = label
            .strip_prefix(root)
            .map_err(|_| BrokerError::syscall(libc::EXDEV))?;
        Ok(Some(Path::new("/").join(relative)))
    }

    pub(super) fn label_under_root(self, root: &Path) -> SysResult<PathBuf> {
        self.label_under_root_opt(root)?
            .ok_or_else(|| BrokerError::syscall(libc::EACCES))
    }
}

enum FdLabel {
    Anonymous,
    Linked(PathBuf),
    Unlinked(PathBuf),
    Relinked {
        path: PathBuf,
        dev: libc::dev_t,
        ino: libc::ino_t,
    },
}

impl FdLabel {
    fn into_path(self) -> SysResult<Option<PathBuf>> {
        match self {
            Self::Anonymous => Ok(None),
            Self::Linked(path) | Self::Unlinked(path) => Ok(Some(path)),
            Self::Relinked { path, dev, ino } => Self::surviving_link(&path, dev, ino)
                .map(Some)
                .ok_or_else(|| BrokerError::syscall(libc::EACCES)),
        }
    }

    fn surviving_link(path: &Path, dev: libc::dev_t, ino: libc::ino_t) -> Option<PathBuf> {
        let dir = ProcFd::open_path(
            path.parent()?,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
        .ok()?;
        let dir_fd = ProcFd::new(dir.as_fd());
        let Ok(Self::Linked(dir_path)) = Self::try_from(dir_fd) else {
            return None;
        };
        fs::read_dir(dir_fd.proc_path())
            .ok()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .find(|name| {
                fstatat(&dir, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .is_ok_and(|stat| stat.st_dev == dev && stat.st_ino == ino)
            })
            .map(|name| dir_path.join(name))
    }
}

impl TryFrom<ProcFd<'_>> for FdLabel {
    type Error = BrokerError;

    fn try_from(fd: ProcFd<'_>) -> SysResult<Self> {
        let label = fd.read_link()?;
        if !label.is_absolute() {
            return Ok(Self::Anonymous);
        }
        let Some(path) = label.as_os_str().as_bytes().strip_suffix(b" (deleted)") else {
            return Ok(Self::Linked(label));
        };
        let path = PathBuf::from(OsStr::from_bytes(path));
        let stat = fstat(fd.0)?;
        Ok(if stat.st_nlink == 0 {
            Self::Unlinked(path)
        } else {
            Self::Relinked {
                path,
                dev: stat.st_dev,
                ino: stat.st_ino,
            }
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct OpenHow {
    pub(super) flags: u64,
    pub(super) mode: u64,
    pub(super) resolve: u64,
}

impl OpenHow {
    pub(super) const SIZE: usize = 24;

    pub(super) fn openat2(&self, dirfd: RawFd, path: &CStr) -> SysResult<OwnedFd> {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                ptr::addr_of!(*self),
                Self::SIZE,
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
        if buf.len() < Self::SIZE {
            return Err(BrokerError::InvalidAddress);
        }
        if buf[Self::SIZE..].iter().any(|byte| *byte != 0) {
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
        ProcFd::new(fd.as_fd()).validate_nofollow(libc::O_NOFOLLOW)?;
        Ok(fd)
    }

    pub(super) fn path(&self) -> SysResult<CString> {
        ProcFd::new(self.dir.as_fd()).child_c_path(&self.name)
    }
}
