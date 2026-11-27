// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use nix::errno::Errno;
use nix::fcntl::AtFlags;
use nix::sys::stat::{fstat, fstatat};
use nix::unistd::Pid;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

#[derive(Clone, Copy)]
pub(super) struct ProcPath {
    buf: [u8; 64],
    len: usize,
}

impl ProcPath {
    pub(super) fn self_fd(fd: RawFd) -> Self {
        let mut buf = [0_u8; 64];
        let mut cursor = &mut buf[..63];
        let _ = write!(cursor, "/proc/self/fd/{fd}");
        let len = 63 - cursor.len();
        Self { buf, len }
    }

    pub(super) fn pid_entry(pid: Pid, entry: &str) -> Self {
        let mut buf = [0_u8; 64];
        let mut cursor = &mut buf[..63];
        let _ = write!(cursor, "/proc/{pid}/{entry}");
        let len = 63 - cursor.len();
        Self { buf, len }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub(super) fn as_path(&self) -> &Path {
        Path::new(OsStr::from_bytes(self.as_bytes()))
    }

    pub(super) fn as_ptr(&self) -> *const libc::c_char {
        self.buf.as_ptr().cast()
    }

    pub(super) fn c_str(&self) -> SysResult<&CStr> {
        CStr::from_bytes_with_nul(&self.buf[..=self.len]).map_err(|_| BrokerError::InvalidAddress)
    }
}

impl AsRef<Path> for ProcPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl AsRef<OsStr> for ProcPath {
    fn as_ref(&self) -> &OsStr {
        OsStr::from_bytes(self.as_bytes())
    }
}

#[derive(Clone, Copy)]
pub(super) struct ProcFd<'a>(BorrowedFd<'a>);

impl<'a> ProcFd<'a> {
    pub(super) fn new(fd: BorrowedFd<'a>) -> Self {
        Self(fd)
    }

    pub(super) fn open_c_path(path: &CStr, flags: i32) -> SysResult<OwnedFd> {
        let fd = unsafe { libc::open(path.as_ptr(), flags) };
        let fd = Errno::result(fd)?;
        let fd = RawFd::try_from(fd).map_err(|_| BrokerError::syscall(libc::EMFILE))?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub(super) fn open_path(path: &Path, flags: i32) -> SysResult<OwnedFd> {
        let cpath = CString::new(path.as_os_str().as_bytes())?;
        Self::open_c_path(&cpath, flags)
    }

    pub(super) fn proc_path(self) -> ProcPath {
        ProcPath::self_fd(self.0.as_raw_fd())
    }

    pub(super) fn child_c_path(self, name: &CStr) -> SysResult<CString> {
        let proc = self.proc_path();
        let name_bytes = name.to_bytes();
        let mut path = Vec::with_capacity(proc.as_bytes().len() + 1 + name_bytes.len());
        path.extend_from_slice(proc.as_bytes());
        path.push(b'/');
        path.extend_from_slice(name_bytes);
        Ok(CString::new(path)?)
    }

    pub(super) fn reopen(self, flags: i32) -> SysResult<OwnedFd> {
        Self::open_c_path(self.proc_path().c_str()?, flags)
    }

    pub(super) fn dup_above_stdio(self) -> SysResult<OwnedFd> {
        let dup = unsafe { libc::fcntl(self.0.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        let dup = Errno::result(dup)?;
        Ok(unsafe { OwnedFd::from_raw_fd(dup) })
    }

    pub(super) fn read_link(self) -> SysResult<PathBuf> {
        let proc = self.proc_path();
        let mut buf = [0_u8; libc::PATH_MAX as usize];
        let len = unsafe { libc::readlink(proc.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        let len = Errno::result(len)?;
        let len = usize::try_from(len)?;
        if len == buf.len() {
            return Err(BrokerError::NameTooLong);
        }
        Ok(PathBuf::from(OsStr::from_bytes(&buf[..len])))
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
        if stat.st_nlink == 0 {
            if path.starts_with("/memfd:") {
                return Ok(Self::Anonymous);
            }
            return Ok(Self::Unlinked(path));
        }
        Ok(Self::Relinked {
            path,
            dev: stat.st_dev,
            ino: stat.st_ino,
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
