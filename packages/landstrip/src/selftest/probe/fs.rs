// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#[cfg(unix)]
use super::{CPath, OsResult};
use super::{ProbeError, ProbeResult};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FsProbe {
    Read {
        path: PathBuf,
    },
    Write {
        path: PathBuf,
        data: String,
    },
    CreateExcl {
        path: PathBuf,
        data: String,
    },
    Truncate {
        path: PathBuf,
        len: u64,
    },
    Mkdir {
        path: PathBuf,
        parents: bool,
    },
    Rmdir {
        path: PathBuf,
        recursive: bool,
    },
    Unlink {
        path: PathBuf,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    #[cfg(unix)]
    Link {
        src: PathBuf,
        dst: PathBuf,
        follow: bool,
    },
    #[cfg(unix)]
    Symlink {
        target: PathBuf,
        link: PathBuf,
    },
    #[cfg(unix)]
    Chmod {
        path: PathBuf,
        mode: u32,
        via: ChmodVia,
    },
    #[cfg(unix)]
    Utimens {
        path: PathBuf,
    },
    #[cfg(target_os = "linux")]
    Xattr {
        path: PathBuf,
        op: XattrOp,
    },
    #[cfg(target_os = "linux")]
    Openat2 {
        dir: PathBuf,
    },
    #[cfg(target_os = "linux")]
    IoSurface {
        dir: PathBuf,
    },
    #[cfg(unix)]
    OpenFds {
        write: bool,
    },
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ChmodVia {
    Fd,
    #[cfg(target_os = "linux")]
    NoFollow,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum XattrOp {
    List,
    LList,
    FList,
    Set,
    FRemove,
}

impl FsProbe {
    /// Runs the probe and returns its output, which only reads, xattr
    /// listings and fd listings have.
    pub fn run(&self) -> ProbeResult<Vec<u8>> {
        match self {
            Self::Read { path } => return fs::read(path).map_err(ProbeError::Denied),
            Self::Write { path, data } => fs::write(path, data).map_err(ProbeError::Denied),
            Self::CreateExcl { path, data } => OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .and_then(|mut file| file.write_all(data.as_bytes()))
                .map_err(ProbeError::Denied),
            Self::Truncate { path, len } => Self::truncate(path, *len),
            Self::Mkdir { path, parents } => if *parents {
                fs::create_dir_all(path)
            } else {
                fs::create_dir(path)
            }
            .map_err(ProbeError::Denied),
            Self::Rmdir { path, recursive } => if *recursive {
                fs::remove_dir_all(path)
            } else {
                fs::remove_dir(path)
            }
            .map_err(ProbeError::Denied),
            Self::Unlink { path } => fs::remove_file(path).map_err(ProbeError::Denied),
            Self::Rename { from, to } => fs::rename(from, to).map_err(ProbeError::Denied),
            #[cfg(unix)]
            Self::Link { src, dst, follow } => Self::link(src, dst, *follow),
            #[cfg(unix)]
            Self::Symlink { target, link } => {
                std::os::unix::fs::symlink(target, link).map_err(ProbeError::Denied)
            }
            #[cfg(unix)]
            Self::Chmod { path, mode, via } => Self::chmod(path, *mode, *via),
            #[cfg(unix)]
            Self::Utimens { path } => Self::utimens(path),
            #[cfg(target_os = "linux")]
            Self::Xattr { path, op } => return Self::xattr(path, *op),
            #[cfg(target_os = "linux")]
            Self::Openat2 { dir } => Self::openat2(dir),
            #[cfg(target_os = "linux")]
            Self::IoSurface { dir } => Self::io_surface(dir),
            #[cfg(unix)]
            Self::OpenFds { write } => return Self::open_fds(*write),
        }?;
        Ok(Vec::new())
    }

    #[cfg(unix)]
    fn truncate(path: &Path, len: u64) -> ProbeResult {
        let len = libc::off_t::try_from(len).map_err(io::Error::other)?;
        let path = path.c_path()?;
        unsafe { libc::truncate(path.as_ptr(), len) }
            .os_result()
            .map_err(ProbeError::Denied)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn truncate(path: &Path, len: u64) -> ProbeResult {
        OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|file| file.set_len(len))
            .map_err(ProbeError::Denied)
    }

    #[cfg(unix)]
    fn link(src: &Path, dst: &Path, follow: bool) -> ProbeResult {
        let flags = if follow { libc::AT_SYMLINK_FOLLOW } else { 0 };
        let (src, dst) = (src.c_path()?, dst.c_path()?);
        unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                src.as_ptr(),
                libc::AT_FDCWD,
                dst.as_ptr(),
                flags,
            )
        }
        .os_result()
        .map_err(ProbeError::Denied)?;
        Ok(())
    }

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32, via: ChmodVia) -> ProbeResult {
        use std::os::unix::fs::PermissionsExt;
        match via {
            ChmodVia::Fd => File::open(path)
                .map_err(ProbeError::Denied)?
                .set_permissions(fs::Permissions::from_mode(mode))
                .map_err(ProbeError::Denied),
            #[cfg(target_os = "linux")]
            ChmodVia::NoFollow => {
                let path = path.c_path()?;
                unsafe {
                    libc::syscall(
                        syscalls::Sysno::fchmodat2 as libc::c_long,
                        libc::AT_FDCWD,
                        path.as_ptr(),
                        mode,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                }
                .os_result()
                .map_err(ProbeError::denied_on(&[
                    libc::EOPNOTSUPP,
                    libc::EACCES,
                    libc::EPERM,
                ]))?;
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    fn utimens(path: &Path) -> ProbeResult {
        use std::os::fd::AsRawFd;
        let file = File::open(path).map_err(ProbeError::Denied)?;
        let time = libc::timespec {
            tv_sec: 1_700_000_000,
            tv_nsec: 0,
        };
        let times = [time, time];
        unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) }
            .os_result()
            .map_err(ProbeError::Denied)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn xattr(path: &Path, op: XattrOp) -> ProbeResult<Vec<u8>> {
        use std::os::fd::AsRawFd;
        const NAME: &std::ffi::CStr = c"user.landstrip-test";
        let c_path = path.c_path()?;
        match op {
            XattrOp::List | XattrOp::LList | XattrOp::FList => {
                let file;
                let (nr, target) = match op {
                    XattrOp::List => (libc::SYS_listxattr, c_path.as_ptr().addr()),
                    XattrOp::LList => (libc::SYS_llistxattr, c_path.as_ptr().addr()),
                    _ => {
                        file = File::open(path)?;
                        let fd = usize::try_from(file.as_raw_fd()).map_err(io::Error::other)?;
                        (libc::SYS_flistxattr, fd)
                    }
                };
                let mut names = [0_u8; 256];
                let len = unsafe { libc::syscall(nr, target, std::ptr::null_mut::<u8>(), 0_usize) }
                    .os_result()
                    .map_err(ProbeError::Denied)?;
                let filled = unsafe { libc::syscall(nr, target, names.as_mut_ptr(), names.len()) }
                    .os_result()
                    .map_err(ProbeError::Denied)?;
                if filled != len {
                    return Err(ProbeError::broken("xattr list size changed between calls"));
                }
                let filled = usize::try_from(filled).map_err(io::Error::other)?;
                let found = names
                    .get(..filled)
                    .unwrap_or_default()
                    .split(|byte| *byte == 0)
                    .any(|name| name == NAME.to_bytes());
                Ok(if found { "found" } else { "absent" }.into())
            }
            XattrOp::Set => {
                let value = b"updated";
                unsafe {
                    libc::setxattr(
                        c_path.as_ptr(),
                        NAME.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                    )
                }
                .os_result()
                .map_err(ProbeError::Denied)?;
                Ok(Vec::new())
            }
            XattrOp::FRemove => {
                let file = File::open(path)?;
                unsafe { libc::fremovexattr(file.as_raw_fd(), NAME.as_ptr()) }
                    .os_result()
                    .map_err(ProbeError::Denied)?;
                Ok(Vec::new())
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn openat2(root: &Path) -> ProbeResult {
        use std::os::fd::AsRawFd;

        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }

        impl OpenHow {
            const RESOLVE_NO_SYMLINKS: u64 = 0x04;
            const RESOLVE_BENEATH: u64 = 0x08;
            const RESOLVE_IN_ROOT: u64 = 0x10;

            fn open(dir: &File, path: &std::ffi::CStr, resolve: u64) -> io::Result<i64> {
                let how = Self {
                    flags: libc::O_RDONLY.cast_unsigned().into(),
                    mode: 0,
                    resolve,
                };
                unsafe {
                    libc::syscall(
                        libc::SYS_openat2,
                        dir.as_raw_fd(),
                        path.as_ptr(),
                        &raw const how,
                        std::mem::size_of::<Self>(),
                    )
                }
                .os_result()
            }
        }

        let link = root.join("oa2_link");
        fs::write(root.join("oa2_target.txt"), b"openat2-ok")?;
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink("oa2_target.txt", &link)?;
        let dir = File::open(root)?;

        let expect_errno = |result: io::Result<i64>, errno: i32, what: &str| match result {
            Err(error) if error.raw_os_error() == Some(errno) => Ok(()),
            _ => Err(ProbeError::broken(what)),
        };
        expect_errno(
            OpenHow::open(&dir, c"oa2_link", OpenHow::RESOLVE_NO_SYMLINKS),
            libc::ELOOP,
            "RESOLVE_NO_SYMLINKS did not fail with ELOOP",
        )?;
        expect_errno(
            OpenHow::open(&dir, c"../open/readme.txt", OpenHow::RESOLVE_BENEATH),
            libc::EXDEV,
            "RESOLVE_BENEATH did not fail with EXDEV",
        )?;
        let in_root = OpenHow::open(&dir, c"/oa2_target.txt", OpenHow::RESOLVE_IN_ROOT)?;
        if let Ok(fd) = i32::try_from(in_root) {
            unsafe { libc::close(fd) };
        }
        let c_link = link.c_path()?;
        let opath =
            unsafe { libc::open(c_link.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW) }.os_result()?;
        unsafe { libc::close(opath) };
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn io_surface(dir: &Path) -> ProbeResult {
        use std::os::fd::AsRawFd;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(dir.join("io_vec.bin"))?;
        let fd = file.as_raw_fd();
        let (head, tail) = (*b"hello-", *b"world!");
        let out_iov = [
            libc::iovec {
                iov_base: head.as_ptr().cast_mut().cast(),
                iov_len: head.len(),
            },
            libc::iovec {
                iov_base: tail.as_ptr().cast_mut().cast(),
                iov_len: tail.len(),
            },
        ];
        if unsafe { libc::pwritev2(fd, out_iov.as_ptr(), 2, 0, 0) }.os_result()? != 12 {
            return Err(ProbeError::broken("pwritev2 short write"));
        }
        let mut read_buf = [0_u8; 12];
        let in_iov = [libc::iovec {
            iov_base: read_buf.as_mut_ptr().cast(),
            iov_len: read_buf.len(),
        }];
        let read = unsafe { libc::preadv2(fd, in_iov.as_ptr(), 1, 0, 0) }.os_result()?;
        if read != 12 || &read_buf != b"hello-world!" {
            return Err(ProbeError::broken("preadv2 returned wrong data"));
        }
        unsafe { libc::fsync(fd) }.os_result()?;
        unsafe { libc::fdatasync(fd) }.os_result()?;
        let memfd = unsafe {
            libc::memfd_create(
                c"selftest-mfd".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        }
        .os_result()?;
        let written = unsafe { libc::write(memfd, b"seal-test".as_ptr().cast(), 9) }.os_result();
        let sealed =
            unsafe { libc::fcntl(memfd, libc::F_ADD_SEALS, libc::F_SEAL_WRITE) }.os_result();
        unsafe { libc::close(memfd) };
        if written? != 9 {
            return Err(ProbeError::broken("memfd short write"));
        }
        sealed?;
        Ok(())
    }

    #[cfg(unix)]
    fn open_fds(write: bool) -> ProbeResult<Vec<u8>> {
        let mut open = Vec::new();
        for fd in (3..=12).chain([5000, 5001]) {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
                continue;
            }
            open.push(fd.to_string());
            if write {
                let marker = format!("fd{fd};");
                unsafe { libc::write(fd, marker.as_ptr().cast(), marker.len()) }.os_result()?;
            }
        }
        Ok(format!("open={}", open.join(",")).into_bytes())
    }
}
