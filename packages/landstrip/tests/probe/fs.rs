// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Jarkko Sakkinen

/// Re-exec probe for `opath` cases: performs an O_PATH directory open of
/// the given path, exiting 0 on success and 1 on failure.
#[cfg(unix)]
pub fn opath_probe(path: Option<std::ffi::OsString>) -> i32 {
    use std::os::unix::fs::OpenOptionsExt;

    // Linux O_PATH | O_DIRECTORY.
    const O_PATH_DIRECTORY: i32 = 0o10000000 | 0o200000;
    let Some(path) = path else {
        return 2;
    };
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH_DIRECTORY)
        .open(path)
    {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[cfg(not(unix))]
pub fn opath_probe(_path: Option<std::ffi::OsString>) -> i32 {
    2
}

/// Re-exec probe for the fd-only form of utimensat used by futimens.
#[cfg(target_os = "linux")]
pub fn futimens_probe(path: Option<std::ffi::OsString>) -> i32 {
    use std::os::fd::AsRawFd;

    let Some(path) = path else {
        return 2;
    };
    let Ok(file) = std::fs::File::open(path) else {
        return 1;
    };
    let times = [
        libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 2,
            tv_nsec: 0,
        },
    ];
    // SAFETY: file is live, times points to two initialized timespecs, and a null
    // pathname selects the fd-only Linux utimensat form used by glibc futimens.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_utimensat,
            file.as_raw_fd(),
            std::ptr::null::<libc::c_char>(),
            times.as_ptr(),
            0,
        )
    };
    if rc == 0 { 0 } else { 1 }
}

#[cfg(not(target_os = "linux"))]
pub fn futimens_probe(_path: Option<std::ffi::OsString>) -> i32 {
    2
}

#[cfg(target_os = "linux")]
pub fn fd_metadata_probe(
    path: Option<std::ffi::OsString>,
    operation: Option<std::ffi::OsString>,
) -> i32 {
    use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

    let (Some(path), Some(operation)) = (path, operation) else {
        return 2;
    };
    let Ok(file) = std::fs::File::open(&path) else {
        return 1;
    };
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return 2;
    };
    let name = c"user.landstrip-test";
    let value = b"value";
    let rc = match operation.to_str() {
        Some("fchmod") => unsafe { libc::fchmod(file.as_raw_fd(), 0o600) },
        Some("fchmodat2-empty") => unsafe {
            libc::syscall(
                libc::SYS_fchmodat2,
                file.as_raw_fd(),
                c"".as_ptr(),
                0o600,
                libc::AT_EMPTY_PATH,
            ) as i32
        },
        Some("fchmodat2-invalid") => {
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_fchmodat2,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    0o600,
                    0x4000_0000_i32,
                )
            };
            return i32::from(
                rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL),
            );
        }
        Some("fchmodat2-nofollow") => {
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_fchmodat2,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    0o600,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            return i32::from(
                rc != -1
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EOPNOTSUPP),
            );
        }
        Some("fchown") => unsafe {
            libc::fchown(file.as_raw_fd(), libc::geteuid(), libc::getegid())
        },
        Some("fchownat-empty") => unsafe {
            libc::fchownat(
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::geteuid(),
                libc::getegid(),
                libc::AT_EMPTY_PATH,
            )
        },
        Some("fchownat-cwd-empty") => unsafe {
            if libc::fchdir(file.as_raw_fd()) != 0 {
                return 1;
            }
            libc::fchownat(
                libc::AT_FDCWD,
                c"".as_ptr(),
                libc::geteuid(),
                libc::getegid(),
                libc::AT_EMPTY_PATH,
            )
        },
        Some("fchownat-invalid") => {
            let rc = unsafe {
                libc::fchownat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    libc::geteuid(),
                    libc::getegid(),
                    0x4000_0000_i32,
                )
            };
            return i32::from(
                rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL),
            );
        }
        Some("utimensat-invalid") => {
            let rc = unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    std::ptr::null(),
                    0x4000_0000_i32,
                )
            };
            return i32::from(
                rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL),
            );
        }
        Some("x32-fchmod") => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let _ = libc::syscall(libc::SYS_fchmod | 0x4000_0000, file.as_raw_fd(), 0o600);
                // Returning means the BPF filter did not reject the x32 ABI.
                return 0;
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                -1
            }
        }
        Some("fsetxattr") => unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        },
        Some("fsetxattr-overlong") => {
            let name = std::ffi::CString::new(vec![b'x'; 256]).unwrap();
            let rc = unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            };
            return i32::from(
                rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ERANGE),
            );
        }
        Some("fremovexattr") => unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) },
        Some("lremovexattr") => unsafe { libc::lremovexattr(path.as_ptr(), name.as_ptr()) },
        Some("legacy-utimes") => {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            unsafe {
                libc::syscall(
                    libc::SYS_utimes,
                    path.as_ptr(),
                    std::ptr::null::<libc::timeval>(),
                ) as i32
            }
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            {
                -1
            }
        }
        Some("chmod-null") => {
            let rc = unsafe { libc::chmod(std::ptr::null(), 0o600) };
            return i32::from(
                rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EFAULT),
            );
        }
        Some("chmod-empty") => {
            let rc = unsafe { libc::chmod(c"".as_ptr(), 0o600) };
            return i32::from(
                rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT),
            );
        }
        _ => return 2,
    };
    if rc == 0 { 0 } else { 1 }
}

#[cfg(not(target_os = "linux"))]
pub fn fd_metadata_probe(
    _path: Option<std::ffi::OsString>,
    _operation: Option<std::ffi::OsString>,
) -> i32 {
    2
}

#[cfg(target_os = "linux")]
pub fn truncate_probe(path: Option<std::ffi::OsString>) -> i32 {
    use std::os::unix::ffi::OsStrExt;

    let Some(path) = path else {
        return 2;
    };
    let Ok(path) = std::ffi::CString::new(path.as_bytes()) else {
        return 2;
    };
    // SAFETY: path is NUL-terminated and length is nonnegative.
    if unsafe { libc::truncate(path.as_ptr(), 1) } == 0 {
        0
    } else {
        1
    }
}

#[cfg(not(target_os = "linux"))]
pub fn truncate_probe(_path: Option<std::ffi::OsString>) -> i32 {
    2
}

#[cfg(target_os = "linux")]
pub fn exclusive_open_probe(path: Option<std::ffi::OsString>) -> i32 {
    use std::os::unix::ffi::OsStrExt;

    let Some(path) = path else {
        return 2;
    };
    let Ok(c_path) = std::ffi::CString::new(path.as_bytes()) else {
        return 2;
    };
    // SAFETY: c_path is NUL-terminated and the mode is valid for O_CREAT.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd >= 0 {
        // SAFETY: open returned a new descriptor.
        unsafe { libc::close(fd) };
        return 1;
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        return 1;
    }
    match std::fs::read(path) {
        Ok(contents) if contents == b"keep\n" => 0,
        _ => 1,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn exclusive_open_probe(_path: Option<std::ffi::OsString>) -> i32 {
    2
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct TestOpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
fn test_openat2(
    dirfd: libc::c_int,
    path: &std::ffi::CStr,
    how: &TestOpenHow,
    size: usize,
) -> Result<std::os::fd::OwnedFd, i32> {
    use std::os::fd::FromRawFd;

    // SAFETY: path and how remain valid for the duration of the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            std::ptr::from_ref(how),
            size,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    let fd = i32::try_from(fd).map_err(|_| libc::EBADF)?;
    // SAFETY: openat2 returned a new owned descriptor.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
pub fn openat2_probe(
    path: Option<std::ffi::OsString>,
    operation: Option<std::ffi::OsString>,
) -> i32 {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let (Some(path), Some(operation)) = (path, operation) else {
        return 2;
    };
    let Ok(c_path) = std::ffi::CString::new(path.as_bytes()) else {
        return 2;
    };
    let readonly = 0_u64;
    match operation.to_str() {
        Some("open-nofollow") => {
            use std::os::fd::FromRawFd;

            let source = std::path::Path::new(&path);
            let (Some(parent), Some(name)) = (source.parent(), source.file_name()) else {
                return 2;
            };
            let parent_path = parent.to_path_buf();
            let Ok(parent) = std::fs::File::open(parent) else {
                return 2;
            };
            let Ok(name) = std::ffi::CString::new(name.as_bytes()) else {
                return 2;
            };
            let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let failed_with_eloop = |fd| {
                if fd >= 0 {
                    // SAFETY: a nonnegative open result is an owned descriptor.
                    unsafe { libc::close(fd) };
                    return false;
                }
                std::io::Error::last_os_error().raw_os_error() == Some(libc::ELOOP)
            };

            // SAFETY: c_path is NUL-terminated.
            let open_eloop = failed_with_eloop(unsafe { libc::open(c_path.as_ptr(), flags) });
            // SAFETY: parent owns a valid directory fd and name is NUL-terminated.
            let openat_eloop = failed_with_eloop(unsafe {
                libc::openat(parent.as_raw_fd(), name.as_ptr(), flags)
            });
            let how = TestOpenHow {
                flags: u64::try_from(flags).expect("open flags fit u64"),
                mode: 0,
                resolve: 0,
            };
            if !open_eloop
                || !openat_eloop
                || !matches!(
                    test_openat2(parent.as_raw_fd(), &name, &how, 24),
                    Err(libc::ELOOP)
                )
            {
                return 1;
            }

            let beneath = TestOpenHow {
                resolve: 0x08,
                ..how
            };
            if !matches!(
                test_openat2(parent.as_raw_fd(), &name, &beneath, 24),
                Err(libc::ELOOP)
            ) {
                return 1;
            }

            // O_PATH|O_NOFOLLOW validly opens the link itself.
            // SAFETY: c_path is NUL-terminated.
            let link_fd = unsafe {
                libc::open(
                    c_path.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if link_fd < 0 {
                return 1;
            }
            // SAFETY: open returned a new owned descriptor.
            let link_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(link_fd) };
            // SAFETY: stat points to initialized storage and link_fd is valid.
            let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(link_fd.as_raw_fd(), std::ptr::addr_of_mut!(stat)) } != 0
                || stat.st_mode & libc::S_IFMT != libc::S_IFLNK
            {
                return 1;
            }

            let mut trailing = path.as_bytes().to_vec();
            trailing.push(b'/');
            let Ok(trailing) = std::ffi::CString::new(trailing) else {
                return 2;
            };
            // A trailing slash requires the terminal directory symlink to be followed.
            // SAFETY: trailing is NUL-terminated.
            let trailing_fd = unsafe { libc::open(trailing.as_ptr(), flags | libc::O_DIRECTORY) };
            if trailing_fd < 0 {
                return 1;
            }
            // SAFETY: open returned a new owned descriptor.
            drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(trailing_fd) });

            // A trailing slash resolves the final component as a directory, so
            // a dangling link, a file, and a create all fail as the kernel says.
            let errno_of = |name: &str, flags: i32| -> i32 {
                let mut target = parent_path.as_os_str().as_bytes().to_vec();
                target.extend_from_slice(name.as_bytes());
                let Ok(target) = std::ffi::CString::new(target) else {
                    return 0;
                };
                // SAFETY: target is NUL-terminated.
                let fd = unsafe { libc::open(target.as_ptr(), flags, 0o600) };
                if fd >= 0 {
                    // SAFETY: a nonnegative open result is an owned descriptor.
                    unsafe { libc::close(fd) };
                    return 0;
                }
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            };
            let directory = flags | libc::O_DIRECTORY;
            if errno_of("/dangling/", directory) != libc::ENOENT
                || errno_of("/file-link/", directory) != libc::ENOTDIR
                || errno_of("/file/", libc::O_RDONLY) != libc::ENOTDIR
                || errno_of("/new-file/", libc::O_CREAT | libc::O_WRONLY) != libc::EISDIR
            {
                return 1;
            }
            0
        }
        Some("openat2-no-symlinks") => test_openat2(
            libc::AT_FDCWD,
            &c_path,
            &TestOpenHow {
                flags: readonly,
                mode: 0,
                resolve: 0x04,
            },
            24,
        )
        .map_or_else(|errno| i32::from(errno != libc::ELOOP), |_| 1),
        Some("openat2-short") => test_openat2(
            libc::AT_FDCWD,
            &c_path,
            &TestOpenHow {
                flags: readonly,
                mode: 0,
                resolve: 0,
            },
            16,
        )
        .map_or_else(|errno| i32::from(errno != libc::EINVAL), |_| 1),
        Some("openat2-beneath") => {
            let Ok(dir) = std::fs::File::open(&path) else {
                return 2;
            };
            test_openat2(
                dir.as_raw_fd(),
                c"../outside.txt",
                &TestOpenHow {
                    flags: readonly,
                    mode: 0,
                    resolve: 0x08,
                },
                24,
            )
            .map_or_else(|errno| i32::from(errno != libc::EXDEV), |_| 1)
        }
        Some("openat2-in-root") => {
            let Ok(dir) = std::fs::File::open(&path) else {
                return 2;
            };
            let opened = test_openat2(
                dir.as_raw_fd(),
                c"/inside.txt",
                &TestOpenHow {
                    flags: readonly,
                    mode: 0,
                    resolve: 0x10,
                },
                24,
            );
            match opened {
                Ok(fd) => {
                    let mut file = std::fs::File::from(fd);
                    let mut contents = String::new();
                    i32::from(file.read_to_string(&mut contents).is_err() || contents != "inside\n")
                }
                Err(_) => 1,
            }
        }
        _ => 2,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn openat2_probe(
    _path: Option<std::ffi::OsString>,
    _operation: Option<std::ffi::OsString>,
) -> i32 {
    2
}
