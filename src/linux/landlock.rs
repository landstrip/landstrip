// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Landlock enforcement for lowered filesystem, network, and Unix socket rules.
//!
//! Filesystem rules grant access to objects opened while creating the ruleset.
//! This gives deny traversal snapshot semantics: a removed and recreated path is
//! a new object unless an allowed ancestor covers it.

use crate::policy::{AccessPolicy, ReadAccess, UnixSocketAccess};
use crate::trap::{Result, Trap};
use nix::errno::Errno;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_RULE_NET_PORT: u32 = 2;

const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const ACCESS_FS_REFER: u64 = 1 << 13;
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
const ACCESS_FS_RESOLVE_UNIX: u64 = 1 << 16;

const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

const ABI_RESOLVE_UNIX: i32 = 9;

const READ_ACCESS: u64 = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;
const WRITE_ACCESS: u64 = ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM
    | ACCESS_FS_REFER
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV;
const FILE_ACCESS: u64 = ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV
    | ACCESS_FS_RESOLVE_UNIX;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

#[derive(Clone, Copy)]
pub(super) struct LandlockFeatures {
    pub(super) resolve_unix: bool,
}

pub(super) fn landlock_features() -> Result<LandlockFeatures> {
    Ok(LandlockFeatures {
        resolve_unix: landlock_abi()? >= ABI_RESOLVE_UNIX,
    })
}

pub(super) fn enforce_access_policy(
    policy: &AccessPolicy,
    features: LandlockFeatures,
) -> Result<()> {
    let resolve_unix = features.resolve_unix && unix_socket_path_access(policy);

    let mut handled_access_fs = match &policy.read_access {
        ReadAccess::Unrestricted => WRITE_ACCESS,
        ReadAccess::AllowRoots(_) => WRITE_ACCESS | READ_ACCESS,
    };
    if resolve_unix {
        handled_access_fs |= ACCESS_FS_RESOLVE_UNIX;
    }

    let mut handled_access_net = 0;
    if policy.network_access.restrict_connect_tcp {
        handled_access_net |= ACCESS_NET_CONNECT_TCP;
    }
    if policy.network_access.restrict_bind_tcp {
        handled_access_net |= ACCESS_NET_BIND_TCP;
    }

    let ruleset_attr = RulesetAttr {
        handled_access_fs,
        handled_access_net,
        scoped: 0,
    };
    let ruleset = create_ruleset(&ruleset_attr)?;

    add_path_rules(&ruleset, &policy.write_roots, WRITE_ACCESS, "write")?;

    if let ReadAccess::AllowRoots(read_roots) = &policy.read_access {
        add_path_rules(&ruleset, read_roots, READ_ACCESS, "read")?;
    }

    if resolve_unix {
        if let UnixSocketAccess::AllowPaths(paths) = &policy.network_access.unix_socket_access {
            add_path_rules(&ruleset, paths, ACCESS_FS_RESOLVE_UNIX, "unix socket")?;
        }
    }

    add_network_rules(&ruleset, policy)?;
    restrict_self(&ruleset)
}

fn unix_socket_path_access(policy: &AccessPolicy) -> bool {
    matches!(policy.network_access.unix_socket_access, UnixSocketAccess::AllowPaths(ref paths) if !paths.is_empty())
}

fn add_path_rules(ruleset: &OwnedFd, paths: &[PathBuf], access: u64, label: &str) -> Result<()> {
    for path in paths {
        let fd = match open_path(path) {
            Ok(fd) => fd,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.kind() == io::ErrorKind::PermissionDenied =>
            {
                log::debug!(
                    "landlock: {label} path {} missing, skipping",
                    path.display()
                );
                continue;
            }
            Err(error) => return Err(Trap::from(error)),
        };

        let path_access = if fd_is_dir(&fd)? {
            access
        } else {
            access & FILE_ACCESS
        };
        if path_access == 0 {
            continue;
        }

        let rule = PathBeneathAttr {
            allowed_access: path_access,
            parent_fd: fd.as_raw_fd(),
        };
        add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule)?;
    }

    Ok(())
}

fn add_network_rules(ruleset: &OwnedFd, policy: &AccessPolicy) -> Result<()> {
    if !policy.network_access.restrict_connect_tcp {
        return Ok(());
    }

    for port in &policy.network_access.connect_tcp_ports {
        let rule = NetPortAttr {
            allowed_access: ACCESS_NET_CONNECT_TCP,
            port: u64::from(*port),
        };
        add_rule(ruleset, LANDLOCK_RULE_NET_PORT, &rule)?;
    }

    Ok(())
}

fn landlock_abi() -> Result<i32> {
    // SAFETY: landlock_create_ruleset copies scalar arguments; null attr is required here.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        return Err(landlock_error("query Landlock ABI"));
    }

    i32::try_from(rc).map_err(|_| Trap::internal())
}

fn create_ruleset(attr: &RulesetAttr) -> Result<OwnedFd> {
    // SAFETY: attr points to a valid ruleset attribute copied by the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            attr,
            std::mem::size_of::<RulesetAttr>(),
            0_u32,
        )
    };
    if rc < 0 {
        return Err(landlock_error("create Landlock ruleset"));
    }

    let fd = i32::try_from(rc).map_err(|_| Trap::internal())?;
    // SAFETY: landlock_create_ruleset returned a new owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn add_rule<T>(ruleset: &OwnedFd, rule_type: u32, rule: &T) -> Result<()> {
    // SAFETY: rule points to a valid rule attribute matching rule_type.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            rule_type,
            rule,
            0_u32,
        )
    };
    if rc < 0 {
        return Err(landlock_error("add Landlock rule"));
    }

    Ok(())
}

fn restrict_self(ruleset: &OwnedFd) -> Result<()> {
    // SAFETY: prctl copies scalar arguments and only affects the current process.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(Trap::from(io::Error::last_os_error()));
    }

    // SAFETY: landlock_restrict_self copies scalar arguments and consumes no ownership.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0_u32) };
    if rc < 0 {
        return Err(landlock_error("enforce Landlock ruleset"));
    }

    Ok(())
}

fn open_path(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: path is a valid NUL-terminated C string copied by open(2).
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: open(2) returned a new owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fd_is_dir(fd: &OwnedFd) -> Result<bool> {
    // SAFETY: stat is initialized by fstat(2) on success.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: fd is valid and stat points to writable storage.
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) };
    if rc != 0 {
        return Err(Trap::from(io::Error::last_os_error()));
    }

    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}

fn landlock_error(action: &str) -> Trap {
    match Errno::last() {
        Errno::ENOSYS => Trap::internal()
            .with_detail("mechanism", "landlock")
            .with_detail("cause_desc", "not_implemented")
            .with_detail("action", action),
        Errno::EOPNOTSUPP => Trap::internal()
            .with_detail("mechanism", "landlock")
            .with_detail("cause_desc", "disabled")
            .with_detail("action", action),
        _ => Trap::from(io::Error::last_os_error()),
    }
}
