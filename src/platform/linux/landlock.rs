// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Landlock enforcement for lowered filesystem and network rules.
//!
//! Filesystem rules grant access to objects opened while creating the ruleset.
//! This gives deny traversal snapshot semantics: a removed and recreated path is
//! a new object unless an allowed ancestor covers it.

use crate::engine::error::Error;
use crate::engine::policy::{AccessPolicy, ReadAccess};
use anyhow::{Result, bail};
use landlock::{
    ABI, AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus,
};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Landlock features handled by this module, pinned to the highest ABI the
/// `landlock` crate understands (audit-logging controls only past ABI 6).
/// `Ruleset`'s default best-effort compatibility masks bits the running
/// kernel doesn't support instead of failing, so this is a ceiling, not an
/// assumption about what is actually available.
const TARGET_ABI: ABI = ABI::V7;

pub(super) fn enforce_access_policy(policy: &AccessPolicy) -> Result<()> {
    enforce_access_policy_with(policy, true)
}

pub(super) fn enforce_broker_access_policy(policy: &AccessPolicy) -> Result<()> {
    enforce_access_policy_with(policy, false)
}

fn enforce_access_policy_with(policy: &AccessPolicy, restrict_read: bool) -> Result<()> {
    let handled_access_fs = match &policy.read_access {
        ReadAccess::AllowRoots(_) if restrict_read => {
            AccessFs::from_write(TARGET_ABI) | read_access_fs()
        }
        ReadAccess::AllowRoots(_) | ReadAccess::Unrestricted => AccessFs::from_write(TARGET_ABI),
    };

    let mut handled_access_net = BitFlags::<AccessNet>::empty();
    if policy.network_access.restrict_connect_tcp {
        handled_access_net |= AccessNet::ConnectTcp;
    }
    if policy.network_access.restrict_bind_tcp {
        handled_access_net |= AccessNet::BindTcp;
    }

    let mut ruleset = Ruleset::default().handle_access(handled_access_fs)?;
    if !handled_access_net.is_empty() {
        ruleset = ruleset.handle_access(handled_access_net)?;
    }
    let mut created = ruleset.create()?;

    created = add_path_rules(
        created,
        &policy.write_roots,
        AccessFs::from_write(TARGET_ABI),
        "write",
    )?;

    if restrict_read {
        if let ReadAccess::AllowRoots(read_roots) = &policy.read_access {
            created = add_path_rules(created, read_roots, read_access_fs(), "read")?;
        }
    }

    if !handled_access_net.is_empty() {
        created = add_network_rules(created, policy)?;
    }

    let status = created.restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {}
        RulesetStatus::PartiallyEnforced => {
            log::warn!(
                "landlock: kernel only partially enforced the policy; access bits missing from \
                 its ABI stay enforced in user space only where a broker exists"
            );
        }
        RulesetStatus::NotEnforced => {
            bail!(
                "landlock: not enforced by the kernel (Linux 5.13+ with CONFIG_SECURITY_LANDLOCK \
                 required, and not disabled via the lsm= boot parameter)"
            );
        }
    }

    Ok(())
}

fn read_access_fs() -> BitFlags<AccessFs> {
    AccessFs::from_read(TARGET_ABI) & !AccessFs::Execute
}

fn add_path_rules(
    mut ruleset: RulesetCreated,
    paths: &[PathBuf],
    access: BitFlags<AccessFs>,
    label: &str,
) -> Result<RulesetCreated> {
    let mut seen_ancestors: Vec<PathBuf> = Vec::new();

    for path in paths {
        let fd = match open_path(path) {
            Ok(fd) => fd,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.kind() == io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(libc::EIO)
                    || error.raw_os_error() == Some(libc::ENOTCONN) =>
            {
                // Walk up to the nearest existing ancestor directory so that
                // allowWrite rules for files that do not exist yet (e.g. a
                // .git/index.lock) still grant MAKE_REG access on the parent.
                let mut ancestor = path.clone();
                loop {
                    match ancestor.parent() {
                        Some(parent) if !parent.as_os_str().is_empty() => {
                            match std::fs::symlink_metadata(parent) {
                                Ok(metadata) if metadata.is_dir() => {
                                    ancestor = parent.to_path_buf();
                                    break;
                                }
                                _ => ancestor = parent.to_path_buf(),
                            }
                        }
                        _ => break,
                    }
                }
                if seen_ancestors.iter().any(|seen| seen == &ancestor) {
                    continue;
                }
                let fd = match open_path(&ancestor) {
                    Ok(fd) => fd,
                    Err(error) => {
                        log::debug!(
                            "landlock: {label} ancestor {} unreachable: {error}",
                            ancestor.display()
                        );
                        continue;
                    }
                };
                seen_ancestors.push(ancestor);
                fd
            }
            Err(error) => return Err(Error::IoFailed(error).into()),
        };

        let path_access = if fd_is_dir(&fd)? {
            access
        } else {
            access & AccessFs::from_file(TARGET_ABI)
        };
        if path_access.is_empty() {
            continue;
        }

        ruleset = ruleset.add_rule(PathBeneath::new(fd, path_access))?;
    }

    Ok(ruleset)
}

fn add_network_rules(mut ruleset: RulesetCreated, policy: &AccessPolicy) -> Result<RulesetCreated> {
    if !policy.network_access.restrict_connect_tcp {
        return Ok(ruleset);
    }

    for port in &policy.network_access.connect_tcp_ports {
        ruleset = ruleset.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))?;
    }

    Ok(ruleset)
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
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EIO) || error.raw_os_error() == Some(libc::ENOTCONN) {
            return Ok(false);
        }
        return Err(Error::IoFailed(error).into());
    }

    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}
