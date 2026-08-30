// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Landlock enforcement for lowered filesystem and network rules.
//!
//! Filesystem rules grant access to objects opened while creating the ruleset.
//! This gives deny traversal snapshot semantics: a removed and recreated path is
//! a new object unless an allowed ancestor covers it.

use crate::error::{Error, Mechanism, PathIo};
use crate::policy::{AccessPolicy, ReadAccess};
use anyhow::Result;
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, Erratum, LandlockStatus, NetPort, PathBeneath,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::{Mode, fstat};
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

/// Landlock features handled by this module, pinned to the highest ABI the
/// `landlock` crate understands (audit-logging controls only past ABI 6).
/// `Ruleset`'s default best-effort compatibility masks bits the running
/// kernel doesn't support instead of failing, so this is a ceiling, not an
/// assumption about what is actually available.
const TARGET_ABI: ABI = ABI::V7;

pub(super) fn enforce_access_policy(policy: &AccessPolicy, restrict_read: bool) -> Result<()> {
    let handled_access_fs = match &policy.read_access {
        ReadAccess::AllowRoots(_) if restrict_read => {
            AccessFs::from_write(TARGET_ABI) | read_access_fs()
        }
        ReadAccess::AllowRoots(_) | ReadAccess::Unrestricted => AccessFs::from_write(TARGET_ABI),
    };

    let mut handled_access_net = BitFlags::<AccessNet>::empty();
    if policy.network_access.restricts_connect_tcp() {
        handled_access_net |= AccessNet::ConnectTcp;
    }
    if policy.network_access.restricts_bind_tcp() {
        handled_access_net |= AccessNet::BindTcp;
    }

    let mut ruleset = Ruleset::default()
        .handle_access(handled_access_fs)
        .map_err(landlock_error)?;
    if !handled_access_net.is_empty() {
        ruleset = ruleset
            .handle_access(handled_access_net)
            .map_err(landlock_error)?;
    }
    // Host-created abstract Unix sockets (D-Bus, systemd) and signals to processes
    // outside the sandbox stay out of reach even when allowNetwork /
    // allowAllUnixSockets leave pathname connect unrestricted.
    // Best-effort: kernels before ABI 6 ignore this and still get the seccomp denylist.
    ruleset = ruleset
        .scope(Scope::AbstractUnixSocket | Scope::Signal)
        .map_err(landlock_error)?;
    let mut created = ruleset
        .create()
        .map_err(landlock_error)?;

    created = add_path_rules(
        created,
        &policy.write_roots,
        AccessFs::from_write(TARGET_ABI),
        "write",
    )?;

    if restrict_read && let ReadAccess::AllowRoots(read_roots) = &policy.read_access {
        created = add_path_rules(created, read_roots, read_access_fs(), "read")?;
    }

    if !handled_access_net.is_empty() {
        created = add_network_rules(created, policy)?;
    }

    let status = created
        .restrict_self()
        .map_err(landlock_error)?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {}
        RulesetStatus::PartiallyEnforced => log::debug!(
            "{}",
            partial_enforcement_warning(status.landlock, handled_access_fs, handled_access_net)
        ),
        RulesetStatus::NotEnforced => {
            return Err(landlock_error(
                "not enforced by the kernel (Linux 5.13+ with CONFIG_SECURITY_LANDLOCK required, \
                 and not disabled via the lsm= boot parameter)",
            ));
        }
    }
    // Keep Scope::Signal even when unfixed: the erratum over-restricts same-process
    // thread signals (libpsx / independent per-thread restrict). Dropping the scope
    // would be less secure. Landstrip restricts then execs, so this path is single-threaded.
    if !Erratum::current().contains(Erratum::ScopedSignalHandling) {
        log::debug!(
            "landlock: kernel has not fixed scoped signal handling (erratum 2); threads that \
             apply Landlock independently in one process may be unable to signal each other"
        );
    }

    Ok(())
}

fn landlock_error(source: impl Into<crate::error::Cause>) -> anyhow::Error {
    Error::sandbox_setup(Mechanism::Landlock, source).into()
}

fn partial_enforcement_warning(
    status: LandlockStatus,
    handled_access_fs: BitFlags<AccessFs>,
    handled_access_net: BitFlags<AccessNet>,
) -> String {
    let LandlockStatus::Available { effective_abi, .. } = status else {
        return "landlock: kernel only partially enforced the policy".to_owned();
    };
    let supported_fs = AccessFs::from_all(effective_abi);
    let supported_net = AccessNet::from_all(effective_abi);
    let mut missing = Vec::new();

    for (access, name) in [
        (AccessFs::Refer, "filesystem REFER"),
        (AccessFs::Truncate, "filesystem TRUNCATE"),
        (AccessFs::IoctlDev, "filesystem IOCTL_DEV"),
    ] {
        if handled_access_fs.contains(access) && !supported_fs.contains(access) {
            missing.push(name);
        }
    }
    for (access, name) in [
        (AccessNet::BindTcp, "network BIND_TCP"),
        (AccessNet::ConnectTcp, "network CONNECT_TCP"),
    ] {
        if handled_access_net.contains(access) && !supported_net.contains(access) {
            missing.push(name);
        }
    }
    let supported_scope = Scope::from_all(effective_abi);
    if !supported_scope.contains(Scope::AbstractUnixSocket) {
        missing.push("scope ABSTRACT_UNIX_SOCKET");
    }
    if !supported_scope.contains(Scope::Signal) {
        missing.push("scope SIGNAL");
    }

    let details = if missing.is_empty() {
        "some requested features".to_owned()
    } else {
        missing.join(", ")
    };
    format!(
        "landlock: kernel ABI {effective_abi} only partially enforced the policy; unsupported \
         access rights: {details}; supported rights remain enforced; Landlock ABI 6 or newer \
         (upstream Linux 6.12+) is required for complete enforcement"
    )
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
    for path in paths {
        let fd = match open(path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
            .map_err(io::Error::from)
        {
            Ok(fd) => fd,
            Err(error) if error.is_opaque() => {
                // Missing / unreachable targets must not promote the parent
                // directory into the ruleset. Granting from_write on that
                // ancestor would let the sandboxed process create and mutate
                // sibling names (e.g. allowWrite of .git/index.lock would open
                // the whole .git tree). The seccomp broker still opens exact
                // allowWrite file paths via ADDFD when they are policy-allowed.
                log::debug!(
                    "landlock: {label} {} unreachable, skipping parent grant: {error}",
                    path.display()
                );
                continue;
            }
            Err(error) => return Err(landlock_error(error)),
        };

        let path_access = if fd_is_dir(&fd)? {
            access
        } else {
            access & AccessFs::from_file(TARGET_ABI)
        };
        if path_access.is_empty() {
            continue;
        }

        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, path_access))
            .map_err(landlock_error)?;
    }

    Ok(ruleset)
}

fn add_network_rules(mut ruleset: RulesetCreated, policy: &AccessPolicy) -> Result<RulesetCreated> {
    if !policy.network_access.restricts_connect_tcp() {
        return Ok(ruleset);
    }

    for port in policy.network_access.connect_tcp_ports() {
        ruleset = ruleset
            .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
            .map_err(landlock_error)?;
    }

    Ok(ruleset)
}

fn fd_is_dir(fd: &OwnedFd) -> Result<bool> {
    let stat = match fstat(fd).map_err(io::Error::from) {
        Ok(stat) => stat,
        Err(error) if error.is_transport_failed() => {
            return Ok(false);
        }
        Err(error) => return Err(landlock_error(error)),
    };

    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}
