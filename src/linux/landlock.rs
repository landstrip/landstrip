// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Landlock enforcement for lowered filesystem and TCP port rules.
//!
//! Filesystem rules grant access to objects opened while creating the ruleset.
//! This gives deny traversal snapshot semantics: a removed and recreated path is
//! a new object unless an allowed ancestor covers it.

use crate::error::{Error, Result};
use crate::policy::{AccessPolicy, ReadAccess};
use landlock::{
    ABI, AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, PathFdError, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
};
use std::io;
use std::path::PathBuf;

pub(super) fn enforce_access_policy(policy: &AccessPolicy) -> Result<()> {
    let write_access = AccessFs::from_write(ABI::V7);
    let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
    let handled_access = match &policy.read_access {
        ReadAccess::Unrestricted => write_access,
        ReadAccess::AllowRoots(_) => write_access | read_access,
    };

    let mut network_access = BitFlags::<AccessNet>::EMPTY;

    if policy.network_access.restrict_connect_tcp {
        network_access |= AccessNet::ConnectTcp;
    }

    if policy.network_access.restrict_bind_tcp {
        network_access |= AccessNet::BindTcp;
    }

    let ruleset = Ruleset::default()
        .handle_access(handled_access)
        .map_err(|error| Error::system(error.to_string()))?;
    let mut ruleset = if network_access.is_empty() {
        ruleset
    } else {
        ruleset
            .handle_access(network_access)
            .map_err(|error| Error::system(error.to_string()))?
    }
    .create()
    .map_err(|error| Error::system(error.to_string()))?;

    ruleset = add_path_rules(ruleset, &policy.write_roots, write_access, "write")?;

    if let ReadAccess::AllowRoots(read_roots) = &policy.read_access {
        ruleset = add_path_rules(ruleset, read_roots, read_access, "read")?;
    }

    ruleset = add_network_rules(ruleset, policy)?;

    let status = ruleset
        .restrict_self()
        .map_err(|error| Error::system(error.to_string()))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => Err(Error::Capability {
            message: "sandbox ruleset partially enforced".to_owned(),
        }),
        RulesetStatus::NotEnforced => Err(Error::Capability {
            message: "sandbox ruleset not enforced".to_owned(),
        }),
    }
}

fn add_path_rules(
    mut ruleset: RulesetCreated,
    paths: &[PathBuf],
    access: BitFlags<AccessFs>,
    label: &str,
) -> Result<RulesetCreated> {
    for path in paths {
        let fd = match PathFd::new(path) {
            Ok(fd) => fd,
            Err(PathFdError::OpenCall { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                log::debug!("policy: {label} path {} missing, skipping", path.display());
                continue;
            }
            Err(error) => return Err(Error::system(error.to_string())),
        };
        let path_access = if path.is_dir() {
            access
        } else {
            access & AccessFs::from_file(ABI::V7)
        };
        let rule = PathBeneath::new(fd, path_access);
        ruleset = ruleset
            .add_rule(rule)
            .map_err(|error| Error::system(error.to_string()))?;
    }

    Ok(ruleset)
}

fn add_network_rules(mut ruleset: RulesetCreated, policy: &AccessPolicy) -> Result<RulesetCreated> {
    if !policy.network_access.restrict_connect_tcp {
        return Ok(ruleset);
    }

    for port in &policy.network_access.connect_tcp_ports {
        let rule = NetPort::new(*port, AccessNet::ConnectTcp);
        ruleset = ruleset
            .add_rule(rule)
            .map_err(|error| Error::system(error.to_string()))?;
    }

    Ok(ruleset)
}
