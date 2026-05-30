// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use crate::policy::{AccessPolicy, ReadAccess};
use landlock::{
    ABI, AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus,
};
use std::path::{Path, PathBuf};

pub(crate) fn enforce_access_policy(
    policy: &AccessPolicy,
    fail_if_unavailable: bool,
) -> Result<()> {
    let write_access = AccessFs::from_write(ABI::V7);
    let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
    let handled_access = match &policy.read_access {
        ReadAccess::Unrestricted => write_access,
        ReadAccess::AllowRoots(_) => write_access | read_access,
    };

    let ruleset = Ruleset::default()
        .handle_access(handled_access)
        .map_err(|source| Error::with_source("landlock: filesystem rights", source))?;
    let mut ruleset = handle_network_access(ruleset, policy)?
        .create()
        .map_err(|source| Error::with_source("landlock: ruleset", source))?;

    ruleset = add_path_rules(ruleset, &policy.write_roots, write_access, "write")?;

    if let ReadAccess::AllowRoots(read_roots) = &policy.read_access {
        ruleset = add_path_rules(ruleset, read_roots, read_access, "read")?;
    }

    ruleset = add_network_rules(ruleset, policy)?;

    let status = ruleset
        .restrict_self()
        .map_err(|source| Error::with_source("landlock", source))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => {
            handle_incomplete_sandbox("landlock: partially enforced", fail_if_unavailable)
        }
        RulesetStatus::NotEnforced => {
            handle_incomplete_sandbox("landlock: not enforced", fail_if_unavailable)
        }
    }
}

fn handle_network_access(mut ruleset: Ruleset, policy: &AccessPolicy) -> Result<Ruleset> {
    let mut access = BitFlags::<AccessNet>::EMPTY;

    if policy.network_access.restrict_connect_tcp {
        access |= AccessNet::ConnectTcp;
    }

    if policy.network_access.restrict_bind_tcp {
        access |= AccessNet::BindTcp;
    }

    if access.is_empty() {
        return Ok(ruleset);
    }

    ruleset = ruleset
        .handle_access(access)
        .map_err(|source| Error::with_source("landlock: network rights", source))?;

    Ok(ruleset)
}

fn add_path_rules(
    mut ruleset: RulesetCreated,
    paths: &[PathBuf],
    access: BitFlags<AccessFs>,
    label: &str,
) -> Result<RulesetCreated> {
    for path in paths {
        let fd = PathFd::new(path).map_err(|source| {
            Error::with_source(format!("landlock: {label} root {}", path.display()), source)
        })?;
        let rule = PathBeneath::new(fd, access_for_path(path, access));
        ruleset = ruleset.add_rule(rule).map_err(|source| {
            Error::with_source(format!("landlock: {label} rule {}", path.display()), source)
        })?;
    }

    Ok(ruleset)
}

fn add_network_rules(mut ruleset: RulesetCreated, policy: &AccessPolicy) -> Result<RulesetCreated> {
    if !policy.network_access.restrict_connect_tcp {
        return Ok(ruleset);
    }

    for port in &policy.network_access.connect_tcp_ports {
        let rule = NetPort::new(*port, AccessNet::ConnectTcp);
        ruleset = ruleset.add_rule(rule).map_err(|source| {
            Error::with_source(format!("landlock: connect TCP {port}"), source)
        })?;
    }

    Ok(ruleset)
}

fn access_for_path(path: &Path, access: BitFlags<AccessFs>) -> BitFlags<AccessFs> {
    if path.is_dir() {
        access
    } else {
        access & AccessFs::from_file(ABI::V7)
    }
}

fn handle_incomplete_sandbox(message: &str, fail_if_unavailable: bool) -> Result<()> {
    if fail_if_unavailable {
        return Err(Error::message(message));
    }

    log::warn!("{message}");
    Ok(())
}
