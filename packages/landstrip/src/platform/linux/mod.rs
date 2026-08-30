// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Linux sandbox platform using Landlock and seccomp.

mod filter;
mod landlock;
mod seccomp;

use crate::policy::{AccessPolicy, ReadAccess};
use crate::trap_fd::TrapFd;
use ::landlock::{AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};
use anyhow::{Context, Result};
use seccomp::ensure_notification_supported;
use std::ffi::{OsStr, OsString};

pub(crate) fn doctor() -> Result<()> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::Execute)
        .context("Landlock execute access is unavailable")?
        .create()
        .context("create a Landlock ruleset")?;

    ensure_notification_supported()?;
    Ok(())
}
pub(crate) fn execute(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    trap_fd: Option<&TrapFd>,
) -> Result<i32> {
    let network = &policy.network_access;
    if network.unix_socket_access().needs_broker() {
        log::debug!("linux: unix socket policy with seccomp enabled");
    }

    let needs_fs_broker = !policy.write_roots.is_empty()
        || !matches!(policy.read_access, ReadAccess::Unrestricted)
        || trap_fd.is_some();

    seccomp::run_broker(
        policy,
        tool,
        args,
        network.needs_network_broker(),
        needs_fs_broker,
        trap_fd,
    )
}
