// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Linux sandbox platform using Landlock and seccomp.

pub(crate) mod fd;
mod filter;
mod landlock;
mod seccomp;

use crate::error::Error;
use crate::policy::AccessPolicy;
use crate::trap_fd::TrapFd;
use ::landlock::{AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};
use anyhow::{Context, Result};
use fd::close_inherited_fds;
use landlock::enforce_access_policy;
use seccomp::ensure_notification_supported;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::process::Command;

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

    let needs_fs_broker = filter::needs_filesystem_broker(policy) || trap_fd.is_some();
    let needs_network_broker = network.needs_network_broker();

    if needs_network_broker || needs_fs_broker {
        let status = seccomp::run_broker(
            policy,
            tool,
            args,
            needs_network_broker,
            needs_fs_broker,
            trap_fd,
        )?;
        return Ok(status);
    }

    enforce_access_policy(policy)?;

    if !network.is_unrestricted() {
        let filters = filter::network_filter(network.unix_socket_access().into(), true)?;
        filters.load()?;
    }
    close_inherited_fds(&[]).map_err(Error::supervise)?;
    let error = Command::new(tool).args(args).exec();
    Err(Error::launch(tool, error).into())
}
