// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Linux sandbox platform using Landlock and seccomp.

mod filter;
mod landlock;
mod namespace;
mod seccomp;
mod signals;

use crate::policy::{AccessPolicy, ReadAccess};
use crate::trap_fd::TrapFd;
use ::landlock::{AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};
use anyhow::{Context, Result};
use seccomp::ensure_notification_supported;
use std::ffi::{OsStr, OsString};
use std::path::Path;

pub(crate) fn doctor() -> Result<()> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::Execute)
        .context("Landlock execute access is unavailable")?
        .create()
        .context("create a Landlock ruleset")?;

    ensure_notification_supported()?;
    namespace::probe()
}

pub(crate) fn validate() -> Result<()> {
    namespace::probe().map_err(|error| {
        crate::error::Error::sandbox_setup(
            crate::error::Mechanism::Namespace,
            error.into_boxed_dyn_error(),
        )
    })?;
    Ok(())
}

pub(crate) fn execute(
    policy: &AccessPolicy,
    cwd: &Path,
    tool: &OsStr,
    args: &[OsString],
    trap_fd: Option<&TrapFd>,
    inherited_fds: &[std::os::fd::RawFd],
) -> Result<i32> {
    let network = &policy.network_access;
    if network.unix_socket_access().needs_broker() {
        log::debug!("linux: unix socket policy with seccomp enabled");
    }

    let needs_fs_broker = !policy.write_roots.is_empty()
        || policy.write_carveouts.has_patterns()
        || !matches!(policy.read_access, ReadAccess::Unrestricted)
        || trap_fd.is_some();

    seccomp::run_broker(
        policy,
        cwd,
        tool,
        args,
        needs_fs_broker,
        trap_fd,
        inherited_fds,
    )
}
