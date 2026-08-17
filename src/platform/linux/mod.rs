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
use filter::NetworkFilter;
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
    let unrestricted_network = network.is_unrestricted();
    if filter::needs_unix_socket_broker(&network.unix_socket_access) {
        log::debug!("linux: unix socket policy with seccomp enabled");
    }

    let needs_fs_broker = filter::needs_filesystem_broker(policy) || trap_fd.is_some();
    let needs_network_broker = !unrestricted_network
        && (network.local_tcp_bind
            || !network.connect_tcp_ports.is_empty()
            || filter::needs_unix_socket_broker(&network.unix_socket_access));

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

    if !unrestricted_network {
        let filters = filter::network_filter(
            NetworkFilter {
                notify_bind: false,
                notify_connect: false,
                notify_filesystem: false,
                unix_sockets: filter::unix_socket_filter(&network.unix_socket_access),
            },
            true,
        )?;
        filters.load()?;
    }
    close_inherited_fds(&[]).map_err(Error::supervise)?;
    let error = Command::new(tool).args(args).exec();
    Err(Error::launch(tool, error).into())
}
