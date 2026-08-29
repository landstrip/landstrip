// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Linux sandbox platform using Landlock and seccomp.

mod filter;
mod landlock;
mod seccomp;

use crate::error::Error;
use crate::platform::unix::close_inherited_fds;
use crate::policy::{AccessPolicy, ReadAccess, UnixSocketAccess};
use crate::trap_fd::TrapFd;
use ::landlock::{AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};
use anyhow::{Context, Result};
use landlock::enforce_access_policy;
use seccomp::ensure_notification_supported;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Reads an integer-valued socket option via `getsockopt(2)`.
pub(crate) fn getsockopt_int(fd: i32, level: i32, name: i32) -> std::io::Result<i32> {
    // SAFETY: getsockopt writes a scalar into value; len bounds the storage.
    let mut value: i32 = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of_val(&value)).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket option size exceeds socklen_t",
        )
    })?;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

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
    let needs_network_broker = network.needs_network_broker();
    // allowNetwork / allowAllUnixSockets leave connect unmediated; still trap it so
    // systemd-run cannot start a process outside Landlock and seccomp.
    let needs_unix_supervisor =
        matches!(network.unix_socket_access(), UnixSocketAccess::Unrestricted);

    if needs_network_broker || needs_fs_broker || needs_unix_supervisor {
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

    enforce_access_policy(policy, true)?;

    if !network.is_unrestricted() {
        let filters = filter::network_filter(network.unix_socket_access().into(), true)?;
        filters.load()?;
    }
    close_inherited_fds(&[]).map_err(Error::supervise)?;
    let error = Command::new(tool).args(args).exec();
    Err(Error::launch(tool, error).into())
}
