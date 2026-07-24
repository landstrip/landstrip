// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows restricted-user sandbox backend.

mod access;
mod account;
mod broker;
mod lease;
mod manage;
mod state;
mod wfp;
mod worker;

use crate::engine::error::{Error, Mechanism};
use crate::engine::policy::AccessPolicy;
use crate::engine::trap_fd::TrapFd;
use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::fs;

pub(super) use manage::manage;
pub(super) fn execute(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    _trap_fd: &TrapFd,
) -> Result<()> {
    let installation = state::load().map_err(setup_failed)?;
    if !installation.complete {
        return Err(setup_failed("restricted-user installation is incomplete").into());
    }
    let network_mode = if policy.network_access.is_unrestricted() {
        state::NetworkMode::Unrestricted
    } else {
        validate_restricted_network(policy, &installation)?;
        state::NetworkMode::Restricted
    };
    let lease = lease::Lease::acquire(&installation, network_mode)?;
    let state_path = state::state_path().map_err(setup_failed)?;
    let request_id = account::random_identifier(16).map_err(setup_failed)?;
    let request_path = state_path
        .parent()
        .context("restricted-user state path has no parent")?
        .join("runs")
        .join(format!("{request_id}.json"));
    let cwd = std::env::current_dir().map_err(setup_failed)?;
    let grants = access::GrantPlan::new(policy, &request_path)?;
    worker::write_request(&request_path, &lease.account().sid, tool, args, &cwd)
        .map_err(setup_failed)?;
    if let Err(error) = lease.write_journal(&grants) {
        let _ = fs::remove_file(&request_path);
        return Err(setup_failed(error).into());
    }

    let launch_result = match grants.apply(&lease.account().sid) {
        Ok(()) => broker::launch(lease.account(), &installation.runner_path, &request_path),
        Err(error) => Err(error),
    };
    let revoke_result = grants.revoke(&lease.account().sid);
    if revoke_result.is_ok() {
        lease.clear_journal().map_err(setup_failed)?;
    }
    let _ = fs::remove_file(&request_path);
    let exit_code = launch_result?;
    revoke_result?;
    std::process::exit(i32::from_ne_bytes(exit_code.to_ne_bytes()));
}

pub(super) fn run_worker(request: &std::path::Path) -> Result<()> {
    worker::run(request)
}

fn validate_restricted_network(
    policy: &AccessPolicy,
    installation: &state::Installation,
) -> Result<()> {
    if policy.allow_windows_loopback {
        return Err(setup_failed(
            "windows.allowLoopback is not supported by the restricted-user backend",
        )
        .into());
    }
    if policy.network_access.local_tcp_bind || !policy.network_access.restrict_bind_tcp {
        return Err(setup_failed(
            "allowLocalBinding is not supported by the restricted-user backend",
        )
        .into());
    }
    if policy
        .network_access
        .connect_tcp_ports
        .iter()
        .any(|port| *port < installation.proxy_port_low || *port > installation.proxy_port_high)
    {
        return Err(setup_failed(
            "restricted-user proxy port is outside the installed WFP allow range",
        )
        .into());
    }
    Ok(())
}

fn setup_failed(source: impl Into<crate::engine::error::Cause>) -> Error {
    Error::SandboxSetupFailed {
        mechanism: Mechanism::Windowsuser,
        source: source.into(),
    }
}
