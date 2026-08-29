// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows restricted-user sandbox implementation.

mod access;
mod account;
mod broker;
mod lease;
mod manage;
pub(super) mod state;
mod wfp;
mod worker;

pub(super) use super::{
    NamedMutex, OwnedLocal, OwnedSecurityDescriptor, SandboxJob, ToWideNul, current_process_token,
    decode_hex, encode_hex, is_locked_error, is_missing_error, join_command_line, own_handle,
    path_access_failed, quote_command_arg, quote_command_text, set_path_access, sid_string,
    token_user, wait_process_exit, win32_error,
};

use crate::error::{Error, Mechanism};
use crate::policy::AccessPolicy;
use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::fs;

pub(super) use manage::active_implementation;
pub(crate) use manage::{manage, status};
pub(crate) use worker::run as run_worker;

pub(super) fn is_installed() -> Result<bool> {
    Ok(state::load_optional()?.is_some())
}
pub(super) fn execute(policy: &AccessPolicy, tool: &OsStr, args: &[OsString]) -> Result<i32> {
    let installation =
        state::load().map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    if !installation.complete {
        return Err(Error::sandbox_setup(
            Mechanism::Windowsuser,
            "restricted-user installation is incomplete",
        )
        .into());
    }
    let network_mode = if policy.network_access.is_unrestricted() {
        state::NetworkMode::Unrestricted
    } else {
        validate_restricted_network(policy, &installation)?;
        state::NetworkMode::Restricted
    };
    let lease = lease::Lease::acquire(&installation, network_mode)?;
    let state_path = state::state_path()
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    let request_id = account::random_identifier(16)
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    let request_path = state_path
        .parent()
        .context("restricted-user state path has no parent")?
        .join("runs")
        .join(format!("{request_id}.json"));
    let cwd = std::env::current_dir()
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    let grants = access::GrantPlan::new(policy, &request_path)?;
    worker::write_request(&request_path, &lease.account().sid, tool, args, &cwd)
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    if let Err(error) = lease.write_journal(&grants) {
        let _ = fs::remove_file(&request_path);
        return Err(Error::sandbox_setup(Mechanism::Windowsuser, error).into());
    }

    let applied_grants;
    let launch_result = match grants.apply(&lease.account().sid) {
        Ok(applied) => {
            // Replace the crash-recovery plan with only entries that reached the
            // DACL update. Pre-update locked grants need no later revocation.
            if let Err(error) = lease.write_journal(&applied) {
                let revoke_result = applied.revoke(&lease.account().sid);
                if revoke_result.is_ok() {
                    let _ = lease.clear_journal();
                }
                let _ = fs::remove_file(&request_path);
                return Err(Error::sandbox_setup(Mechanism::Windowsuser, error).into());
            }
            applied_grants = applied;
            broker::launch(lease.account(), &installation.runner_path, &request_path)
        }
        Err(error) => {
            // A propagating update can fail after partial mutation. Keep and
            // revoke the full pre-apply journal rather than narrowing it.
            applied_grants = grants.clone();
            Err(error)
        }
    };
    let revoke_result = applied_grants.revoke(&lease.account().sid);
    let clear_result = if revoke_result.is_ok() {
        lease
            .clear_journal()
            .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))
    } else {
        Ok(())
    };
    let _ = fs::remove_file(&request_path);
    let exit_code = launch_result?;
    revoke_result?;
    clear_result?;
    Ok(exit_code.cast_signed())
}

pub(super) fn validate(policy: &AccessPolicy) -> Result<()> {
    let installation =
        state::load().map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    if !installation.complete {
        return Err(Error::sandbox_setup(
            Mechanism::Windowsuser,
            "restricted-user installation is incomplete",
        )
        .into());
    }
    if !policy.network_access.is_unrestricted() {
        validate_restricted_network(policy, &installation)?;
    }
    Ok(())
}

fn validate_restricted_network(
    policy: &AccessPolicy,
    installation: &state::Installation,
) -> Result<()> {
    if policy.allow_windows_loopback {
        return Err(Error::sandbox_setup(
            Mechanism::Windowsuser,
            "windows.allowLoopback is not supported by restricted-user isolation",
        )
        .into());
    }
    if policy.network_access.allows_local_tcp_bind() {
        return Err(Error::sandbox_setup(
            Mechanism::Windowsuser,
            "allowLocalBinding is not supported by restricted-user isolation",
        )
        .into());
    }
    if policy
        .network_access
        .connect_tcp_ports()
        .iter()
        .any(|port| *port < installation.proxy_port_low || *port > installation.proxy_port_high)
    {
        return Err(Error::sandbox_setup(
            Mechanism::Windowsuser,
            "restricted-user proxy port is outside the installed WFP allow range",
        )
        .into());
    }
    Ok(())
}
