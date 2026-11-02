// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows restricted-user sandbox implementation.

mod access;
mod account;
mod broker;
mod lease;
mod manage;
mod state;
mod wfp;
mod worker;

use crate::error::{Error, Mechanism};
use crate::policy::AccessPolicy;
use anyhow::Result;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;

pub(super) use manage::{install, status, uninstall};
pub(super) use state::Installation;
pub(crate) use worker::run as run_worker;

pub(super) fn execute(
    installation: &state::Installation,
    policy: &AccessPolicy,
    cwd: &Path,
    tool: &OsStr,
    args: &[OsString],
) -> Result<i32> {
    installation.ensure_ready()?;
    let network_mode = installation.resolve_network_mode(policy)?;
    let store = state::StateStore::locate()
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    let lease = lease::Lease::acquire(&store, installation, network_mode)?;
    // Loopback stays closed for the account unless this run's policy names the
    // ports, and then only for as long as the run lasts.
    let permits = match network_mode {
        state::NetworkMode::Restricted => wfp::RunPermits::add(
            installation,
            &lease.account().sid,
            policy.network_access.connect_tcp_ports(),
        )
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?,
        state::NetworkMode::Unrestricted => None,
    };
    let request_id = account::random_identifier(16)
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    let request_path = store.runs_dir().join(format!("{request_id}.json"));
    let grants = access::GrantPlan::new(policy, &request_path)?;
    worker::write_request(&request_path, &lease.account().sid, tool, args, cwd)
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
    drop(permits);
    Ok(exit_code.cast_signed())
}

pub(super) fn validate(
    installation: &state::Installation,
    policy: &AccessPolicy,
) -> crate::error::Result<()> {
    installation.validate_policy(policy)
}
