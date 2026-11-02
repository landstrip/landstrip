// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox implementations.

mod acl;
mod appcontainer;
mod null_device;
mod process;
mod restricted_user;
mod win32;

pub(crate) use restricted_user::run_worker;

use crate::outcome::WindowsStatusReport;
use crate::platform::WindowsCommand;
use crate::policy::AccessPolicy;
use anyhow::Result;
use process::SpawnedProcess;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use win32::ProcessToken;

pub(crate) const RESTRICTED_USER_RUNNER: &str = "landstrip-restricted-user-runner.exe";

pub(crate) fn manage(command: &WindowsCommand) -> Result<WindowsStatusReport> {
    match command {
        WindowsCommand::Status => status(),
        WindowsCommand::PrepareAppContainer => {
            if ProcessToken::is_current_elevated()? {
                null_device::prepare()?;
                appcontainer::LookupRoots::discover().prepare()?;
            } else {
                SpawnedProcess::elevate("windows prepare-appcontainer")?;
            }
            appcontainer::probe_null_device()?;
            status()
        }
        WindowsCommand::Install {
            restricted_accounts,
            unrestricted_accounts,
            proxy_port_low,
            proxy_port_high,
        } => {
            restricted_user::install(
                *restricted_accounts,
                *unrestricted_accounts,
                *proxy_port_low,
                *proxy_port_high,
            )?;
            status()
        }
        WindowsCommand::Uninstall => {
            restricted_user::uninstall()?;
            status()
        }
    }
}

pub(crate) fn status() -> Result<WindowsStatusReport> {
    Ok(restricted_user::status()?.unwrap_or_else(appcontainer::status))
}

pub(crate) fn execute(
    policy: &AccessPolicy,
    cwd: &Path,
    tool: &OsStr,
    args: &[OsString],
) -> Result<i32> {
    if let Some(installation) = restricted_user::Installation::load_installed()? {
        restricted_user::execute(&installation, policy, cwd, tool, args)
    } else {
        appcontainer::execute(policy, cwd, tool, args)
    }
}

pub(crate) fn validate(policy: &AccessPolicy) -> crate::error::Result<()> {
    appcontainer::AppContainerProfile::validate_policy(policy)?;
    if let Some(installation) = restricted_user::Installation::load_installed()? {
        restricted_user::validate(&installation, policy)?;
    }
    Ok(())
}
