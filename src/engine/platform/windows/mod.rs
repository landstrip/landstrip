// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox implementations.

use super::WindowsCommand;

mod appcontainer;
mod restricted_user;

use crate::engine::outcome::WindowsStatusReport;
use crate::engine::policy::AccessPolicy;
use anyhow::Result;
use std::ffi::{OsStr, OsString};

pub(crate) fn execute(policy: &AccessPolicy, tool: &OsStr, args: &[OsString]) -> Result<i32> {
    if restricted_user::is_installed()? {
        restricted_user::execute(policy, tool, args)
    } else {
        appcontainer::execute(policy, tool, args)
    }
}

pub(crate) fn validate(policy: &AccessPolicy) -> Result<()> {
    policy.validate()?;
    if restricted_user::is_installed()? {
        restricted_user::active_implementation()?;
        restricted_user::validate(policy)?;
    }
    Ok(())
}

pub(crate) fn manage(command: &WindowsCommand) -> Result<WindowsStatusReport> {
    restricted_user::manage(command)
}

pub(crate) fn run_worker(request: &std::path::Path) -> Result<i32> {
    restricted_user::run_worker(request)
}

pub(crate) fn status() -> Result<WindowsStatusReport> {
    restricted_user::status()
}
