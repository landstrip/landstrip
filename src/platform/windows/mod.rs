// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox implementations.

use crate::cli::WindowsCommand;

mod appcontainer;
mod restricted_user;

use crate::engine::policy::AccessPolicy;
use crate::engine::trap_fd::TrapFd;
use anyhow::Result;
use std::ffi::{OsStr, OsString};

pub(crate) fn execute(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    trap_fd: &TrapFd,
) -> Result<()> {
    if restricted_user::is_installed()? {
        restricted_user::execute(policy, tool, args, trap_fd)
    } else {
        appcontainer::execute(policy, tool, args, trap_fd)
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

pub(crate) fn manage(command: &WindowsCommand) -> Result<()> {
    restricted_user::manage(command)
}

pub(crate) fn run_worker(request: &std::path::Path) -> Result<()> {
    restricted_user::run_worker(request)
}

pub(crate) fn doctor() -> Result<&'static str> {
    restricted_user::active_implementation()
}
