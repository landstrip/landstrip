// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox backends.

use crate::cli::WindowsCommand;

mod appcontainer;
mod restricted_user;

use crate::config::WindowsBackend;
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
    match policy.windows_backend {
        WindowsBackend::AppContainer => appcontainer::execute(policy, tool, args, trap_fd),
        WindowsBackend::RestrictedUser => restricted_user::execute(policy, tool, args, trap_fd),
    }
}

pub(crate) fn manage(command: &WindowsCommand) -> Result<()> {
    match command {
        WindowsCommand::Worker { request } => restricted_user::run_worker(request),
        command => restricted_user::manage(command),
    }
}
