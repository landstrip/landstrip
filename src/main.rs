// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod cli;
mod config;
mod paths;
#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    path = "fallback.rs"
)]
mod platform;
mod policy;
mod trap;
mod trap_fd;
mod traversal;

use crate::cli::{Cli, parse_cli};
use crate::config::load_settings;
use crate::policy::resolve_policy;
use crate::trap::{Result, Trap};
use crate::trap_fd::TrapFd;
use std::process;

fn main() {
    let cli = parse_cli().unwrap_or_else(|e| exit_with_trap(&e));

    if let Err(trap) = run_with_cli(&cli) {
        exit_with_trap(&trap);
    }
}

fn exit_with_trap(trap: &Trap) -> ! {
    trap.emit();
    process::exit(if trap.is_usage() { 2 } else { 1 });
}

fn run_with_cli(cli: &Cli) -> Result<()> {
    let default_filter = if cli.debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();

    let cwd = std::env::current_dir()?;

    log::debug!("cli: cwd: {}", cwd.display());
    let settings = load_settings(&cli.policy_paths, cli.format)?;
    let policy = resolve_policy(
        &settings.filesystem,
        &settings.network,
        &settings.windows,
        &cwd,
    )?;

    let trap_fd = TrapFd::from_fd(cli.trap_fd);
    platform::execute(&policy, &cli.tool, &cli.tool_args, trap_fd)?;

    Ok(())
}
