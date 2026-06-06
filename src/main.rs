// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    path = "fallback.rs"
)]
mod backend;
mod cli;
mod config;
mod error;
#[cfg(target_os = "linux")]
mod fd;
#[cfg(target_os = "linux")]
mod landlock;
mod paths;
mod policy;
#[cfg(target_os = "linux")]
mod seccomp;
mod traversal;

use crate::cli::parse_cli;
use crate::config::load_settings;
use crate::error::{Error, Result};
use crate::policy::lower_sandbox_policy;
use std::process;

fn main() {
    if let Err(error) = run() {
        let exit_code = match error {
            Error::Usage(_) => 2,
            _ => 1,
        };

        eprintln!("{error}");
        process::exit(exit_code);
    }
}

fn run() -> Result<()> {
    let cli = parse_cli()?;
    let default_filter = if cli.debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();

    log::debug!("policy: base {}", cli.policy_base.display());
    let settings = load_settings(&cli.policy_paths)?;
    let policy = lower_sandbox_policy(&settings.filesystem, &settings.network, &cli.policy_base)?;

    backend::execute(&policy, &cli.policy_base, &cli.command, &cli.command_args)?;

    Ok(())
}
