// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
// Large Err variant expected — Error carries optional diagnostic context
#![allow(clippy::result_large_err)]

mod cli;
mod config;
mod error;
mod error_fd;
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
mod traversal;

use crate::cli::{Cli, parse_cli};
use crate::config::load_settings;
use crate::error::{ErrorKind, Result};
use crate::error_fd::ErrorFd;
use crate::policy::resolve_policy;
use std::process;

fn main() {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(error) => {
            error.emit();
            process::exit(if matches!(error.kind, ErrorKind::Usage) {
                2
            } else {
                1
            });
        }
    };

    if let Err(error) = run_with_cli(&cli) {
        if let ErrorKind::Usage = error.kind {
            eprintln!("{error}");
            process::exit(2);
        }
        error.emit();
        process::exit(1);
    }
}

fn run_with_cli(cli: &Cli) -> Result<()> {
    let default_filter = if cli.debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();

    let cwd = std::env::current_dir()?;

    log::debug!("cli: cwd: {}", cwd.display());
    let settings = load_settings(&cli.policy_paths, cli.format)?;
    let policy = resolve_policy(&settings.filesystem, &settings.network, &cwd)?;

    let error_fd = ErrorFd::from_fd(cli.error_fd);
    platform::execute(&policy, &cli.tool, &cli.tool_args, error_fd)?;

    Ok(())
}
