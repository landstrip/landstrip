// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod cli;
mod config;
mod error;
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

use crate::cli::parse_cli;
use crate::config::load_settings;
use crate::error::{Error, Result};
use crate::policy::resolve_policy;
use std::process;

fn main() {
    if let Err(error) = run() {
        if let Error::Usage(_) = &error {
            eprintln!("{error}");
            process::exit(2);
        }
        let _ = print_error_response(&error);

        process::exit(1);
    }
}
fn print_error_response(error: &Error) -> std::result::Result<(), serde_json::Error> {
    let Some(response) = error.response() else {
        return Ok(());
    };

    eprintln!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn run() -> Result<()> {
    let cli = parse_cli()?;
    let default_filter = if cli.debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();

    let cwd = std::env::current_dir()?;

    log::debug!("policy: cwd: {}", cwd.display());
    let settings = load_settings(&cli.policy_paths)?;
    let policy = resolve_policy(&settings.filesystem, &settings.network, &cwd)?;

    platform::execute(&policy, &cli.tool, &cli.tool_args)?;

    Ok(())
}
