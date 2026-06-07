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
use crate::policy::lower_sandbox_policy;
use std::process;

fn main() {
    if let Err(error) = run() {
        if let Error::Usage(_) = &error {
            eprintln!("{error}");
            process::exit(2);
        }

        if let Err(error) = print_error_response(&error) {
            eprintln!("failed to serialize error response: {error}");
        }
        process::exit(1);
    }
}
fn print_error_response(error: &Error) -> std::result::Result<(), serde_json::Error> {
    let Some(response) = error.response() else {
        return Ok(());
    };

    println!("{}", serde_json::to_string(&response)?);
    Ok(())
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

    platform::execute(&policy, &cli.policy_base, &cli.tool, &cli.tool_args)?;

    Ok(())
}
