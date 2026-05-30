// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod cli;
mod config;
mod error;
mod landlock;
mod paths;
mod policy;
mod traversal;

use crate::cli::parse_cli;
use crate::config::load_settings;
use crate::error::{Error, Result};
use crate::landlock::enforce_access_policy;
use crate::policy::lower_sandbox_policy;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{self, Command};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:?}");
        process::exit(error.exit_code());
    }
}

fn run() -> Result<()> {
    let cli = parse_cli()?;
    init_logger(cli.debug);

    log::debug!("policy: base {}", cli.policy_base.display());
    let settings = load_settings(&cli.policy_paths)?;
    apply_sandbox(&settings, &cli.policy_base)?;
    exec_command(&cli.command, &cli.command_args)
}

fn init_logger(debug: bool) {
    let default_filter = if debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();
}

fn apply_sandbox(settings: &config::Settings, policy_base: &Path) -> Result<()> {
    let policy = lower_sandbox_policy(&settings.filesystem, &settings.network, policy_base)?;

    enforce_access_policy(&policy)
}

fn exec_command(command: &OsStr, args: &[OsString]) -> Result<()> {
    let error = Command::new(command).args(args).exec();
    Err(Error::with_source(
        format!("exec: {}", command.to_string_lossy()),
        error,
    ))
}
