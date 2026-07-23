// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

mod cli;
mod config;
mod engine;
mod platform;

use crate::cli::{Cli, parse_cli};
use crate::config::load_settings;
use crate::engine::error::Error;
use crate::engine::policy::resolve_policy;
use crate::engine::trap::Trap;
use crate::engine::trap_fd::TrapFd;
use anyhow::Result;
use std::error::Error as StdError;
use std::process;

fn main() {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(error) => {
            // The trap fd is part of the arguments that just failed to parse, so
            // a usage trap can only go to stderr.
            if let Error::Usage { message } = &error {
                eprintln!("{message}");
            }
            Trap::from_error(&error).emit();
            process::exit(2);
        }
    };

    if let Err(error) = run_with_cli(&cli) {
        let trap = error
            .chain()
            .find_map(<dyn StdError + 'static>::downcast_ref::<Error>)
            .map_or_else(|| Trap::internal(format!("{error:#}")), Trap::from_error);
        TrapFd::from_fd(cli.trap_fd).write(&trap);
        trap.emit();
        log::error!("{error:#}");
        process::exit(1);
    }
}

fn run_with_cli(cli: &Cli) -> Result<()> {
    let default_filter = if cli.debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();

    let cwd = std::env::current_dir().map_err(|source| Error::PolicyIoFailed { source })?;

    log::debug!("cli: cwd: {}", cwd.display());
    let settings = load_settings(&cli.policy_paths, cli.format)?;
    let policy = resolve_policy(
        &settings.filesystem,
        &settings.network,
        &settings.windows,
        &cwd,
    )?;

    let trap_fd = TrapFd::from_fd(cli.trap_fd);

    platform::execute(&policy, &cli.tool, &cli.tool_args, &trap_fd)
}
