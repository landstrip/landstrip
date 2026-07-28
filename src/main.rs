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

use crate::cli::{Command, Invocation, PolicyCommand, PolicyRequest, RunCommand, parse_cli};
use crate::config::load_settings;
use crate::engine::error::Error;
use crate::engine::policy::{AccessPolicy, resolve_policy};
use crate::engine::trap::Trap;
use crate::engine::trap_fd::TrapFd;
use anyhow::Result;
use std::error::Error as StdError;
use std::process;

fn main() {
    let invocation = match parse_cli() {
        Ok(invocation) => invocation,
        Err(error) => exit_with_error(&error.into(), &TrapFd::from_fd(None)),
    };
    init_logging(invocation.debug);

    let trap_fd = match &invocation.command {
        Command::Run(command) => TrapFd::from_fd(command.trap_fd),
        _ => TrapFd::from_fd(None),
    };
    if let Err(error) = dispatch(&invocation) {
        exit_with_error(&error, &trap_fd);
    }
}

fn init_logging(debug: bool) {
    let default_filter = if debug { "debug" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();
}

fn dispatch(invocation: &Invocation) -> Result<()> {
    match &invocation.command {
        Command::Run(command) => run(command),
        Command::Policy(command) => inspect_policy(command),
        Command::Doctor => platform::doctor(),
        Command::Windows(command) => platform::manage_windows(command),
        Command::Worker { request } => platform::run_worker(request),
    }
}

fn run(command: &RunCommand) -> Result<()> {
    let policy = load_policy(&command.policy, Some(command.tool.as_os_str()))?;
    platform::validate(&policy)?;
    let trap_fd = TrapFd::from_fd(command.trap_fd);
    platform::execute(&policy, &command.tool, &command.tool_args, &trap_fd)
}

fn inspect_policy(command: &PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Validate(request) => {
            let policy = load_requested_policy(request)?;
            platform::validate(&policy)?;
            println!("policy valid");
        }
        PolicyCommand::Resolve(request) => {
            let policy = load_requested_policy(request)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
    }
    Ok(())
}

fn load_requested_policy(request: &PolicyRequest) -> Result<AccessPolicy> {
    load_policy(&request.policy, request.tool.as_deref())
}

fn load_policy(
    input: &crate::cli::PolicyInput,
    tool: Option<&std::ffi::OsStr>,
) -> Result<AccessPolicy> {
    let format = crate::cli::policy_format(input)?;
    let cwd = std::env::current_dir().map_err(|source| Error::PolicyIoFailed { source })?;
    log::debug!("cli: cwd: {}", cwd.display());
    let settings = load_settings(&input.paths, format, tool)?;
    resolve_policy(
        &settings.filesystem,
        &settings.network,
        &settings.windows,
        &cwd,
    )
}

fn exit_with_error(error: &anyhow::Error, trap_fd: &TrapFd) -> ! {
    let engine_error = error
        .chain()
        .find_map(<dyn StdError + 'static>::downcast_ref::<Error>);
    let trap = engine_error.map_or_else(|| Trap::internal(format!("{error:#}")), Trap::from_error);

    if let Some(Error::Usage { message }) = engine_error {
        eprintln!("{message}");
        trap_fd.write(&trap);
        trap.emit();
        process::exit(2);
    }

    trap_fd.write(&trap);
    trap.emit();
    log::error!("{error:#}");
    process::exit(1)
}
