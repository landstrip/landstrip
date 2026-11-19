// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

mod args;

use self::args::{Command, Invocation, ParseOutcome, PolicyRequest, RunCommand};
use crate::error::Error;
use crate::outcome::{CommandOutcome, PolicyValidationReport};
use crate::platform;
use crate::trap::Trap;
#[cfg(unix)]
use crate::trap_fd::TrapFd;
use anyhow::Result;
use std::io;
use std::process;

pub fn execute() {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    if let Some(result) = platform::resume_if_requested() {
        process::exit(result.unwrap_or_else(|error| {
            eprintln!("broker restart: {error:#}");
            127
        }));
    }
    let mut invocation = match ParseOutcome::parse() {
        Ok(ParseOutcome::Invocation(invocation)) => invocation,
        Ok(ParseOutcome::Display(error)) => {
            if let Err(error) = error.print() {
                exit_with_error(&error.into(), None);
            }
            let exit_code = error.exit_code();
            if exit_code != 0 {
                process::exit(exit_code);
            }
            return;
        }
        Err(error) => exit_with_error(&error.into(), None),
    };

    if let Err(error) = init_logging(invocation.debug) {
        exit_with_error(&error, trap_descriptor(&invocation));
    }

    let outcome = match dispatch(&mut invocation) {
        Ok(outcome) => outcome,
        Err(error) => exit_with_error(&error, trap_descriptor(&invocation)),
    };
    if let Err(error) = outcome
        .write_to(&mut io::stdout().lock())
        .map_err(anyhow::Error::from)
    {
        exit_with_error(&error, trap_descriptor(&invocation));
    }
    let exit_code = outcome.exit_code();
    if exit_code != 0 {
        process::exit(exit_code);
    }
}

fn init_logging(debug: bool) -> Result<()> {
    let default_filter = if debug { "debug" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .try_init()?;
    Ok(())
}

/// Names the trap descriptor an error is reported on.
#[cfg(unix)]
fn trap_descriptor(invocation: &Invocation) -> Option<&TrapFd> {
    match &invocation.command {
        Command::Run(command) => command.trap_fd.as_ref(),
        _ => None,
    }
}

#[cfg(not(unix))]
fn trap_descriptor(_invocation: &Invocation) -> Option<&()> {
    None
}

fn dispatch(invocation: &mut Invocation) -> Result<CommandOutcome> {
    match &mut invocation.command {
        Command::Run(command) => run(command),
        Command::Check(request) => check_policy(request),
        Command::Resolve(request) => resolve_policy(request),
        Command::Doctor => {
            let report = platform::doctor()?;
            Ok(CommandOutcome::json(report.ok, report)?)
        }
        Command::Selftest(args) => Ok(args.run()?),
        Command::SelftestWorker(args) => Ok(args.run()),
        #[cfg(target_os = "windows")]
        Command::Windows(command) => {
            let report = platform::manage_windows(command)?;
            Ok(CommandOutcome::json(report.healthy, report)?)
        }
        #[cfg(target_os = "windows")]
        Command::Worker { request } => platform::run_worker(request).map(CommandOutcome::Exit),
    }
}

fn run(command: &mut RunCommand) -> Result<CommandOutcome> {
    let policy = command
        .policy
        .resolve(&command.cwd, Some(command.tool.as_os_str()))?;
    platform::validate(&policy)?;
    #[cfg(unix)]
    let result = platform::execute(
        &policy,
        &command.cwd,
        &command.tool,
        &command.tool_args,
        command.trap_fd.as_mut(),
        &command
            .inherited_fds
            .iter()
            .map(std::os::fd::AsRawFd::as_raw_fd)
            .collect::<Vec<_>>(),
    );
    #[cfg(not(unix))]
    let result = platform::execute(&policy, &command.cwd, &command.tool, &command.tool_args);

    result.map(CommandOutcome::Exit)
}

fn check_policy(request: &PolicyRequest) -> Result<CommandOutcome> {
    let result = request
        .policy
        .resolve(&request.cwd, request.tool.as_deref())
        .and_then(|policy| platform::check(&policy));
    let report = PolicyValidationReport::try_from(result)?;
    Ok(CommandOutcome::json(report.valid, report)?)
}

fn resolve_policy(request: &PolicyRequest) -> Result<CommandOutcome> {
    let policy = request
        .policy
        .resolve(&request.cwd, request.tool.as_deref())?;
    Ok(CommandOutcome::json(true, policy)?)
}

fn exit_with_error(
    error: &anyhow::Error,
    #[cfg(unix)] trap_fd: Option<&TrapFd>,
    #[cfg(not(unix))] _trap_fd: Option<&()>,
) -> ! {
    let (trap, exit_code) = error_trap(error);
    #[cfg(unix)]
    trap.emit_with_fd(trap_fd);
    #[cfg(not(unix))]
    trap.emit();
    process::exit(exit_code)
}

fn error_trap(error: &anyhow::Error) -> (Trap, i32) {
    let trap = Trap::from(error);
    let exit_code = if matches!(Error::find_in(error), Some(Error::Usage { .. })) {
        2
    } else {
        1
    };
    (trap, exit_code)
}
