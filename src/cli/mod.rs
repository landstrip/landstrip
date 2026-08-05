// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

mod args;

use self::args::{
    Command, Invocation, ParseOutcome, PolicyCommand, PolicyInput, PolicyRequest, RunCommand,
    parse_cli,
};
use crate::engine::config::{PolicyFormat, load_settings};
use crate::engine::error::Error;
use crate::engine::outcome::{CommandOutcome, PolicyValidationError, PolicyValidationReport};
use crate::engine::platform;
use crate::engine::policy::AccessPolicy;
use crate::engine::trap::Trap;
#[cfg(unix)]
use crate::engine::trap_fd::TrapFd;
use anyhow::Result;
use serde::Serialize;
use std::error::Error as StdError;
use std::io::{self, Write};
use std::process;

pub(crate) fn execute() {
    let invocation = match parse_cli() {
        Ok(ParseOutcome::Invocation(invocation)) => invocation,
        Ok(ParseOutcome::Display(text)) => {
            if let Err(error) = render_display(&text) {
                exit_with_error(&error);
            }
            return;
        }
        Err(error) => exit_with_error(&error.into()),
    };
    init_logging(invocation.debug);

    #[cfg(unix)]
    let trap_fd = match &invocation.command {
        Command::Run(command) => TrapFd::from_fd(command.trap_fd),
        _ => TrapFd::from_fd(None),
    };
    let outcome = match dispatch(&invocation) {
        Ok(outcome) => outcome,
        Err(error) => {
            #[cfg(unix)]
            exit_with_trap_fd(&error, &trap_fd);
            #[cfg(not(unix))]
            exit_with_error(&error);
        }
    };
    if let Err(error) = render_outcome(&outcome) {
        #[cfg(unix)]
        exit_with_trap_fd(&error, &trap_fd);
        #[cfg(not(unix))]
        exit_with_error(&error);
    }
    let exit_code = outcome.exit_code();
    if exit_code != 0 {
        process::exit(exit_code);
    }
}

fn init_logging(debug: bool) {
    let default_filter = if debug { "debug" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();
}

fn dispatch(invocation: &Invocation) -> Result<CommandOutcome> {
    match &invocation.command {
        Command::Run(command) => run(command),
        Command::Policy(command) => inspect_policy(command),
        Command::Doctor => platform::doctor().map(CommandOutcome::Doctor),
        #[cfg(target_os = "windows")]
        Command::Windows(command) => platform::manage_windows(command).map(CommandOutcome::Windows),
        #[cfg(target_os = "windows")]
        Command::Worker { request } => platform::run_worker(request).map(CommandOutcome::Exit),
    }
}

fn run(command: &RunCommand) -> Result<CommandOutcome> {
    let policy = load_policy(&command.policy, Some(command.tool.as_os_str()))?;
    platform::validate(&policy)?;
    execute_run(&policy, command).map(CommandOutcome::Exit)
}

#[cfg(unix)]
fn execute_run(policy: &AccessPolicy, command: &RunCommand) -> Result<i32> {
    let trap_fd = TrapFd::from_fd(command.trap_fd);
    platform::execute(policy, &command.tool, &command.tool_args, &trap_fd)
}

#[cfg(not(unix))]
fn execute_run(policy: &AccessPolicy, command: &RunCommand) -> Result<i32> {
    platform::execute(policy, &command.tool, &command.tool_args)
}

fn inspect_policy(command: &PolicyCommand) -> Result<CommandOutcome> {
    match command {
        PolicyCommand::Validate(request) => {
            validate_requested_policy(request).map(CommandOutcome::PolicyValidated)
        }
        PolicyCommand::Resolve(request) => {
            let policy = load_requested_policy(request)?;
            Ok(CommandOutcome::PolicyResolved(policy))
        }
    }
}

fn load_requested_policy(request: &PolicyRequest) -> Result<AccessPolicy> {
    load_policy(&request.policy, request.tool.as_deref())
}

fn validate_requested_policy(request: &PolicyRequest) -> Result<PolicyValidationReport> {
    let result = load_requested_policy(request).and_then(|policy| platform::validate(&policy));
    policy_validation_report(result)
}

fn policy_validation_report(result: Result<()>) -> Result<PolicyValidationReport> {
    match result {
        Ok(()) => Ok(PolicyValidationReport {
            valid: true,
            error: None,
        }),
        Err(error) => {
            let Some(engine_error) = find_engine_error(&error) else {
                return Err(error);
            };
            let Some(fallback_message) = engine_error.policy_validation_message() else {
                return Err(error);
            };
            let code = engine_error.code();
            let rendered_message = format!("{error:#}");
            let message = if rendered_message == code {
                fallback_message.to_owned()
            } else {
                rendered_message
            };

            Ok(PolicyValidationReport {
                valid: false,
                error: Some(PolicyValidationError { code, message }),
            })
        }
    }
}

fn load_policy(input: &PolicyInput, tool: Option<&std::ffi::OsStr>) -> Result<AccessPolicy> {
    let format = PolicyFormat::try_from(input)?;
    let cwd = std::env::current_dir()?;
    log::debug!("cli: cwd: {}", cwd.display());
    let settings = load_settings(&input.paths, format, tool)?;
    settings.resolve(&cwd)
}

fn render_display(text: &str) -> Result<()> {
    let stdout = io::stdout();
    stdout.lock().write_all(text.as_bytes())?;
    Ok(())
}
fn render_outcome(outcome: &CommandOutcome) -> Result<()> {
    let stdout = io::stdout();
    render_outcome_to(&mut stdout.lock(), outcome)
}

fn render_outcome_to(output: &mut impl Write, outcome: &CommandOutcome) -> Result<()> {
    match outcome {
        CommandOutcome::Exit(_) => Ok(()),
        CommandOutcome::PolicyValidated(report) => write_json(output, report),
        CommandOutcome::PolicyResolved(policy) => write_json(output, policy),
        CommandOutcome::Doctor(report) => write_json(output, report),
        #[cfg(target_os = "windows")]
        CommandOutcome::Windows(report) => write_json(output, report),
    }
}

fn write_json(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    writeln!(output)?;
    Ok(())
}

fn exit_with_error(error: &anyhow::Error) -> ! {
    let (trap, exit_code) = error_trap(error);
    trap.emit();
    process::exit(exit_code)
}

#[cfg(unix)]
fn exit_with_trap_fd(error: &anyhow::Error, trap_fd: &TrapFd) -> ! {
    let (trap, exit_code) = error_trap(error);
    trap_fd.write(&trap);
    trap.emit();
    process::exit(exit_code)
}

fn error_trap(error: &anyhow::Error) -> (Trap, i32) {
    let engine_error = find_engine_error(error);
    let trap = engine_error.map_or_else(|| Trap::internal(format!("{error:#}")), Trap::from_error);
    let exit_code = if matches!(engine_error, Some(Error::Usage { .. })) {
        2
    } else {
        1
    };
    (trap, exit_code)
}

fn find_engine_error(error: &anyhow::Error) -> Option<&Error> {
    error
        .chain()
        .find_map(<dyn StdError + 'static>::downcast_ref::<Error>)
}
