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
mod outcome;
mod platform;

use crate::cli::{
    Command, Invocation, ParseOutcome, PolicyCommand, PolicyRequest, RunCommand, parse_cli,
};
use crate::config::load_settings;
use crate::engine::error::Error;
use crate::engine::policy::{AccessPolicy, resolve_policy};
use crate::engine::trap::Trap;
use crate::engine::trap_fd::TrapFd;
use crate::outcome::{CommandOutcome, PolicyValidationReport};
use anyhow::Result;
use serde::Serialize;
use std::error::Error as StdError;
use std::io::{self, Write};
use std::process;

fn main() {
    let invocation = match parse_cli() {
        Ok(ParseOutcome::Invocation(invocation)) => invocation,
        Ok(ParseOutcome::Display(text)) => {
            if let Err(error) = render_display(&text) {
                exit_with_error(&error, &TrapFd::from_fd(None));
            }
            return;
        }
        Err(error) => exit_with_error(&error.into(), &TrapFd::from_fd(None)),
    };
    init_logging(invocation.debug);

    let trap_fd = match &invocation.command {
        Command::Run(command) => TrapFd::from_fd(command.trap_fd),
        _ => TrapFd::from_fd(None),
    };
    let outcome = match dispatch(&invocation) {
        Ok(outcome) => outcome,
        Err(error) => exit_with_error(&error, &trap_fd),
    };
    if let Err(error) = render_outcome(&outcome) {
        exit_with_error(&error, &trap_fd);
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
        Command::Windows(command) => platform::manage_windows(command).map(CommandOutcome::Windows),
        Command::Worker { request } => platform::run_worker(request).map(CommandOutcome::Exit),
    }
}

fn run(command: &RunCommand) -> Result<CommandOutcome> {
    let policy = load_policy(&command.policy, Some(command.tool.as_os_str()))?;
    platform::validate(&policy)?;
    let trap_fd = TrapFd::from_fd(command.trap_fd);
    platform::execute(&policy, &command.tool, &command.tool_args, &trap_fd)
        .map(CommandOutcome::Exit)
}

fn inspect_policy(command: &PolicyCommand) -> Result<CommandOutcome> {
    match command {
        PolicyCommand::Validate(request) => {
            let policy = load_requested_policy(request)?;
            platform::validate(&policy)?;
            Ok(CommandOutcome::PolicyValidated(PolicyValidationReport {
                valid: true,
            }))
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
        CommandOutcome::Windows(report) => write_json(output, report),
    }
}

fn write_json(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    writeln!(output)?;
    Ok(())
}

fn exit_with_error(error: &anyhow::Error, trap_fd: &TrapFd) -> ! {
    let engine_error = error
        .chain()
        .find_map(<dyn StdError + 'static>::downcast_ref::<Error>);
    let trap = engine_error.map_or_else(|| Trap::internal(format!("{error:#}")), Trap::from_error);

    trap_fd.write(&trap);
    trap.emit();
    let exit_code = if matches!(engine_error, Some(Error::Usage { .. })) {
        2
    } else {
        1
    };
    process::exit(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::outcome::{DoctorReport, SandboxImplementation};

    #[test]
    fn policy_validation_output_is_stable() -> Result<()> {
        let outcome = CommandOutcome::PolicyValidated(PolicyValidationReport { valid: true });
        let mut output = Vec::new();

        render_outcome_to(&mut output, &outcome)?;

        assert_eq!(String::from_utf8(output)?, "{\"valid\":true}\n");
        assert_eq!(outcome.exit_code(), 0);
        Ok(())
    }

    #[test]
    fn child_exit_status_is_preserved() -> Result<()> {
        let outcome = CommandOutcome::Exit(23);
        let mut output = Vec::new();

        render_outcome_to(&mut output, &outcome)?;

        assert!(output.is_empty());
        assert_eq!(outcome.exit_code(), 23);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_doctor_output_is_stable() -> Result<()> {
        let outcome = CommandOutcome::Doctor(DoctorReport {
            ok: true,
            platform: "linux",
            implementation: SandboxImplementation::LandlockSeccomp,
            error: None,
        });
        let mut output = Vec::new();

        render_outcome_to(&mut output, &outcome)?;

        assert_eq!(
            String::from_utf8(output)?,
            "{\"ok\":true,\"platform\":\"linux\",\"implementation\":\"landlock+seccomp\"}\n"
        );
        assert_eq!(outcome.exit_code(), 0);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_doctor_output_is_stable() -> Result<()> {
        let outcome = CommandOutcome::Doctor(DoctorReport {
            ok: false,
            platform: "macos",
            implementation: SandboxImplementation::Seatbelt,
            error: Some("Seatbelt unavailable".to_owned()),
        });
        let mut output = Vec::new();

        render_outcome_to(&mut output, &outcome)?;

        assert_eq!(
            String::from_utf8(output)?,
            "{\"ok\":false,\"platform\":\"macos\",\"implementation\":\"seatbelt\",\"error\":\"Seatbelt unavailable\"}\n"
        );
        assert_eq!(outcome.exit_code(), 1);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_status_output_is_stable() -> Result<()> {
        let outcome = CommandOutcome::Windows(crate::outcome::WindowsStatusReport::app_container());
        let mut output = Vec::new();

        render_outcome_to(&mut output, &outcome)?;

        assert_eq!(
            String::from_utf8(output)?,
            "{\"active\":\"appContainer\",\"installed\":false,\"healthy\":true}\n"
        );
        assert_eq!(outcome.exit_code(), 0);
        Ok(())
    }
}
