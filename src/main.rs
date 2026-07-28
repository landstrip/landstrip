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
#[cfg(unix)]
use crate::engine::trap_fd::TrapFd;
use crate::outcome::{CommandOutcome, PolicyValidationError, PolicyValidationReport};
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::outcome::{DoctorReport, SandboxImplementation};

    #[test]
    fn policy_validation_output_is_stable() -> Result<()> {
        let outcome = CommandOutcome::PolicyValidated(PolicyValidationReport {
            valid: true,
            error: None,
        });
        let mut output = Vec::new();

        render_outcome_to(&mut output, &outcome)?;

        assert_eq!(String::from_utf8(output)?, "{\"valid\":true}\n");
        assert_eq!(outcome.exit_code(), 0);
        Ok(())
    }

    #[test]
    fn invalid_policy_output_is_stable() -> Result<()> {
        let outcome = CommandOutcome::PolicyValidated(PolicyValidationReport {
            valid: false,
            error: Some(PolicyValidationError {
                code: "POLICY_INVALID_PORT",
                message: "proxy ports must be between 1 and 65535".to_owned(),
            }),
        });
        let mut output = Vec::new();

        render_outcome_to(&mut output, &outcome)?;

        assert_eq!(
            String::from_utf8(output)?,
            "{\"valid\":false,\"error\":{\"code\":\"POLICY_INVALID_PORT\",\"message\":\"proxy ports must be between 1 and 65535\"}}\n"
        );
        assert_eq!(outcome.exit_code(), 1);
        Ok(())
    }

    #[test]
    fn semantic_rejection_becomes_a_validation_report() -> Result<()> {
        assert_policy_rejection(
            Error::PolicyInvalidPort,
            "POLICY_INVALID_PORT",
            "proxy ports must be between 1 and 65535",
        )
    }

    #[test]
    fn parse_rejection_becomes_a_validation_report() -> Result<()> {
        assert_policy_rejection(
            Error::PolicyParseFailed {
                source: io::Error::new(io::ErrorKind::InvalidData, "malformed policy").into(),
            },
            "POLICY_PARSE_FAILED",
            "POLICY_PARSE_FAILED: malformed policy",
        )
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_rejections_become_validation_reports() -> Result<()> {
        for (error, code, message) in [
            (
                Error::PolicyUnrestrictedRead,
                "POLICY_UNRESTRICTED_READ",
                "unrestricted reads are unsupported by the active Windows sandbox",
            ),
            (
                Error::PolicyTcpBindUnsupported,
                "POLICY_TCP_BIND_UNSUPPORTED",
                "local TCP binding is unsupported by the active Windows sandbox",
            ),
            (
                Error::PolicyUnixSocketUnsupported,
                "POLICY_UNIX_SOCKET_UNSUPPORTED",
                "Unix socket policy is unsupported by the active Windows sandbox",
            ),
        ] {
            assert_policy_rejection(error, code, message)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_rejections_become_validation_reports() -> Result<()> {
        for (error, code, message) in [
            (
                Error::PolicyUnixSocketPath,
                "POLICY_UNIX_SOCKET_PATH",
                "an allowed Unix socket path exists but is not a socket",
            ),
            (
                Error::PolicyDenyWriteSymlinkAncestor,
                "POLICY_DENY_WRITE_SYMLINK_ANCESTOR",
                "a denied write symlink ancestor is reachable through an allowed write root",
            ),
        ] {
            assert_policy_rejection(error, code, message)?;
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[test]
    fn unsupported_platform_rejection_becomes_a_validation_report() -> Result<()> {
        assert_policy_rejection(
            Error::PlatformUnsupported,
            "PLATFORM_UNSUPPORTED",
            "the current platform is unsupported",
        )
    }

    fn assert_policy_rejection(error: Error, code: &'static str, message: &str) -> Result<()> {
        let report = policy_validation_report(Err(error.into()))?;
        let outcome = CommandOutcome::PolicyValidated(report);
        let mut output = Vec::new();

        render_outcome_to(&mut output, &outcome)?;

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output)?,
            serde_json::json!({
                "valid": false,
                "error": {
                    "code": code,
                    "message": message,
                },
            })
        );
        assert_eq!(outcome.exit_code(), 1);
        Ok(())
    }

    #[test]
    fn policy_io_failure_remains_operational() {
        let error = Error::PolicyIoFailed {
            source: io::Error::new(io::ErrorKind::NotFound, "missing policy"),
        };

        assert!(policy_validation_report(Err(error.into())).is_err());
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
