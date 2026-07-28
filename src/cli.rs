// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::engine::error::Error;
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use serde::Serialize;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::str::FromStr;

const PROGRAM_NAME: &str = "landstrip";
#[cfg(target_os = "windows")]
const RESTRICTED_USER_RUNNER: &str = "landstrip-restricted-user-runner.exe";

#[derive(Debug)]
pub(crate) struct Invocation {
    pub(crate) debug: bool,
    pub(crate) command: Command,
}

#[derive(Debug)]
pub(crate) enum ParseOutcome {
    Invocation(Invocation),
    Display(String),
}

#[derive(Debug)]
pub(crate) enum Command {
    Run(RunCommand),
    Policy(PolicyCommand),
    Doctor,
    #[cfg(target_os = "windows")]
    Windows(WindowsCommand),
    #[cfg(target_os = "windows")]
    Worker {
        request: PathBuf,
    },
}

#[derive(Debug)]
pub(crate) struct RunCommand {
    pub(crate) policy: PolicyInput,
    #[cfg(unix)]
    pub(crate) trap_fd: Option<i32>,
    pub(crate) tool: OsString,
    pub(crate) tool_args: Vec<OsString>,
}

#[derive(Debug)]
pub(crate) enum PolicyCommand {
    Validate(PolicyRequest),
    Resolve(PolicyRequest),
}

#[derive(Debug)]
pub(crate) struct PolicyRequest {
    pub(crate) policy: PolicyInput,
    pub(crate) tool: Option<OsString>,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(crate) enum WindowsCommand {
    Install {
        restricted_accounts: u16,
        unrestricted_accounts: u16,
        proxy_port_low: u16,
        proxy_port_high: u16,
    },
    Status,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Default, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PolicyFormat {
    #[default]
    Json,
    Yaml,
}

#[derive(Debug)]
pub(crate) struct PolicyInput {
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) format: Option<PolicyFormat>,
}

#[derive(Debug, Parser)]
#[command(name = PROGRAM_NAME, version, about = "OS-level sandbox runner")]
struct Cli {
    /// Enable debug logs.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Run a program inside the sandbox.
    Run(RunArgs),
    /// Inspect a policy without running a program.
    Policy(PolicyArgs),
    /// Verify that the current OS sandbox is operational.
    Doctor,
    #[cfg(target_os = "windows")]
    /// Manage Windows restricted-user provisioning.
    Windows(WindowsArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    policy: PolicyInputArgs,

    #[cfg(unix)]
    /// Write traps to an already-open file descriptor.
    #[arg(long, value_name = "FD", value_parser = parse_trap_fd)]
    trap_fd: Option<i32>,

    /// Program and arguments. The `--` separator is required.
    #[arg(last = true, required = true, num_args = 1.., value_name = "PROGRAM [ARGS...]")]
    program: Vec<OsString>,
}

#[derive(Debug, Args)]
struct PolicyInputArgs {
    /// Policy file; repeat to merge; use `-` for standard input.
    #[arg(short = 'p', long = "policy", value_name = "FILE", value_parser = parse_policy_path)]
    policy: Vec<PathBuf>,

    /// Policy format. Required when a policy is read from standard input.
    #[arg(long = "policy-format", value_enum, value_name = "FORMAT")]
    policy_format: Option<PolicyFormat>,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyAction,
}

#[derive(Debug, Subcommand)]
enum PolicyAction {
    /// Check policy parsing, merging, resolution, and platform support.
    Validate(PolicyRequestArgs),
    /// Print the final normalized policy as JSON.
    Resolve(PolicyRequestArgs),
}

#[derive(Debug, Args)]
struct PolicyRequestArgs {
    #[command(flatten)]
    policy: PolicyInputArgs,

    /// Include policy attached to this executable.
    #[arg(long, value_name = "PROGRAM")]
    tool: Option<OsString>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Args)]
struct WindowsArgs {
    #[command(subcommand)]
    command: WindowsAction,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Subcommand)]
enum WindowsAction {
    /// Install and activate restricted-user isolation.
    Install(WindowsInstallArgs),
    /// Report the active Windows isolation implementation and its health.
    Status,
    /// Uninstall restricted-user isolation and return to `AppContainer`.
    Uninstall,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Args)]
struct WindowsInstallArgs {
    /// Restricted-network account pool size.
    #[arg(long, default_value_t = 8, value_parser = parse_restricted_accounts)]
    restricted_accounts: u16,

    /// Unrestricted-network account pool size.
    #[arg(long, default_value_t = 2, value_parser = parse_unrestricted_accounts)]
    unrestricted_accounts: u16,

    /// Permitted loopback proxy port range.
    #[arg(long, default_value = "60080-60111", value_name = "LOW-HIGH")]
    proxy_port_range: ProxyPortRange,
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug)]
struct ProxyPortRange {
    low: u16,
    high: u16,
}

#[cfg(target_os = "windows")]
impl FromStr for ProxyPortRange {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (low, high) = value
            .split_once('-')
            .ok_or_else(|| "proxy port range must have the form LOW-HIGH".to_owned())?;
        let low = parse_port(low)?;
        let high = parse_port(high)?;
        if low > high {
            return Err("proxy port range must be ordered".to_owned());
        }
        if high - low > 64 {
            return Err("proxy port range may contain at most 65 ports".to_owned());
        }
        Ok(Self { low, high })
    }
}

pub(crate) fn parse_cli() -> Result<ParseOutcome, Error> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_else(|| OsString::from(PROGRAM_NAME));
    let args = args.collect::<Vec<_>>();

    #[cfg(target_os = "windows")]
    if is_restricted_user_runner()? {
        return parse_worker(&args).map(ParseOutcome::Invocation);
    }

    parse_from(program, args)
}

fn parse_from(program: OsString, args: Vec<OsString>) -> Result<ParseOutcome, Error> {
    let mut command_line = Vec::with_capacity(args.len() + 1);
    command_line.push(program);
    command_line.extend(args);

    let cli = match Cli::try_parse_from(command_line) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            return Ok(ParseOutcome::Display(error.to_string()));
        }
        Err(error) => {
            return Err(Error::Usage {
                message: error.to_string(),
            });
        }
    };

    let command = match cli.command {
        CliCommand::Run(args) => Command::Run(run_command(args)?),
        CliCommand::Policy(args) => Command::Policy(policy_command(args)),
        CliCommand::Doctor => Command::Doctor,
        #[cfg(target_os = "windows")]
        CliCommand::Windows(args) => Command::Windows(windows_command(args)),
    };

    Ok(ParseOutcome::Invocation(Invocation {
        debug: cli.debug,
        command,
    }))
}

fn run_command(args: RunArgs) -> Result<RunCommand, Error> {
    let mut program = args.program.into_iter();
    let Some(tool) = program.next() else {
        return Err(Error::Usage {
            message: "a program is required after --".to_owned(),
        });
    };
    Ok(RunCommand {
        policy: policy_input(args.policy),
        #[cfg(unix)]
        trap_fd: args.trap_fd,
        tool,
        tool_args: program.collect(),
    })
}

fn policy_command(args: PolicyArgs) -> PolicyCommand {
    match args.command {
        PolicyAction::Validate(args) => PolicyCommand::Validate(policy_request(args)),
        PolicyAction::Resolve(args) => PolicyCommand::Resolve(policy_request(args)),
    }
}

fn policy_request(args: PolicyRequestArgs) -> PolicyRequest {
    PolicyRequest {
        policy: policy_input(args.policy),
        tool: args.tool,
    }
}

fn policy_input(args: PolicyInputArgs) -> PolicyInput {
    PolicyInput {
        paths: args.policy,
        format: args.policy_format,
    }
}

#[cfg(target_os = "windows")]
fn windows_command(args: WindowsArgs) -> WindowsCommand {
    match args.command {
        WindowsAction::Install(args) => WindowsCommand::Install {
            restricted_accounts: args.restricted_accounts,
            unrestricted_accounts: args.unrestricted_accounts,
            proxy_port_low: args.proxy_port_range.low,
            proxy_port_high: args.proxy_port_range.high,
        },
        WindowsAction::Status => WindowsCommand::Status,
        WindowsAction::Uninstall => WindowsCommand::Uninstall,
    }
}

#[cfg(target_os = "windows")]
fn is_restricted_user_runner() -> Result<bool, Error> {
    let executable = env::current_exe().map_err(|source| Error::PolicyIoFailed { source })?;
    Ok(executable
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(RESTRICTED_USER_RUNNER)))
}

#[cfg(target_os = "windows")]
fn parse_worker(args: &[OsString]) -> Result<Invocation, Error> {
    let [request] = args else {
        return Err(Error::Usage {
            message: "restricted-user runner requires one request path".to_owned(),
        });
    };
    Ok(Invocation {
        debug: false,
        command: Command::Worker {
            request: PathBuf::from(request),
        },
    })
}

fn parse_policy_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("policy path cannot be empty".to_owned());
    }
    Ok(PathBuf::from(path))
}

#[cfg(unix)]
fn parse_trap_fd(value: &str) -> Result<i32, String> {
    let fd = value
        .parse::<i32>()
        .map_err(|_| "trap fd must be an integer greater than or equal to 3".to_owned())?;
    if fd < 3 {
        return Err("trap fd must be an integer greater than or equal to 3".to_owned());
    }
    Ok(fd)
}

#[cfg(target_os = "windows")]
fn parse_restricted_accounts(value: &str) -> Result<u16, String> {
    parse_count(value, 1, "restricted accounts")
}

#[cfg(target_os = "windows")]
fn parse_unrestricted_accounts(value: &str) -> Result<u16, String> {
    parse_count(value, 0, "unrestricted accounts")
}

#[cfg(target_os = "windows")]
fn parse_count(value: &str, minimum: u16, name: &str) -> Result<u16, String> {
    let count = value
        .parse::<u16>()
        .map_err(|_| format!("{name} must be an integer between {minimum} and 64"))?;
    if !(minimum..=64).contains(&count) {
        return Err(format!("{name} must be between {minimum} and 64"));
    }
    Ok(count)
}

#[cfg(target_os = "windows")]
fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| "proxy ports must be integers between 1 and 65535".to_owned())?;
    if port == 0 {
        return Err("proxy ports must be between 1 and 65535".to_owned());
    }
    Ok(port)
}

pub(crate) fn policy_format(input: &PolicyInput) -> Result<PolicyFormat, Error> {
    let stdin_count = input
        .paths
        .iter()
        .filter(|path| path.as_path() == Path::new("-"))
        .count();
    if stdin_count > 1 {
        return Err(Error::Usage {
            message: "standard input may be specified as a policy only once".to_owned(),
        });
    }
    if stdin_count == 1 && input.format.is_none() {
        return Err(Error::Usage {
            message: "--policy-format is required when --policy - is used".to_owned(),
        });
    }
    Ok(input.format.unwrap_or_default())
}
