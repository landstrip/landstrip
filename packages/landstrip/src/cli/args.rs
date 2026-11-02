// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::config::{PolicyFormat, Settings};
#[allow(unused_imports)]
use crate::error::{Error, Mechanism};
#[cfg(target_os = "windows")]
use crate::platform::{RESTRICTED_USER_RUNNER, WindowsCommand};
use crate::policy::AccessPolicy;
#[cfg(unix)]
use crate::trap_fd::TrapFd;
use clap::builder::{PathBufValueParser, TypedValueParser};
use clap::{Args, Parser, Subcommand, error::ErrorKind};
use std::env;
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "windows")]
use std::num::NonZeroU16;
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
#[cfg(any(unix, target_os = "windows"))]
use std::str::FromStr;

const PROGRAM_NAME: &str = "landstrip";

#[derive(Debug)]
pub(super) struct Invocation {
    pub(super) debug: bool,
    pub(super) command: Command,
}

#[derive(Debug)]
pub(super) enum ParseOutcome {
    Invocation(Invocation),
    Display(clap::Error),
}

#[derive(Debug)]
pub(super) enum Command {
    Run(RunCommand),
    Check(PolicyRequest),
    Resolve(PolicyRequest),
    Doctor,
    #[cfg(target_os = "windows")]
    Windows(WindowsCommand),
    #[cfg(target_os = "windows")]
    Worker {
        request: PathBuf,
    },
}

#[derive(Debug)]
pub(super) struct RunCommand {
    pub(super) policy: PolicyInput,
    pub(super) cwd: PathBuf,
    #[cfg(unix)]
    pub(super) trap_fd: Option<TrapFd>,
    #[cfg(unix)]
    pub(super) inherited_fds: Vec<OwnedFd>,
    pub(super) tool: OsString,
    pub(super) tool_args: Vec<OsString>,
}

#[derive(Debug, Args)]
pub(super) struct PolicyRequest {
    #[command(flatten)]
    pub(super) policy: PolicyInput,

    /// Working directory for execution and relative path resolution.
    #[arg(
        long,
        value_name = "DIR",
        default_value = ".",
        value_parser = PathBufValueParser::new().try_map(std::path::absolute)
    )]
    pub(super) cwd: PathBuf,

    /// Include policy attached to this executable.
    #[arg(long, value_name = "PROGRAM")]
    pub(super) tool: Option<OsString>,
}

#[derive(Debug, Args)]
pub(super) struct PolicyInput {
    /// Policy file; repeat to merge; use `-` for standard input.
    #[arg(short = 'p', long = "policy", value_name = "FILE", value_parser = parse_policy_path)]
    pub(super) paths: Vec<PathBuf>,

    /// Policy format. Required when a policy is read from standard input.
    #[arg(long = "policy-format", value_enum, value_name = "FORMAT")]
    format: Option<PolicyFormat>,
}

#[derive(Debug, Parser)]
#[command(
    name = PROGRAM_NAME,
    version,
    about = "OS-level sandbox runner",
)]
struct Cli {
    /// Enable debug logs.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Run a command inside the sandbox.
    Run(RunArgs),
    /// Check policy parsing, merging, resolution, and platform support.
    Check(PolicyRequest),
    /// Print the final normalized policy as JSON.
    Resolve(PolicyRequest),
    /// Verify sandbox health and report supported/available capabilities.
    Doctor,
    #[cfg(target_os = "windows")]
    /// Manage Windows sandbox preparation and restricted-user provisioning.
    Windows(WindowsArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    policy: PolicyInput,

    /// Working directory for execution and relative path resolution.
    #[arg(
        long,
        value_name = "DIR",
        default_value = ".",
        value_parser = PathBufValueParser::new().try_map(std::path::absolute)
    )]
    cwd: PathBuf,

    #[cfg(unix)]
    /// Write traps to an open file descriptor or Unix domain socket path.
    #[arg(long = "trap", value_name = "FD|PATH")]
    trap: Option<TrapTarget>,

    #[cfg(unix)]
    /// Preserve open descriptors across sandbox exec (grants access to those resources).
    #[arg(long = "inherit", value_name = "FD[,FD...]", value_delimiter = ',', value_parser = parse_fd)]
    inherited_fds: Vec<i32>,

    /// Program to run.
    #[arg(required = true, value_name = "PROGRAM")]
    tool: OsString,

    /// Arguments passed to the program.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ARGS"
    )]
    tool_args: Vec<OsString>,
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
    #[command(
        name = "prepare-appcontainer",
        about = "Grant AppContainer access to NUL and root directories (requests elevation)"
    )]
    PrepareAppContainer,
    /// Report the active Windows isolation implementation and its health.
    Status,
    /// Uninstall restricted-user isolation and return to `AppContainer`.
    Uninstall,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Args)]
struct WindowsInstallArgs {
    /// Restricted-network account pool size.
    #[arg(long, default_value_t = 8, value_parser = |v: &str| parse_count(v, 1, "restricted accounts"))]
    restricted_accounts: u16,

    /// Unrestricted-network account pool size.
    #[arg(long, default_value_t = 2, value_parser = |v: &str| parse_count(v, 0, "unrestricted accounts"))]
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

impl ParseOutcome {
    pub(super) fn parse() -> Result<Self, Error> {
        let mut args = env::args_os();
        let program = args.next().unwrap_or_else(|| OsString::from(PROGRAM_NAME));
        let args = args.collect::<Vec<_>>();

        #[cfg(target_os = "windows")]
        if is_restricted_user_runner()? {
            return Invocation::try_from_worker_args(&args).map(Self::Invocation);
        }

        Self::parse_from(program, args)
    }

    fn parse_from(program: OsString, args: Vec<OsString>) -> Result<Self, Error> {
        let cli = match Cli::try_parse_from(std::iter::once(program).chain(args)) {
            Ok(cli) => cli,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::DisplayHelp
                        | ErrorKind::DisplayVersion
                        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                ) =>
            {
                return Ok(Self::Display(error));
            }
            Err(error) => {
                return Err(Error::Usage {
                    message: error.to_string(),
                });
            }
        };

        Ok(Self::Invocation(Invocation {
            debug: cli.debug,
            command: Command::try_from(cli.command)?,
        }))
    }
}

impl TryFrom<CliCommand> for Command {
    type Error = Error;

    fn try_from(command: CliCommand) -> Result<Self, Self::Error> {
        Ok(match command {
            CliCommand::Run(args) => Self::Run(args.try_into()?),
            CliCommand::Check(request) => Self::Check(request),
            CliCommand::Resolve(request) => Self::Resolve(request),
            CliCommand::Doctor => Self::Doctor,
            #[cfg(target_os = "windows")]
            CliCommand::Windows(args) => Self::Windows(args.into()),
        })
    }
}

impl TryFrom<RunArgs> for RunCommand {
    type Error = Error;

    fn try_from(args: RunArgs) -> Result<Self, Self::Error> {
        #[cfg(unix)]
        let inherited_fds = {
            let mut fds = args.inherited_fds;
            fds.sort_unstable();
            if fds.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(Error::Usage {
                    message: "--inherit must not contain duplicate descriptors".to_owned(),
                });
            }
            if let Some(TrapTarget::Fd(fd)) = args.trap
                && fds.contains(&fd)
            {
                return Err(Error::Usage {
                    message: "--inherit must not include --trap".to_owned(),
                });
            }
            fds.into_iter()
                .map(|fd| {
                    // SAFETY: parse_fd validated this inherited descriptor. The
                    // CLI owns it; duplicate and trap checks ensure unique ownership.
                    unsafe { OwnedFd::from_raw_fd(fd) }
                })
                .collect()
        };
        #[cfg(unix)]
        let trap_fd = args.trap.map(TrapFd::try_from).transpose()?;
        Ok(Self {
            policy: args.policy,
            cwd: args.cwd,
            #[cfg(unix)]
            trap_fd,
            #[cfg(unix)]
            inherited_fds,
            tool: args.tool,
            tool_args: args.tool_args,
        })
    }
}

#[cfg(target_os = "windows")]
impl From<WindowsArgs> for WindowsCommand {
    fn from(args: WindowsArgs) -> Self {
        match args.command {
            WindowsAction::Install(args) => Self::Install {
                restricted_accounts: args.restricted_accounts,
                unrestricted_accounts: args.unrestricted_accounts,
                proxy_port_low: args.proxy_port_range.low,
                proxy_port_high: args.proxy_port_range.high,
            },
            WindowsAction::PrepareAppContainer => Self::PrepareAppContainer,
            WindowsAction::Status => Self::Status,
            WindowsAction::Uninstall => Self::Uninstall,
        }
    }
}

#[cfg(target_os = "windows")]
fn is_restricted_user_runner() -> Result<bool, Error> {
    let executable = env::current_exe()
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    Ok(executable
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(RESTRICTED_USER_RUNNER)))
}

#[cfg(target_os = "windows")]
impl Invocation {
    fn try_from_worker_args(args: &[OsString]) -> Result<Self, Error> {
        let [request] = args else {
            return Err(Error::Usage {
                message: "restricted-user runner requires one request path".to_owned(),
            });
        };
        Ok(Self {
            debug: false,
            command: Command::Worker {
                request: PathBuf::from(request),
            },
        })
    }
}

fn parse_policy_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("policy path cannot be empty".to_owned());
    }
    Ok(PathBuf::from(path))
}

#[cfg(unix)]
#[derive(Clone, Debug)]
enum TrapTarget {
    Fd(i32),
    Socket(PathBuf),
}

#[cfg(unix)]
impl FromStr for TrapTarget {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.starts_with('/') {
            return Ok(Self::Socket(PathBuf::from(value)));
        }
        parse_fd(value).map(Self::Fd)
    }
}

#[cfg(unix)]
impl TryFrom<TrapTarget> for TrapFd {
    type Error = Error;

    fn try_from(target: TrapTarget) -> Result<Self, Self::Error> {
        match target {
            TrapTarget::Fd(fd) => {
                // SAFETY: parse_fd established that the inherited descriptor is open,
                // and `--trap` transfers its ownership to this process.
                Ok(Self::from(unsafe { OwnedFd::from_raw_fd(fd) }))
            }
            TrapTarget::Socket(path) => Self::connect(&path).map_err(|error| Error::Usage {
                message: format!("trap socket {}: {error}", path.display()),
            }),
        }
    }
}

#[cfg(unix)]
fn parse_fd(value: &str) -> Result<i32, String> {
    let fd = value
        .parse::<i32>()
        .map_err(|_| "fd must be an integer greater than or equal to 3".to_owned())?;
    if fd < 3 {
        return Err("fd must be an integer greater than or equal to 3".to_owned());
    }

    // SAFETY: F_GETFD only inspects the scalar descriptor number.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(format!(
            "fd {fd} is not open: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(fd)
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
    NonZeroU16::new(port)
        .map(NonZeroU16::get)
        .ok_or_else(|| "proxy ports must be between 1 and 65535".to_owned())
}

impl TryFrom<&PolicyInput> for PolicyFormat {
    type Error = Error;

    fn try_from(input: &PolicyInput) -> Result<Self, Self::Error> {
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
}

impl PolicyInput {
    pub(super) fn resolve(&self, cwd: &Path, tool: Option<&OsStr>) -> Result<AccessPolicy, Error> {
        let format = PolicyFormat::try_from(self)?;
        log::debug!("cli: cwd: {}", cwd.display());
        let settings = Settings::load(&self.paths, format, tool, cwd)?;
        settings.resolve(cwd)
    }
}
