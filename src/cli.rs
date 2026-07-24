// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process;

use argh::FromArgs;

use crate::config::WindowsBackend;
use crate::engine::error::Error;

type Result<T> = std::result::Result<T, String>;

const PROGRAM_NAME: &str = "landstrip";

#[derive(Debug)]
pub(crate) struct Cli {
    pub(crate) policy_paths: Vec<PathBuf>,
    pub(crate) format: PolicyFormat,
    pub(crate) debug: bool,
    pub(crate) trap_fd: Option<i32>,
    pub(crate) windows_backend: WindowsBackend,
    pub(crate) tool: OsString,
    pub(crate) tool_args: Vec<OsString>,
}

#[derive(Debug)]
pub(crate) enum Invocation {
    Run(Cli),
    Windows(WindowsCommand),
}

#[derive(Debug)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) enum WindowsCommand {
    Setup {
        restricted_accounts: u16,
        unrestricted_accounts: u16,
        proxy_port_low: u16,
        proxy_port_high: u16,
        elevated: bool,
    },
    Status,
    Uninstall {
        elevated: bool,
    },
    Worker {
        request: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Default, strum_macros::EnumString)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum PolicyFormat {
    #[default]
    Json,
    Yaml,
}

#[derive(Debug, FromArgs)]
#[argh(
    help_triggers("-h", "--help"),
    description = "OS-level sandbox runner",
    usage = "[OPTIONS] <TOOL> [ARG...]",
    example = "{command_name} -p policy.json cargo test"
)]
struct CliOptions {
    /// enable debug logs
    #[argh(switch)]
    debug: bool,

    /// print version and exit
    #[argh(switch, short = 'V')]
    version: bool,

    /// policy file; repeat to merge; stdin when omitted
    #[argh(option, short = 'p', from_str_fn(parse_policy_path))]
    policy: Vec<PathBuf>,

    /// policy format: json or yaml; defaults to json
    #[argh(option, from_str_fn(parse_policy_format))]
    format: Option<PolicyFormat>,

    /// write landstrip trap responses to an already-open file descriptor
    #[argh(option, from_str_fn(parse_trap_fd))]
    trap_fd: Option<i32>,

    /// windows sandbox backend: app-container or restricted-user
    #[argh(option, from_str_fn(parse_windows_backend))]
    windows_backend: Option<WindowsBackend>,
}

#[derive(Debug)]
enum CliAction {
    Run(Cli),
    Windows(WindowsCommand),
    Exit(String),
}

pub(crate) fn parse_cli() -> std::result::Result<Invocation, Error> {
    let mut env_args = env::args_os();
    let program = env_args.next().unwrap_or(OsString::from(PROGRAM_NAME));

    match parse_cli_action(&program, env_args) {
        Ok(CliAction::Run(cli)) => Ok(Invocation::Run(cli)),
        Ok(CliAction::Windows(command)) => Ok(Invocation::Windows(command)),
        Ok(CliAction::Exit(output)) => {
            print!("{output}");
            process::exit(0);
        }
        Err(message) => Err(Error::Usage { message }),
    }
}

fn parse_cli_action(
    program: &OsStr,
    args: impl IntoIterator<Item = OsString>,
) -> Result<CliAction> {
    let program_name = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(PROGRAM_NAME)
        .to_owned();
    let args = args.into_iter().collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == OsStr::new("windows")) {
        return parse_windows_action(&program_name, &args[1..]);
    }
    let (option_args, tool_tail) = split_cli_args(args);
    let options = match parse_cli_options(&program_name, option_args)? {
        ParsedOptions::Options(options) => options,
        ParsedOptions::Exit(output) => return Ok(CliAction::Exit(output)),
    };

    if options.version {
        return Ok(CliAction::Exit(format!(
            "{PROGRAM_NAME} {}\n",
            env!("CARGO_PKG_VERSION")
        )));
    }

    if tool_tail.is_empty() {
        return Err(tool_required_usage(&program_name));
    }

    let mut tool_tail = tool_tail.into_iter();
    let tool = tool_tail
        .next()
        .ok_or_else(|| tool_required_usage(&program_name))?;

    Ok(CliAction::Run(Cli {
        policy_paths: options.policy,
        format: options.format.unwrap_or(PolicyFormat::Json),
        debug: options.debug,
        trap_fd: options.trap_fd,
        windows_backend: options.windows_backend.unwrap_or_default(),
        tool,
        tool_args: tool_tail.collect(),
    }))
}

fn parse_windows_action(program_name: &str, args: &[OsString]) -> Result<CliAction> {
    let Some(command) = args.first().and_then(|arg| arg.to_str()) else {
        return Err(windows_usage(program_name));
    };
    if command == "--help" || command == "-h" {
        return Ok(CliAction::Exit(windows_usage(program_name)));
    }

    match command {
        "status" if args.len() == 1 => Ok(CliAction::Windows(WindowsCommand::Status)),
        "uninstall"
            if args.get(1).is_some_and(|option| {
                option == OsStr::new("--help") || option == OsStr::new("-h")
            }) =>
        {
            Ok(CliAction::Exit(format!(
                "Usage: {program_name} windows uninstall\n"
            )))
        }
        "uninstall" => {
            let elevated = parse_elevated_only(program_name, "uninstall", &args[1..])?;
            Ok(CliAction::Windows(WindowsCommand::Uninstall { elevated }))
        }
        "setup" => parse_windows_setup(program_name, &args[1..]),
        "worker" if args.len() == 2 => Ok(CliAction::Windows(WindowsCommand::Worker {
            request: PathBuf::from(&args[1]),
        })),
        _ => Err(windows_usage(program_name)),
    }
}

fn parse_windows_setup(program_name: &str, args: &[OsString]) -> Result<CliAction> {
    const DEFAULT_RESTRICTED_ACCOUNTS: u16 = 8;
    const DEFAULT_UNRESTRICTED_ACCOUNTS: u16 = 2;
    const DEFAULT_PROXY_PORT_LOW: u16 = 60_080;
    const DEFAULT_PROXY_PORT_HIGH: u16 = 60_111;

    let mut restricted_accounts = DEFAULT_RESTRICTED_ACCOUNTS;
    let mut unrestricted_accounts = DEFAULT_UNRESTRICTED_ACCOUNTS;
    let mut proxy_port_low = DEFAULT_PROXY_PORT_LOW;
    let mut proxy_port_high = DEFAULT_PROXY_PORT_HIGH;
    let mut elevated = false;
    let mut index = 0;

    while index < args.len() {
        let option = args[index]
            .to_str()
            .ok_or_else(|| "argument encoding".to_owned())?;
        match option {
            "--elevated" => elevated = true,
            "--restricted-accounts" => {
                restricted_accounts = parse_windows_number(args, &mut index, option)?;
            }
            "--unrestricted-accounts" => {
                unrestricted_accounts = parse_windows_number(args, &mut index, option)?;
            }
            "--proxy-port-low" => {
                proxy_port_low = parse_windows_number(args, &mut index, option)?;
            }
            "--proxy-port-high" => {
                proxy_port_high = parse_windows_number(args, &mut index, option)?;
            }
            "--help" | "-h" => {
                return Ok(CliAction::Exit(windows_setup_usage(program_name)));
            }
            _ => return Err(windows_setup_usage(program_name)),
        }
        index += 1;
    }

    if restricted_accounts == 0 || restricted_accounts > 64 {
        return Err("--restricted-accounts must be between 1 and 64".to_owned());
    }
    if unrestricted_accounts > 64 {
        return Err("--unrestricted-accounts must be between 0 and 64".to_owned());
    }
    if proxy_port_low == 0 || proxy_port_low > proxy_port_high {
        return Err("proxy port range must be non-zero and ordered".to_owned());
    }
    if proxy_port_high - proxy_port_low > 64 {
        return Err("proxy port range may contain at most 65 ports".to_owned());
    }

    Ok(CliAction::Windows(WindowsCommand::Setup {
        restricted_accounts,
        unrestricted_accounts,
        proxy_port_low,
        proxy_port_high,
        elevated,
    }))
}

fn parse_elevated_only(program_name: &str, command: &str, args: &[OsString]) -> Result<bool> {
    match args {
        [] => Ok(false),
        [option] if option == OsStr::new("--elevated") => Ok(true),
        _ => Err(format!(
            "Usage: {program_name} windows {command} [--elevated]\n"
        )),
    }
}

fn parse_windows_number(args: &[OsString], index: &mut usize, option: &str) -> Result<u16> {
    *index += 1;
    let value = args
        .get(*index)
        .and_then(|arg| arg.to_str())
        .ok_or_else(|| format!("{option} requires an integer"))?;
    value
        .parse::<u16>()
        .map_err(|_| format!("{option} requires an integer between 0 and 65535"))
}

fn windows_usage(program_name: &str) -> String {
    format!(
        "Usage: {program_name} windows <setup|status|uninstall> [OPTIONS]\n\nFor command help, run '{program_name} windows <COMMAND> --help'.\n"
    )
}

fn windows_setup_usage(program_name: &str) -> String {
    format!(
        "Usage: {program_name} windows setup [OPTIONS]\n\nOptions:\n  --restricted-accounts N     Restricted-network account pool (default: 8)\n  --unrestricted-accounts N   Unrestricted-network account pool (default: 2)\n  --proxy-port-low PORT        First permitted loopback proxy port (default: 60080)\n  --proxy-port-high PORT       Last permitted loopback proxy port (default: 60111)\n"
    )
}

fn split_cli_args(args: impl IntoIterator<Item = OsString>) -> (Vec<OsString>, Vec<OsString>) {
    let mut args = args.into_iter();
    let mut option_args = Vec::new();

    while let Some(arg) = args.next() {
        if arg == OsStr::new("--") {
            return (option_args, args.collect());
        }

        if take_option_value(&["--policy", "-p"], &arg, &mut option_args, &mut args) {
            continue;
        }
        if take_option_value(&["--format"], &arg, &mut option_args, &mut args) {
            continue;
        }
        if take_option_value(&["--trap-fd"], &arg, &mut option_args, &mut args) {
            continue;
        }
        if take_option_value(&["--windows-backend"], &arg, &mut option_args, &mut args) {
            continue;
        }

        if arg.to_string_lossy().starts_with('-') {
            option_args.push(arg);
            continue;
        }

        let mut tool_tail = vec![arg];
        tool_tail.extend(args);
        return (option_args, tool_tail);
    }

    (option_args, Vec::new())
}

fn take_option_value(
    names: &[&str],
    arg: &OsStr,
    option_args: &mut Vec<OsString>,
    args: &mut impl Iterator<Item = OsString>,
) -> bool {
    if names.iter().any(|name| arg == OsStr::new(name)) {
        option_args.push(arg.to_os_string());
        if let Some(value) = args.next() {
            option_args.push(value);
        }
        return true;
    }
    false
}

fn parse_policy_path(path: &str) -> std::result::Result<PathBuf, String> {
    if path.is_empty() {
        return Err("policy path empty".to_owned());
    }

    Ok(PathBuf::from(path))
}

fn parse_trap_fd(fd: &str) -> std::result::Result<i32, String> {
    let fd = fd
        .parse::<i32>()
        .map_err(|_| "trap fd must be an integer >= 3".to_owned())?;
    if fd < 3 {
        return Err("trap fd must be an integer >= 3".to_owned());
    }
    Ok(fd)
}

fn parse_policy_format(format: &str) -> std::result::Result<PolicyFormat, String> {
    format
        .parse()
        .map_err(|_| "policy format must be json or yaml".to_owned())
}

fn parse_windows_backend(value: &str) -> std::result::Result<WindowsBackend, String> {
    match value {
        "app-container" => Ok(WindowsBackend::AppContainer),
        "restricted-user" => Ok(WindowsBackend::RestrictedUser),
        _ => Err("Windows backend must be app-container or restricted-user".to_owned()),
    }
}

enum ParsedOptions {
    Options(CliOptions),
    Exit(String),
}

fn parse_cli_options(
    program_name: &str,
    args: impl IntoIterator<Item = OsString>,
) -> Result<ParsedOptions> {
    let args = args.into_iter();
    let mut arg_strings = Vec::with_capacity(args.size_hint().0);

    for arg in args {
        let string = arg
            .into_string()
            .map_err(|_| "argument encoding".to_owned())?;

        arg_strings.push(string);
    }

    let arg_refs = arg_strings.iter().map(String::as_str).collect::<Vec<_>>();

    match CliOptions::from_args(&[program_name], &arg_refs) {
        Ok(options) => Ok(ParsedOptions::Options(options)),
        Err(early_exit) => {
            if early_exit.status.is_ok() {
                Ok(ParsedOptions::Exit(early_exit.output))
            } else {
                let message = early_exit
                    .output
                    .lines()
                    .next()
                    .filter(|line| !line.is_empty())
                    .unwrap_or("arguments invalid");
                Err(message.to_owned())
            }
        }
    }
}

fn tool_required_usage(program_name: &str) -> String {
    format!("Usage: {program_name} [OPTIONS] <TOOL>\n\nFor more information, try '--help'.")
}
