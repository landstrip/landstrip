// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use argh::FromArgs;
use std::env;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process;

const PROGRAM_NAME: &str = "landstrip";

#[derive(Debug)]
pub(crate) struct Cli {
    pub(crate) policy_paths: Vec<PathBuf>,
    pub(crate) policy_base: PathBuf,
    pub(crate) debug: bool,
    pub(crate) command: OsString,
    pub(crate) command_args: Vec<OsString>,
}

#[derive(Debug, FromArgs)]
#[argh(
    help_triggers("-h", "--help"),
    description = "Landlock sandbox runner",
    usage = "[OPTIONS] <COMMAND> [ARG...]",
    example = "{command_name} -p policy.json cargo test"
)]
struct CliOptions {
    /// enable debug logs
    #[argh(switch)]
    debug: bool,

    /// print version and exit
    #[argh(switch, short = 'V')]
    version: bool,

    /// policy JSON file; repeat to merge; stdin when omitted
    #[argh(option, short = 'p', from_str_fn(parse_policy_path))]
    policy: Vec<PathBuf>,

    /// command to run inside the sandbox, followed by its arguments
    #[argh(positional)]
    command: Option<String>,
}

#[derive(Debug)]
enum CliAction {
    Run(Cli),
    Exit(String),
}

pub(crate) fn parse_cli() -> Result<Cli> {
    let mut env_args = env::args_os();
    let program = env_args
        .next()
        .unwrap_or_else(|| OsString::from(PROGRAM_NAME));

    match parse_cli_action(&program, env_args) {
        Ok(CliAction::Run(cli)) => Ok(cli),
        Ok(CliAction::Exit(output)) => {
            print!("{output}");
            process::exit(0);
        }
        Err(error) => Err(error),
    }
}

fn parse_cli_action(
    program: &OsStr,
    args: impl IntoIterator<Item = OsString>,
) -> Result<CliAction> {
    let program_name = program_name(program);
    let (option_args, command_tail) = split_cli_args(args);
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

    if command_tail.is_empty() {
        return Err(Error::usage(command_required_usage(&program_name)));
    }

    let policy_base =
        env::current_dir().map_err(|source| Error::with_source("current directory", source))?;

    cli_from_options(options, policy_base, command_tail).map(CliAction::Run)
}

fn split_cli_args(args: impl IntoIterator<Item = OsString>) -> (Vec<OsString>, Vec<OsString>) {
    let mut args = args.into_iter();
    let mut option_args = Vec::new();

    while let Some(arg) = args.next() {
        if arg == OsStr::new("--") {
            return (option_args, args.collect());
        }

        if arg == OsStr::new("--policy") || arg == OsStr::new("-p") {
            option_args.push(arg);
            if let Some(value) = args.next() {
                option_args.push(value);
            }
            continue;
        }

        if arg.as_os_str().as_bytes().starts_with(b"-") {
            option_args.push(arg);
            continue;
        }

        let mut command_tail = vec![arg];
        command_tail.extend(args);
        return (option_args, command_tail);
    }

    (option_args, Vec::new())
}

fn cli_from_options(
    options: CliOptions,
    policy_base: PathBuf,
    command_tail: Vec<OsString>,
) -> Result<Cli> {
    debug_assert!(options.command.is_none());

    let mut command_tail = command_tail.into_iter();
    let command = command_tail
        .next()
        .ok_or_else(|| Error::usage(command_required_usage(PROGRAM_NAME)))?;

    Ok(Cli {
        policy_paths: options.policy,
        policy_base,
        debug: options.debug,
        command,
        command_args: command_tail.collect(),
    })
}

fn parse_policy_path(path: &str) -> std::result::Result<PathBuf, String> {
    if path.is_empty() {
        return Err("policy path empty".to_owned());
    }

    Ok(PathBuf::from(path))
}

enum ParsedOptions {
    Options(CliOptions),
    Exit(String),
}

fn parse_cli_options(
    program_name: &str,
    args: impl IntoIterator<Item = OsString>,
) -> Result<ParsedOptions> {
    let arg_strings = option_args_to_strings(args)?;
    let arg_refs = arg_strings.iter().map(String::as_str).collect::<Vec<_>>();

    match CliOptions::from_args(&[program_name], &arg_refs) {
        Ok(options) => Ok(ParsedOptions::Options(options)),
        Err(early_exit) => handle_cli_options_early_exit(&early_exit),
    }
}

fn option_args_to_strings(args: impl IntoIterator<Item = OsString>) -> Result<Vec<String>> {
    let args = args.into_iter();
    let mut strings = Vec::with_capacity(args.size_hint().0);

    for arg in args {
        let string = arg.into_string().map_err(|arg| {
            Error::message(format!("argument encoding: {}", arg.to_string_lossy()))
        })?;

        strings.push(string);
    }

    Ok(strings)
}

fn handle_cli_options_early_exit(early_exit: &argh::EarlyExit) -> Result<ParsedOptions> {
    if early_exit.status.is_ok() {
        return Ok(ParsedOptions::Exit(early_exit.output.clone()));
    }

    let message = early_exit
        .output
        .lines()
        .next()
        .filter(|line| !line.is_empty())
        .unwrap_or("arguments invalid");
    Err(Error::usage(message.to_owned()))
}

fn command_required_usage(program_name: &str) -> String {
    format!("Usage: {program_name} [OPTIONS] <COMMAND>\n\nFor more information, try '--help'.")
}

fn program_name(program: &OsStr) -> String {
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(PROGRAM_NAME)
        .to_owned()
}
