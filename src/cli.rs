// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use argh::FromArgs;
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process;

const PROGRAM_NAME: &str = "landstrip";

#[derive(Debug)]
pub(crate) struct Cli {
    pub(crate) policy_paths: Vec<PathBuf>,
    pub(crate) input_format: PolicyFormat,
    pub(crate) output_format: PolicyFormat,
    pub(crate) debug: bool,
    pub(crate) tool: OsString,
    pub(crate) tool_args: Vec<OsString>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PolicyFormat {
    Json,
    Yaml,
}

#[derive(Debug, FromArgs)]
#[argh(
    help_triggers("-h", "--help"),
    description = "Landlock sandbox runner",
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

    /// policy input format: json or yaml; defaults to json
    #[argh(option, from_str_fn(parse_policy_format))]
    input_format: Option<PolicyFormat>,

    /// error output format: json or yaml; defaults to json
    #[argh(option, from_str_fn(parse_policy_format))]
    output_format: Option<PolicyFormat>,

    /// tool to run inside the sandbox, followed by its arguments
    #[argh(positional)]
    tool: Option<String>,
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
    let program_name = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(PROGRAM_NAME)
        .to_owned();
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
        return Err(Error::Usage(tool_required_usage(&program_name)));
    }

    debug_assert!(options.tool.is_none());
    let mut tool_tail = tool_tail.into_iter();
    let tool = tool_tail
        .next()
        .ok_or_else(|| Error::Usage(tool_required_usage(PROGRAM_NAME)))?;

    Ok(CliAction::Run(Cli {
        policy_paths: options.policy,
        input_format: options.input_format.unwrap_or(PolicyFormat::Json),
        output_format: options.output_format.unwrap_or(PolicyFormat::Json),
        debug: options.debug,
        tool,
        tool_args: tool_tail.collect(),
    }))
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

        if arg == OsStr::new("--input-format") || arg == OsStr::new("--output-format") {
            option_args.push(arg);
            if let Some(value) = args.next() {
                option_args.push(value);
            }
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

fn parse_policy_path(path: &str) -> std::result::Result<PathBuf, String> {
    if path.is_empty() {
        return Err("policy path empty".to_owned());
    }

    Ok(PathBuf::from(path))
}

fn parse_policy_format(format: &str) -> std::result::Result<PolicyFormat, String> {
    match format {
        "json" => Ok(PolicyFormat::Json),
        "yaml" => Ok(PolicyFormat::Yaml),
        _ => Err("policy format must be json or yaml".to_owned()),
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
            .map_err(|_| Error::Usage("argument encoding".to_owned()))?;

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
                Err(Error::Usage(message.to_owned()))
            }
        }
    }
}

fn tool_required_usage(program_name: &str) -> String {
    format!("Usage: {program_name} [OPTIONS] <TOOL>\n\nFor more information, try '--help'.")
}
