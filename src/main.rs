// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    path = "fallback.rs"
)]
mod backend;
mod cli;
mod config;
mod error;
mod paths;
mod policy;
mod traversal;

use crate::cli::parse_cli;
use crate::config::load_settings;
use crate::error::{Error, Result};
use crate::policy::lower_sandbox_policy;
use serde::Serialize;
use std::process;

fn main() {
    if let Err(error) = run() {
        if let Error::Usage(_) = &error {
            eprintln!("{error}");
            process::exit(2);
        }

        if let Err(error) = print_error_response(&error) {
            eprintln!("failed to serialize error response: {error}");
        }
        process::exit(1);
    }
}
fn print_error_response(error: &Error) -> std::result::Result<(), serde_json::Error> {
    let Some(response) = response_error(error) else {
        return Ok(());
    };

    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn response_error(error: &Error) -> Option<Response<'_>> {
    match error {
        Error::Usage(_) => None,
        Error::Policy { file, message } => Some(Response {
            code: "policy",
            file: file.as_ref().map(|file| file.display().to_string()),
            program: None,
            message,
        }),
        Error::Tool { program, message } => Some(Response {
            code: "tool",
            file: None,
            program: program
                .as_ref()
                .map(|program| program.to_string_lossy().into_owned()),
            message,
        }),
        Error::Capability { message } => Some(Response {
            code: "capability",
            file: None,
            program: None,
            message,
        }),
        Error::System { message } => Some(Response {
            code: "system",
            file: None,
            program: None,
            message,
        }),
    }
}

#[derive(Serialize)]
struct Response<'a> {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    program: Option<String>,
    message: &'a str,
}

fn run() -> Result<()> {
    let cli = parse_cli()?;
    let default_filter = if cli.debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();

    log::debug!("policy: base {}", cli.policy_base.display());
    let settings = load_settings(&cli.policy_paths)?;
    let policy = lower_sandbox_policy(&settings.filesystem, &settings.network, &cli.policy_base)?;

    backend::execute(&policy, &cli.policy_base, &cli.tool, &cli.tool_args)?;

    Ok(())
}
