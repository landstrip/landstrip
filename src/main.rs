// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod cli;
mod config;
mod error;
mod landlock;
mod paths;
mod policy;
mod proxy;
mod seccomp;
mod traversal;

use crate::cli::parse_cli;
use crate::config::load_settings;
use crate::error::{Error, Result};
use crate::landlock::enforce_access_policy;
use crate::policy::{UnixSocketAccess, lower_sandbox_policy};
use crate::proxy::NetworkProxies;
use std::ffi::{OsStr, OsString};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::process::CommandExt;
use std::process::{self, Command};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:?}");
        process::exit(error.exit_code());
    }
}

fn run() -> Result<()> {
    let cli = parse_cli()?;
    init_logger(cli.debug);

    log::debug!("policy: base {}", cli.policy_base.display());
    let settings = load_settings(&cli.policy_paths)?;
    let mut policy =
        lower_sandbox_policy(&settings.filesystem, &settings.network, &cli.policy_base)?;
    let proxies = if !settings.network.allowed_domains.is_empty()
        || !settings.network.denied_domains.is_empty()
    {
        let http_listener = TcpListener::bind((
            Ipv4Addr::LOCALHOST,
            settings.network.http_proxy_port.unwrap_or(0),
        ))
        .map_err(|source| Error::with_source("proxy: bind HTTP", source))?;
        let http_addr = http_listener
            .local_addr()
            .map_err(|source| Error::with_source("proxy: HTTP address", source))?;
        let socks_listener = TcpListener::bind((
            Ipv4Addr::LOCALHOST,
            settings.network.socks_proxy_port.unwrap_or(0),
        ))
        .map_err(|source| Error::with_source("proxy: bind SOCKS", source))?;
        let socks_addr = socks_listener
            .local_addr()
            .map_err(|source| Error::with_source("proxy: SOCKS address", source))?;

        Some(NetworkProxies {
            domain_policy: policy.network_access.domain_policy.clone(),
            http_listener,
            http_addr,
            socks_listener,
            socks_addr,
        })
    } else {
        None
    };
    if let Some(proxies) = &proxies {
        policy
            .network_access
            .connect_tcp_ports
            .extend([proxies.http_addr.port(), proxies.socks_addr.port()]);
        policy.network_access.connect_tcp_ports.sort_unstable();
        policy.network_access.connect_tcp_ports.dedup();
    }

    if policy.network_access.local_tcp_bind
        || !policy.network_access.connect_tcp_ports.is_empty()
        || needs_unix_socket_broker(&policy.network_access.unix_socket_access)
    {
        let status =
            seccomp::run_network_broker(&policy, &cli.command, &cli.command_args, proxies)?;
        process::exit(status);
    }

    enforce_access_policy(&policy)?;
    let filter = seccomp::network_filter(seccomp::NetworkFilter {
        notify_bind: false,
        notify_connect: false,
        unix_sockets: unix_socket_filter(&policy.network_access.unix_socket_access),
    })?;
    filter
        .load()
        .map_err(|source| Error::with_source("seccomp: load", source))?;
    exec_command(&cli.command, &cli.command_args)
}

fn init_logger(debug: bool) {
    let default_filter = if debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();
}

fn needs_unix_socket_broker(access: &UnixSocketAccess) -> bool {
    matches!(access, UnixSocketAccess::AllowPaths(paths) if !paths.is_empty())
}

fn unix_socket_filter(access: &UnixSocketAccess) -> seccomp::UnixSocketFilter {
    match access {
        UnixSocketAccess::Unrestricted => seccomp::UnixSocketFilter::Unrestricted,
        UnixSocketAccess::AllowPaths(paths) if paths.is_empty() => {
            seccomp::UnixSocketFilter::DenyAll
        }
        UnixSocketAccess::AllowPaths(_) => seccomp::UnixSocketFilter::PathMediated,
    }
}

fn exec_command(command: &OsStr, args: &[OsString]) -> Result<()> {
    let error = Command::new(command).args(args).exec();
    Err(Error::with_source(
        format!("exec: {}", command.to_string_lossy()),
        error,
    ))
}
