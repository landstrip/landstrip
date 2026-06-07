// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Linux sandbox backend using Landlock and seccomp.

mod fd;
mod landlock;
mod seccomp;

use crate::error::{Error, Result};
use crate::policy::AccessPolicy;
use fd::close_inherited_fds;
use landlock::enforce_access_policy;
use seccomp::NetworkFilter;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{self, Command};

pub(crate) fn execute(
    policy: &AccessPolicy,
    _policy_base: &Path,
    command: &OsStr,
    args: &[OsString],
) -> Result<()> {
    let network = &policy.network_access;
    let unrestricted_network = network.is_unrestricted();

    if !unrestricted_network
        && (network.local_tcp_bind
            || !network.connect_tcp_ports.is_empty()
            || seccomp::needs_unix_socket_broker(&network.unix_socket_access))
    {
        let status = seccomp::run_network_broker(policy, command, args)?;
        process::exit(status);
    }

    enforce_access_policy(policy)?;

    if !unrestricted_network {
        let filter = seccomp::network_filter(NetworkFilter {
            notify_bind: false,
            notify_connect: false,
            unix_sockets: seccomp::unix_socket_filter(&network.unix_socket_access),
        })?;
        filter.load()?;
    }
    close_inherited_fds();
    let error = Command::new(command).args(args).exec();
    Err(Error::command(
        Some(command.to_os_string()),
        error.to_string(),
    ))
}
