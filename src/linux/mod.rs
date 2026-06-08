// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Linux sandbox platform using Landlock and seccomp.

mod fd;
mod landlock;
mod seccomp;

use crate::error::{Error, Result};
use crate::policy::AccessPolicy;
use fd::close_inherited_fds;
use landlock::{enforce_access_policy, landlock_features};
use seccomp::NetworkFilter;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::process::{self, Command};

pub(crate) fn execute(policy: &AccessPolicy, tool: &OsStr, args: &[OsString]) -> Result<()> {
    let network = &policy.network_access;
    let unrestricted_network = network.is_unrestricted();
    let landlock_features = landlock_features()?;
    if seccomp::needs_unix_socket_broker(&network.unix_socket_access) {
        let engine = if landlock_features.resolve_unix {
            "landlock"
        } else {
            "seccomp"
        };
        log::debug!("{engine}: Unix socket policy enabled");
    }

    if !unrestricted_network
        && (network.local_tcp_bind
            || !network.connect_tcp_ports.is_empty()
            || seccomp::needs_unix_socket_broker(&network.unix_socket_access))
    {
        let status = seccomp::run_network_broker(policy, landlock_features, tool, args)?;
        process::exit(status);
    }

    enforce_access_policy(policy, landlock_features)?;

    if !unrestricted_network {
        let filter = seccomp::network_filter(NetworkFilter {
            notify_bind: false,
            notify_connect: false,
            unix_sockets: seccomp::unix_socket_filter(&network.unix_socket_access),
        })?;
        filter.load()?;
    }
    close_inherited_fds();
    let error = Command::new(tool).args(args).exec();
    Err(Error::tool_exec(Some(tool.to_os_string()), error))
}
