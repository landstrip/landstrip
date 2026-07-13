// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Linux sandbox platform using Landlock and seccomp.

pub(crate) mod fd;
mod filter;
mod landlock;
mod seccomp;

use crate::engine::error::Error;
use crate::engine::policy::AccessPolicy;
use crate::engine::trap_fd::TrapFd;
use anyhow::Result;
use fd::close_inherited_fds;
use filter::NetworkFilter;
use landlock::enforce_access_policy;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{self, Command};

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn execute(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    trap_fd: &TrapFd,
) -> Result<()> {
    let network = &policy.network_access;
    let unrestricted_network = network.is_unrestricted();
    if filter::needs_unix_socket_broker(&network.unix_socket_access) {
        log::debug!("linux: unix socket policy with seccomp enabled");
    }

    let needs_fs_broker = filter::needs_filesystem_broker(policy) || trap_fd.is_enabled();
    let needs_network_broker = !unrestricted_network
        && (network.local_tcp_bind
            || !network.connect_tcp_ports.is_empty()
            || filter::needs_unix_socket_broker(&network.unix_socket_access));

    if needs_network_broker || needs_fs_broker {
        let status = seccomp::run_broker(
            policy,
            tool,
            args,
            needs_network_broker,
            needs_fs_broker,
            trap_fd,
        )?;
        trap_fd.close();
        process::exit(status);
    }

    enforce_access_policy(policy)?;

    if !unrestricted_network {
        let filters = filter::network_filter(
            NetworkFilter {
                notify_bind: false,
                notify_connect: false,
                notify_filesystem: false,
                unix_sockets: filter::unix_socket_filter(&network.unix_socket_access),
            },
            true,
        )?;
        filters.load()?;
    }
    close_inherited_fds(&[]).map_err(|source| Error::SuperviseFailed {
        source: source.into(),
    })?;
    let error = Command::new(tool).args(args).exec();
    Err(Error::LaunchFailed {
        tool: PathBuf::from(tool),
        source: error.into(),
    }
    .into())
}
