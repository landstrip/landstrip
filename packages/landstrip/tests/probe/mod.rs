// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

pub mod fs;
pub mod net;
pub mod process;

pub trait Probe {
    fn run(&self, args: &mut std::env::ArgsOs) -> i32;
}

/// Dispatches a probe subcommand to its implementation.
///
/// Returns `Some(exit_code)` if `subcommand` matches a known probe name,
/// or `None` if it is not a probe command.
pub fn dispatch(subcommand: &std::ffi::OsStr, mut args: std::env::ArgsOs) -> Option<i32> {
    let sub = subcommand.to_str()?;
    let probe: &dyn Probe = match sub {
        "opath" => &fs::Opath,
        "futimens" => &fs::Futimens,
        "truncate" => &fs::Truncate,
        "unlink" => &fs::Unlink,
        "exclusive-open" => &fs::ExclusiveOpen,
        "openat2" => &fs::Openat2,
        "fd-metadata" => &fs::FdMetadata,
        "abstract-connect" => &net::AbstractConnect,
        "unix-connect" => &net::UnixConnect,
        "unix-bind" => &net::UnixBind,
        "route-socket" => &net::RouteSocket,
        "udp-bind" => &net::UdpBind,
        "udp-local" => &net::UdpLocal,
        "udp-remote" => &net::UdpRemote,
        "signal-outside" => &process::SignalOutside,
        "signal-thread" => &process::SignalThread,
        "io-uring" => &process::IoUring,
        "namespace-proc" => &process::NamespaceProc,
        "namespace-network-denied" => &process::NamespaceNetworkDenied,
        "namespace-lifetime" => &process::NamespaceLifetime,
        "daemon" => &process::Daemon,
        _ => return None,
    };
    Some(probe.run(&mut args))
}
