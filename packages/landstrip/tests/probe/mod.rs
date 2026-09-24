// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Jarkko Sakkinen

pub mod fs;
pub mod net;
pub mod process;

/// Dispatches a probe subcommand to its implementation.
///
/// Returns `Some(exit_code)` if `subcommand` matches a known probe name,
/// or `None` if it is not a probe command.
pub fn dispatch(subcommand: &std::ffi::OsStr, mut args: std::env::ArgsOs) -> Option<i32> {
    let sub = subcommand.to_str()?;
    match sub {
        "opath" => Some(fs::opath_probe(args.next())),
        "futimens" => Some(fs::futimens_probe(args.next())),
        "truncate" => Some(fs::truncate_probe(args.next())),
        "exclusive-open" => Some(fs::exclusive_open_probe(args.next())),
        "openat2" => Some(fs::openat2_probe(args.next(), args.next())),
        "fd-metadata" => Some(fs::fd_metadata_probe(args.next(), args.next())),
        "abstract-connect" => Some(net::abstract_connect_probe(args.next())),
        "route-socket" => Some(net::route_socket_probe()),
        "signal-outside" => Some(process::signal_outside_probe()),
        "signal-thread" => Some(process::signal_thread_probe()),
        "io-uring" => Some(process::io_uring_probe()),
        "daemon" => Some(process::daemon_probe(args.next())),
        _ => None,
    }
}
