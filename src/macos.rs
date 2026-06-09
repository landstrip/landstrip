// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! macOS Seatbelt (SBPL) sandbox platform.

use crate::error::{Error, Result};
use crate::policy::{AccessPolicy, NetworkAccess, ReadAccess, UnixSocketAccess};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;

const SBPL_PROFILE_FLAGS: u64 = 0;

pub(crate) fn execute(policy: &AccessPolicy, tool: &OsStr, args: &[OsString]) -> Result<()> {
    let profile = render_profile(policy).map_err(Error::system_source)?;
    let args = canonicalize_args(args);
    apply_profile(&profile)?;
    let error = Command::new(tool).args(&args).exec();
    Err(Error::tool_exec(Some(tool.to_os_string()), error))
}

fn canonicalize_args(args: &[OsString]) -> Vec<OsString> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        let path = PathBuf::from(arg);
        let resolved = match std::fs::canonicalize(&path) {
            Ok(canonical) => canonical.into_os_string(),
            Err(_) => arg.clone(),
        };
        out.push(resolved);
    }
    out
}

fn apply_profile(profile: &str) -> Result<()> {
    let profile = CString::new(profile).map_err(|source| {
        let nul_position = source.nul_position();
        Error::system(format!(
            "generated SBPL profile contains an interior NUL byte at offset {nul_position}"
        ))
    })?;
    let mut errorbuf = ptr::null_mut();

    // SAFETY: profile is a live NULL-terminated C string and errorbuf points to writable
    // storage through a raw out pointer.
    let rc = unsafe { ffi::sandbox_init(profile.as_ptr(), SBPL_PROFILE_FLAGS, &raw mut errorbuf) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::system(take_sandbox_error(errorbuf)))
    }
}

fn render_profile(policy: &AccessPolicy) -> std::result::Result<String, fmt::Error> {
    let mut sb = String::new();
    writeln!(sb, "(version 1)")?;
    writeln!(sb, "(deny default)")?;

    render_process_rules(&mut sb)?;
    render_write_rules(&mut sb, &policy.write_roots)?;
    render_read_rules(&mut sb, &policy.read_access)?;
    render_network_rules(&mut sb, &policy.network_access)?;

    Ok(sb)
}

fn render_process_rules(sb: &mut String) -> fmt::Result {
    writeln!(sb, "(allow process-exec)")?;
    writeln!(sb, "(allow process-fork)")
}

fn render_write_rules(sb: &mut String, write_roots: &[PathBuf]) -> fmt::Result {
    for root in write_roots {
        let escaped = escape_sbpl_literal(&root.to_string_lossy());
        writeln!(sb, "(allow file-write* (subpath \"{escaped}\"))")?;
    }

    Ok(())
}

fn render_read_rules(sb: &mut String, read_access: &ReadAccess) -> fmt::Result {
    match read_access {
        ReadAccess::Unrestricted => sb.push_str("(allow file-read*)\n"),
        ReadAccess::AllowRoots(roots) => {
            writeln!(sb, "(deny file-read*)")?;
            writeln!(sb, "(allow file-read* (literal \"/\"))")?;
            for root in roots {
                let escaped = escape_sbpl_literal(&root.to_string_lossy());
                writeln!(sb, "(allow file-read* (subpath \"{escaped}\"))")?;
            }
            render_parent_dir_rules(sb, roots)?;
        }
    }

    Ok(())
}

fn render_parent_dir_rules(sb: &mut String, roots: &[PathBuf]) -> fmt::Result {
    let mut ancestors: Vec<PathBuf> = Vec::new();
    for root in roots {
        let mut current = root.as_path();
        while let Some(parent) = current.parent() {
            if parent.as_os_str().is_empty() {
                break;
            }
            if let Ok(real) = std::fs::canonicalize(parent) {
                ancestors.push(real);
            }
            current = parent;
        }
    }
    ancestors.sort_unstable();
    ancestors.dedup();
    for ancestor in &ancestors {
        let escaped = escape_sbpl_literal(&ancestor.to_string_lossy());
        writeln!(sb, "(allow file-read-data (literal \"{escaped}\"))")?;
    }
    Ok(())
}

fn render_network_rules(sb: &mut String, network: &NetworkAccess) -> fmt::Result {
    if network.is_unrestricted() {
        sb.push_str("(allow network*)\n");
        return Ok(());
    }

    // Outbound TCP: deny everything, then allow only proxy loopback ports.
    if network.restrict_connect_tcp {
        sb.push_str("(deny network-outbound)\n");
        for port in &network.connect_tcp_ports {
            writeln!(
                sb,
                "(allow network-outbound (remote tcp \"localhost:{port}\"))"
            )?;
        }
    }

    // TCP binding/listening.
    if network.restrict_bind_tcp {
        sb.push_str("(deny network-bind)\n");
        sb.push_str("(deny network-inbound)\n");
    }
    if network.local_tcp_bind {
        sb.push_str("(allow network-bind (local tcp \"localhost:*\"))\n");
        sb.push_str("(allow network-inbound (local tcp \"localhost:*\"))\n");
    }

    // Unix sockets.
    match &network.unix_socket_access {
        UnixSocketAccess::Unrestricted => {
            // No additional Unix socket rules.
        }
        UnixSocketAccess::AllowPaths(paths) if paths.is_empty() => {
            sb.push_str("(deny network*)\n");
        }
        UnixSocketAccess::AllowPaths(paths) => {
            sb.push_str("(deny network*)\n");
            for path in paths {
                let escaped = escape_sbpl_literal(&path.to_string_lossy());
                writeln!(
                    sb,
                    "(allow network-outbound (remote unix-socket (path-literal \"{escaped}\")))"
                )?;
                writeln!(
                    sb,
                    "(allow network-bind (local unix-socket (path-literal \"{escaped}\")))"
                )?;
            }
        }
    }

    Ok(())
}

/// Escape special characters in an SBPL literal string.
///
/// SBPL literals are not Scheme strings — they contain raw characters.
/// The following must be escaped: `"`, `\`, `(`, `)`, and newlines.
fn escape_sbpl_literal(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '(' => escaped.push_str("\\("),
            ')' => escaped.push_str("\\)"),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn take_sandbox_error(errorbuf: *mut libc::c_char) -> String {
    if errorbuf.is_null() {
        return "sandbox_init failed without an error message".to_string();
    }

    // SAFETY: sandbox_init returns a NULL-terminated error buffer on failure.
    let message = unsafe { CStr::from_ptr(errorbuf) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: errorbuf was allocated by sandbox_init for this API.
    unsafe { ffi::sandbox_free_error(errorbuf) };
    message
}

mod ffi {
    use libc::{c_char, c_int};

    #[link(name = "sandbox")]
    unsafe extern "C" {
        pub(super) fn sandbox_init(
            profile: *const c_char,
            flags: u64,
            errorbuf: *mut *mut c_char,
        ) -> c_int;
        pub(super) fn sandbox_free_error(errorbuf: *mut c_char);
    }
}
