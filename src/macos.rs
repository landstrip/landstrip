// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! macOS Seatbelt (SBPL) sandbox platform.

use crate::error::Error;
use crate::policy::{AccessPolicy, NetworkAccess, ReadAccess, UnixSocketAccess};
use crate::trap_fd::TrapFd;
use anyhow::{Context, Result, anyhow};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt::{self, Write};
use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;

const SBPL_PROFILE_FLAGS: u64 = 0;
const FIRST_INHERITED_FD: RawFd = 3;
const FALLBACK_FD_LIMIT: RawFd = 1_048_576;

pub(crate) fn execute(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    trap_fd: &TrapFd,
) -> Result<()> {
    let profile = render_profile(policy).context("render sandbox profile")?;
    apply_profile(&profile)?;
    trap_fd.close();
    close_inherited_fds();
    let error = Command::new(tool).args(args).exec();
    Err(Error::IoFailed(error).into())
}

fn close_inherited_fds() {
    if let Ok(mut entries) = fs::read_dir("/dev/fd") {
        let mut fds = Vec::new();
        for entry in entries.by_ref().flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(fd) = name.parse::<RawFd>() else {
                continue;
            };
            if fd >= FIRST_INHERITED_FD {
                fds.push(fd);
            }
        }

        drop(entries);

        fds.sort_unstable();
        fds.dedup();
        for fd in fds {
            close_fd(fd);
        }
        return;
    }

    for fd in FIRST_INHERITED_FD..open_fd_limit() {
        close_fd(fd);
    }
}

fn open_fd_limit() -> RawFd {
    let limit = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    RawFd::try_from(limit).map_or(FALLBACK_FD_LIMIT, |limit| {
        limit.clamp(FIRST_INHERITED_FD, FALLBACK_FD_LIMIT)
    })
}

fn close_fd(fd: RawFd) {
    if fd >= FIRST_INHERITED_FD {
        unsafe { libc::close(fd) };
    }
}

fn apply_profile(profile: &str) -> Result<()> {
    let profile = CString::new(profile).map_err(|source| {
        anyhow!(
            "SBPL profile contains interior NUL byte at offset {}",
            source.nul_position()
        )
    })?;
    let mut errorbuf = ptr::null_mut();

    // SAFETY: profile is a live NULL-terminated C string and errorbuf points to writable
    // storage through a raw out pointer.
    let rc = unsafe { ffi::sandbox_init(profile.as_ptr(), SBPL_PROFILE_FLAGS, &raw mut errorbuf) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::IoFailed(io::Error::other(take_sandbox_error(errorbuf))).into())
    }
}

fn render_profile(policy: &AccessPolicy) -> std::result::Result<String, fmt::Error> {
    let mut sb = String::new();
    writeln!(sb, "(version 1)")?;
    writeln!(sb, "(deny default)")?;

    render_process_rules(&mut sb)?;
    render_write_rules(&mut sb, &policy.write_roots, &policy.write_denied_roots)?;
    render_read_rules(&mut sb, &policy.read_access)?;
    render_network_rules(&mut sb, &policy.network_access)?;

    Ok(sb)
}

fn render_process_rules(sb: &mut String) -> fmt::Result {
    writeln!(sb, "(allow process-exec)")?;
    writeln!(sb, "(allow process-fork)")?;
    writeln!(sb, "(allow sysctl-read)")
}

fn render_write_rules(
    sb: &mut String,
    write_roots: &[PathBuf],
    write_denied_roots: &[PathBuf],
) -> fmt::Result {
    for root in write_roots {
        let escaped = escape_sbpl_literal(&root.to_string_lossy());
        writeln!(sb, "(allow file-write* (subpath \"{escaped}\"))")?;
    }

    // Deny rules follow the allow rules so SBPL's last-match-wins precedence
    // subtracts the denied subtrees from the granted write roots.
    for root in write_denied_roots {
        let escaped = escape_sbpl_literal(&root.to_string_lossy());
        writeln!(sb, "(deny file-write* (subpath \"{escaped}\"))")?;
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
            ancestors.push(parent.to_path_buf());
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
        writeln!(sb, "(allow file-read* (literal \"{escaped}\"))")?;
    }
    Ok(())
}

fn render_network_rules(sb: &mut String, network: &NetworkAccess) -> fmt::Result {
    if network.is_unrestricted() {
        sb.push_str("(allow network*)\n");
        return Ok(());
    }

    if network.restrict_connect_tcp {
        sb.push_str("(deny network-outbound)\n");
        for port in &network.connect_tcp_ports {
            writeln!(
                sb,
                "(allow network-outbound (remote tcp \"localhost:{port}\"))"
            )?;
        }
    }

    if network.restrict_bind_tcp {
        sb.push_str("(deny network-bind)\n");
        sb.push_str("(deny network-inbound)\n");
    }
    if network.local_tcp_bind {
        sb.push_str("(allow network-bind (local tcp \"localhost:*\"))\n");
        sb.push_str("(allow network-inbound (local tcp \"localhost:*\"))\n");
    }

    match &network.unix_socket_access {
        UnixSocketAccess::Unrestricted => {
            sb.push_str("(allow system-socket (socket-domain AF_UNIX))\n");
            sb.push_str("(allow network-outbound (remote unix-socket))\n");
            sb.push_str("(allow network-bind (local unix-socket))\n");
        }
        UnixSocketAccess::AllowPaths(paths) if !paths.is_empty() => {
            sb.push_str("(allow system-socket (socket-domain AF_UNIX))\n");
            for path in paths {
                let escaped = escape_sbpl_literal(&path.to_string_lossy());
                writeln!(
                    sb,
                    "(allow network-outbound (remote unix-socket (subpath \"{escaped}\")))"
                )?;
                writeln!(
                    sb,
                    "(allow network-bind (local unix-socket (subpath \"{escaped}\")))"
                )?;
            }
        }
        UnixSocketAccess::AllowPaths(_) => {}
    }

    Ok(())
}

fn escape_sbpl_literal(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::escape_sbpl_literal;

    #[test]
    fn escape_sbpl_literal_preserves_parentheses() {
        assert_eq!(escape_sbpl_literal("/tmp/App (Beta)"), "/tmp/App (Beta)");
    }

    #[test]
    fn escape_sbpl_literal_escapes_string_delimiters() {
        assert_eq!(escape_sbpl_literal("/tmp/a\"b"), "/tmp/a\\\"b");
        assert_eq!(escape_sbpl_literal("/tmp/a\\b"), "/tmp/a\\\\b");
        assert_eq!(escape_sbpl_literal("/tmp/a\nb"), "/tmp/a\\nb");
    }
}

fn take_sandbox_error(errorbuf: *mut libc::c_char) -> String {
    if errorbuf.is_null() {
        return "sandbox_init failed without an error message".to_string();
    }

    let message = unsafe { CStr::from_ptr(errorbuf) }
        .to_string_lossy()
        .into_owned();
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
