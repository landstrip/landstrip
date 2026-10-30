// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! macOS Seatbelt (SBPL) sandbox platform.

use super::unix::close_inherited_fds;
use crate::config::SandboxDarwin;
use crate::error::Error;
use crate::paths::{GlobPatternBuf, OverridesDeny, PathExt};
use crate::policy::{AccessPolicy, Carveouts, NetworkAccess, ReadAccess, UnixSocketAccess};
use crate::trap_fd::TrapFd;
use anyhow::Result;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt::{self, Write};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

const SBPL_PROFILE_FLAGS: u64 = 0;
const SANDBOX_FILTER_NONE: libc::c_int = 0;

pub(crate) fn execute(
    policy: &AccessPolicy,
    cwd: &Path,
    tool: &OsStr,
    args: &[OsString],
    trap_fd: Option<&TrapFd>,
    inherited_fds: &[std::os::fd::RawFd],
) -> Result<i32> {
    SeatbeltProfile::try_from(policy)?.apply()?;
    close_inherited_fds(trap_fd.map(AsRawFd::as_raw_fd).as_slice(), inherited_fds)
        .map_err(Error::seatbelt)?;
    let mut command = Command::new(tool);
    command.args(args).current_dir(cwd);
    let error = command.exec();
    Err(Error::launch(tool, error).into())
}

pub(crate) fn doctor() -> Result<()> {
    let operation = CString::new("file-read-data").map_err(Error::seatbelt)?;
    let result =
        unsafe { ffi::sandbox_check(libc::getpid(), operation.as_ptr(), SANDBOX_FILTER_NONE) };
    if result < 0 {
        return Err(Error::seatbelt(io::Error::last_os_error()).into());
    }
    Ok(())
}

struct SeatbeltProfile(CString);

impl TryFrom<&AccessPolicy> for SeatbeltProfile {
    type Error = Error;

    fn try_from(policy: &AccessPolicy) -> std::result::Result<Self, Self::Error> {
        let rendered = ProfileBuilder::render(policy).map_err(Error::seatbelt)?;
        log::debug!("seatbelt profile:\n{rendered}");
        CString::new(rendered).map(Self).map_err(|source| {
            Error::seatbelt(format!(
                "profile: interior nul at offset {}",
                source.nul_position()
            ))
        })
    }
}

impl SeatbeltProfile {
    fn apply(&self) -> Result<()> {
        let mut errorbuf = ptr::null_mut();

        // SAFETY: profile is a live NULL-terminated C string and errorbuf points to writable
        // storage through a raw out pointer.
        let rc =
            unsafe { ffi::sandbox_init(self.0.as_ptr(), SBPL_PROFILE_FLAGS, &raw mut errorbuf) };
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::seatbelt(take_sandbox_error(errorbuf)).into())
        }
    }
}

struct ProfileBuilder {
    sb: String,
    message: String,
}

impl ProfileBuilder {
    fn render(policy: &AccessPolicy) -> std::result::Result<String, fmt::Error> {
        let message = policy
            .macos
            .log_tag
            .as_ref()
            .map_or_else(String::new, |tag| format!(" (with message \"{tag}\")"));
        let mut builder = Self {
            sb: String::new(),
            message,
        };
        writeln!(builder.sb, "(version 1)")?;
        writeln!(builder.sb, "(deny default{})", builder.message)?;

        builder.process_rules()?;
        builder.mach_rules(&policy.macos)?;
        builder.write_rules(policy)?;
        builder.read_rules(policy)?;
        builder.network_rules(&policy.network_access)?;
        Ok(builder.sb)
    }

    fn process_rules(&mut self) -> fmt::Result {
        writeln!(self.sb, "(allow process-exec)")?;
        // Seatbelt blocks the setuid system ps binary unless it executes outside the sandbox.
        writeln!(
            self.sb,
            "(allow process-exec (path \"/bin/ps\") (with no-sandbox))",
        )?;
        writeln!(self.sb, "(allow process-fork)")?;
        writeln!(self.sb, "(allow process-info* (target same-sandbox))")?;
        writeln!(self.sb, "(allow signal (target same-sandbox))")?;
        writeln!(self.sb, "(allow sysctl-read)")
    }

    /// Default Mach services, matching the Anthropic sandbox-runtime (srt) base
    /// profile plus `SecurityServer` for Keychain access.
    fn mach_rules(&mut self, macos: &SandboxDarwin) -> fmt::Result {
        writeln!(self.sb, "(allow mach-lookup")?;
        writeln!(self.sb, "  (global-name \"com.apple.SecurityServer\")")?;
        if macos.allow_trustd {
            writeln!(self.sb, "  (global-name \"com.apple.trustd.agent\")")?;
        }
        if macos.allow_apple_events {
            writeln!(
                self.sb,
                "  (global-name \"com.apple.coreservices.appleevents\")"
            )?;
            writeln!(
                self.sb,
                "  (global-name \"com.apple.CoreServices.coreservicesd\")"
            )?;
            writeln!(
                self.sb,
                "  (global-name \"com.apple.coreservices.quarantine-resolver\")"
            )?;
        }
        for service in &macos.allow_mach_lookup {
            if let Some(prefix) = service.strip_suffix('*') {
                let escaped = escape_sbpl_literal(prefix);
                writeln!(self.sb, "  (global-name-prefix \"{escaped}\")")?;
            } else {
                let escaped = escape_sbpl_literal(service);
                writeln!(self.sb, "  (global-name \"{escaped}\")")?;
            }
        }
        writeln!(
            self.sb,
            "  (global-name \"com.apple.audio.systemsoundserver\")"
        )?;
        writeln!(self.sb, "  (global-name \"com.apple.bsd.dirhelper\")")?;
        writeln!(
            self.sb,
            "  (global-name \"com.apple.coreservices.launchservicesd\")"
        )?;
        writeln!(
            self.sb,
            "  (global-name \"com.apple.distributed_notifications@Uv3\")"
        )?;
        writeln!(self.sb, "  (global-name \"com.apple.FontObjectsServer\")")?;
        writeln!(self.sb, "  (global-name \"com.apple.fonts\")")?;
        writeln!(self.sb, "  (global-name \"com.apple.logd\")")?;
        writeln!(self.sb, "  (global-name \"com.apple.lsd.mapdb\")")?;
        writeln!(
            self.sb,
            "  (global-name \"com.apple.PowerManagement.control\")"
        )?;
        writeln!(self.sb, "  (global-name \"com.apple.securityd.xpc\")")?;
        // apple/container CLI talks to its daemons over XPC.
        writeln!(self.sb, "  (global-name-prefix \"com.apple.container.\")")?;
        writeln!(self.sb, "  (global-name \"com.apple.system.logger\")")?;
        writeln!(
            self.sb,
            "  (global-name \"com.apple.system.notification_center\")"
        )?;
        writeln!(
            self.sb,
            "  (global-name \"com.apple.system.opendirectoryd.libinfo\")"
        )?;
        writeln!(
            self.sb,
            "  (global-name \"com.apple.system.opendirectoryd.membership\")"
        )?;
        writeln!(self.sb, ")")?;
        if macos.allow_apple_events {
            writeln!(self.sb, "(allow appleevent-send)")?;
            writeln!(self.sb, "(allow lsopen)")?;
        }
        writeln!(
            self.sb,
            "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))"
        )?;
        writeln!(self.sb, "(allow system-socket (socket-domain AF_ROUTE))")
    }

    fn glob_to_sbpl_regex(pattern: &str) -> String {
        let mut regex = String::from("^");
        let mut rest = pattern;

        while !rest.is_empty() {
            if let Some(tail) = rest.strip_prefix("**/") {
                regex.push_str("(.*/)?");
                rest = tail;
            } else if let Some(tail) = rest.strip_prefix("**") {
                regex.push_str(".*");
                rest = tail;
            } else if let Some(tail) = rest.strip_prefix('*') {
                regex.push_str("[^/]*");
                rest = tail;
            } else if let Some(tail) = rest.strip_prefix('?') {
                regex.push_str("[^/]");
                rest = tail;
            } else if rest.starts_with('[') {
                if let Some(offset) = rest[1..].find(']') {
                    let end = 1 + offset;
                    regex.push_str(&rest[..=end]);
                    rest = &rest[end + 1..];
                } else {
                    regex.push_str("\\[");
                    rest = &rest[1..];
                }
            } else {
                let mut chars = rest.chars();
                let Some(ch) = chars.next() else {
                    break;
                };
                match ch {
                    '.' | '(' | ')' | '{' | '}' | '+' | '|' | '^' | '$' | '\\' => {
                        regex.push('\\');
                        regex.push(ch);
                    }
                    _ => regex.push(ch),
                }
                rest = chars.as_str();
            }
        }

        if !pattern.ends_with('/') {
            regex.push_str("(/.*)?");
        }
        regex.push('$');
        regex
    }

    fn render_pattern_filter(pattern: &GlobPatternBuf, carveouts: &Carveouts) -> String {
        let regex = Self::glob_to_sbpl_regex(pattern.as_str());
        let escaped = escape_sbpl_regex_literal(&regex);
        let glob = pattern.as_glob();
        let filter = format!("(regex #\"{escaped}\")");
        let matching_carveouts: Vec<&Path> = carveouts
            .roots
            .iter()
            .map(PathBuf::as_path)
            .filter(|carveout| glob.matches_tree(carveout))
            .collect();
        let matching_patterns: Vec<&str> = carveouts
            .patterns
            .iter()
            .filter(|allow| allow.overrides_deny(&glob))
            .map(GlobPatternBuf::as_str)
            .collect();
        if matching_carveouts.is_empty() && matching_patterns.is_empty() {
            return filter;
        }

        let mut wrapped = format!("(require-all {filter}");
        for carveout in matching_carveouts {
            let escaped_carveout = escape_sbpl_literal(&carveout.to_string_lossy());
            let _ = write!(wrapped, " (require-not (subpath \"{escaped_carveout}\"))");
        }
        for allow in matching_patterns {
            let allow_regex = Self::glob_to_sbpl_regex(allow);
            let escaped_allow = escape_sbpl_regex_literal(&allow_regex);
            let _ = write!(wrapped, " (require-not (regex #\"{escaped_allow}\"))");
        }
        wrapped.push(')');
        wrapped
    }

    fn write_rules(&mut self, policy: &AccessPolicy) -> fmt::Result {
        let message = &self.message;
        for root in &policy.write_roots {
            let escaped = escape_sbpl_literal(&root.to_string_lossy());
            writeln!(self.sb, "(allow file-write* (subpath \"{escaped}\"))")?;
        }
        for pattern in &policy.write_carveouts.patterns {
            let regex = Self::glob_to_sbpl_regex(pattern.as_str());
            let escaped = escape_sbpl_regex_literal(&regex);
            writeln!(self.sb, "(allow file-write* (regex #\"{escaped}\"))")?;
        }
        if policy.macos.allow_pty {
            writeln!(self.sb, "(allow pseudo-tty)")?;
            writeln!(
                self.sb,
                "(allow file-ioctl file-write* (literal \"/dev/ptmx\") (regex #\"^/dev/ttys\"))"
            )?;
        }
        // Deny rules follow the allow rules so SBPL's last-match-wins precedence
        // subtracts the denied subtrees from the granted write roots.
        for root in &policy.write_denied_roots {
            let escaped = escape_sbpl_literal(&root.to_string_lossy());
            writeln!(
                self.sb,
                "(deny file-write* (subpath \"{escaped}\"){message})"
            )?;
        }
        for carveout in &policy.write_carveouts.roots {
            if carveout.is_under_any(&policy.write_denied_roots) {
                let escaped = escape_sbpl_literal(&carveout.to_string_lossy());
                writeln!(self.sb, "(allow file-write* (subpath \"{escaped}\"))")?;
            }
        }
        for pattern in &policy.write_carveouts.patterns {
            if policy
                .write_denied_roots
                .iter()
                .any(|root| pattern.overrides_deny(root.as_path()))
            {
                let regex = Self::glob_to_sbpl_regex(pattern.as_str());
                let escaped = escape_sbpl_regex_literal(&regex);
                writeln!(self.sb, "(allow file-write* (regex #\"{escaped}\"))")?;
            }
        }

        // Regex rules are evaluated at syscall time, so unlike expand_glob_path
        // they also cover paths created after sandbox_init.
        for pattern in &policy.write_denied_patterns {
            let filter = Self::render_pattern_filter(pattern, &policy.write_carveouts);
            writeln!(self.sb, "(deny file-write* {filter}{message})")?;
        }
        for root in &policy.write_denied_always_roots {
            let escaped = escape_sbpl_literal(&root.to_string_lossy());
            writeln!(
                self.sb,
                "(deny file-write* (subpath \"{escaped}\"){message})"
            )?;
        }
        for pattern in &policy.write_denied_always_patterns {
            let regex = Self::glob_to_sbpl_regex(pattern.as_str());
            let escaped = escape_sbpl_regex_literal(&regex);
            writeln!(
                self.sb,
                "(deny file-write* (regex #\"{escaped}\"){message})"
            )?;
        }

        if !policy.write_roots.is_empty() || policy.write_carveouts.has_patterns() {
            self.write_unlink_rules(policy)?;
        }

        Ok(())
    }

    fn write_unlink_rules(&mut self, policy: &AccessPolicy) -> fmt::Result {
        let message = &self.message;
        for root in &policy.read_denied_roots {
            let escaped = escape_sbpl_literal(&root.to_string_lossy());
            writeln!(
                self.sb,
                "(deny file-write-unlink (subpath \"{escaped}\"){message})"
            )?;
        }
        for pattern in &policy.read_denied_patterns {
            let filter = Self::render_pattern_filter(pattern, &policy.read_carveouts);
            writeln!(self.sb, "(deny file-write-unlink {filter}{message})")?;
        }
        for link in policy.write_denied_links.iter() {
            let escaped = escape_sbpl_literal(&link.path.to_string_lossy());
            writeln!(
                self.sb,
                "(deny file-write-unlink (literal \"{escaped}\"){message})"
            )?;
        }

        let mut ancestors: Vec<PathBuf> = Vec::new();
        // Ancestors that are themselves granted write roots must not
        // receive unlink protection: a granted root's own lifecycle (for
        // example a lock directory released with rmdir) must stay intact,
        // and denied descendants are already protected by their own write
        // denies.
        let is_granted_root = |p: &Path| policy.write_roots.iter().any(|root| root.as_path() == p);
        for root in policy
            .write_denied_roots
            .iter()
            .chain(policy.read_denied_roots.iter())
        {
            for ancestor in root.ancestors().skip(1) {
                if ancestor != Path::new("/")
                    && !is_granted_root(ancestor)
                    && ancestor.is_under_any(&policy.write_roots)
                {
                    ancestors.push(ancestor.to_path_buf());
                }
            }
        }
        for pattern in policy
            .write_denied_patterns
            .iter()
            .chain(policy.read_denied_patterns.iter())
        {
            let base = pattern.base();
            for ancestor in base.ancestors() {
                if ancestor != Path::new("/")
                    && !is_granted_root(ancestor)
                    && (ancestor.is_under_any(&policy.write_roots)
                        || policy
                            .write_carveouts
                            .patterns
                            .iter()
                            .any(|allow| ancestor.is_under(&allow.base())))
                {
                    ancestors.push(ancestor.to_path_buf());
                }
            }
        }
        ancestors.sort_unstable();
        ancestors.dedup();
        for ancestor in &ancestors {
            let escaped = escape_sbpl_literal(&ancestor.to_string_lossy());
            writeln!(
                self.sb,
                "(deny file-write-unlink (literal \"{escaped}\"){message})"
            )?;
        }

        Ok(())
    }

    fn read_rules(&mut self, policy: &AccessPolicy) -> fmt::Result {
        match &policy.read_access {
            ReadAccess::Unrestricted => self.sb.push_str("(allow file-read*)\n"),
            ReadAccess::AllowRoots(roots) => {
                writeln!(self.sb, "(deny file-read*{})", self.message)?;
                writeln!(self.sb, "(allow file-read* (literal \"/\"))")?;
                for root in roots {
                    let escaped = escape_sbpl_literal(&root.to_string_lossy());
                    writeln!(self.sb, "(allow file-read* (subpath \"{escaped}\"))")?;
                }
                for pattern in &policy.read_carveouts.patterns {
                    let regex = Self::glob_to_sbpl_regex(pattern.as_str());
                    let escaped = escape_sbpl_regex_literal(&regex);
                    writeln!(self.sb, "(allow file-read* (regex #\"{escaped}\"))")?;
                }
                if policy.macos.allow_pty {
                    writeln!(
                        self.sb,
                        "(allow file-read* (literal \"/dev/ptmx\") (regex #\"^/dev/ttys\"))"
                    )?;
                }
                let mut parent_roots = roots.clone();
                parent_roots.extend(
                    policy
                        .read_carveouts
                        .patterns
                        .iter()
                        .map(GlobPatternBuf::base),
                );
                self.parent_dir_rules(&parent_roots)?;
                self.symlink_metadata_rules(&policy.read_symlinks)?;
            }
        }
        // Deny rules follow the allow rules so SBPL's last-match-wins
        // precedence subtracts the denied subtrees from the read grants.
        for root in &policy.read_denied_roots {
            let escaped = escape_sbpl_literal(&root.to_string_lossy());
            writeln!(
                self.sb,
                "(deny file-read* (subpath \"{escaped}\"){})",
                self.message
            )?;
        }
        for carveout in &policy.read_carveouts.roots {
            if carveout.is_under_any(&policy.read_denied_roots) {
                let escaped = escape_sbpl_literal(&carveout.to_string_lossy());
                writeln!(self.sb, "(allow file-read* (subpath \"{escaped}\"))")?;
            }
        }
        for pattern in &policy.read_carveouts.patterns {
            if policy
                .read_denied_roots
                .iter()
                .any(|root| pattern.overrides_deny(root.as_path()))
            {
                let regex = Self::glob_to_sbpl_regex(pattern.as_str());
                let escaped = escape_sbpl_regex_literal(&regex);
                writeln!(self.sb, "(allow file-read* (regex #\"{escaped}\"))")?;
            }
        }
        for pattern in &policy.read_denied_patterns {
            let filter = Self::render_pattern_filter(pattern, &policy.read_carveouts);
            writeln!(self.sb, "(deny file-read* {filter}{})", self.message)?;
        }
        for root in &policy.read_denied_always_roots {
            let escaped = escape_sbpl_literal(&root.to_string_lossy());
            writeln!(
                self.sb,
                "(deny file-read* (subpath \"{escaped}\"){})",
                self.message
            )?;
        }
        for pattern in &policy.read_denied_always_patterns {
            let regex = Self::glob_to_sbpl_regex(pattern.as_str());
            let escaped = escape_sbpl_regex_literal(&regex);
            writeln!(
                self.sb,
                "(deny file-read* (regex #\"{escaped}\"){})",
                self.message
            )?;
        }

        Ok(())
    }

    fn parent_dir_rules(&mut self, roots: &[PathBuf]) -> fmt::Result {
        let mut ancestors: Vec<PathBuf> = roots
            .iter()
            .flat_map(|root| root.ancestors().skip(1))
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .collect();
        ancestors.sort_unstable();
        ancestors.dedup();
        for ancestor in &ancestors {
            let escaped = escape_sbpl_literal(&ancestor.to_string_lossy());
            writeln!(self.sb, "(allow file-read* (literal \"{escaped}\"))")?;
        }
        Ok(())
    }

    /// Allow `readlink` on the lexical symlink inodes the read scan skipped.
    ///
    /// Mirrors Apple's system.sb: `readlink` only permits resolution; the target
    /// is still gated by the existing allow/deny rules, so this grants no new read
    /// access.
    fn symlink_metadata_rules(&mut self, symlinks: &[PathBuf]) -> fmt::Result {
        if symlinks.is_empty() {
            return Ok(());
        }
        self.sb.push_str("(allow file-read-metadata");
        for sym in symlinks {
            let escaped = escape_sbpl_literal(&sym.to_string_lossy());
            write!(self.sb, "\n  (literal \"{escaped}\")")?;
        }
        self.sb.push_str(")\n");
        Ok(())
    }

    fn network_rules(&mut self, network: &NetworkAccess) -> fmt::Result {
        if network.is_unrestricted() {
            self.sb.push_str("(allow network*)\n");
            if !matches!(network.unix_socket_access(), UnixSocketAccess::Unrestricted) {
                writeln!(
                    self.sb,
                    "(deny network-outbound (remote unix-socket){})",
                    self.message
                )?;
                writeln!(
                    self.sb,
                    "(deny network-bind (local unix-socket){})",
                    self.message
                )?;
            }
            if let UnixSocketAccess::AllowPaths(paths) = network.unix_socket_access() {
                self.unix_socket_path_rules(paths)?;
            }
            return Ok(());
        }

        // AF_UNIX socket creation stays allowed regardless of the socket policy.
        self.sb
            .push_str("(allow system-socket (socket-domain AF_UNIX))\n");

        // Seatbelt accepts only `*` or `localhost` as the host token in an IP
        // endpoint filter. `localhost` permits IPv4 and IPv6 loopback connections,
        // matching the macOS Anthropic Sandbox Runtime behavior. On some hosts it
        // also matches addresses assigned to other local interfaces; Seatbelt
        // cannot express a stricter loopback-only rule.
        writeln!(self.sb, "(deny network-outbound{})", self.message)?;
        for port in network.connect_tcp_ports() {
            writeln!(
                self.sb,
                "(allow network-outbound (remote tcp \"localhost:{port}\"))"
            )?;
        }

        if network.allows_local_binding() {
            // allowLocalBinding also grants host-local UDP on Seatbelt. Match the
            // destination for outbound traffic: a local/source filter would allow
            // remote egress from a locally bound socket.
            for protocol in ["tcp", "udp"] {
                writeln!(
                    self.sb,
                    "(allow network-outbound (remote {protocol} \"localhost:*\"))"
                )?;
                writeln!(
                    self.sb,
                    "(allow network-bind (local {protocol} \"localhost:*\"))"
                )?;
                writeln!(
                    self.sb,
                    "(allow network-inbound (local {protocol} \"localhost:*\"))"
                )?;
            }
        }

        match network.unix_socket_access() {
            UnixSocketAccess::Unrestricted => {
                self.sb
                    .push_str("(allow network-outbound (remote unix-socket))\n");
                self.sb
                    .push_str("(allow network-bind (local unix-socket))\n");
            }
            UnixSocketAccess::AllowPaths(paths) => self.unix_socket_path_rules(paths)?,
            UnixSocketAccess::Denied => {}
        }

        Ok(())
    }

    fn unix_socket_path_rules(&mut self, paths: &[PathBuf]) -> fmt::Result {
        for path in paths {
            let escaped = escape_sbpl_literal(&path.to_string_lossy());
            writeln!(
                self.sb,
                "(allow network-outbound (remote unix-socket (subpath \"{escaped}\")))"
            )?;
            writeln!(
                self.sb,
                "(allow network-bind (local unix-socket (subpath \"{escaped}\")))"
            )?;
        }
        Ok(())
    }
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

fn escape_sbpl_regex_literal(regex: &str) -> String {
    let mut escaped = String::with_capacity(regex.len());
    for ch in regex.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
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
        pub(super) fn sandbox_check(
            pid: libc::pid_t,
            operation: *const c_char,
            filter_type: c_int,
            ...
        ) -> c_int;
    }
}
