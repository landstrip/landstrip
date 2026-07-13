// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Policy lowering from JSON settings to platform access rules.
//!
//! Filesystem policy follows the Seatbelt-compatible shape. Writes start
//! denied; `allowWrite` grants roots and `denyWrite` subtracts from them. Reads
//! stay unrestricted unless `denyRead` is set; `allowRead` then adds paths back,
//! with the most specific rule winning where an allow and a deny overlap.
//!
//! Paths accept absolute names, names relative to the policy base, `~`, and the
//! macOS-style `*`, `**`, `?`, and character-class globs. Globs are expanded
//! while lowering the policy.

use crate::config::{SandboxFilesystem, SandboxNetwork};
use crate::engine::error::Error;
#[cfg(not(target_os = "macos"))]
use crate::engine::paths::normalize_path;
use crate::engine::paths::{normalize_path_lexically, normalize_roots};
use anyhow::Result;
use rayon::prelude::*;
use std::env;
use std::fs;
use std::io;
#[cfg(target_os = "macos")]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct AccessPolicy {
    pub(crate) write_roots: Vec<PathBuf>,
    pub(crate) write_denied_roots: Vec<PathBuf>,
    pub(crate) write_denied_patterns: Vec<String>,
    pub(crate) write_denied_links: Vec<PathBuf>,
    pub(crate) read_access: ReadAccess,
    pub(crate) read_denied_roots: Vec<PathBuf>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) read_symlinks: Vec<PathBuf>,
    pub(crate) network_access: NetworkAccess,
}

// The write broker that consults these lives only in the Linux seccomp path.
#[cfg(target_os = "linux")]
impl AccessPolicy {
    /// Whether a write to `canonical` (with lexical form `lexical`, used for the
    /// symlink-ancestor deny-list) lands in the `denyWrite` deny-list. Glob
    /// patterns in `write_denied_patterns` are evaluated dynamically against the
    /// lexical path so files created after sandbox startup are also blocked.
    pub(crate) fn is_write_denied(&self, canonical: &Path, lexical: &Path) -> bool {
        self.write_denied_roots
            .iter()
            .any(|root| canonical == root || canonical.starts_with(root))
            || self
                .write_denied_links
                .iter()
                .any(|root| lexical == root || lexical.starts_with(root))
            || self
                .write_denied_patterns
                .iter()
                .any(|pattern| path_matches_glob_str(lexical, pattern))
    }

    /// Why a write to `canonical` is mediated, or `None` when the policy permits
    /// it. `allow_miss` (outside every `allowWrite` root) is reported only when
    /// `surface_allow_miss` is set: content syscalls leave it to Landlock unless
    /// a query can resolve it, but metadata syscalls Landlock does not cover must
    /// always surface it so the broker can gate them.
    pub(crate) fn to_reason(
        &self,
        canonical: &Path,
        lexical: &Path,
        surface_allow_miss: bool,
    ) -> Option<&'static str> {
        if self.is_write_denied(canonical, lexical) {
            Some("deny_match")
        } else if surface_allow_miss
            && !self
                .write_roots
                .iter()
                .any(|root| canonical == root || canonical.starts_with(root))
        {
            Some("allow_miss")
        } else {
            None
        }
    }
}

#[cfg(target_os = "macos")]
impl AccessPolicy {
    /// Reject policies macOS Seatbelt cannot enforce: an existing non-socket
    /// `allowUnixSockets` path or a `denyWrite` symlink ancestor.
    pub(crate) fn validate(&self) -> std::result::Result<(), Error> {
        if let UnixSocketAccess::AllowPaths(paths) = &self.network_access.unix_socket_access {
            for path in paths {
                match fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.file_type().is_socket() => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        log::debug!(
                            "macos: allowUnixSockets path absent, skipping {}",
                            path.display()
                        );
                    }
                    _ => return Err(Error::PolicyUnixSocketPath),
                }
            }
        }

        let has_writable_symlink_ancestor = self.write_denied_links.iter().any(|link| {
            self.write_roots
                .iter()
                .any(|root| link == root || link.starts_with(root))
        });
        if has_writable_symlink_ancestor {
            return Err(Error::PolicyDenyWriteSymlinkAncestor);
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl AccessPolicy {
    /// Reject policies the Windows `AppContainer` cannot enforce: unrestricted
    /// read, a local TCP bind, or a non-empty Unix socket allowlist. Connect
    /// proxy ports are accepted but unenforceable, so the container then runs
    /// with no network access.
    pub(crate) fn validate(&self) -> std::result::Result<(), Error> {
        if matches!(self.read_access, ReadAccess::Unrestricted) {
            return Err(Error::PolicyUnrestrictedRead);
        }

        let network = &self.network_access;
        if network.is_unrestricted() {
            return Ok(());
        }

        if network.local_tcp_bind {
            return Err(Error::PolicyTcpBindUnsupported);
        }

        if !matches!(&network.unix_socket_access, UnixSocketAccess::AllowPaths(paths) if paths.is_empty())
        {
            return Err(Error::PolicyUnixSocketUnsupported);
        }

        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl AccessPolicy {
    /// The Linux broker enforces every supported policy shape, so nothing is
    /// rejected ahead of time.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(crate) fn validate(&self) -> std::result::Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum ReadAccess {
    Unrestricted,
    AllowRoots(Vec<PathBuf>),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct NetworkAccess {
    pub(crate) restrict_connect_tcp: bool,
    pub(crate) connect_tcp_ports: Vec<u16>,
    pub(crate) restrict_bind_tcp: bool,
    pub(crate) local_tcp_bind: bool,
    pub(crate) unix_socket_access: UnixSocketAccess,
}

impl NetworkAccess {
    pub(crate) fn unrestricted() -> Self {
        Self {
            restrict_connect_tcp: false,
            connect_tcp_ports: Vec::new(),
            restrict_bind_tcp: false,
            local_tcp_bind: false,
            unix_socket_access: UnixSocketAccess::Unrestricted,
        }
    }

    pub(crate) fn is_unrestricted(&self) -> bool {
        !self.restrict_connect_tcp
            && self.connect_tcp_ports.is_empty()
            && !self.restrict_bind_tcp
            && !self.local_tcp_bind
            && matches!(self.unix_socket_access, UnixSocketAccess::Unrestricted)
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum UnixSocketAccess {
    Unrestricted,
    AllowPaths(Vec<PathBuf>),
}

pub(crate) fn resolve_policy(
    filesystem: &SandboxFilesystem,
    network: &SandboxNetwork,
    policy_base: &Path,
) -> Result<AccessPolicy> {
    let home_dir = dirs::home_dir();
    let home = home_dir.as_deref();
    let policy_base = if policy_base.is_absolute() {
        policy_base.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|source| Error::PolicyIoFailed { source })?
            .join(policy_base)
    };
    let policy_base = normalize_path_lexically(&policy_base);

    let write_allow = resolve_paths(&filesystem.allow_write, &policy_base, home)?;
    let (write_deny, write_denied_patterns) =
        resolve_deny_paths(&filesystem.deny_write, &policy_base, home)?;
    let write_denied_links = collect_symlink_ancestors(&filesystem.deny_write, &policy_base, home)?;

    let read_allow = resolve_paths(&filesystem.allow_read, &policy_base, home)?;
    let read_deny = resolve_paths(&filesystem.deny_read, &policy_base, home)?;
    let read_denied_roots = effective_denied_roots(&read_deny, &read_allow);
    let (read_access, read_symlinks) = if read_deny.is_empty() {
        (ReadAccess::Unrestricted, Vec::new())
    } else if read_allow.iter().any(|root| root == Path::new("/")) {
        // A `/` allowRead grants the whole tree; the surviving denyRead roots are
        // layered back as deny rules rather than by carving the live filesystem.
        (ReadAccess::AllowRoots(vec![PathBuf::from("/")]), Vec::new())
    } else {
        let (mut read_roots, read_symlinks) = {
            let mut allowed = vec![PathBuf::from("/")];
            normalize_roots(&mut allowed);
            let mut denied = read_deny.clone();
            normalize_roots(&mut denied);
            let scanned = allowed
                .par_iter()
                .map(|root| scan_allowed_root(root, &denied, true, 0))
                .collect::<Result<Vec<RootScan>>>()?;
            let mut roots: Vec<PathBuf> = Vec::new();
            let mut syms: Vec<PathBuf> = Vec::new();
            for scan in scanned {
                roots.extend(scan.roots);
                syms.extend(scan.symlinks);
            }
            normalize_roots(&mut roots);
            normalize_roots(&mut syms);
            (roots, syms)
        };
        // Push each allowRead root as-is; nested denyRead entries are
        // enforced by the seccomp broker (deny_match) without snapshot-
        // enumerating the parent directory. Landlock path_beneath on the
        // parent covers all descendants including runtime-created ones.
        for allow in &read_allow {
            read_roots.push(allow.clone());
        }
        normalize_roots(&mut read_roots);
        (ReadAccess::AllowRoots(read_roots), read_symlinks)
    };
    let policy = AccessPolicy {
        write_roots: write_allow,
        write_denied_roots: write_deny,
        write_denied_patterns,
        write_denied_links,
        read_access,
        read_denied_roots,
        read_symlinks,
        network_access: lower_network_policy(network, &policy_base, home)?,
    };
    policy.validate()?;
    Ok(policy)
}

fn lower_network_policy(
    network: &SandboxNetwork,
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<NetworkAccess> {
    if network.allow_network {
        return Ok(NetworkAccess::unrestricted());
    }

    let mut connect_tcp_ports = Vec::new();
    push_proxy_port(&mut connect_tcp_ports, network.http_proxy_port)?;
    push_proxy_port(&mut connect_tcp_ports, network.socks_proxy_port)?;
    connect_tcp_ports.sort_unstable();
    connect_tcp_ports.dedup();

    let unix_socket_paths = resolve_paths(&network.allow_unix_sockets, policy_base, home)?;
    let unix_socket_access = if network.allow_all_unix_sockets {
        UnixSocketAccess::Unrestricted
    } else {
        UnixSocketAccess::AllowPaths(unix_socket_paths)
    };

    Ok(NetworkAccess {
        restrict_connect_tcp: true,
        connect_tcp_ports,
        restrict_bind_tcp: !network.allow_local_binding,
        local_tcp_bind: network.allow_local_binding,
        unix_socket_access,
    })
}

fn push_proxy_port(ports: &mut Vec<u16>, port: Option<u16>) -> Result<()> {
    let Some(port) = port else {
        return Ok(());
    };

    if port == 0 {
        return Err(Error::PolicyInvalidPort.into());
    }

    ports.push(port);
    Ok(())
}

fn resolve_paths(
    paths: &[String],
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut resolved: Vec<PathBuf> = paths
        .par_iter()
        .map(|path| {
            let path = resolve_sandbox_path(path, policy_base, home)?;
            let candidates = if path.to_string_lossy().bytes().any(is_glob_byte) {
                let matches = expand_glob_path(&path)?;
                if matches.is_empty() && fs::symlink_metadata(&path).is_ok() {
                    vec![path]
                } else {
                    matches
                }
            } else {
                vec![path]
            };
            let mut resolved = Vec::new();
            for candidate in &candidates {
                push_path_variants(&mut resolved, candidate);
            }
            Ok(resolved)
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    normalize_roots(&mut resolved);

    Ok(resolved)
}

fn resolve_deny_paths(
    paths: &[String],
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<(Vec<PathBuf>, Vec<String>)> {
    let mut concrete: Vec<PathBuf> = Vec::new();
    let mut patterns: Vec<String> = Vec::new();

    for path in paths {
        let resolved = resolve_sandbox_path(path, policy_base, home)?;
        let resolved_str = resolved.to_string_lossy();
        if resolved_str.bytes().any(is_glob_byte) {
            patterns.push(resolved_str.into_owned());
        } else {
            let mut variants = Vec::new();
            push_path_variants(&mut variants, &resolved);
            concrete.extend(variants);
        }
    }

    normalize_roots(&mut concrete);

    Ok((concrete, patterns))
}

const MAX_TRAVERSAL_DEPTH: u32 = 40;

/// Roots and skipped symlinks collected from a single `scan_allowed_root` traversal.
struct RootScan {
    roots: Vec<PathBuf>,
    symlinks: Vec<PathBuf>,
}

fn scan_allowed_root(
    root: &Path,
    denied: &[PathBuf],
    is_explicit_root: bool,
    depth: u32,
) -> Result<RootScan> {
    let mut results = Vec::new();
    let mut symlinks = Vec::new();
    let mut stack = vec![(root.to_path_buf(), is_explicit_root, depth)];

    while let Some((current, is_explicit, depth)) = stack.pop() {
        if depth >= MAX_TRAVERSAL_DEPTH {
            return Err(Error::PolicyTraversalDepth.into());
        }

        if denied
            .iter()
            .any(|denied_root| current == *denied_root || current.starts_with(denied_root))
        {
            continue;
        }

        let has_denied_descendant = denied
            .iter()
            .any(|denied_root| denied_root.starts_with(&current));

        // A transient EIO (e.g. an autofs automount such as macOS `/home`) is
        // treated as an opaque boundary alongside a missing or denied path: keep
        // the path and stop descending rather than abort. A path landstrip cannot
        // stat is also unreadable to the sandboxed child.
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.kind() == io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(libc::EIO)
                    || error.raw_os_error() == Some(libc::ENOTCONN) =>
            {
                results.push(current);
                continue;
            }
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        let file_type = metadata.file_type();

        if file_type.is_symlink() && !is_explicit {
            symlinks.push(normalize_path_lexically(&current));
            continue;
        }
        if !has_denied_descendant || !file_type.is_dir() {
            results.push(current);
            continue;
        }

        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(libc::EIO)
                    || error.raw_os_error() == Some(libc::ENOTCONN) =>
            {
                results.push(current);
                continue;
            }
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error)
                    if error.raw_os_error() == Some(libc::EIO)
                        || error.raw_os_error() == Some(libc::ENOTCONN) =>
                {
                    continue;
                }
                Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
            };
            let child = entry.path();
            stack.push((child, false, depth + 1));
        }
    }

    Ok(RootScan {
        roots: results,
        symlinks,
    })
}

/// The `denyRead` roots that survive `allowRead` overrides.
///
/// An `allowRead` root that equals a `denyRead` root, or is nested under it,
/// re-grants that subtree and overrides the broader-or-equal deny per the
/// most-specific-rule-wins precedence. Such denies are dropped so they neither
/// emit a macOS deny rule nor gate the Linux broker.
fn effective_denied_roots(read_deny: &[PathBuf], read_allow: &[PathBuf]) -> Vec<PathBuf> {
    read_deny
        .iter()
        .filter(|deny| {
            !read_allow
                .iter()
                .any(|allow| allow.as_path() == deny.as_path() || allow.starts_with(deny))
        })
        .cloned()
        .collect()
}

fn collect_symlink_ancestors(
    paths: &[String],
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut links = Vec::new();
    for path in paths {
        let resolved = resolve_sandbox_path(path, policy_base, home)?;
        let mut current = PathBuf::new();
        for component in resolved.components() {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    links.push(normalize_path_lexically(&current));
                }
                _ => {}
            }
        }
    }
    links.sort_unstable();
    links.dedup();
    Ok(links)
}

#[cfg(target_os = "macos")]
fn push_path_variants(paths: &mut Vec<PathBuf>, path: &Path) {
    paths.push(normalize_path_lexically(path));
    if let Ok(canonical) = fs::canonicalize(path) {
        paths.push(normalize_path_lexically(&canonical));
    }
}

#[cfg(not(target_os = "macos"))]
fn push_path_variants(paths: &mut Vec<PathBuf>, path: &Path) {
    paths.push(normalize_path(path));
}

fn resolve_sandbox_path(path: &str, base: &Path, home: Option<&Path>) -> Result<PathBuf> {
    if path.is_empty() {
        return Err(Error::PolicyEmptyPath.into());
    }

    let raw = Path::new(path);
    let resolved = if raw.has_root() {
        raw.to_path_buf()
    } else if path == "~" {
        home.map(Path::to_path_buf)
            .ok_or(Error::PolicyHomeUnavailable)?
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.map(|home| home.join(rest))
            .ok_or(Error::PolicyHomeUnavailable)?
    } else {
        base.join(raw)
    };

    Ok(normalize_path_lexically(&resolved))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn path_matches_glob_str(path: &Path, pattern: &str) -> bool {
    let path_bytes = path.to_string_lossy();
    let pattern_bytes = pattern.as_bytes();
    let path_len = path_bytes.len();
    let pattern_len = pattern_bytes.len();
    let mut memo = vec![vec![None; path_len + 1]; pattern_len + 1];
    glob_matches_at(pattern_bytes, path_bytes.as_bytes(), 0, 0, &mut memo)
}

pub(crate) fn expand_glob_path(pattern: &Path) -> Result<Vec<PathBuf>> {
    let pattern = pattern.to_string_lossy();
    let base = glob_base(&pattern);
    let mut matches = Vec::new();

    match fs::symlink_metadata(&base) {
        Ok(_) => collect_glob_matches(&base, &pattern, &mut matches, 0)?,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.kind() == io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(libc::EIO)
                || error.raw_os_error() == Some(libc::ENOTCONN) => {}
        Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
    }

    Ok(matches)
}

fn is_glob_byte(byte: u8) -> bool {
    matches!(byte, b'*' | b'?' | b'[' | b']')
}

fn glob_base(pattern: &str) -> PathBuf {
    let Some(glob_at) = pattern.bytes().position(is_glob_byte) else {
        return PathBuf::from(pattern);
    };
    let prefix = &pattern[..glob_at];
    let base = if prefix.ends_with('/') {
        Path::new(prefix.trim_end_matches('/'))
    } else {
        Path::new(prefix).parent().unwrap_or(Path::new("/"))
    };

    if base.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        base.to_path_buf()
    }
}

fn collect_glob_matches(
    path: &Path,
    pattern: &str,
    matches: &mut Vec<PathBuf>,
    depth: u32,
) -> Result<()> {
    const LIMIT: u32 = 40;

    if depth >= LIMIT {
        return Err(Error::PolicyTraversalDepth.into());
    }

    let candidate = normalize_path_lexically(path);
    let candidate_text = candidate.to_string_lossy();
    let pattern_bytes = pattern.as_bytes();
    let candidate_bytes = candidate_text.as_bytes();
    let mut memo = vec![vec![None; candidate_bytes.len() + 1]; pattern_bytes.len() + 1];

    if glob_matches_at(pattern_bytes, candidate_bytes, 0, 0, &mut memo) {
        matches.push(candidate.clone());
    }

    // A directory the broker cannot stat or read contributes no further glob
    // matches. Skip it rather than aborting the whole policy: an unreadable
    // directory is also unreadable to the sandboxed child, and the seccomp
    // broker still enforces denied paths regardless of glob expansion.
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.kind() == io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(libc::EIO)
                || error.raw_os_error() == Some(libc::ENOTCONN) =>
        {
            return Ok(());
        }
        Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Ok(());
    }

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error)
            if error.kind() == io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(libc::EIO)
                || error.raw_os_error() == Some(libc::ENOTCONN) =>
        {
            return Ok(());
        }
        Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error)
                if error.raw_os_error() == Some(libc::EIO)
                    || error.raw_os_error() == Some(libc::ENOTCONN) =>
            {
                continue;
            }
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        collect_glob_matches(&entry.path(), pattern, matches, depth + 1)?;
    }

    Ok(())
}
fn glob_matches_at(
    pattern: &[u8],
    text: &[u8],
    pattern_at: usize,
    text_at: usize,
    memo: &mut [Vec<Option<bool>>],
) -> bool {
    if let Some(result) = memo[pattern_at][text_at] {
        return result;
    }

    let result = if pattern_at == pattern.len() {
        text_at == text.len()
    } else if pattern[pattern_at..].starts_with(b"**/") {
        globstar_slash_matches(pattern, text, pattern_at, text_at, memo)
    } else if pattern[pattern_at..].starts_with(b"**") {
        globstar_matches(pattern, text, pattern_at, text_at, memo)
    } else {
        match pattern[pattern_at] {
            b'*' => star_matches(pattern, text, pattern_at, text_at, memo),
            b'?' => {
                text_at < text.len()
                    && text[text_at] != b'/'
                    && glob_matches_at(pattern, text, pattern_at + 1, text_at + 1, memo)
            }
            b'[' => class_matches(pattern, text, pattern_at, text_at, memo),
            byte => {
                text_at < text.len()
                    && text[text_at] == byte
                    && glob_matches_at(pattern, text, pattern_at + 1, text_at + 1, memo)
            }
        }
    };

    memo[pattern_at][text_at] = Some(result);
    result
}

fn globstar_slash_matches(
    pattern: &[u8],
    text: &[u8],
    pattern_at: usize,
    text_at: usize,
    memo: &mut [Vec<Option<bool>>],
) -> bool {
    if glob_matches_at(pattern, text, pattern_at + 3, text_at, memo) {
        return true;
    }

    for next in text_at..text.len() {
        if text[next] == b'/' && glob_matches_at(pattern, text, pattern_at + 3, next + 1, memo) {
            return true;
        }
    }

    false
}

fn globstar_matches(
    pattern: &[u8],
    text: &[u8],
    pattern_at: usize,
    text_at: usize,
    memo: &mut [Vec<Option<bool>>],
) -> bool {
    for next in text_at..=text.len() {
        if glob_matches_at(pattern, text, pattern_at + 2, next, memo) {
            return true;
        }
    }

    false
}

fn star_matches(
    pattern: &[u8],
    text: &[u8],
    pattern_at: usize,
    text_at: usize,
    memo: &mut [Vec<Option<bool>>],
) -> bool {
    let mut next = text_at;
    while next <= text.len() {
        if glob_matches_at(pattern, text, pattern_at + 1, next, memo) {
            return true;
        }
        if next == text.len() || text[next] == b'/' {
            break;
        }
        next += 1;
    }

    false
}

fn class_matches(
    pattern: &[u8],
    text: &[u8],
    pattern_at: usize,
    text_at: usize,
    memo: &mut [Vec<Option<bool>>],
) -> bool {
    let Some(class_end) = pattern[pattern_at + 1..]
        .iter()
        .position(|byte| *byte == b']')
        .map(|offset| pattern_at + 1 + offset)
    else {
        return text_at < text.len()
            && text[text_at] == b'['
            && glob_matches_at(pattern, text, pattern_at + 1, text_at + 1, memo);
    };

    text_at < text.len()
        && text[text_at] != b'/'
        && byte_in_class(text[text_at], &pattern[pattern_at + 1..class_end])
        && glob_matches_at(pattern, text, class_end + 1, text_at + 1, memo)
}

fn byte_in_class(byte: u8, class: &[u8]) -> bool {
    let mut at = 0;

    while at < class.len() {
        if at + 2 < class.len() && class[at + 1] == b'-' {
            if byte >= class[at] && byte <= class[at + 2] {
                return true;
            }
            at += 3;
        } else {
            if byte == class[at] {
                return true;
            }
            at += 1;
        }
    }

    false
}
