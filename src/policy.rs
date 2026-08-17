// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Policy lowering from JSON settings to platform access rules.
//!
//! Filesystem policy follows the Seatbelt-compatible shape. Writes start
//! denied; `allowWrite` grants roots and `denyWrite` subtracts from them. Reads
//! stay unrestricted unless `denyRead` is set; `allowRead` then adds paths back,
//! with the most specific rule winning where an allow and a deny overlap.
//! Hard links and renames that would give a `denyRead` inode a readable name
//! stay denied even when the destination is under `allowWrite`.
//!
//! Paths accept absolute names, names relative to the policy base, `~`, and the
//! macOS-style `*`, `**`, `?`, and character-class globs. Globs are expanded
//! while lowering the policy.

use crate::config::{AppContainerMode, SandboxFilesystem, SandboxNetwork, SandboxWindows};
use crate::error::{Error, PathIo};
use crate::paths::{PathCoverage, normalize_path, normalize_path_lexically, normalize_roots};
use anyhow::Result;
use rayon::prelude::*;
use serde::Serialize;
use std::env;
use std::fs;
use std::io;
#[cfg(target_os = "macos")]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
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
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) app_container_mode: AppContainerMode,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) allow_windows_loopback: bool,
}

// The write broker that consults these lives only in the Linux seccomp path.
#[cfg(target_os = "linux")]
impl AccessPolicy {
    /// Whether a write to `canonical` (with lexical form `lexical`, used for the
    /// symlink-ancestor deny-list) lands in the `denyWrite` deny-list. Glob
    /// patterns in `write_denied_patterns` are evaluated dynamically against the
    /// lexical path so files created after sandbox startup are also blocked.
    pub(crate) fn is_write_denied(&self, canonical: &Path, lexical: &Path) -> bool {
        canonical.is_under_any(&self.write_denied_roots)
            || lexical.is_under_any(&self.write_denied_links)
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
        } else if surface_allow_miss && !canonical.is_under_any(&self.write_roots) {
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
        if let UnixSocketAccess::AllowPaths(paths) = self.network_access.unix_socket_access() {
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

        let has_writable_symlink_ancestor = self
            .write_denied_links
            .iter()
            .any(|link| link.is_under_any(&self.write_roots));
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

        if network.allows_local_tcp_bind() {
            return Err(Error::PolicyTcpBindUnsupported);
        }

        if !network.unix_socket_access().is_denied() {
            return Err(Error::PolicyUnixSocketUnsupported);
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase", tag = "mode", content = "roots")]
pub(crate) enum ReadAccess {
    Unrestricted,
    AllowRoots(Vec<PathBuf>),
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase", tag = "mode")]
pub(crate) enum NetworkAccess {
    Unrestricted,
    Restricted {
        connect_tcp_ports: Vec<u16>,
        bind: TcpBindAccess,
        unix_socket_access: UnixSocketAccess,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum TcpBindAccess {
    Deny,
    Localhost,
}

impl NetworkAccess {
    pub(crate) fn is_unrestricted(&self) -> bool {
        matches!(self, Self::Unrestricted)
    }

    pub(crate) fn connect_tcp_ports(&self) -> &[u16] {
        match self {
            Self::Unrestricted => &[],
            Self::Restricted {
                connect_tcp_ports, ..
            } => connect_tcp_ports,
        }
    }

    pub(crate) fn unix_socket_access(&self) -> &UnixSocketAccess {
        match self {
            Self::Unrestricted => const { &UnixSocketAccess::Unrestricted },
            Self::Restricted {
                unix_socket_access, ..
            } => unix_socket_access,
        }
    }

    pub(crate) fn allows_local_tcp_bind(&self) -> bool {
        matches!(
            self,
            Self::Restricted {
                bind: TcpBindAccess::Localhost,
                ..
            }
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn restricts_bind_tcp(&self) -> bool {
        matches!(
            self,
            Self::Restricted {
                bind: TcpBindAccess::Deny,
                ..
            }
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn restricts_connect_tcp(&self) -> bool {
        matches!(self, Self::Restricted { .. })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn needs_bind_broker(&self) -> bool {
        match self {
            Self::Unrestricted => false,
            Self::Restricted {
                bind,
                unix_socket_access,
                ..
            } => matches!(bind, TcpBindAccess::Localhost) || unix_socket_access.needs_broker(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn needs_network_broker(&self) -> bool {
        match self {
            Self::Unrestricted => false,
            Self::Restricted {
                connect_tcp_ports,
                bind,
                unix_socket_access,
            } => {
                matches!(bind, TcpBindAccess::Localhost)
                    || !connect_tcp_ports.is_empty()
                    || unix_socket_access.needs_broker()
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase", tag = "mode", content = "paths")]
pub(crate) enum UnixSocketAccess {
    Unrestricted,
    AllowPaths(Vec<PathBuf>),
    Denied,
}

impl UnixSocketAccess {
    #[cfg(target_os = "linux")]
    pub(crate) fn needs_broker(&self) -> bool {
        !matches!(self, Self::Unrestricted)
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn is_denied(&self) -> bool {
        matches!(self, Self::Denied)
    }
}

pub(crate) fn resolve_policy(
    filesystem: &SandboxFilesystem,
    network: &SandboxNetwork,
    windows: &SandboxWindows,
    policy_base: &Path,
) -> Result<AccessPolicy> {
    let home_dir = dirs::home_dir();
    let home = home_dir.as_deref();
    let policy_base = if policy_base.is_absolute() {
        policy_base.to_path_buf()
    } else {
        env::current_dir()?.join(policy_base)
    };
    let policy_base = normalize_path_lexically(&policy_base);

    let write_allow = resolve_paths(&filesystem.allow_write, &policy_base, home)?;
    // Missing Windows allow roots cannot receive ACL entries. Dropping them is
    // fail-closed because sandbox SIDs receive no access to those paths.
    #[cfg(target_os = "windows")]
    let write_allow = write_allow
        .into_iter()
        .filter(|path| path.try_exists().unwrap_or(false))
        .collect::<Vec<_>>();
    let (write_deny, write_denied_patterns) =
        resolve_deny_paths(&filesystem.deny_write, &policy_base, home)?;
    let write_denied_links = collect_symlink_ancestors(&filesystem.deny_write, &policy_base, home)?;

    let read_allow = resolve_paths(&filesystem.allow_read, &policy_base, home)?;
    #[cfg(target_os = "windows")]
    let read_allow = read_allow
        .into_iter()
        .filter(|path| path.try_exists().unwrap_or(false))
        .collect::<Vec<_>>();

    let read_deny = resolve_paths(&filesystem.deny_read, &policy_base, home)?;
    let mut read_denied_roots = effective_denied_roots(&read_deny, &read_allow);
    // Windows cannot attach deny entries to missing paths.
    #[cfg(target_os = "windows")]
    read_denied_roots.retain(|path| path.try_exists().unwrap_or(true));

    #[cfg(target_os = "windows")]
    let (write_allow, write_deny) =
        lower_windows_write_access(&write_allow, write_deny, &read_deny)?;

    let (read_access, read_symlinks) =
        lower_read_access(&read_allow, &read_deny, &mut read_denied_roots)?;
    let policy = AccessPolicy {
        write_roots: write_allow,
        write_denied_roots: write_deny,
        write_denied_patterns,
        write_denied_links,
        read_access,
        read_denied_roots,
        read_symlinks,
        network_access: lower_network_policy(network, &policy_base, home)?,
        app_container_mode: windows.app_container_mode,
        allow_windows_loopback: windows.allow_loopback,
    };
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    policy.validate()?;
    Ok(policy)
}

#[cfg(target_os = "windows")]
fn lower_windows_write_access(
    write_allow: &[PathBuf],
    write_deny: Vec<PathBuf>,
    read_deny: &[PathBuf],
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    // Windows ACLs cannot attach deny entries to paths that do not exist. Glob
    // denials have the same snapshot limitation on both Windows backends.
    let write_deny: Vec<PathBuf> = write_deny
        .into_iter()
        .filter(|path| path.try_exists().unwrap_or(true))
        .collect();

    // Carve nested denials out of inheriting write grants. Omit write roots
    // fully covered by denyWrite.
    let mut carve_denials = write_deny.clone();
    for deny in read_deny {
        if !carve_denials.iter().any(|existing| existing == deny) {
            carve_denials.push(deny.clone());
        }
    }
    normalize_roots(&mut carve_denials);

    let mut carved_writes = Vec::new();
    for allow in write_allow {
        let needs_carve = carve_denials
            .iter()
            .any(|deny| deny.is_strictly_under(allow));
        if needs_carve {
            let scan = scan_allowed_root(allow, &carve_denials, true, 0)?;
            carved_writes.extend(scan.roots);
        } else if allow.is_under_any(&write_deny) {
            // Fully covered by a write deny — omit.
        } else {
            carved_writes.push(allow.clone());
        }
    }
    normalize_roots(&mut carved_writes);

    // Independent denyWrite roots stay as DENY ACEs for defense in depth.
    let write_deny = write_deny
        .into_iter()
        .filter(|deny| {
            !carved_writes
                .iter()
                .any(|allow| deny.is_strictly_under(allow))
        })
        .collect();
    Ok((carved_writes, write_deny))
}

fn lower_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    read_denied_roots: &mut Vec<PathBuf>,
) -> Result<(ReadAccess, Vec<PathBuf>)> {
    let fs_root = normalize_path(Path::new("/"));
    // Reject a full-volume Windows grant because propagating it over `C:\`
    // can hang while walking the volume.
    #[cfg(target_os = "windows")]
    if read_allow.contains(&fs_root) {
        return Err(Error::PolicyUnrestrictedRead.into());
    }

    if read_deny.is_empty() {
        Ok((ReadAccess::Unrestricted, Vec::new()))
    } else if read_allow.contains(&fs_root)
        && !read_deny
            .iter()
            .any(|deny| read_allow.iter().any(|allow| allow.is_strictly_under(deny)))
    {
        // Layer surviving denyRead roots over a full-tree allowRead grant.
        // Windows rejects the full-volume grant above.
        Ok((ReadAccess::AllowRoots(vec![fs_root]), Vec::new()))
    } else {
        lower_restricted_read_access(read_allow, read_deny, read_denied_roots)
    }
}

#[cfg(target_os = "windows")]
fn lower_restricted_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    read_denied_roots: &mut Vec<PathBuf>,
) -> Result<(ReadAccess, Vec<PathBuf>)> {
    // Grant explicit roots and carve nested denials out of inheriting ALLOW
    // entries.
    let mut denied = read_deny.to_vec();
    normalize_roots(&mut denied);
    let mut roots = Vec::new();
    let mut symlinks = Vec::new();
    for allow in read_allow {
        let needs_carve = denied.iter().any(|deny| deny.is_strictly_under(allow));
        if needs_carve {
            let scan = scan_allowed_root(allow, &denied, true, 0)?;
            roots.extend(scan.roots);
            symlinks.extend(scan.symlinks);
        } else {
            roots.push(allow.clone());
        }
    }
    normalize_roots(&mut roots);
    normalize_roots(&mut symlinks);
    read_denied_roots.clear();
    Ok((ReadAccess::AllowRoots(roots), symlinks))
}

#[cfg(not(target_os = "windows"))]
fn lower_restricted_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    _read_denied_roots: &mut Vec<PathBuf>,
) -> Result<(ReadAccess, Vec<PathBuf>)> {
    let mut allowed = vec![PathBuf::from("/")];
    normalize_roots(&mut allowed);
    let mut denied = read_deny.to_vec();
    normalize_roots(&mut denied);
    let scanned = allowed
        .par_iter()
        .map(|root| scan_allowed_root(root, &denied, true, 0))
        .collect::<Result<Vec<RootScan>>>()?;
    let mut roots = Vec::new();
    let mut symlinks = Vec::new();
    for scan in scanned {
        roots.extend(scan.roots);
        symlinks.extend(scan.symlinks);
    }
    normalize_roots(&mut roots);
    normalize_roots(&mut symlinks);

    // The seccomp broker enforces nested denials under explicit allow roots.
    for allow in read_allow {
        if allow.as_path() != Path::new("/") {
            roots.push(allow.clone());
        }
    }
    normalize_roots(&mut roots);
    Ok((ReadAccess::AllowRoots(roots), symlinks))
}

fn lower_network_policy(
    network: &SandboxNetwork,
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<NetworkAccess> {
    if network.allow_network {
        return Ok(NetworkAccess::Unrestricted);
    }

    let mut connect_tcp_ports = Vec::new();
    push_proxy_port(&mut connect_tcp_ports, network.http_proxy_port)?;
    push_proxy_port(&mut connect_tcp_ports, network.socks_proxy_port)?;
    connect_tcp_ports.sort_unstable();
    connect_tcp_ports.dedup();

    let unix_socket_paths = resolve_paths(&network.allow_unix_sockets, policy_base, home)?;
    let unix_socket_access = if network.allow_all_unix_sockets {
        UnixSocketAccess::Unrestricted
    } else if unix_socket_paths.is_empty() {
        UnixSocketAccess::Denied
    } else {
        UnixSocketAccess::AllowPaths(unix_socket_paths)
    };

    let bind = if network.allow_local_binding {
        TcpBindAccess::Localhost
    } else {
        TcpBindAccess::Deny
    };
    Ok(NetworkAccess::Restricted {
        connect_tcp_ports,
        bind,
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

        if current.is_under_any(denied) {
            continue;
        }

        let has_denied_descendant = denied
            .iter()
            .any(|denied_root| denied_root.is_strictly_under(&current));

        // A transient EIO (e.g. an autofs automount such as macOS `/home`) is
        // treated as an opaque boundary alongside a missing or denied path: keep
        // the path and stop descending rather than abort. A path landstrip cannot
        // stat is also unreadable to the sandboxed child.
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.is_opaque() => {
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
                    || error.is_transport_failed() =>
            {
                results.push(current);
                continue;
            }
            Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.is_transport_failed() => {
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
        .filter(|deny| !read_allow.iter().any(|allow| allow.is_under(deny)))
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
    let mut memo = vec![None; (pattern_len + 1) * (path_len + 1)];
    glob_matches_at(pattern_bytes, path_bytes.as_bytes(), 0, 0, &mut memo)
}

pub(crate) fn expand_glob_path(pattern: &Path) -> Result<Vec<PathBuf>> {
    let pattern = pattern.to_string_lossy();
    let base = glob_base(&pattern);
    let mut matches = Vec::new();

    match fs::symlink_metadata(&base) {
        Ok(_) => collect_glob_matches(&base, &pattern, &mut matches, 0)?,
        Err(error) if error.is_opaque() => {}
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
    let mut memo = vec![None; (pattern_bytes.len() + 1) * (candidate_bytes.len() + 1)];

    if glob_matches_at(pattern_bytes, candidate_bytes, 0, 0, &mut memo) {
        matches.push(candidate.clone());
    }

    // A directory the broker cannot stat or read contributes no further glob
    // matches. Skip it rather than aborting the whole policy: an unreadable
    // directory is also unreadable to the sandboxed child, and the seccomp
    // broker still enforces denied paths regardless of glob expansion.
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.is_opaque() => {
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
            if error.kind() == io::ErrorKind::PermissionDenied || error.is_transport_failed() =>
        {
            return Ok(());
        }
        Err(source) => return Err(Error::PolicyIoFailed { source }.into()),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.is_transport_failed() => {
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
    memo: &mut [Option<bool>],
) -> bool {
    let memo_at = pattern_at * (text.len() + 1) + text_at;
    if let Some(result) = memo[memo_at] {
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

    memo[memo_at] = Some(result);
    result
}

fn globstar_slash_matches(
    pattern: &[u8],
    text: &[u8],
    pattern_at: usize,
    text_at: usize,
    memo: &mut [Option<bool>],
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
    memo: &mut [Option<bool>],
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
    memo: &mut [Option<bool>],
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
    memo: &mut [Option<bool>],
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
