// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Policy lowering from JSON settings to platform access rules.
//!
//! Filesystem policy follows the Seatbelt-compatible shape. Writes start
//! denied; `allowWrite` grants roots and `denyWrite` subtracts from them. Reads
//! stay unrestricted unless `denyRead` is set; `allowRead` then adds paths back.
//!
//! Paths accept absolute names, names relative to the policy base, `~`, and the
//! macOS-style `*`, `**`, `?`, and character-class globs. Globs are expanded
//! while lowering the policy.

use crate::config::{SandboxFilesystem, SandboxNetwork};
use crate::error::{Error, PolicyPort, PolicyType, Result};
use crate::paths::{normalize_path, normalize_path_lexically, normalize_roots};
use crate::traversal::subtract_denied_roots;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct AccessPolicy {
    pub(crate) write_roots: Vec<PathBuf>,
    pub(crate) read_access: ReadAccess,
    pub(crate) network_access: NetworkAccess,
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
        env::current_dir()?.join(policy_base)
    };
    let policy_base = normalize_path_lexically(&policy_base);

    let write_allow = resolve_paths(&filesystem.allow_write, &policy_base, home)?;
    let write_deny = resolve_paths(&filesystem.deny_write, &policy_base, home)?;
    let write_roots = subtract_denied_roots(write_allow, &write_deny)?;

    let read_allow = resolve_paths(&filesystem.allow_read, &policy_base, home)?;
    let read_deny = resolve_paths(&filesystem.deny_read, &policy_base, home)?;
    let read_access = if read_deny.is_empty() {
        ReadAccess::Unrestricted
    } else {
        let mut read_roots = subtract_denied_roots(vec![PathBuf::from("/")], &read_deny)?;
        read_roots.extend(read_allow);
        normalize_roots(&mut read_roots);
        ReadAccess::AllowRoots(read_roots)
    };

    Ok(AccessPolicy {
        write_roots,
        read_access,
        network_access: lower_network_policy(network, &policy_base, home)?,
    })
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
    push_proxy_port(
        &mut connect_tcp_ports,
        network.http_proxy_port,
        PolicyPort::HttpProxyPolicy,
    )?;
    push_proxy_port(
        &mut connect_tcp_ports,
        network.socks_proxy_port,
        PolicyPort::SocksProxyPolicy,
    )?;
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

fn push_proxy_port(ports: &mut Vec<u16>, port: Option<u16>, port_name: PolicyPort) -> Result<()> {
    let Some(port) = port else {
        return Ok(());
    };

    if port == 0 {
        return Err(Error::policy(
            PolicyType::Network,
            format!("{port_name} port out of range"),
        ));
    }

    ports.push(port);
    Ok(())
}

fn resolve_paths(
    paths: &[String],
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut resolved = Vec::with_capacity(paths.len());

    for path in paths {
        let path = resolve_sandbox_path(path, policy_base, home)?;
        if path
            .to_string_lossy()
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']'))
        {
            resolved.extend(expand_glob_path(&path)?);
        } else {
            resolved.push(normalize_path(&path));
        }
    }

    normalize_roots(&mut resolved);

    Ok(resolved)
}
fn resolve_sandbox_path(path: &str, base: &Path, home: Option<&Path>) -> Result<PathBuf> {
    if path.is_empty() {
        return Err(Error::policy(PolicyType::Filesystem, "path empty"));
    }

    let raw = Path::new(path);
    let resolved = if raw.has_root() {
        raw.to_path_buf()
    } else if path == "~" {
        home.map(Path::to_path_buf)
            .ok_or_else(|| Error::policy(PolicyType::Filesystem, "home unavailable"))?
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.map(|home| home.join(rest))
            .ok_or_else(|| Error::policy(PolicyType::Filesystem, "home unavailable"))?
    } else {
        base.join(raw)
    };

    Ok(normalize_path_lexically(&resolved))
}

fn expand_glob_path(pattern: &Path) -> Result<Vec<PathBuf>> {
    let pattern = pattern.to_string_lossy();
    let base = glob_base(&pattern);
    let mut matches = Vec::new();

    match fs::symlink_metadata(&base) {
        Ok(_) => collect_glob_matches(&base, &pattern, &mut matches)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(source.into()),
    }

    Ok(matches)
}

fn glob_base(pattern: &str) -> PathBuf {
    let Some(glob_at) = pattern
        .bytes()
        .position(|byte| matches!(byte, b'*' | b'?' | b'[' | b']'))
    else {
        return PathBuf::from(pattern);
    };
    let prefix = &pattern[..glob_at];
    let base = if prefix.ends_with('/') {
        prefix.trim_end_matches('/')
    } else {
        Path::new(prefix)
            .parent()
            .and_then(Path::to_str)
            .unwrap_or("/")
    };

    if base.is_empty() {
        PathBuf::from("/")
    } else {
        PathBuf::from(base)
    }
}

fn collect_glob_matches(path: &Path, pattern: &str, matches: &mut Vec<PathBuf>) -> Result<()> {
    let candidate = normalize_path_lexically(path);
    let candidate_text = candidate.to_string_lossy();
    let pattern_bytes = pattern.as_bytes();
    let candidate_bytes = candidate_text.as_bytes();
    let mut memo = vec![vec![None; candidate_bytes.len() + 1]; pattern_bytes.len() + 1];

    if glob_matches_at(pattern_bytes, candidate_bytes, 0, 0, &mut memo) {
        matches.push(candidate.clone());
    }

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        collect_glob_matches(&entry?.path(), pattern, matches)?;
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
