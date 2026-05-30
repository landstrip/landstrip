// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::config::{SandboxFilesystem, SandboxNetwork};
use crate::error::{Error, Result};
use crate::paths::{normalize_path, normalize_roots};
use crate::traversal::subtract_denied_roots;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AccessPolicy {
    pub(crate) write_roots: Vec<PathBuf>,
    pub(crate) read_access: ReadAccess,
    pub(crate) network_access: NetworkAccess,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadAccess {
    Unrestricted,
    AllowRoots(Vec<PathBuf>),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct NetworkAccess {
    pub(crate) restrict_connect_tcp: bool,
    pub(crate) connect_tcp_ports: Vec<u16>,
    pub(crate) restrict_bind_tcp: bool,
}

pub(crate) fn lower_sandbox_policy(
    filesystem: &SandboxFilesystem,
    network: Option<&SandboxNetwork>,
    policy_base: &Path,
) -> Result<AccessPolicy> {
    let home_dir = dirs::home_dir();
    let home = home_dir.as_deref();
    let policy_base = absolute_policy_base(policy_base)?;

    let write_allow = resolve_write_roots(filesystem, &policy_base, home)?;
    let write_deny = resolve_paths(&filesystem.deny_write, &policy_base, home)?;
    let write_roots = subtract_denied_roots(write_allow, &write_deny)
        .map_err(|source| Error::with_source("policy: write traversal", source))?;

    let read_allow = resolve_paths(&filesystem.allow_read, &policy_base, home)?;
    let read_deny = resolve_paths(&filesystem.deny_read, &policy_base, home)?;
    let read_access = if read_deny.is_empty() {
        ReadAccess::Unrestricted
    } else {
        let mut read_roots = subtract_denied_roots(vec![PathBuf::from("/")], &read_deny)
            .map_err(|source| Error::with_source("policy: read traversal", source))?;
        read_roots.extend(read_allow);
        normalize_roots(&mut read_roots);
        ReadAccess::AllowRoots(read_roots)
    };

    Ok(AccessPolicy {
        write_roots,
        read_access,
        network_access: lower_network_policy(network)?,
    })
}

fn lower_network_policy(source: Option<&SandboxNetwork>) -> Result<NetworkAccess> {
    let Some(source) = source else {
        return Ok(NetworkAccess::default());
    };

    let mut connect_tcp_ports = Vec::new();
    push_proxy_port(
        &mut connect_tcp_ports,
        source.http_proxy_port,
        "httpProxyPort",
    )?;
    push_proxy_port(
        &mut connect_tcp_ports,
        source.socks_proxy_port,
        "socksProxyPort",
    )?;
    connect_tcp_ports.sort_unstable();
    connect_tcp_ports.dedup();

    if (!source.allowed_domains.is_empty() || !source.denied_domains.is_empty())
        && connect_tcp_ports.is_empty()
    {
        return Err(Error::message(
            "policy: network domains require httpProxyPort or socksProxyPort",
        ));
    }

    if !source.allowed_domains.is_empty() || !source.denied_domains.is_empty() {
        log::warn!("network domain filtering is delegated to the configured proxy port");
    }

    Ok(NetworkAccess {
        restrict_connect_tcp: true,
        connect_tcp_ports,
        restrict_bind_tcp: !source.allow_local_binding,
    })
}

fn push_proxy_port(ports: &mut Vec<u16>, port: Option<u16>, label: &str) -> Result<()> {
    let Some(port) = port else {
        return Ok(());
    };

    if port == 0 {
        return Err(Error::message(format!(
            "policy: network {label} must be in range 1..=65535"
        )));
    }

    ports.push(port);
    Ok(())
}

fn resolve_write_roots(
    source: &SandboxFilesystem,
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut roots = vec![policy_base.to_path_buf()];

    for path in &source.allow_write {
        roots.push(resolve_sandbox_path(path, policy_base, home)?);
    }

    normalize_roots(&mut roots);

    Ok(roots)
}

fn resolve_paths(
    paths: &[String],
    policy_base: &Path,
    home: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut resolved = Vec::with_capacity(paths.len());

    for path in paths {
        resolved.push(resolve_sandbox_path(path, policy_base, home)?);
    }

    normalize_roots(&mut resolved);

    Ok(resolved)
}

fn absolute_policy_base(policy_base: &Path) -> Result<PathBuf> {
    let policy_base = if policy_base.is_absolute() {
        policy_base.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|source| Error::with_source("current directory", source))?
            .join(policy_base)
    };

    Ok(normalize_path(&policy_base))
}

fn resolve_sandbox_path(path: &str, base: &Path, home: Option<&Path>) -> Result<PathBuf> {
    if path.is_empty() {
        return Err(Error::message("empty sandbox path"));
    }

    let raw = Path::new(path);
    let resolved = if raw.is_absolute() {
        raw.to_path_buf()
    } else if path == "~" {
        home.map(Path::to_path_buf)
            .ok_or_else(|| Error::message("~: home directory unavailable"))?
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.map(|home| home.join(rest))
            .ok_or_else(|| Error::message("~/: home directory unavailable"))?
    } else if path.starts_with('~') {
        return Err(Error::message("unsupported ~user path"));
    } else {
        base.join(raw)
    };

    Ok(normalize_path(&resolved))
}
