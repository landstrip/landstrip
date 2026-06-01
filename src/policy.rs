// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::config::{SandboxFilesystem, SandboxNetwork};
use crate::error::{Error, Result};
use crate::paths::{normalize_path, normalize_roots};
use crate::traversal::subtract_denied_roots;
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Host;

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

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NetworkAccess {
    pub(crate) restrict_connect_tcp: bool,
    pub(crate) connect_tcp_ports: Vec<u16>,
    pub(crate) restrict_bind_tcp: bool,
    pub(crate) local_tcp_bind: bool,
    pub(crate) unix_socket_access: UnixSocketAccess,
    pub(crate) domain_policy: DomainPolicy,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UnixSocketAccess {
    Unrestricted,
    AllowPaths(Vec<PathBuf>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DomainPolicy {
    allowed: Vec<DomainPattern>,
    denied: Vec<DomainPattern>,
}

pub(crate) fn lower_sandbox_policy(
    filesystem: &SandboxFilesystem,
    network: &SandboxNetwork,
    policy_base: &Path,
) -> Result<AccessPolicy> {
    let home_dir = dirs::home_dir();
    let home = home_dir.as_deref();
    let policy_base = absolute_policy_base(policy_base)?;

    let write_allow = resolve_paths(&filesystem.allow_write, &policy_base, home)?;
    let write_deny = resolve_paths(&filesystem.deny_write, &policy_base, home)?;
    let write_roots = subtract_denied_roots(write_allow, &write_deny)
        .map_err(|source| Error::with_source("policy: fs write", source))?;

    let read_allow = resolve_paths(&filesystem.allow_read, &policy_base, home)?;
    let read_deny = resolve_paths(&filesystem.deny_read, &policy_base, home)?;
    let read_access = if read_deny.is_empty() {
        ReadAccess::Unrestricted
    } else {
        let mut read_roots = subtract_denied_roots(vec![PathBuf::from("/")], &read_deny)
            .map_err(|source| Error::with_source("policy: fs read", source))?;
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
    let mut connect_tcp_ports = Vec::new();
    push_proxy_port(
        &mut connect_tcp_ports,
        network.http_proxy_port,
        "httpProxyPort",
    )?;
    push_proxy_port(
        &mut connect_tcp_ports,
        network.socks_proxy_port,
        "socksProxyPort",
    )?;
    connect_tcp_ports.sort_unstable();
    connect_tcp_ports.dedup();

    let domain_policy = DomainPolicy::try_from(network)?;
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
        domain_policy,
    })
}

impl TryFrom<&SandboxNetwork> for DomainPolicy {
    type Error = Error;

    fn try_from(network: &SandboxNetwork) -> Result<Self> {
        Ok(Self {
            allowed: parse_domains("allowedDomains", &network.allowed_domains)?,
            denied: parse_domains("deniedDomains", &network.denied_domains)?,
        })
    }
}

impl DomainPolicy {
    #[must_use]
    pub(crate) fn allows_host(&self, host: &str) -> bool {
        let Ok(host) = host.parse::<DomainName>() else {
            return false;
        };

        if self.denied.iter().any(|pattern| pattern.matches(&host)) {
            return false;
        }

        self.allowed.iter().any(|pattern| pattern.matches(&host))
    }
}

fn parse_domains(label: &str, values: &[String]) -> Result<Vec<DomainPattern>> {
    let mut patterns = Vec::with_capacity(values.len());

    for value in values {
        let pattern = value
            .parse::<DomainPattern>()
            .map_err(|source| Error::message(format!("policy: net {label} {source}: {value}")))?;
        if !patterns.contains(&pattern) {
            patterns.push(pattern);
        }
    }

    Ok(patterns)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DomainPattern {
    Exact(DomainName),
    Wildcard(DomainName),
}

impl FromStr for DomainPattern {
    type Err = DomainParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(DomainParseError::Empty);
        }

        if let Some(domain) = value.strip_prefix("*.") {
            return domain.parse().map(Self::Wildcard);
        }

        if value.contains('*') {
            return Err(DomainParseError::InvalidWildcard);
        }

        value.parse().map(Self::Exact)
    }
}

impl DomainPattern {
    fn matches(&self, host: &DomainName) -> bool {
        let host = host.as_ref();
        match self {
            Self::Exact(domain) => host == domain.as_ref(),
            Self::Wildcard(domain) => host
                .strip_suffix(domain.as_ref())
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DomainName(String);

impl AsRef<str> for DomainName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for DomainName {
    type Err = DomainParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let value = value.trim().trim_end_matches('.');
        if value.is_empty() {
            return Err(DomainParseError::Empty);
        }

        match Host::parse(value).map_err(|_| DomainParseError::InvalidHost)? {
            Host::Domain(domain) => Ok(Self(domain.to_ascii_lowercase())),
            Host::Ipv4(_) | Host::Ipv6(_) => Err(DomainParseError::IpLiteral),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DomainParseError {
    Empty,
    InvalidHost,
    InvalidWildcard,
    IpLiteral,
}

impl fmt::Display for DomainParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "domain empty",
            Self::InvalidHost => "domain invalid",
            Self::InvalidWildcard => "wildcard must use *.domain",
            Self::IpLiteral => "domain must not be an IP literal",
        })
    }
}

fn push_proxy_port(ports: &mut Vec<u16>, port: Option<u16>, label: &str) -> Result<()> {
    let Some(port) = port else {
        return Ok(());
    };

    if port == 0 {
        return Err(Error::message(format!(
            "policy: net {label} range 1..=65535"
        )));
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
            .map_err(|source| Error::with_source("policy: cwd", source))?
            .join(policy_base)
    };

    Ok(normalize_path(&policy_base))
}

fn resolve_sandbox_path(path: &str, base: &Path, home: Option<&Path>) -> Result<PathBuf> {
    if path.is_empty() {
        return Err(Error::message("policy: path empty"));
    }

    let raw = Path::new(path);
    let resolved = if raw.is_absolute() {
        raw.to_path_buf()
    } else if path == "~" {
        home.map(Path::to_path_buf)
            .ok_or_else(|| Error::message("policy: home unavailable"))?
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.map(|home| home.join(rest))
            .ok_or_else(|| Error::message("policy: home unavailable"))?
    } else if path.starts_with('~') {
        return Err(Error::message("policy: path ~user unsupported"));
    } else {
        base.join(raw)
    };

    Ok(normalize_path(&resolved))
}
