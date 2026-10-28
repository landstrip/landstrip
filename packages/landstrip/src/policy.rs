// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Policy lowering from JSON settings to platform access rules.
//!
//! Filesystem policy follows the Seatbelt-compatible shape. Writes start
//! denied; `allowWrite` grants roots and `denyWrite` subtracts from them. Reads
//! stay unrestricted unless `denyRead` or `denyReadAlways` is set. `allowRead`
//! adds paths back from ordinary denials, with the most specific rule winning;
//! `denyReadAlways` roots and descendants cannot be restored by any allow.
//! Hard links and renames that would give a `denyRead` inode a readable name
//! stay denied even when the destination is under `allowWrite`.
//!
//! Paths accept absolute names, names relative to the policy base, `~`, and the
//! macOS-style `*`, `**`, `?`, and character-class globs. Globs are expanded
//! while lowering the policy. Relative write-deny entries additionally anchor
//! at every write root that is a directory, so the deny list follows the
//! granted write scopes.

use crate::config::{AppContainerMode, PathSelector, SandboxDarwin, SandboxNetwork, Settings};
use crate::error::{Error, PathIo};
use crate::paths::{GlobPattern, NormalizeRoots, PathExt};
use anyhow::Result;
#[cfg(target_os = "linux")]
use nix::sys::stat::fstat;
use serde::Serialize;
use std::env;
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::fs;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::FileTypeExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessPolicy {
    pub(crate) write_roots: Vec<PathBuf>,
    pub(crate) write_denied_roots: Vec<PathBuf>,
    pub(crate) write_denied_always_roots: Box<[PathBuf]>,
    pub(crate) write_denied_always_patterns: Box<[String]>,
    pub(crate) write_denied_patterns: Vec<String>,
    pub(crate) write_denied_links: DeniedLinks,
    pub(crate) read_access: ReadAccess,
    pub(crate) read_denied_roots: Vec<PathBuf>,
    pub(crate) read_denied_patterns: Vec<String>,
    pub(crate) read_carveouts: Vec<PathBuf>,
    pub(crate) read_denied_always_roots: Box<[PathBuf]>,
    pub(crate) read_denied_always_patterns: Box<[String]>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) read_symlinks: Vec<PathBuf>,
    pub(crate) network_access: NetworkAccess,
    #[cfg(target_os = "linux")]
    pub(crate) supervisor_sockets: SupervisorSocketSet,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) macos: SandboxDarwin,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) app_container_mode: AppContainerMode,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) allow_windows_loopback: bool,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) allow_windows_additive_grants: bool,
}

/// How strongly a denied link is protected: `always` links cannot be removed
/// even by broker approval.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DenialTier {
    Queryable,
    Always,
}

/// A symlink leading into a denied write subtree. Its own path is protected
/// from unlink and rename, otherwise the subtree could be re-pointed after the
/// sandbox started.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeniedLink {
    pub(crate) path: PathBuf,
    pub(crate) tier: DenialTier,
}

impl DeniedLink {
    fn new(path: PathBuf, tier: DenialTier) -> Self {
        Self { path, tier }
    }
}

/// Every protected link, sorted by path and collapsed to the strongest tier.
/// The ordering is an invariant of the type, so membership is a binary search.
#[derive(Debug, Default, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub(crate) struct DeniedLinks(Vec<DeniedLink>);

impl DeniedLinks {
    fn new(mut links: Vec<DeniedLink>) -> Self {
        links.sort_by(|left, right| {
            let strength = |link: &DeniedLink| u8::from(link.tier == DenialTier::Always);
            left.path
                .cmp(&right.path)
                .then_with(|| strength(right).cmp(&strength(left)))
        });
        links.dedup_by(|left, right| left.path == right.path);
        Self(links)
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &DeniedLink> {
        self.0.iter()
    }

    #[cfg(target_os = "linux")]
    fn find(&self, path: &Path) -> Option<&DeniedLink> {
        self.0
            .binary_search_by(|link| link.path.as_path().cmp(path))
            .ok()
            .map(|index| &self.0[index])
    }

    #[cfg(target_os = "linux")]
    fn contains(&self, path: &Path) -> bool {
        self.find(path).is_some()
    }

    #[cfg(target_os = "linux")]
    fn contains_always(&self, path: &Path) -> bool {
        self.find(path)
            .is_some_and(|link| link.tier == DenialTier::Always)
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DenialReason {
    DenyMatch,
    AllowMiss,
}

// The write broker that consults these lives only in the Linux seccomp path.
#[cfg(target_os = "linux")]
impl AccessPolicy {
    /// Whether a write to `canonical` lands in the `denyWrite` deny-list. Glob
    /// patterns in `write_denied_patterns` are evaluated dynamically so files
    /// created after sandbox startup are also blocked.
    pub(crate) fn is_write_denied(&self, canonical: &Path) -> bool {
        matches_denied(
            &self.write_denied_roots,
            &self.write_denied_patterns,
            canonical,
        )
    }

    /// A denied subtree is only as strong as the symlinks leading into it:
    /// unlinking or renaming a link would re-point the denied path.
    pub(crate) fn is_denied_link(&self, path: &Path) -> bool {
        self.write_denied_links.contains(path)
    }

    pub(crate) fn is_denied_link_always(&self, path: &Path) -> bool {
        self.write_denied_links.contains_always(path)
    }

    pub(crate) fn is_write_denied_always(&self, canonical: &Path, lexical: &Path) -> bool {
        matches_denied(
            &self.write_denied_always_roots,
            &self.write_denied_always_patterns,
            canonical,
        ) || matches_denied(
            &self.write_denied_always_roots,
            &self.write_denied_always_patterns,
            lexical,
        )
    }

    pub(crate) fn is_read_denied(&self, path: &Path) -> bool {
        path.is_under_any(&self.read_denied_roots)
            || self.is_read_denied_always(path)
            || self.read_denied_patterns.iter().any(|pattern| {
                let glob = GlobPattern::new(pattern);
                glob.matches_tree(path)
                    && !self
                        .read_carveouts
                        .iter()
                        .any(|carveout| path.is_under(carveout) && glob.matches_tree(carveout))
            })
    }

    pub(crate) fn is_read_denied_always(&self, path: &Path) -> bool {
        matches_denied(
            &self.read_denied_always_roots,
            &self.read_denied_always_patterns,
            path,
        )
    }

    pub(crate) fn has_read_denied_under(&self, dir: &Path) -> bool {
        has_denied_under(&self.read_denied_roots, &self.read_denied_patterns, dir)
    }

    pub(crate) fn has_write_denied_under(&self, dir: &Path) -> bool {
        has_denied_under(&self.write_denied_roots, &self.write_denied_patterns, dir)
    }

    pub(crate) fn has_read_denied_always_under(&self, dir: &Path) -> bool {
        has_denied_under(
            &self.read_denied_always_roots,
            &self.read_denied_always_patterns,
            dir,
        )
    }

    pub(crate) fn has_write_denied_always_under(&self, dir: &Path) -> bool {
        has_denied_under(
            &self.write_denied_always_roots,
            &self.write_denied_always_patterns,
            dir,
        )
    }

    /// Why a write to `canonical` is mediated, or `None` when the policy permits
    /// it. `allow_miss` (outside every `allowWrite` root) is reported only when
    /// `surface_allow_miss` is set: content syscalls leave it to Landlock unless
    /// a query can resolve it, but metadata syscalls Landlock does not cover must
    /// always surface it so the broker can gate them.
    pub(crate) fn write_reason(
        &self,
        canonical: &Path,
        surface_allow_miss: bool,
    ) -> Option<DenialReason> {
        if self.is_write_denied(canonical) {
            Some(DenialReason::DenyMatch)
        } else if surface_allow_miss && !canonical.is_under_any(&self.write_roots) {
            Some(DenialReason::AllowMiss)
        } else {
            None
        }
    }

    pub(crate) fn read_reason(&self, path: &Path) -> Option<DenialReason> {
        match &self.read_access {
            ReadAccess::Unrestricted => None,
            ReadAccess::AllowRoots(roots) => {
                if self.is_read_denied(path) {
                    Some(DenialReason::DenyMatch)
                } else if path.is_under_any(roots) {
                    None
                } else {
                    Some(DenialReason::AllowMiss)
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl AccessPolicy {
    /// Reject policies macOS Seatbelt cannot enforce: an existing non-socket
    /// `allowUnixSockets` path.
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
        if !network.unix_socket_access().is_denied() {
            return Err(Error::PolicyUnixSocketUnsupported);
        }

        if network.is_unrestricted() {
            return Ok(());
        }

        if network.allows_local_binding() {
            return Err(Error::PolicyLocalBindingUnsupported);
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
    Unrestricted {
        unix_socket_access: UnixSocketAccess,
    },
    Restricted {
        connect_tcp_ports: Vec<u16>,
        bind: IpBindAccess,
        unix_socket_access: UnixSocketAccess,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum IpBindAccess {
    Deny,
    Localhost,
}

impl NetworkAccess {
    pub(crate) fn is_unrestricted(&self) -> bool {
        matches!(self, Self::Unrestricted { .. })
    }

    pub(crate) fn connect_tcp_ports(&self) -> &[u16] {
        match self {
            Self::Unrestricted { .. } => &[],
            Self::Restricted {
                connect_tcp_ports, ..
            } => connect_tcp_ports,
        }
    }

    pub(crate) fn unix_socket_access(&self) -> &UnixSocketAccess {
        match self {
            Self::Unrestricted { unix_socket_access }
            | Self::Restricted {
                unix_socket_access, ..
            } => unix_socket_access,
        }
    }

    pub(crate) fn allows_local_binding(&self) -> bool {
        matches!(
            self,
            Self::Restricted {
                bind: IpBindAccess::Localhost,
                ..
            }
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn restricts_bind_ip(&self) -> bool {
        matches!(
            self,
            Self::Restricted {
                bind: IpBindAccess::Deny,
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
            Self::Unrestricted { unix_socket_access } => unix_socket_access.needs_broker(),
            Self::Restricted {
                bind,
                unix_socket_access,
                ..
            } => matches!(bind, IpBindAccess::Localhost) || unix_socket_access.needs_broker(),
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

/// Decision for a Unix socket `connect` or `bind` target.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum UnixPathAccess {
    Allowed,
    /// Denied by policy; the interactive supervisor may offer a grant.
    Denied,
    /// Names a service manager socket. No grant can make this safe, so the
    /// denial is terminal and the broker only reports it.
    Supervisor,
}

/// Sockets a sandboxed child could use to ask an unsandboxed service manager to
/// start a process that inherits neither Landlock nor seccomp.
///
/// The defaults are discovered from `DBUS_SYSTEM_BUS_ADDRESS`,
/// `DBUS_SESSION_BUS_ADDRESS`, and `XDG_RUNTIME_DIR`; `network.supervisorSockets`
/// replaces them.
#[cfg(target_os = "linux")]
#[derive(Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub(crate) struct SupervisorSocketSet(Vec<PathBuf>);

#[cfg(target_os = "linux")]
impl SupervisorSocketSet {
    /// `None` selects the discovered defaults. An explicit list replaces them,
    /// so a policy naming its own service manager is not also restricted by the
    /// sockets this host happens to have.
    pub(crate) fn new(overrides: Option<Vec<PathBuf>>) -> Self {
        let mut paths = match overrides {
            Some(paths) => paths,
            None => Self::discovered(),
        };
        paths.normalize_roots();
        Self(paths)
    }

    /// Each entry covers the path and, for a directory, its subtree. The inode
    /// comparison keeps a symlink or hard link from naming a denied socket.
    pub(crate) fn contains(&self, target: &Path, object: Option<BorrowedFd<'_>>) -> bool {
        self.0.iter().any(|candidate| {
            target.is_under(candidate) || object.is_some_and(|fd| Self::same_inode(fd, candidate))
        })
    }

    fn discovered() -> Vec<PathBuf> {
        // SAFETY: getuid(2) is always defined and has no preconditions.
        let uid = unsafe { libc::getuid() };
        let uid_runtime = Path::new("/run/user").join(uid.to_string());
        let runtime =
            env::var_os("XDG_RUNTIME_DIR").map_or_else(|| uid_runtime.clone(), PathBuf::from);
        let mut paths = vec![
            PathBuf::from("/run/dbus/system_bus_socket"),
            runtime.join("bus"),
            uid_runtime.join("bus"),
            PathBuf::from("/run/systemd"),
            runtime.join("systemd"),
            uid_runtime.join("systemd"),
        ];
        paths.extend(
            ["DBUS_SYSTEM_BUS_ADDRESS", "DBUS_SESSION_BUS_ADDRESS"]
                .into_iter()
                .filter_map(env::var_os)
                .filter_map(|addresses| Self::bus_path(&addresses)),
        );
        paths
    }

    /// First pathname in a D-Bus server address list.
    fn bus_path(addresses: &OsStr) -> Option<PathBuf> {
        addresses
            .as_bytes()
            .split(|byte| *byte == b';')
            .filter_map(|entry| entry.strip_prefix(b"unix:"))
            .find_map(|params| {
                params
                    .split(|byte| *byte == b',')
                    .find_map(|param| param.strip_prefix(b"path="))
            })
            .map(|path| PathBuf::from(OsStr::from_bytes(path)))
    }

    fn same_inode(left: BorrowedFd<'_>, right: &Path) -> bool {
        let Ok(stat) = fstat(left) else {
            return true;
        };
        let Ok(right) = fs::metadata(right) else {
            return false;
        };
        stat.st_dev == right.dev() && stat.st_ino == right.ino()
    }
}

#[cfg(target_os = "linux")]
impl AccessPolicy {
    /// A service manager socket stays denied whatever the unix socket policy
    /// says: approving one would start a process outside Landlock and seccomp,
    /// which no later rule can undo.
    pub(crate) fn unix_path_access(
        &self,
        target: &Path,
        object: Option<BorrowedFd<'_>>,
    ) -> UnixPathAccess {
        if self.supervisor_sockets.contains(target, object) {
            return UnixPathAccess::Supervisor;
        }
        match self.network_access.unix_socket_access() {
            UnixSocketAccess::Unrestricted => UnixPathAccess::Allowed,
            UnixSocketAccess::AllowPaths(paths) if target.is_under_any(paths) => {
                UnixPathAccess::Allowed
            }
            UnixSocketAccess::AllowPaths(_) | UnixSocketAccess::Denied => UnixPathAccess::Denied,
        }
    }
}

impl Settings {
    pub(crate) fn resolve(&self, policy_base: &Path) -> Result<AccessPolicy> {
        let filesystem = &self.filesystem;
        let network = &self.network;
        let windows = &self.windows;
        #[cfg(target_os = "windows")]
        if !filesystem.deny_read_always.is_empty() {
            return Err(Error::PolicyDenyReadAlwaysUnsupported.into());
        }
        #[cfg(target_os = "windows")]
        if !filesystem.deny_write_always.is_empty() {
            return Err(Error::PolicyDenyWriteAlwaysUnsupported.into());
        }
        let resolver = PolicyResolver::new(policy_base)?;

        let mut write_allow = resolver.resolve_paths(&filesystem.allow_write)?;
        // Missing Windows allow roots cannot receive ACL entries. Dropping them is
        // fail-closed because sandbox SIDs receive no access to those paths.
        #[cfg(target_os = "windows")]
        retain_windows_allow_roots(&mut write_allow);
        let write_deny_selectors =
            PolicyResolver::anchor_write_deny_selectors(&filesystem.deny_write, &write_allow);
        let write_always_selectors = PolicyResolver::anchor_write_deny_selectors(
            &filesystem.deny_write_always,
            &write_allow,
        );
        // Linux mediates denyWrite globs dynamically; expanding them here can scan
        // an entire project before even starting a simple command.
        let mut resolved_write_deny =
            resolver.resolve_deny_paths(&write_deny_selectors, !cfg!(target_os = "linux"))?;
        let resolved_write_always = resolver.resolve_deny_paths(&write_always_selectors, true)?;
        let mut denied_links: Vec<DeniedLink> = resolver
            .collect_symlink_ancestors(&write_deny_selectors)?
            .into_iter()
            .map(|path| DeniedLink::new(path, DenialTier::Queryable))
            .collect();
        denied_links.extend(
            resolver
                .collect_symlink_ancestors(&write_always_selectors)?
                .into_iter()
                .map(|path| DeniedLink::new(path, DenialTier::Always)),
        );
        let write_denied_links = DeniedLinks::new(denied_links);
        resolved_write_deny.merge_always(&resolved_write_always, &mut write_allow);
        let write_deny = resolved_write_deny.concrete;
        let write_denied_patterns = resolved_write_deny.patterns;
        let mut write_denied_always_roots = resolved_write_always.concrete;
        write_denied_always_roots.normalize_roots();
        let write_denied_always_patterns = resolved_write_always.patterns;

        let mut read_allow = resolver.resolve_paths(&filesystem.allow_read)?;
        #[cfg(target_os = "windows")]
        retain_windows_allow_roots(&mut read_allow);
        let mut resolved_read_deny = resolver.resolve_deny_paths(&filesystem.deny_read, true)?;
        let mut read_denied_roots =
            effective_denied_roots(&resolved_read_deny.concrete, &read_allow);
        let resolved_read_always =
            resolver.resolve_deny_paths(&filesystem.deny_read_always, true)?;
        let read_carveouts = resolved_read_deny.carveouts(&resolved_read_always, &read_allow);
        resolved_read_deny.merge_always(&resolved_read_always, &mut read_allow);
        let read_deny = resolved_read_deny.concrete;
        let read_denied_patterns = resolved_read_deny.patterns;
        let read_denied_always_roots = resolved_read_always.concrete;
        let read_denied_always_patterns = resolved_read_always.patterns;
        // Windows cannot attach deny entries to missing paths or volume roots.
        #[cfg(target_os = "windows")]
        retain_windows_deny_roots(&mut read_denied_roots);

        #[cfg(target_os = "windows")]
        let (write_allow, write_deny) = {
            let write_roots = lower_windows_write_access(&write_allow, write_deny);
            (write_roots.allow, write_roots.deny)
        };

        let lowered_read = lower_read_access(
            &read_allow,
            &read_deny,
            &read_denied_patterns,
            &read_denied_roots,
        )?;
        let (read_access, read_symlinks) = (lowered_read.access, lowered_read.symlinks);
        read_denied_roots.extend(read_denied_always_roots.iter().cloned());
        read_denied_roots.normalize_roots();
        let policy = AccessPolicy {
            write_roots: write_allow,
            write_denied_roots: write_deny,
            write_denied_always_roots: write_denied_always_roots.into_boxed_slice(),
            write_denied_always_patterns: write_denied_always_patterns.into_boxed_slice(),
            write_denied_patterns,
            write_denied_links,
            read_access,
            read_denied_roots,
            read_denied_patterns,
            read_carveouts,
            read_denied_always_roots: read_denied_always_roots.into_boxed_slice(),
            read_denied_always_patterns: read_denied_always_patterns.into_boxed_slice(),
            read_symlinks,
            network_access: resolver.lower_network_policy(network)?,
            #[cfg(target_os = "linux")]
            supervisor_sockets: resolver
                .resolve_supervisor_sockets(network.supervisor_sockets.as_deref())?,
            macos: self.macos.normalize()?,
            app_container_mode: windows.app_container_mode,
            allow_windows_loopback: windows.allow_loopback,
            allow_windows_additive_grants: windows.allow_additive_grants,
        };
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        policy.validate()?;
        Ok(policy)
    }
}

struct LoweredReadAccess {
    access: ReadAccess,
    symlinks: Vec<PathBuf>,
}

struct ResolvedDenyPaths {
    concrete: Vec<PathBuf>,
    patterns: Vec<String>,
}

impl ResolvedDenyPaths {
    fn matches(&self, path: &Path) -> bool {
        matches_denied(&self.concrete, &self.patterns, path)
    }

    fn carveouts(&self, always: &Self, allow: &[PathBuf]) -> Vec<PathBuf> {
        allow
            .iter()
            .filter(|path| !always.matches(path) && matches_any_pattern(path, &self.patterns))
            .cloned()
            .collect()
    }

    fn merge_always(&mut self, always: &Self, allow: &mut Vec<PathBuf>) {
        allow.retain(|path| !always.matches(path));
        self.concrete.extend(always.concrete.iter().cloned());
        self.concrete.normalize_roots();
        self.patterns.extend(always.patterns.iter().cloned());
        self.patterns.sort_unstable();
        self.patterns.dedup();
    }
}

#[cfg(target_os = "windows")]
struct WindowsWriteRoots {
    allow: Vec<PathBuf>,
    deny: Vec<PathBuf>,
}

#[cfg(target_os = "windows")]
fn retain_windows_allow_roots(paths: &mut Vec<PathBuf>) {
    paths.retain(|path| path.try_exists().unwrap_or(false));
}

#[cfg(target_os = "windows")]
fn retain_windows_deny_roots(paths: &mut Vec<PathBuf>) {
    paths.retain(|path| path.parent().is_some() && path.try_exists().unwrap_or(true));
}

#[cfg(target_os = "windows")]
fn lower_windows_write_access(
    write_allow: &[PathBuf],
    mut write_deny: Vec<PathBuf>,
) -> WindowsWriteRoots {
    // Windows ACLs cannot attach deny entries to paths that do not exist or to
    // volume roots. Nested denials under `allowWrite` are enforced by explicit
    // DENY ACEs applied after the write grants so parent directories keep their
    // write permission for sibling creation.
    retain_windows_deny_roots(&mut write_deny);

    // `denyRead` gates reads only; it must not cancel a granted write root the
    // way a `denyWrite` does.
    let mut carved_writes: Vec<PathBuf> = write_allow
        .iter()
        .filter(|allow| !allow.is_under_any(&write_deny))
        .cloned()
        .collect();
    carved_writes.normalize_roots();

    WindowsWriteRoots {
        allow: carved_writes,
        deny: write_deny,
    }
}

fn lower_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    read_denied_patterns: &[String],
    read_denied_roots: &[PathBuf],
) -> Result<LoweredReadAccess> {
    let fs_root = Path::new("/").normalize();
    // Reject a full-volume Windows grant because propagating it over `C:\`
    // can hang while walking the volume.
    #[cfg(target_os = "windows")]
    if read_allow.contains(&fs_root) {
        return Err(Error::PolicyUnrestrictedRead.into());
    }

    let has_dynamic_patterns = cfg!(not(target_os = "windows")) && !read_denied_patterns.is_empty();
    let has_windows_allow_roots = cfg!(target_os = "windows") && !read_allow.is_empty();
    if read_deny.is_empty() && !has_dynamic_patterns && !has_windows_allow_roots {
        Ok(LoweredReadAccess {
            access: ReadAccess::Unrestricted,
            symlinks: Vec::new(),
        })
    } else if (has_dynamic_patterns && read_deny.is_empty())
        || (read_allow.contains(&fs_root)
            && !read_deny
                .iter()
                .any(|deny| read_allow.iter().any(|allow| allow.is_strictly_under(deny))))
    {
        // Layer surviving denyRead roots over a full-tree allowRead grant.
        // Windows rejects the full-volume grant above.
        Ok(LoweredReadAccess {
            access: ReadAccess::AllowRoots(vec![fs_root]),
            symlinks: Vec::new(),
        })
    } else {
        lower_restricted_read_access(read_allow, read_deny, read_denied_roots)
    }
}

#[cfg(target_os = "windows")]
fn lower_restricted_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    read_denied_roots: &[PathBuf],
) -> Result<LoweredReadAccess> {
    // Denials that survive in `read_denied_roots` receive explicit DENY ACEs.
    // Only non-root denials overridden by a more specific `allowRead` (and
    // therefore omitted from `read_denied_roots`) need directory carving.
    let mut carve_denials: Vec<PathBuf> = read_deny
        .iter()
        .filter(|deny| {
            deny.parent().is_some()
                && !read_denied_roots.contains(deny)
                && read_allow.iter().any(|allow| allow.is_strictly_under(deny))
        })
        .cloned()
        .collect();
    carve_denials.normalize_roots();

    let mut roots = Vec::new();
    let mut symlinks = Vec::new();
    for allow in read_allow {
        let nested_denials: Vec<PathBuf> = carve_denials
            .iter()
            .filter(|deny| deny.is_strictly_under(allow))
            .cloned()
            .collect();
        if nested_denials.is_empty() {
            roots.push(allow.clone());
        } else {
            let scan = scan_allowed_root(allow, &nested_denials, true, 0)?;
            roots.extend(scan.roots);
            symlinks.extend(scan.symlinks);
        }
    }
    roots.normalize_roots();
    symlinks.normalize_roots();
    Ok(LoweredReadAccess {
        access: ReadAccess::AllowRoots(roots),
        symlinks,
    })
}

#[cfg(not(target_os = "windows"))]
fn lower_restricted_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    _read_denied_roots: &[PathBuf],
) -> Result<LoweredReadAccess> {
    let mut denied = read_deny.to_vec();
    denied.normalize_roots();
    let scan = scan_allowed_root(Path::new("/"), &denied, true, 0)?;
    let mut roots = scan.roots;
    let mut symlinks = scan.symlinks;

    // The seccomp broker enforces nested denials under explicit allow roots.
    for allow in read_allow {
        if allow.as_path() != Path::new("/") {
            roots.push(allow.clone());
        }
    }
    roots.normalize_roots();
    symlinks.normalize_roots();
    Ok(LoweredReadAccess {
        access: ReadAccess::AllowRoots(roots),
        symlinks,
    })
}

impl SandboxDarwin {
    fn normalize(&self) -> Result<Self> {
        let mut allow_mach_lookup = Vec::with_capacity(self.allow_mach_lookup.len());
        for service in &self.allow_mach_lookup {
            if service.strip_suffix('*').unwrap_or(service).is_empty() {
                return Err(Error::PolicyInvalidMachLookup.into());
            }
            allow_mach_lookup.push(service.clone());
        }
        allow_mach_lookup.sort_unstable();
        allow_mach_lookup.dedup();

        if let Some(tag) = &self.log_tag
            && (tag.is_empty()
                || tag
                    .bytes()
                    .any(|byte| byte < 0x20 || byte == 0x7f || byte == b'"' || byte == b'\\'))
        {
            return Err(Error::PolicyInvalidLogTag.into());
        }

        Ok(Self {
            allow_trustd: self.allow_trustd,
            allow_mach_lookup,
            allow_apple_events: self.allow_apple_events,
            allow_pty: self.allow_pty,
            log_tag: self.log_tag.clone(),
        })
    }
}

struct PolicyResolver {
    base: PathBuf,
    home: Option<PathBuf>,
}

impl PolicyResolver {
    fn new(policy_base: &Path) -> Result<Self> {
        let base = if policy_base.is_absolute() {
            policy_base.to_path_buf()
        } else {
            env::current_dir()?.join(policy_base)
        };
        Ok(Self {
            base: base.clean_lexically(),
            home: dirs::home_dir(),
        })
    }

    fn resolve_sandbox_path(&self, path: &str) -> Result<PathBuf> {
        if path.is_empty() {
            return Err(Error::PolicyEmptyPath.into());
        }

        let raw = Path::new(path);
        let resolved = if raw.has_root() {
            raw.to_path_buf()
        } else if path == "~" {
            self.home
                .as_deref()
                .map(Path::to_path_buf)
                .ok_or(Error::PolicyHomeUnavailable)?
        } else if let Some(rest) = path.strip_prefix("~/") {
            self.home
                .as_deref()
                .map(|home| home.join(rest))
                .ok_or(Error::PolicyHomeUnavailable)?
        } else {
            self.base.join(raw)
        };

        Ok(resolved.clean_lexically())
    }

    #[cfg(target_os = "linux")]
    fn resolve_supervisor_sockets(
        &self,
        overrides: Option<&[PathSelector]>,
    ) -> Result<SupervisorSocketSet> {
        let resolved = match overrides {
            Some(paths) => Some(self.resolve_paths(paths)?),
            None => None,
        };
        Ok(SupervisorSocketSet::new(resolved))
    }

    fn resolve_paths(&self, paths: &[PathSelector]) -> Result<Vec<PathBuf>> {
        let mut resolved = Vec::new();
        for selector in paths {
            let path = self.resolve_sandbox_path(selector.as_str())?;
            let path_str = path.to_string_lossy();
            if !selector.is_literal() && GlobPattern::is_glob_str(&path_str) {
                let matches = GlobPattern::new(&path_str).expand()?;
                if matches!(selector, PathSelector::Bare(_))
                    && matches.is_empty()
                    && fs::symlink_metadata(&path).is_ok()
                {
                    push_path_variants(&mut resolved, &path);
                } else {
                    for candidate in &matches {
                        push_path_variants(&mut resolved, candidate);
                    }
                }
            } else {
                push_path_variants(&mut resolved, &path);
            }
        }

        resolved.normalize_roots();

        Ok(resolved)
    }

    /// Anchor base-relative write-deny selectors at every granted write root, so
    /// `denyWrite: [".git"]` protects each root rather than only the policy base.
    fn anchor_write_deny_selectors(
        paths: &[PathSelector],
        write_allow: &[PathBuf],
    ) -> Vec<PathSelector> {
        let mut anchored = Vec::with_capacity(paths.len() * (1 + write_allow.len()));
        for selector in paths {
            anchored.push(selector.clone());
            if selector.is_base_relative() {
                let relative = Path::new(selector.as_str()).clean_lexically();
                let relative_str = relative.to_string_lossy();
                let pattern = GlobPattern::new(&relative_str);
                for root in write_allow {
                    // A write root can itself be a protected file or directory.
                    if root.file_name().is_some_and(|name| {
                        let name = Path::new(name);
                        if selector.is_literal() {
                            relative == name
                        } else {
                            pattern.matches_path(name)
                        }
                    }) {
                        anchored.push(PathSelector::Literal {
                            literal: root.to_string_lossy().into_owned(),
                        });
                    }
                    // Only directory roots can contain denied descendants.
                    // Anchoring at a file root would create unreachable deny
                    // roots whose ancestors receive unlink protection, blocking
                    // removal of the granted root itself (for example a lock
                    // directory released with rmdir).
                    if !fs::metadata(root).is_ok_and(|md| md.is_dir()) {
                        continue;
                    }
                    let joined = root.join(selector.as_str()).to_string_lossy().into_owned();
                    anchored.push(match selector {
                        PathSelector::Literal { .. } => PathSelector::Literal { literal: joined },
                        PathSelector::Glob { .. } => PathSelector::Glob { glob: joined },
                        PathSelector::Bare(_) => PathSelector::Bare(joined),
                    });
                }
            }
        }
        anchored
    }

    fn resolve_deny_paths(
        &self,
        paths: &[PathSelector],
        expand_globs: bool,
    ) -> Result<ResolvedDenyPaths> {
        let mut concrete: Vec<PathBuf> = Vec::new();
        let mut patterns: Vec<String> = Vec::new();

        for selector in paths {
            let resolved = self.resolve_sandbox_path(selector.as_str())?;
            let resolved_str = resolved.to_string_lossy();
            if !selector.is_literal() && GlobPattern::is_glob_str(&resolved_str) {
                if expand_globs {
                    for candidate in GlobPattern::new(&resolved_str).expand()? {
                        push_path_variants(&mut concrete, &candidate);
                    }
                }
                patterns.push(resolved_str.clone().into_owned());
                let base = GlobPattern::new(&resolved_str).base();
                let canonical = base.canonicalize_existing_prefix().clean_lexically();
                let base_str = base.to_string_lossy();
                let canonical_str = canonical.to_string_lossy();
                if canonical_str != base_str
                    && let Some(suffix) = resolved_str.strip_prefix(base_str.as_ref())
                {
                    let mut canonical_pattern = canonical_str.into_owned();
                    canonical_pattern.push_str(suffix);
                    patterns.push(canonical_pattern);
                }
            } else {
                push_path_variants(&mut concrete, &resolved);
            }
        }

        concrete.normalize_roots();
        patterns.sort_unstable();
        patterns.dedup();

        Ok(ResolvedDenyPaths { concrete, patterns })
    }

    fn collect_symlink_ancestors(&self, paths: &[PathSelector]) -> Result<Vec<PathBuf>> {
        let mut links = Vec::new();
        for selector in paths {
            let resolved = self.resolve_sandbox_path(selector.as_str())?;
            let resolved_str = resolved.to_string_lossy();
            let check_path = if !selector.is_literal() && GlobPattern::is_glob_str(&resolved_str) {
                GlobPattern::new(&resolved_str).base()
            } else {
                resolved
            };
            let mut current = PathBuf::new();
            for component in check_path.components() {
                current.push(component);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        links.extend(Self::link_spellings(&current));
                    }
                    _ => {}
                }
            }
        }
        links.sort_unstable();
        links.dedup();
        Ok(links)
    }

    /// Spellings of a symlink's own path. Backends match kernel-canonical
    /// paths, so a link below another symlink (macOS `/var`) needs both forms.
    /// Canonicalizing the parent keeps the link itself unresolved.
    fn link_spellings(link: &Path) -> impl Iterator<Item = PathBuf> {
        let lexical = link.clean_lexically();
        let canonical = match (lexical.parent(), lexical.file_name()) {
            (Some(parent), Some(name)) => fs::canonicalize(parent)
                .ok()
                .map(|parent| parent.join(name)),
            _ => None,
        };
        canonical
            .filter(|canonical| *canonical != lexical)
            .into_iter()
            .chain(std::iter::once(lexical))
    }

    fn lower_network_policy(&self, network: &SandboxNetwork) -> Result<NetworkAccess> {
        let unix_socket_paths = self.resolve_paths(&network.allow_unix_sockets)?;
        let unix_socket_access = if network.allow_all_unix_sockets {
            UnixSocketAccess::Unrestricted
        } else if unix_socket_paths.is_empty() {
            UnixSocketAccess::Denied
        } else {
            UnixSocketAccess::AllowPaths(unix_socket_paths)
        };

        if network.allow_network {
            return Ok(NetworkAccess::Unrestricted { unix_socket_access });
        }

        let mut connect_tcp_ports = Vec::new();
        for port in [network.http_proxy_port, network.socks_proxy_port]
            .into_iter()
            .flatten()
        {
            if port == 0 {
                return Err(Error::PolicyInvalidPort.into());
            }
            connect_tcp_ports.push(port);
        }
        connect_tcp_ports.sort_unstable();
        connect_tcp_ports.dedup();

        let bind = if network.allow_local_binding {
            IpBindAccess::Localhost
        } else {
            IpBindAccess::Deny
        };
        Ok(NetworkAccess::Restricted {
            connect_tcp_ports,
            bind,
            unix_socket_access,
        })
    }
}

fn matches_denied(roots: &[PathBuf], patterns: &[String], path: &Path) -> bool {
    path.is_under_any(roots) || matches_any_pattern(path, patterns)
}

#[cfg(target_os = "linux")]
fn has_denied_under(roots: &[PathBuf], patterns: &[String], dir: &Path) -> bool {
    roots.iter().any(|root| root.is_under(dir))
        || patterns
            .iter()
            .any(|pattern| GlobPattern::new(pattern).matches_under(dir))
}

fn matches_any_pattern(path: &Path, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| GlobPattern::new(pattern).matches_tree(path))
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
            symlinks.push(current.clean_lexically());
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

#[cfg(target_os = "macos")]
fn push_path_variants(paths: &mut Vec<PathBuf>, path: &Path) {
    paths.push(path.clean_lexically());
    paths.push(path.canonicalize_existing_prefix().clean_lexically());
}

#[cfg(not(target_os = "macos"))]
fn push_path_variants(paths: &mut Vec<PathBuf>, path: &Path) {
    paths.push(path.normalize());
}
