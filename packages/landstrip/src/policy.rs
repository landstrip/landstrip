// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Policy lowering from JSON settings to platform access rules.
//!
//! Filesystem policy follows the Seatbelt-compatible shape. Writes start
//! denied; `allowWrite` grants roots and adds paths back from `denyWrite`
//! denials, with the most specific rule winning; `denyWriteAlways` roots and
//! descendants cannot be restored by any allow. Reads stay unrestricted unless
//! `denyRead` or `denyReadAlways` is set. `allowRead` adds paths back from
//! ordinary denials, with the most specific rule winning; `denyReadAlways`
//! roots and descendants cannot be restored by any allow.
//! Hard links and renames that would give a `denyRead` inode a readable name
//! stay denied even when the destination is under `allowWrite`.
//!
//! Paths accept absolute names, names relative to the policy base, `~`, and the
//! macOS-style `*`, `**`, `?`, and character-class globs. Globs are expanded
//! while lowering the policy. Relative write-deny entries additionally anchor
//! at every write root that is a directory, so the deny list follows the
//! granted write scopes.

pub(crate) mod resolver;

use crate::config::{AppContainerMode, SandboxDarwin};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::error::Error;
#[cfg(target_os = "linux")]
use crate::paths::NormalizeRoots;
use crate::paths::{GlobPattern, GlobPatternBuf, OverridesDeny, PathExt};
#[cfg(target_os = "linux")]
use nix::sys::stat::fstat;
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs;
#[cfg(target_os = "macos")]
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
    pub(crate) write_denied_always_patterns: Box<[GlobPatternBuf]>,
    pub(crate) write_denied_patterns: Vec<GlobPatternBuf>,
    pub(crate) write_carveouts: Carveouts,
    pub(crate) write_denied_links: DeniedLinks,
    pub(crate) read_access: ReadAccess,
    pub(crate) read_denied_roots: Vec<PathBuf>,
    pub(crate) read_denied_patterns: Vec<GlobPatternBuf>,
    pub(crate) read_carveouts: Carveouts,
    pub(crate) read_denied_always_roots: Box<[PathBuf]>,
    pub(crate) read_denied_always_patterns: Box<[GlobPatternBuf]>,
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

#[derive(Debug, Default, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Carveouts {
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) patterns: Vec<GlobPatternBuf>,
}

impl Carveouts {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn matches_pattern(&self, path: &Path) -> bool {
        self.patterns.iter().any(|pattern| pattern.matches_tree(path))
    }

    pub(crate) fn overrides_root(&self, deny_root: &Path, path: &Path) -> bool {
        self.roots
            .iter()
            .any(|carveout| carveout.as_path().overrides_deny(deny_root) && path.is_under(carveout))
            || self.patterns.iter().any(|allow| {
                allow.as_glob().overrides_deny(deny_root) && allow.matches_tree(path)
            })
    }

    pub(crate) fn overrides_pattern(&self, deny: &GlobPatternBuf, path: &Path) -> bool {
        self.roots
            .iter()
            .any(|carveout| carveout.overrides_deny(deny) && path.is_under(carveout))
            || self
                .patterns
                .iter()
                .any(|allow| allow.overrides_deny(deny) && allow.matches_tree(path))
    }
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
    pub(crate) fn write_denied(&self) -> DenyRuleSet<'_> {
        DenyRuleSet::with_carveouts(
            &self.write_denied_roots,
            &self.write_denied_patterns,
            &self.write_carveouts,
        )
    }

    pub(crate) fn write_denied_always(&self) -> DenyRuleSet<'_> {
        DenyRuleSet::new(
            &self.write_denied_always_roots,
            &self.write_denied_always_patterns,
        )
    }

    pub(crate) fn read_denied(&self) -> DenyRuleSet<'_> {
        DenyRuleSet::with_carveouts(
            &self.read_denied_roots,
            &self.read_denied_patterns,
            &self.read_carveouts,
        )
    }

    pub(crate) fn read_denied_always(&self) -> DenyRuleSet<'_> {
        DenyRuleSet::new(
            &self.read_denied_always_roots,
            &self.read_denied_always_patterns,
        )
    }

    pub(crate) fn is_write_denied(&self, canonical: &Path) -> bool {
        self.is_write_denied_always(canonical, canonical) || self.write_denied().matches(canonical)
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
        self.write_denied_always().matches(canonical) || self.write_denied_always().matches(lexical)
    }

    pub(crate) fn is_read_denied(&self, path: &Path) -> bool {
        self.is_read_denied_always(path) || self.read_denied().matches(path)
    }

    pub(crate) fn is_read_denied_always(&self, path: &Path) -> bool {
        self.read_denied_always().matches(path)
    }

    pub(crate) fn has_read_denied_under(&self, dir: &Path) -> bool {
        self.has_read_denied_always_under(dir) || self.read_denied().has_denied_under(dir)
    }

    pub(crate) fn has_write_denied_under(&self, dir: &Path) -> bool {
        self.has_write_denied_always_under(dir) || self.write_denied().has_denied_under(dir)
    }

    pub(crate) fn has_read_denied_always_under(&self, dir: &Path) -> bool {
        self.read_denied_always().has_denied_under(dir)
    }

    pub(crate) fn has_write_denied_always_under(&self, dir: &Path) -> bool {
        self.write_denied_always().has_denied_under(dir)
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
        } else if surface_allow_miss
            && !canonical.is_under_any(&self.write_roots)
            && !self.write_carveouts.matches_pattern(canonical)
        {
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
                } else if path.is_under_any(roots) || self.read_carveouts.matches_pattern(path) {
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
#[derive(Clone, Copy)]
pub(crate) struct DenyRuleSet<'a> {
    roots: &'a [PathBuf],
    patterns: &'a [GlobPatternBuf],
    carveouts: Option<&'a Carveouts>,
}

impl<'a> DenyRuleSet<'a> {
    pub(crate) fn new(roots: &'a [PathBuf], patterns: &'a [GlobPatternBuf]) -> Self {
        Self {
            roots,
            patterns,
            carveouts: None,
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn with_carveouts(
        roots: &'a [PathBuf],
        patterns: &'a [GlobPatternBuf],
        carveouts: &'a Carveouts,
    ) -> Self {
        Self {
            roots,
            patterns,
            carveouts: Some(carveouts),
        }
    }

    pub(crate) fn roots(self) -> &'a [PathBuf] {
        self.roots
    }

    pub(crate) fn patterns(self) -> &'a [GlobPatternBuf] {
        self.patterns
    }

    pub(crate) fn matches(self, path: &Path) -> bool {
        self.roots.iter().any(|root| {
            path.is_under(root)
                && !self
                    .carveouts
                    .is_some_and(|carveouts| carveouts.overrides_root(root, path))
        }) || self.matches_patterns(path)
    }

    pub(crate) fn matches_patterns(self, path: &Path) -> bool {
        self.patterns.iter().any(|pattern| {
            pattern.matches_tree(path)
                && !self
                    .carveouts
                    .is_some_and(|carveouts| carveouts.overrides_pattern(pattern, path))
        })
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn has_denied_under(self, dir: &Path) -> bool {
        let root_denied = self
            .roots
            .iter()
            .any(|root| root.is_under(dir) && (self.carveouts.is_none() || self.matches(root)));
        root_denied
            || self.patterns.iter().any(|pattern| match self.carveouts {
                None => pattern.as_glob().matches_under(dir),
                Some(carveouts) => {
                    !carveouts.patterns.contains(pattern)
                        && pattern
                            .as_glob()
                            .has_unexcused_under(dir, |candidate| self.matches(candidate))
                }
            })
    }
}

impl OverridesDeny<DenyRuleSet<'_>> for Path {
    fn overrides_deny(&self, deny: &DenyRuleSet<'_>) -> bool {
        deny.roots().iter().any(|root| self.overrides_deny(root))
            || deny
                .patterns()
                .iter()
                .any(|pattern| self.overrides_deny(pattern))
    }
}

impl OverridesDeny<DenyRuleSet<'_>> for GlobPattern<'_> {
    fn overrides_deny(&self, deny: &DenyRuleSet<'_>) -> bool {
        deny.roots().iter().any(|root| self.overrides_deny(root))
            || deny
                .patterns()
                .iter()
                .any(|pattern| self.overrides_deny(pattern))
    }
}
