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
#[cfg(target_os = "linux")]
use crate::paths::NormalizeRoots;
use crate::paths::{GlobPattern, GlobPatternBuf, OverridesDeny, PathExt};
#[cfg(target_os = "linux")]
use nix::sys::stat::fstat;
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use walkdir::DirEntryExt as _;

#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessPolicy {
    pub(crate) write_roots: Vec<PathBuf>,
    pub(crate) write_denials: DenialScope,
    pub(crate) write_denied_links: DeniedLinks,
    pub(crate) read_access: ReadAccess,
    pub(crate) read_denials: DenialScope,
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

#[derive(Debug, Default, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DenialScope {
    pub(crate) roots: Vec<PathBuf>,
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub(crate) patterns: Vec<GlobPatternBuf>,
    pub(crate) carveouts: Carveouts,
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub(crate) always_roots: Vec<PathBuf>,
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub(crate) always_patterns: Vec<GlobPatternBuf>,
}

#[cfg(target_os = "linux")]
impl DenialScope {
    pub(crate) fn denied(&self) -> DenyRuleSet<'_> {
        DenyRuleSet::with_carveouts(&self.roots, &self.patterns, &self.carveouts)
    }

    pub(crate) fn always(&self) -> DenyRuleSet<'_> {
        DenyRuleSet::new(&self.always_roots, &self.always_patterns)
    }

    pub(crate) fn is_denied(&self, path: &Path) -> bool {
        self.always().matches(path) || self.denied().matches(path)
    }

    pub(crate) fn is_denied_pair(&self, canonical: &Path, lexical: &Path) -> bool {
        self.is_denied(canonical) || (lexical != canonical && self.is_denied(lexical))
    }

    pub(crate) fn is_denied_always(&self, canonical: &Path, lexical: &Path) -> bool {
        let always = self.always();
        always.matches(canonical) || (lexical != canonical && always.matches(lexical))
    }

    pub(crate) fn has_denied_under(&self, dir: &Path) -> bool {
        self.has_denied_always_under(dir) || self.denied().has_denied_under(dir)
    }

    pub(crate) fn has_denied_always_under(&self, dir: &Path) -> bool {
        self.always().has_denied_under(dir)
    }
}

impl Carveouts {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn matches_pattern(&self, path: &Path) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.matches_tree(path))
    }

    pub(crate) fn overrides<D: ?Sized>(&self, deny: &D, path: &Path) -> bool
    where
        PathBuf: OverridesDeny<D>,
        GlobPatternBuf: OverridesDeny<D>,
    {
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
    pub(crate) fn is_denied_link(&self, path: &Path) -> bool {
        self.write_denied_links.contains(path)
    }

    pub(crate) fn is_denied_link_always(&self, path: &Path) -> bool {
        self.write_denied_links.contains_always(path)
    }

    pub(crate) fn write_reason(
        &self,
        canonical: &Path,
        surface_allow_miss: bool,
    ) -> Option<DenialReason> {
        if self.write_denials.is_denied(canonical) {
            Some(DenialReason::DenyMatch)
        } else if surface_allow_miss
            && !canonical.is_under_any(&self.write_roots)
            && !self.write_denials.carveouts.matches_pattern(canonical)
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
                if self.read_denials.is_denied(path) {
                    Some(DenialReason::DenyMatch)
                } else if path.is_under_any(roots)
                    || self.read_denials.carveouts.matches_pattern(path)
                {
                    None
                } else {
                    Some(DenialReason::AllowMiss)
                }
            }
        }
    }

    pub(crate) fn read_access_reason(
        &self,
        canonical: &Path,
        lexical: &Path,
    ) -> Option<DenialReason> {
        self.read_reason(canonical).or_else(|| {
            self.read_denials
                .is_denied_pair(canonical, lexical)
                .then_some(DenialReason::DenyMatch)
        })
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
pub(crate) enum UnixPathAccess<'a> {
    Allowed,
    /// Denied by policy; the interactive supervisor may offer a grant.
    Denied,
    /// User D-Bus session socket filtered via `xdg-dbus-proxy` (`org.freedesktop.secrets`).
    SessionBus {
        label: &'a Path,
        allowed: bool,
    },
    /// Names a service manager socket. No grant can make this safe, so the
    /// denial is terminal and the broker only reports it at debug level.
    Supervisor,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Eq, Hash, PartialEq)]
struct SessionBus {
    path: PathBuf,
    allowed: bool,
}

/// Sockets a sandboxed child could use to ask an unsandboxed service manager to
/// start a process that inherits neither Landlock nor seccomp.
///
/// The defaults are discovered from `DBUS_SYSTEM_BUS_ADDRESS`,
/// `DBUS_SESSION_BUS_ADDRESS`, and `XDG_RUNTIME_DIR`; `network.supervisorSockets`
/// replaces them.
#[cfg(target_os = "linux")]
#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) struct SupervisorSocketSet {
    all: Vec<PathBuf>,
    system: Vec<PathBuf>,
    session_buses: Vec<SessionBus>,
}

#[cfg(target_os = "linux")]
impl Serialize for SupervisorSocketSet {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.all.serialize(serializer)
    }
}

#[cfg(target_os = "linux")]
impl SupervisorSocketSet {
    /// `None` selects the discovered defaults. An explicit list replaces them,
    /// so a policy naming its own service manager is not also restricted by the
    /// sockets this host happens to have.
    pub(crate) fn new(overrides: Option<Vec<PathBuf>>, allow_unix_sockets: &[PathBuf]) -> Self {
        match overrides {
            Some(mut paths) => {
                paths.normalize_roots();
                Self {
                    system: paths.clone(),
                    all: paths,
                    session_buses: Vec::new(),
                }
            }
            None => Self::discovered(allow_unix_sockets),
        }
    }

    pub(crate) fn access(
        &self,
        target: &Path,
        object: Option<BorrowedFd<'_>>,
        allow_session_bus: bool,
        unrestricted_unix: bool,
    ) -> Option<UnixPathAccess<'_>> {
        if self
            .system
            .iter()
            .any(|path| Self::matches(path, target, object))
        {
            return Some(UnixPathAccess::Supervisor);
        }
        let mut buses = self
            .session_buses
            .iter()
            .filter(|bus| Self::matches(&bus.path, target, object));
        let first = buses.next()?;
        if !allow_session_bus {
            return Some(UnixPathAccess::Supervisor);
        }
        if let Some(bus) = std::iter::once(first).chain(buses).find(|bus| bus.allowed) {
            return Some(UnixPathAccess::SessionBus {
                label: &bus.path,
                allowed: true,
            });
        }
        if unrestricted_unix {
            return Some(UnixPathAccess::Supervisor);
        }
        Some(UnixPathAccess::SessionBus {
            label: &first.path,
            allowed: false,
        })
    }

    fn matches(candidate: &Path, target: &Path, object: Option<BorrowedFd<'_>>) -> bool {
        target.is_under(candidate) || object.is_some_and(|fd| Self::same_inode(fd, candidate))
    }

    fn discovered(allow_unix_sockets: &[PathBuf]) -> Self {
        // SAFETY: getuid(2) is always defined and has no preconditions.
        let uid = unsafe { libc::getuid() };
        let uid_runtime = Path::new("/run/user").join(uid.to_string());
        let runtime = dirs::runtime_dir()
            .map(|path| path.normalize())
            .filter(|path| Self::is_valid_socket_path(path))
            .unwrap_or_else(|| uid_runtime.clone());

        let mut system = vec![
            PathBuf::from("/run/dbus/system_bus_socket"),
            PathBuf::from("/run/systemd"),
            runtime.join("systemd"),
            uid_runtime.join("systemd"),
        ];
        if let Some(addresses) = env::var_os("DBUS_SYSTEM_BUS_ADDRESS") {
            system.extend(Self::bus_paths(&addresses));
        }
        system = system
            .into_iter()
            .map(|path| path.normalize())
            .filter(|path| Self::is_valid_socket_path(path))
            .collect();
        system.normalize_roots();

        let mut bus_paths = vec![runtime.join("bus"), uid_runtime.join("bus")];
        if let Some(addresses) = env::var_os("DBUS_SESSION_BUS_ADDRESS") {
            bus_paths.extend(Self::bus_paths(&addresses));
        }
        bus_paths = bus_paths
            .into_iter()
            .map(|path| path.normalize())
            .filter(|path| Self::is_valid_socket_path(path) && !path.is_under_any(&system))
            .collect();
        bus_paths.normalize_roots();

        let mut all = system.clone();
        all.extend(bus_paths.iter().cloned());
        all.normalize_roots();

        let session_buses = bus_paths
            .into_iter()
            .map(|path| {
                let allowed = path.is_under_any(allow_unix_sockets);
                SessionBus { path, allowed }
            })
            .collect();

        Self {
            all,
            system,
            session_buses,
        }
    }

    fn is_valid_socket_path(path: &Path) -> bool {
        path.is_absolute()
            && !path.as_os_str().as_bytes().contains(&0)
            && path.clean_lexically() != Path::new("/")
    }

    /// All valid pathname sockets in a `;`-separated D-Bus server address list.
    fn bus_paths(addresses: &OsStr) -> Vec<PathBuf> {
        addresses
            .as_bytes()
            .split(|byte| *byte == b';')
            .filter_map(|entry| entry.strip_prefix(b"unix:"))
            .filter_map(|params| {
                params
                    .split(|byte| *byte == b',')
                    .find_map(|param| param.strip_prefix(b"path="))
            })
            .filter_map(Self::unescape_bus_value)
            .map(|bytes| PathBuf::from(OsString::from_vec(bytes)))
            .filter(|path| Self::is_valid_socket_path(path))
            .collect()
    }

    fn unescape_bus_value(encoded: &[u8]) -> Option<Vec<u8>> {
        if encoded.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(encoded.len());
        let mut rest = encoded;
        while let Some((&first, tail)) = rest.split_first() {
            let decoded = if first == b'%' {
                let (pair, after) = tail.split_at_checked(2)?;
                let mut byte = [0_u8; 1];
                hex::decode_to_slice(pair, &mut byte).ok()?;
                rest = after;
                byte[0]
            } else {
                rest = tail;
                first
            };
            if decoded == 0 {
                return None;
            }
            out.push(decoded);
        }
        Some(out)
    }

    fn same_inode(left: BorrowedFd<'_>, right: &Path) -> bool {
        let Ok(stat) = fstat(left) else {
            return true;
        };
        let Ok(right_meta) = fs::metadata(right) else {
            return false;
        };
        if stat.st_dev == right_meta.dev() && stat.st_ino == right_meta.ino() {
            return true;
        }
        right_meta.is_dir()
            && stat.st_dev == right_meta.dev()
            && walkdir::WalkDir::new(right)
                .max_depth(5)
                .follow_links(false)
                .follow_root_links(true)
                .same_file_system(true)
                .into_iter()
                .flatten()
                .any(|entry| {
                    !entry.file_type().is_symlink()
                        && entry.ino() == stat.st_ino
                        && entry.metadata().is_ok_and(|meta| {
                            meta.dev() == stat.st_dev && meta.ino() == stat.st_ino
                        })
                })
    }
}

#[cfg(target_os = "linux")]
impl AccessPolicy {
    /// Service manager sockets stay denied whatever the unix socket policy
    /// says: raw access would start a process outside Landlock and seccomp.
    /// When `allow_session_bus` is true (`connect`), discovered user D-Bus
    /// session sockets are mediated through `xdg-dbus-proxy` instead.
    pub(crate) fn unix_path_access(
        &self,
        target: &Path,
        object: Option<BorrowedFd<'_>>,
        allow_session_bus: bool,
    ) -> UnixPathAccess<'_> {
        let unrestricted = matches!(
            self.network_access.unix_socket_access(),
            UnixSocketAccess::Unrestricted
        );
        if let Some(access) =
            self.supervisor_sockets
                .access(target, object, allow_session_bus, unrestricted)
        {
            return access;
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
                    .is_some_and(|carveouts| carveouts.overrides(root.as_path(), path))
        }) || self.matches_patterns(path)
    }

    pub(crate) fn matches_patterns(self, path: &Path) -> bool {
        self.patterns.iter().any(|pattern| {
            pattern.matches_tree(path)
                && !self
                    .carveouts
                    .is_some_and(|carveouts| carveouts.overrides(pattern, path))
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
