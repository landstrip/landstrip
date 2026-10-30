// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#[cfg(target_os = "linux")]
use super::SupervisorSocketSet;
use super::{
    AccessPolicy, Carveouts, DenialTier, DeniedLink, DeniedLinks, DenyRuleSet, IpBindAccess,
    NetworkAccess, ReadAccess, UnixSocketAccess,
};
use crate::config::{PathSelector, SandboxDarwin, SandboxFilesystem, SandboxNetwork, Settings};
use crate::error::{Error, PathIo};
use crate::paths::{GlobPattern, GlobPatternBuf, NormalizePatterns, NormalizeRoots, OverridesDeny, PathExt};
use anyhow::Result;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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

        let write = resolver.resolve_write_policy(filesystem)?;

        let resolved_read_allow = resolver.resolve_allow_paths(&filesystem.allow_read)?;
        let mut read_allow = resolved_read_allow.roots;
        #[cfg(target_os = "windows")]
        read_allow.retain_windows_allow_roots();
        let mut resolved_read_deny = resolver.resolve_deny_paths(&filesystem.deny_read, true)?;
        resolved_read_deny.merge_expanded();
        let mut read_denied_roots =
            effective_denied_roots(&resolved_read_deny.concrete, &read_allow);
        let mut resolved_read_always =
            resolver.resolve_deny_paths(&filesystem.deny_read_always, true)?;
        resolved_read_always.merge_expanded();
        let read_carveouts = Carveouts {
            roots: resolved_read_deny.carveouts(&resolved_read_always, &read_allow),
            patterns: if cfg!(target_os = "windows") {
                Vec::new()
            } else {
                resolved_read_deny.carveout_patterns(&resolved_read_allow.patterns)
            },
        };
        resolved_read_deny.merge_always(&resolved_read_always, &mut read_allow);
        let read_deny = resolved_read_deny.concrete;
        let read_denied_patterns = resolved_read_deny.patterns;
        let read_denied_always_roots = resolved_read_always.concrete;
        let read_denied_always_patterns = resolved_read_always.patterns;
        // Windows cannot attach deny entries to missing paths or volume roots.
        #[cfg(target_os = "windows")]
        read_denied_roots.retain_windows_deny_roots();

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
            write_roots: write.roots,
            write_denied_roots: write.denied_roots,
            write_denied_always_roots: write.denied_always_roots,
            write_denied_always_patterns: write.denied_always_patterns,
            write_denied_patterns: write.denied_patterns,
            write_carveouts: write.carveouts,
            write_denied_links: write.denied_links,
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

struct ResolvedWritePolicy {
    roots: Vec<PathBuf>,
    denied_roots: Vec<PathBuf>,
    denied_always_roots: Box<[PathBuf]>,
    denied_always_patterns: Box<[GlobPatternBuf]>,
    denied_patterns: Vec<GlobPatternBuf>,
    carveouts: Carveouts,
    denied_links: DeniedLinks,
}

struct LoweredReadAccess {
    access: ReadAccess,
    symlinks: Vec<PathBuf>,
}

struct ResolvedDenyPaths {
    concrete: Vec<PathBuf>,
    expanded: Vec<PathBuf>,
    patterns: Vec<GlobPatternBuf>,
}

struct ResolvedAllowPaths {
    roots: Vec<PathBuf>,
    patterns: Vec<GlobPatternBuf>,
}

impl ResolvedDenyPaths {
    fn as_rules(&self) -> DenyRuleSet<'_> {
        DenyRuleSet::new(&self.concrete, &self.patterns)
    }

    fn matches(&self, path: &Path) -> bool {
        self.as_rules().matches(path)
    }

    fn merge_expanded(&mut self) {
        self.concrete.extend(std::mem::take(&mut self.expanded));
        self.concrete.normalize_roots();
    }

    fn carveouts(&self, always: &Self, allow: &[PathBuf]) -> Vec<PathBuf> {
        allow
            .iter()
            .filter(|path| !always.matches(path) && self.as_rules().matches_patterns(path))
            .cloned()
            .collect()
    }

    fn carveout_patterns(&self, allow_patterns: &[GlobPatternBuf]) -> Vec<GlobPatternBuf> {
        let rules = self.as_rules();
        allow_patterns
            .iter()
            .filter(|allow| allow.overrides_deny(&rules))
            .cloned()
            .collect()
    }

    fn apply_write_carveouts(
        &mut self,
        always: &Self,
        allow: &[PathBuf],
        allow_patterns: &[GlobPatternBuf],
    ) -> Carveouts {
        let roots: Vec<PathBuf> = allow
            .iter()
            .filter(|path| !always.matches(path) && self.matches(path))
            .cloned()
            .collect();
        self.concrete.retain(|deny| !roots.contains(deny));
        let patterns = &self.patterns;
        let matches_pattern = |path: &Path| {
            patterns
                .iter()
                .any(|pattern| pattern.matches_tree(path))
        };
        self.expanded.retain(|candidate| {
            !roots
                .iter()
                .any(|carveout| candidate.is_under(carveout) && matches_pattern(carveout))
        });
        self.merge_expanded();
        let patterns = if cfg!(target_os = "windows") {
            Vec::new()
        } else {
            self.carveout_patterns(allow_patterns)
        };
        Carveouts { roots, patterns }
    }

    fn merge_always(&mut self, always: &Self, allow: &mut Vec<PathBuf>) {
        allow.retain(|path| !always.matches(path));
        self.concrete.extend(always.concrete.iter().cloned());
        self.concrete.normalize_roots();
        self.patterns.extend(always.patterns.iter().cloned());
        self.patterns.normalize_patterns();
    }
}

#[cfg(target_os = "windows")]
struct WindowsWriteRoots {
    allow: Vec<PathBuf>,
    deny: Vec<PathBuf>,
}

#[cfg(target_os = "windows")]
fn lower_windows_write_access(
    write_allow: &[PathBuf],
    mut write_deny: Vec<PathBuf>,
) -> WindowsWriteRoots {
    write_deny.retain_windows_deny_roots();

    let mut carved_writes = write_allow.to_vec();
    carved_writes.normalize_roots();

    WindowsWriteRoots {
        allow: carved_writes,
        deny: write_deny,
    }
}

fn lower_read_access(
    read_allow: &[PathBuf],
    read_deny: &[PathBuf],
    read_denied_patterns: &[GlobPatternBuf],
    read_denied_roots: &[PathBuf],
) -> Result<LoweredReadAccess> {
    let fs_root = Path::new("/").normalize();
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

    fn resolve_write_policy(&self, filesystem: &SandboxFilesystem) -> Result<ResolvedWritePolicy> {
        let resolved_write_allow = self.resolve_allow_paths(&filesystem.allow_write)?;
        let mut write_allow = resolved_write_allow.roots;
        // Missing Windows allow roots cannot receive ACL entries. Dropping them is
        // fail-closed because sandbox SIDs receive no access to those paths.
        #[cfg(target_os = "windows")]
        write_allow.retain_windows_allow_roots();
        let mut write_anchor_roots = write_allow.clone();
        write_anchor_roots.extend(
            resolved_write_allow
                .patterns
                .iter()
                .map(GlobPatternBuf::base),
        );
        write_anchor_roots.normalize_roots();
        let write_always_selectors = Self::anchor_write_deny_selectors(
            &filesystem.deny_write_always,
            &write_anchor_roots,
            true,
        );
        let mut resolved_write_always = self.resolve_deny_paths(&write_always_selectors, true)?;
        resolved_write_always.merge_expanded();
        write_allow.retain(|path| !resolved_write_always.matches(path));
        write_anchor_roots.retain(|path| !resolved_write_always.matches(path));
        let write_deny_selectors =
            Self::anchor_write_deny_selectors(&filesystem.deny_write, &write_anchor_roots, false);
        // Linux mediates denyWrite globs dynamically; expanding them here can scan
        // an entire project before even starting a simple command.
        let mut resolved_write_deny =
            self.resolve_deny_paths(&write_deny_selectors, !cfg!(target_os = "linux"))?;
        let carveouts = resolved_write_deny.apply_write_carveouts(
            &resolved_write_always,
            &write_allow,
            &resolved_write_allow.patterns,
        );
        let mut denied_links: Vec<DeniedLink> = self
            .collect_symlink_ancestors(&write_deny_selectors)?
            .into_iter()
            .map(|path| DeniedLink::new(path, DenialTier::Queryable))
            .collect();
        denied_links.extend(
            self.collect_symlink_ancestors(&write_always_selectors)?
                .into_iter()
                .map(|path| DeniedLink::new(path, DenialTier::Always)),
        );
        let denied_links = DeniedLinks::new(denied_links);
        resolved_write_deny.merge_always(&resolved_write_always, &mut write_allow);
        let write_deny = resolved_write_deny.concrete;
        let denied_patterns = resolved_write_deny.patterns;
        let mut denied_always_roots = resolved_write_always.concrete;
        denied_always_roots.normalize_roots();
        let denied_always_patterns = resolved_write_always.patterns;

        #[cfg(target_os = "windows")]
        let (write_allow, write_deny) = {
            let write_roots = lower_windows_write_access(&write_allow, write_deny);
            (write_roots.allow, write_roots.deny)
        };

        Ok(ResolvedWritePolicy {
            roots: write_allow,
            denied_roots: write_deny,
            denied_always_roots: denied_always_roots.into_boxed_slice(),
            denied_always_patterns: denied_always_patterns.into_boxed_slice(),
            denied_patterns,
            carveouts,
            denied_links,
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
        Ok(self.resolve_allow_paths(paths)?.roots)
    }

    fn resolve_allow_paths(&self, paths: &[PathSelector]) -> Result<ResolvedAllowPaths> {
        let mut roots = Vec::new();
        let mut glob_selectors = Vec::new();
        for selector in paths {
            let path = self.resolve_sandbox_path(selector.as_str())?;
            let path_str = path.to_string_lossy().into_owned();
            if !selector.is_literal() && GlobPattern::is_glob_str(&path_str) {
                glob_selectors.push((selector, path, path_str));
            } else {
                roots.extend(path.spellings());
            }
        }
        roots.normalize_roots();

        let mut patterns = Vec::new();
        for (selector, path, path_str) in glob_selectors {
            // Recursive globs rooted under an already-granted concrete root only
            // act as dynamic carveouts on Unix; skipping their tree walk avoids
            // scanning large caches at startup.
            let covered_recursive = cfg!(not(target_os = "windows"))
                && path_str.contains("**")
                && GlobPattern::new(&path_str).base().is_under_any(&roots);
            if !covered_recursive {
                let matches = GlobPattern::new(&path_str).expand()?;
                if matches!(selector, PathSelector::Bare(_))
                    && matches.is_empty()
                    && fs::symlink_metadata(&path).is_ok()
                {
                    roots.extend(path.spellings());
                    continue;
                }
                for candidate in &matches {
                    roots.extend(candidate.spellings());
                }
            } else if matches!(selector, PathSelector::Bare(_))
                && fs::symlink_metadata(&path).is_ok()
            {
                roots.extend(path.spellings());
                continue;
            }
            patterns.extend(GlobPatternBuf::new(path_str).spellings());
        }
        roots.normalize_roots();
        patterns.normalize_patterns();

        Ok(ResolvedAllowPaths { roots, patterns })
    }

    fn anchor_write_deny_selectors(
        paths: &[PathSelector],
        write_allow: &[PathBuf],
        anchor_root_name: bool,
    ) -> Vec<PathSelector> {
        let mut anchored = Vec::with_capacity(paths.len() * (1 + write_allow.len()));
        for selector in paths {
            anchored.push(selector.clone());
            if selector.is_base_relative() {
                let relative = Path::new(selector.as_str()).clean_lexically();
                let relative_str = relative.to_string_lossy();
                let pattern = GlobPattern::new(&relative_str);
                for root in write_allow {
                    if anchor_root_name
                        && root.file_name().is_some_and(|name| {
                            let name = Path::new(name);
                            if selector.is_literal() {
                                relative == name
                            } else {
                                pattern.matches_path(name)
                            }
                        })
                    {
                        anchored.push(PathSelector::literal_path(root));
                    }
                    if !fs::metadata(root).is_ok_and(|md| md.is_dir()) {
                        continue;
                    }
                    anchored.push(selector.join_under(root));
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
        let mut expanded: Vec<PathBuf> = Vec::new();
        let mut patterns: Vec<GlobPatternBuf> = Vec::new();

        for selector in paths {
            let resolved = self.resolve_sandbox_path(selector.as_str())?;
            let resolved_str = resolved.to_string_lossy();
            if !selector.is_literal() && GlobPattern::is_glob_str(&resolved_str) {
                if expand_globs {
                    for candidate in GlobPattern::new(&resolved_str).expand()? {
                        expanded.extend(candidate.spellings());
                    }
                }
                patterns.extend(GlobPatternBuf::new(resolved_str.into_owned()).spellings());
            } else {
                concrete.extend(resolved.spellings());
            }
        }

        concrete.normalize_roots();
        expanded.normalize_roots();
        patterns.normalize_patterns();

        Ok(ResolvedDenyPaths {
            concrete,
            expanded,
            patterns,
        })
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

const MAX_TRAVERSAL_DEPTH: u32 = 40;

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

fn effective_denied_roots(read_deny: &[PathBuf], read_allow: &[PathBuf]) -> Vec<PathBuf> {
    read_deny
        .iter()
        .filter(|deny| !read_allow.iter().any(|allow| allow.is_under(deny)))
        .cloned()
        .collect()
}

