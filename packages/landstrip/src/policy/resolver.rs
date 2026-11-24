// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#[cfg(target_os = "linux")]
use super::SupervisorSocketSet;
use super::{
    AccessPolicy, Carveouts, DenialScope, DenialTier, DeniedLink, DeniedLinks, DenyRuleSet,
    IpBindAccess, NetworkAccess, ReadAccess, UnixSocketAccess,
};
use crate::config::{
    PathSelector, SandboxDarwin, SandboxFilesystem, SandboxNetwork, SelectorMode, SelectorPath,
    Settings,
};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::error::PathIo;
use crate::error::{Error, PolicyViolation, Result};
use crate::paths::{GlobPattern, NormalizePatterns, NormalizeRoots, OverridesDeny, PathExt};
use std::cell::OnceCell;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

impl Settings {
    pub(crate) fn resolve(&self, policy_base: &Path) -> Result<AccessPolicy> {
        #[cfg(target_os = "windows")]
        if !self.filesystem.deny_read_always.is_empty() {
            return Err(PolicyViolation::DenyReadAlwaysUnsupported.into());
        }
        #[cfg(target_os = "windows")]
        if !self.filesystem.deny_write_always.is_empty() {
            return Err(PolicyViolation::DenyWriteAlwaysUnsupported.into());
        }
        let resolver = PolicyResolver::new(policy_base)?;
        let write = resolver.resolve_write_policy(&self.filesystem)?;
        let read = resolver.resolve_read_policy(&self.filesystem)?;
        let unix_socket_paths = resolver.resolve_paths(&self.network.allow_unix_sockets)?;
        #[cfg(target_os = "linux")]
        let supervisor_sockets = resolver.resolve_supervisor_sockets(
            self.network.supervisor_sockets.as_deref(),
            &unix_socket_paths,
        )?;
        Ok(AccessPolicy {
            write_roots: write.roots,
            write_denials: write.denials,
            write_denied_links: write.denied_links,
            read_access: read.access,
            read_denials: read.denials,
            read_symlinks: read.symlinks,
            network_access: PolicyResolver::lower_network_policy(&self.network, unix_socket_paths)?,
            #[cfg(target_os = "linux")]
            supervisor_sockets,
            macos: self.macos.normalize()?,
            app_container_mode: self.windows.app_container_mode,
            allow_windows_loopback: self.windows.allow_loopback,
            allow_windows_additive_grants: self.windows.allow_additive_grants,
        })
    }
}

struct ResolvedWritePolicy {
    roots: Vec<PathBuf>,
    denials: DenialScope,
    denied_links: DeniedLinks,
}

struct ResolvedReadPolicy {
    access: ReadAccess,
    denials: DenialScope,
    symlinks: Vec<PathBuf>,
}

struct LoweredReadAccess {
    access: ReadAccess,
    symlinks: Vec<PathBuf>,
}

struct ResolvedDenyPaths {
    concrete: Vec<PathBuf>,
    expanded: Vec<PathBuf>,
    patterns: Vec<GlobPattern>,
    check_paths: Vec<PathBuf>,
}

struct ResolvedAllowPaths {
    roots: Vec<PathBuf>,
    patterns: Vec<GlobPattern>,
}

enum ResolvedSelector {
    Concrete(PathBuf),
    Glob {
        glob: GlobPattern,
        bare_fallback: Option<PathBuf>,
    },
}

impl ResolvedSelector {
    fn rooted(mode: SelectorMode, raw: &str) -> Result<Self> {
        let cleaned = Path::new(raw).clean_lexically();
        match mode {
            SelectorMode::Literal => Ok(Self::Concrete(cleaned)),
            SelectorMode::Glob | SelectorMode::Bare => match GlobPattern::parse(raw)? {
                Some(glob) => Ok(Self::Glob {
                    glob,
                    bare_fallback: (mode == SelectorMode::Bare).then_some(cleaned),
                }),
                None => Ok(Self::Concrete(cleaned)),
            },
        }
    }

    fn under(mode: SelectorMode, root: &Path, relative: &str) -> Result<Self> {
        match mode {
            SelectorMode::Literal => Ok(Self::Concrete(root.join_clean(relative))),
            SelectorMode::Glob | SelectorMode::Bare => match GlobPattern::under(root, relative)? {
                Some(glob) => Ok(Self::Glob {
                    glob,
                    bare_fallback: (mode == SelectorMode::Bare).then(|| root.join_clean(relative)),
                }),
                None => Ok(Self::Concrete(root.join_clean(relative))),
            },
        }
    }
}

enum RootNameMatcher {
    Literal(PathBuf),
    Glob(GlobPattern),
}

impl RootNameMatcher {
    fn new(mode: SelectorMode, relative: &str) -> Result<Self> {
        if mode != SelectorMode::Literal
            && let Some(glob) = GlobPattern::parse(relative)?
        {
            return Ok(Self::Glob(glob));
        }
        Ok(Self::Literal(Path::new(relative).clean_lexically()))
    }

    fn matches(&self, name: &Path) -> bool {
        match self {
            Self::Literal(expected) => expected == name,
            Self::Glob(pattern) => pattern.matches_path(name),
        }
    }
}

struct WriteAnchorRoot {
    path: PathBuf,
    is_dir: OnceCell<bool>,
}

impl WriteAnchorRoot {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            is_dir: OnceCell::new(),
        }
    }

    fn is_dir(&self) -> bool {
        *self
            .is_dir
            .get_or_init(|| fs::metadata(&self.path).is_ok_and(|md| md.is_dir()))
    }
}

#[derive(Default)]
struct SymlinkAncestorCollector {
    checked: HashMap<PathBuf, Vec<PathBuf>>,
    links: Vec<DeniedLink>,
}

impl SymlinkAncestorCollector {
    fn collect(&mut self, check_paths: &[PathBuf], tier: DenialTier) {
        let mut current = PathBuf::new();
        for check_path in check_paths {
            current.clear();
            for component in check_path.components() {
                current.push(component);
                let spellings = if let Some(cached) = self.checked.get(&current) {
                    cached.as_slice()
                } else {
                    let computed = match fs::symlink_metadata(&current) {
                        Ok(metadata) if metadata.file_type().is_symlink() => {
                            Self::link_spellings(&current)
                        }
                        _ => Vec::new(),
                    };
                    self.checked.entry(current.clone()).or_insert(computed)
                };
                self.links.extend(
                    spellings
                        .iter()
                        .cloned()
                        .map(|path| DeniedLink::new(path, tier)),
                );
            }
        }
    }

    fn finish(self) -> DeniedLinks {
        DeniedLinks::new(self.links)
    }

    fn link_spellings(link: &Path) -> Vec<PathBuf> {
        let lexical = link.clean_lexically();
        let canonical = match (lexical.parent(), lexical.file_name()) {
            (Some(parent), Some(name)) => fs::canonicalize(parent)
                .ok()
                .map(|parent| parent.join(name)),
            _ => None,
        };
        let mut spellings = Vec::with_capacity(2);
        if let Some(canonical) = canonical.filter(|canonical| *canonical != lexical) {
            spellings.push(canonical);
        }
        spellings.push(lexical);
        spellings
    }
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

    fn uncarved_roots(&self, allow: &[PathBuf]) -> Vec<PathBuf> {
        self.concrete
            .iter()
            .filter(|deny| !allow.iter().any(|allow| allow.is_under(deny)))
            .cloned()
            .collect()
    }

    fn read_carveouts(&self, always: &Self, allow: &[PathBuf], fs_root: &Path) -> Vec<PathBuf> {
        allow
            .iter()
            .filter(|path| {
                path.as_path() != fs_root
                    && !always.matches(path)
                    && (self.as_rules().matches_patterns(path)
                        || self
                            .concrete
                            .iter()
                            .any(|deny| deny.as_path() != fs_root && path.is_under(deny)))
            })
            .cloned()
            .collect()
    }

    fn carveout_patterns(&self, allow_patterns: &[GlobPattern]) -> Vec<GlobPattern> {
        if cfg!(target_os = "windows") {
            return Vec::new();
        }
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
        allow_patterns: &[GlobPattern],
    ) -> Carveouts {
        let roots: Vec<PathBuf> = allow
            .iter()
            .filter(|path| !always.matches(path) && self.matches(path))
            .cloned()
            .collect();
        self.concrete.retain(|deny| !roots.contains(deny));
        let patterns = &self.patterns;
        let matches_pattern =
            |path: &Path| patterns.iter().any(|pattern| pattern.matches_tree(path));
        self.expanded.retain(|candidate| {
            !roots
                .iter()
                .any(|carveout| candidate.is_under(carveout) && matches_pattern(carveout))
        });
        self.merge_expanded();
        let patterns = self.carveout_patterns(allow_patterns);
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

impl LoweredReadAccess {
    fn lower(
        read_allow: &[PathBuf],
        read_deny: &[PathBuf],
        read_denied_patterns: &[GlobPattern],
        read_denied_roots: &[PathBuf],
    ) -> Result<Self> {
        let fs_root = Path::new("/").normalize();
        #[cfg(target_os = "windows")]
        if read_allow.contains(&fs_root) {
            return Err(PolicyViolation::UnrestrictedRead.into());
        }

        let has_dynamic_patterns =
            cfg!(not(target_os = "windows")) && !read_denied_patterns.is_empty();
        let has_windows_allow_roots = cfg!(target_os = "windows") && !read_allow.is_empty();
        if read_deny.is_empty() && !has_dynamic_patterns && !has_windows_allow_roots {
            Ok(Self {
                access: ReadAccess::Unrestricted,
                symlinks: Vec::new(),
            })
        } else if (has_dynamic_patterns && read_deny.is_empty())
            || (read_allow.contains(&fs_root)
                && !read_deny
                    .iter()
                    .any(|deny| read_allow.iter().any(|allow| allow.is_strictly_under(deny))))
        {
            Ok(Self {
                access: ReadAccess::AllowRoots(vec![fs_root]),
                symlinks: Vec::new(),
            })
        } else {
            Self::restricted(read_allow, read_deny, read_denied_roots)
        }
    }

    #[cfg(target_os = "windows")]
    fn restricted(
        read_allow: &[PathBuf],
        read_deny: &[PathBuf],
        read_denied_roots: &[PathBuf],
    ) -> Result<Self> {
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
                let scan = RootScan::scan(allow, &nested_denials)?;
                roots.extend(scan.roots);
                symlinks.extend(scan.symlinks);
            }
        }
        roots.normalize_roots();
        symlinks.normalize_roots();
        Ok(Self {
            access: ReadAccess::AllowRoots(roots),
            symlinks,
        })
    }

    #[cfg(target_os = "linux")]
    #[allow(
        clippy::unnecessary_wraps,
        reason = "uniform with macOS and Windows read lowering"
    )]
    fn restricted(
        read_allow: &[PathBuf],
        read_deny: &[PathBuf],
        _read_denied_roots: &[PathBuf],
    ) -> Result<Self> {
        let mut denied_roots = read_deny.to_vec();
        denied_roots.normalize_roots();
        let mut allow_roots: Vec<PathBuf> = read_allow
            .iter()
            .filter(|allow| allow.as_path() != Path::new("/"))
            .cloned()
            .collect();
        allow_roots.normalize_roots();
        Ok(Self {
            access: ReadAccess::OutsideDenied {
                denied_roots,
                allow_roots,
            },
            symlinks: Vec::new(),
        })
    }

    #[cfg(target_os = "macos")]
    fn restricted(
        read_allow: &[PathBuf],
        read_deny: &[PathBuf],
        _read_denied_roots: &[PathBuf],
    ) -> Result<Self> {
        let mut denied = read_deny.to_vec();
        denied.normalize_roots();
        let scan = RootScan::scan(Path::new("/"), &denied)?;
        let mut roots = scan.roots;
        let mut symlinks = scan.symlinks;

        for allow in read_allow {
            if allow.as_path() != Path::new("/") {
                roots.push(allow.clone());
            }
        }
        roots.normalize_roots();
        symlinks.normalize_roots();
        Ok(Self {
            access: ReadAccess::AllowRoots(roots),
            symlinks,
        })
    }
}
impl SandboxDarwin {
    fn normalize(&self) -> Result<Self> {
        let mut allow_mach_lookup = Vec::with_capacity(self.allow_mach_lookup.len());
        for service in &self.allow_mach_lookup {
            if service.strip_suffix('*').unwrap_or(service).is_empty() {
                return Err(PolicyViolation::InvalidMachLookup.into());
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
            return Err(PolicyViolation::InvalidLogTag.into());
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
            env::current_dir()
                .map_err(Error::policy_io)?
                .join(policy_base)
        };
        Ok(Self {
            base: base.clean_lexically(),
            home: dirs::home_dir(),
        })
    }

    fn resolve_write_policy(&self, filesystem: &SandboxFilesystem) -> Result<ResolvedWritePolicy> {
        let resolved_allow = self.resolve_allow_paths(&filesystem.allow_write)?;
        let mut allow = resolved_allow.roots;
        #[cfg(target_os = "windows")]
        allow.retain_windows_allow_roots();

        let mut anchor_paths = allow.clone();
        anchor_paths.extend(
            resolved_allow
                .patterns
                .iter()
                .map(|pattern| pattern.base().to_path_buf()),
        );
        anchor_paths.normalize_roots();
        let mut anchor_roots: Vec<WriteAnchorRoot> =
            anchor_paths.into_iter().map(WriteAnchorRoot::new).collect();

        let always_selectors =
            self.anchor_write_deny_selectors(&filesystem.deny_write_always, &anchor_roots, true)?;
        let mut resolved_always = Self::lower_deny_selectors(always_selectors, true)?;
        resolved_always.merge_expanded();
        allow.retain(|path| !resolved_always.matches(path));
        anchor_roots.retain(|root| !resolved_always.matches(&root.path));

        let deny_selectors =
            self.anchor_write_deny_selectors(&filesystem.deny_write, &anchor_roots, false)?;
        // Unix mediates denyWrite globs dynamically (the KVM broker on Linux, Seatbelt
        // regex on macOS); expanding them here scans the entire project tree before
        // even starting a simple command.
        let mut resolved_deny =
            Self::lower_deny_selectors(deny_selectors, cfg!(target_os = "windows"))?;
        let carveouts =
            resolved_deny.apply_write_carveouts(&resolved_always, &allow, &resolved_allow.patterns);
        let mut symlink_ancestors = SymlinkAncestorCollector::default();
        symlink_ancestors.collect(&resolved_deny.check_paths, DenialTier::Queryable);
        symlink_ancestors.collect(&resolved_always.check_paths, DenialTier::Always);
        let denied_links = symlink_ancestors.finish();

        resolved_deny.merge_always(&resolved_always, &mut allow);
        #[allow(unused_mut)]
        let mut denied_roots = resolved_deny.concrete;
        #[cfg(target_os = "windows")]
        denied_roots.retain_windows_deny_roots();
        Ok(ResolvedWritePolicy {
            roots: allow,
            denials: DenialScope {
                roots: denied_roots,
                patterns: resolved_deny.patterns,
                carveouts,
                always_roots: resolved_always.concrete,
                always_patterns: resolved_always.patterns,
            },
            denied_links,
        })
    }

    fn resolve_read_policy(&self, filesystem: &SandboxFilesystem) -> Result<ResolvedReadPolicy> {
        let fs_root = Path::new("/").normalize();
        let resolved_allow = self.resolve_allow_paths(&filesystem.allow_read)?;
        let mut allow = resolved_allow.roots;
        #[cfg(target_os = "windows")]
        allow.retain_windows_allow_roots();

        let mut resolved_deny =
            Self::lower_deny_selectors(self.resolve_selectors(&filesystem.deny_read)?, true)?;
        resolved_deny.merge_expanded();
        let uncarved_roots = resolved_deny.uncarved_roots(&allow);

        let mut resolved_always = Self::lower_deny_selectors(
            self.resolve_selectors(&filesystem.deny_read_always)?,
            true,
        )?;
        resolved_always.merge_expanded();
        let carveouts = Carveouts {
            roots: resolved_deny.read_carveouts(&resolved_always, &allow, &fs_root),
            patterns: resolved_deny.carveout_patterns(&resolved_allow.patterns),
        };
        let mut denied_roots = if cfg!(target_os = "windows") {
            uncarved_roots.clone()
        } else {
            resolved_deny
                .concrete
                .iter()
                .filter(|deny| {
                    if deny.as_path() == fs_root {
                        !allow.iter().any(|grant| grant.is_under(deny))
                    } else {
                        !carveouts.roots.contains(deny)
                    }
                })
                .cloned()
                .collect()
        };
        resolved_deny
            .concrete
            .retain(|deny| deny.as_path() == fs_root || !carveouts.roots.contains(deny));
        resolved_deny.merge_always(&resolved_always, &mut allow);

        #[cfg(target_os = "windows")]
        denied_roots.retain_windows_deny_roots();

        let lowered = LoweredReadAccess::lower(
            &allow,
            &resolved_deny.concrete,
            &resolved_deny.patterns,
            &uncarved_roots,
        )?;
        denied_roots.extend(resolved_always.concrete.iter().cloned());
        denied_roots.normalize_roots();

        Ok(ResolvedReadPolicy {
            access: lowered.access,
            denials: DenialScope {
                roots: denied_roots,
                patterns: resolved_deny.patterns,
                carveouts,
                always_roots: resolved_always.concrete,
                always_patterns: resolved_always.patterns,
            },
            symlinks: lowered.symlinks,
        })
    }

    fn resolve_selector(&self, selector: &PathSelector) -> Result<ResolvedSelector> {
        let (mode, path) = selector.parse()?;
        self.resolve_parsed_selector(mode, path)
    }

    fn resolve_parsed_selector(
        &self,
        mode: SelectorMode,
        path: SelectorPath<'_>,
    ) -> Result<ResolvedSelector> {
        match path {
            SelectorPath::Rooted(raw) => ResolvedSelector::rooted(mode, raw),
            SelectorPath::Home(None) => {
                let home = self
                    .home
                    .as_deref()
                    .ok_or(PolicyViolation::HomeUnavailable)?;
                Ok(ResolvedSelector::Concrete(home.clean_lexically()))
            }
            SelectorPath::Home(Some(rest)) => {
                let home = self
                    .home
                    .as_deref()
                    .ok_or(PolicyViolation::HomeUnavailable)?;
                ResolvedSelector::under(mode, home, rest)
            }
            SelectorPath::Relative(rel) => ResolvedSelector::under(mode, &self.base, rel),
        }
    }

    fn resolve_selectors(&self, paths: &[PathSelector]) -> Result<Vec<ResolvedSelector>> {
        paths
            .iter()
            .map(|selector| self.resolve_selector(selector))
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn resolve_supervisor_sockets(
        &self,
        overrides: Option<&[PathSelector]>,
        allow_unix_sockets: &[PathBuf],
    ) -> Result<SupervisorSocketSet> {
        let resolved = match overrides {
            Some(paths) => Some(self.resolve_paths(paths)?),
            None => None,
        };
        Ok(SupervisorSocketSet::new(resolved, allow_unix_sockets))
    }

    fn resolve_paths(&self, paths: &[PathSelector]) -> Result<Vec<PathBuf>> {
        Ok(self.resolve_allow_paths(paths)?.roots)
    }

    fn resolve_allow_paths(&self, paths: &[PathSelector]) -> Result<ResolvedAllowPaths> {
        let selectors = self.resolve_selectors(paths)?;
        let mut roots = Vec::new();
        let mut glob_selectors = Vec::new();
        for selector in selectors {
            match selector {
                ResolvedSelector::Concrete(path) => roots.extend(path.spellings()),
                ResolvedSelector::Glob {
                    glob,
                    bare_fallback,
                } => glob_selectors.push((glob, bare_fallback)),
            }
        }
        roots.normalize_roots();

        let mut patterns = Vec::new();
        for (glob, bare_fallback) in glob_selectors {
            // Recursive globs rooted under an already-granted concrete root only
            // act as dynamic carveouts on Unix; skipping their tree walk avoids
            // scanning large caches at startup.
            let covered_recursive = cfg!(not(target_os = "windows"))
                && glob.is_recursive()
                && glob.base().is_under_any(&roots);
            if !covered_recursive {
                let matches = glob.expand()?;
                if matches.is_empty()
                    && let Some(path) = bare_fallback
                    && fs::symlink_metadata(&path).is_ok()
                {
                    roots.extend(path.spellings());
                    continue;
                }
                for candidate in &matches {
                    roots.extend(candidate.spellings());
                }
            } else if let Some(path) = bare_fallback
                && fs::symlink_metadata(&path).is_ok()
            {
                roots.extend(path.spellings());
                continue;
            }
            patterns.extend(glob.into_spellings()?);
        }
        roots.normalize_roots();
        patterns.normalize_patterns();

        Ok(ResolvedAllowPaths { roots, patterns })
    }

    fn anchor_write_deny_selectors(
        &self,
        paths: &[PathSelector],
        write_allow: &[WriteAnchorRoot],
        anchor_root_name: bool,
    ) -> Result<Vec<ResolvedSelector>> {
        let mut anchored = Vec::new();
        let mut push = |selector| -> Result<()> {
            const LIMIT: usize = 65_536;
            if anchored.len() >= LIMIT {
                return Err(PolicyViolation::SelectorLimit.into());
            }
            anchored
                .try_reserve(1)
                .map_err(|error| Error::policy_io(io::Error::other(error)))?;
            anchored.push(selector);
            Ok(())
        };
        for selector in paths {
            let (mode, path) = selector.parse()?;
            push(self.resolve_parsed_selector(mode, path)?)?;
            if let SelectorPath::Relative(rel) = path {
                let root_name_matcher = anchor_root_name
                    .then(|| RootNameMatcher::new(mode, rel))
                    .transpose()?;
                for root in write_allow {
                    if let Some(matcher) = &root_name_matcher
                        && root
                            .path
                            .file_name()
                            .is_some_and(|name| matcher.matches(Path::new(name)))
                    {
                        push(ResolvedSelector::Concrete(root.path.clone()))?;
                    }
                    if !root.is_dir() {
                        continue;
                    }
                    push(ResolvedSelector::under(mode, &root.path, rel)?)?;
                }
            }
        }
        Ok(anchored)
    }

    fn lower_deny_selectors(
        selectors: Vec<ResolvedSelector>,
        expand_globs: bool,
    ) -> Result<ResolvedDenyPaths> {
        let mut concrete: Vec<PathBuf> = Vec::new();
        let mut expanded: Vec<PathBuf> = Vec::new();
        let mut patterns: Vec<GlobPattern> = Vec::new();
        let mut check_paths: Vec<PathBuf> = Vec::with_capacity(selectors.len());

        for selector in selectors {
            match selector {
                ResolvedSelector::Concrete(resolved) => {
                    concrete.extend(resolved.spellings());
                    check_paths.push(resolved);
                }
                ResolvedSelector::Glob { glob, .. } => {
                    check_paths.push(glob.base().to_path_buf());
                    if expand_globs {
                        for candidate in glob.expand()? {
                            expanded.extend(candidate.spellings());
                        }
                    }
                    patterns.extend(glob.into_spellings()?);
                }
            }
        }

        concrete.normalize_roots();
        expanded.normalize_roots();
        patterns.normalize_patterns();

        Ok(ResolvedDenyPaths {
            concrete,
            expanded,
            patterns,
            check_paths,
        })
    }

    fn lower_network_policy(
        network: &SandboxNetwork,
        unix_socket_paths: Vec<PathBuf>,
    ) -> Result<NetworkAccess> {
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
                return Err(PolicyViolation::InvalidPort.into());
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

#[cfg(any(target_os = "macos", target_os = "windows"))]
const MAX_TRAVERSAL_DEPTH: u32 = 40;

#[cfg(any(target_os = "macos", target_os = "windows"))]
struct RootScan {
    roots: Vec<PathBuf>,
    symlinks: Vec<PathBuf>,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl RootScan {
    fn scan(root: &Path, denied: &[PathBuf]) -> Result<Self> {
        let mut results = Vec::new();
        let mut symlinks = Vec::new();
        let mut stack = vec![(root.to_path_buf(), true, 0u32)];

        while let Some((current, is_explicit, depth)) = stack.pop() {
            if depth >= MAX_TRAVERSAL_DEPTH {
                return Err(PolicyViolation::TraversalDepth.into());
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
                Err(source) => return Err(Error::policy_io(source)),
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
                Err(source) => return Err(Error::policy_io(source)),
            };
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) if error.is_transport_failed() => {
                        continue;
                    }
                    Err(source) => return Err(Error::policy_io(source)),
                };
                stack.push((entry.path(), false, depth + 1));
            }
        }

        Ok(Self {
            roots: results,
            symlinks,
        })
    }
}
