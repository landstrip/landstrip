// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::PathExt;
use crate::error::{Error, PathIo, PolicyViolation, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Serialize;
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Component, MAIN_SEPARATOR_STR, Path, PathBuf, is_separator};

const MAX_PATTERN_BYTES: usize = 4096;

fn compile_pattern(pattern: &str) -> Result<(GlobSet, String)> {
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .case_insensitive(cfg!(windows))
        .backslash_escape(false)
        .allow_unclosed_class(true)
        .build()
        .map_err(Error::parse_failed)?;
    let regex = glob.regex().to_owned();
    // Use the fallible set builder, not Glob::compile_matcher(), which panics
    // if regex compilation exceeds its resource limit.
    let matcher = GlobSetBuilder::new()
        .add(glob)
        .build()
        .map_err(Error::parse_failed)?;
    Ok((matcher, regex))
}

fn is_glob_byte(byte: u8) -> bool {
    matches!(byte, b'*' | b'?' | b'[' | b']')
}

fn is_glob_component(component: Component<'_>) -> bool {
    matches!(
        component,
        Component::Normal(part) if part.as_encoded_bytes().iter().copied().any(is_glob_byte)
    )
}

fn split_glob(path: &Path) -> Option<(PathBuf, String)> {
    let cleaned = path.clean_lexically();
    let mut base = PathBuf::new();
    let mut suffix = PathBuf::new();
    let mut has_glob = false;
    for component in cleaned.components() {
        if !has_glob && is_glob_component(component) {
            has_glob = true;
        }
        if has_glob {
            suffix.push(component.as_os_str());
        } else {
            base.push(component);
        }
    }
    has_glob.then(|| (base, suffix.to_string_lossy().into_owned()))
}

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub(crate) struct GlobPattern {
    pattern: String,
    #[serde(skip)]
    base: PathBuf,
    #[serde(skip)]
    suffix_offset: usize,
    #[serde(skip)]
    matcher: GlobSet,
    #[serde(skip)]
    #[cfg(target_os = "macos")]
    regex: String,
}

impl PartialEq for GlobPattern {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for GlobPattern {}

impl Hash for GlobPattern {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
    }
}

impl GlobPattern {
    pub(crate) fn parse(raw: &str) -> Result<Option<Self>> {
        let Some((base, suffix)) = split_glob(Path::new(raw)) else {
            return Ok(None);
        };
        Self::from_parts(&base, &suffix).map(Some)
    }

    pub(crate) fn under(root: &Path, relative: &str) -> Result<Option<Self>> {
        let Some((rel_base, suffix)) = split_glob(Path::new(relative)) else {
            return Ok(None);
        };
        Self::from_parts(&root.join_clean(rel_base), &suffix).map(Some)
    }

    fn from_parts(base: &Path, suffix: &str) -> Result<Self> {
        let base = base.clean_lexically();
        let base_str = base.to_string_lossy();
        let needs_sep = !base_str.is_empty()
            && !base_str
                .chars()
                .next_back()
                .is_some_and(|ch| is_separator(ch) || (cfg!(windows) && ch == ':'));
        let sep = if needs_sep { MAIN_SEPARATOR_STR } else { "" };
        let pattern = format!("{base_str}{sep}{suffix}");
        if pattern.len() > MAX_PATTERN_BYTES {
            return Err(PolicyViolation::GlobTooLong.into());
        }
        let suffix_offset = base_str.len() + sep.len();
        let escaped_base = globset::escape(&base_str);
        let compiled = format!("{escaped_base}{sep}{suffix}");
        let (matcher, regex) = compile_pattern(&compiled)?;
        #[cfg(not(target_os = "macos"))]
        drop(regex);
        Ok(Self {
            pattern,
            base,
            suffix_offset,
            matcher,
            #[cfg(target_os = "macos")]
            regex,
        })
    }

    fn suffix(&self) -> &str {
        &self.pattern[self.suffix_offset..]
    }

    pub(crate) fn base(&self) -> &Path {
        &self.base
    }

    pub(crate) fn is_recursive(&self) -> bool {
        self.suffix().contains("**")
    }

    pub(crate) fn matches_path(&self, path: &Path) -> bool {
        self.matcher.is_match(path)
    }

    pub(crate) fn matches_tree(&self, path: &Path) -> bool {
        path.ancestors().any(|ancestor| self.matches_path(ancestor))
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn matches_under(&self, root: &Path) -> bool {
        self.has_unexcused_under(root, |_| true)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn has_unexcused_under(
        &self,
        root: &Path,
        mut is_denied: impl FnMut(&Path) -> bool,
    ) -> bool {
        if self.base.is_under(root) {
            return true;
        }
        if !root.is_under(&self.base) {
            return false;
        }
        let mut matches = Vec::new();
        self.collect_matches(root, &mut matches, 0).is_err()
            || matches.iter().any(|candidate| is_denied(candidate))
    }

    pub(crate) fn expand(&self) -> Result<Vec<PathBuf>> {
        let mut matches = Vec::new();

        match fs::symlink_metadata(&self.base) {
            Ok(_) => self.collect_matches(&self.base, &mut matches, 0)?,
            Err(error) if error.is_opaque() || error.kind() == io::ErrorKind::NotADirectory => {}
            Err(source) => return Err(Error::policy_io(source)),
        }

        Ok(matches)
    }

    fn collect_matches(&self, path: &Path, matches: &mut Vec<PathBuf>, depth: u32) -> Result<()> {
        const LIMIT: u32 = 40;

        if depth >= LIMIT {
            return Err(PolicyViolation::TraversalDepth.into());
        }

        let remaining_depth = (LIMIT - depth) as usize;
        let mut walk = walkdir::WalkDir::new(path)
            .follow_links(false)
            .follow_root_links(false)
            .into_iter();
        let mut directory = None;
        while let Some(result) = walk.next() {
            // Walkdir yields directories before reporting failures to open them.
            let previous_directory = directory.take();
            let entry = match result {
                Ok(entry) => entry,
                Err(error) => {
                    let opening_directory =
                        error.path().is_some() && error.path() == previous_directory.as_deref();
                    let metadata_failed = error.path().is_some() && !opening_directory;
                    if metadata_failed {
                        if error.depth() >= remaining_depth {
                            return Err(PolicyViolation::TraversalDepth.into());
                        }
                        if let Some(path) = error.path() {
                            let candidate = path.clean_lexically();
                            if self.matches_path(&candidate) {
                                matches.push(candidate);
                            }
                        }
                    }
                    if let Some(source) = error.io_error()
                        && (source.is_transport_failed()
                            || (opening_directory
                                && source.kind() == io::ErrorKind::PermissionDenied)
                            || (metadata_failed && source.is_opaque()))
                    {
                        continue;
                    }
                    return Err(Error::policy_io(error.into()));
                }
            };
            if entry.depth() >= remaining_depth {
                return Err(PolicyViolation::TraversalDepth.into());
            }
            let candidate = entry.path().clean_lexically();
            if self.matches_path(&candidate) {
                matches.push(candidate);
            }

            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.is_opaque() => {
                    if entry.file_type().is_dir() {
                        walk.skip_current_dir();
                    }
                    continue;
                }
                Err(source) => return Err(Error::policy_io(source)),
            };
            if entry.file_type().is_dir() {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    walk.skip_current_dir();
                } else {
                    directory = Some(entry.into_path());
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn sbpl_regex(&self) -> String {
        // Seatbelt uses capturing groups and has no Rust regex Unicode flag.
        let regex = self.regex.strip_prefix("(?-u)").unwrap_or(&self.regex);
        let regex = regex.strip_suffix('$').unwrap_or(regex).replace("(?:", "(");
        if self.pattern.ends_with('/') {
            format!("{regex}$")
        } else {
            format!("{regex}(/.*)?$")
        }
    }

    pub(crate) fn into_spellings(self) -> Result<impl Iterator<Item = Self>> {
        let canonical = self.base.canonicalize_existing_prefix().clean_lexically();
        let alias = (canonical != self.base)
            .then(|| Self::from_parts(&canonical, self.suffix()))
            .transpose()?;
        Ok(std::iter::once(self).chain(alias))
    }
}

impl AsRef<str> for GlobPattern {
    fn as_ref(&self) -> &str {
        &self.pattern
    }
}

impl fmt::Display for GlobPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pattern)
    }
}

pub(crate) trait NormalizePatterns {
    fn normalize_patterns(&mut self);
}

impl NormalizePatterns for Vec<GlobPattern> {
    fn normalize_patterns(&mut self) {
        self.sort_unstable_by(|left, right| left.pattern.cmp(&right.pattern));
        self.dedup();
    }
}

pub(crate) trait OverridesDeny<Rhs: ?Sized> {
    fn overrides_deny(&self, deny: &Rhs) -> bool;
}

impl OverridesDeny<Path> for Path {
    fn overrides_deny(&self, deny: &Path) -> bool {
        self.is_under(deny)
    }
}

impl OverridesDeny<GlobPattern> for Path {
    fn overrides_deny(&self, deny: &GlobPattern) -> bool {
        deny.matches_tree(self)
    }
}

impl OverridesDeny<Path> for GlobPattern {
    fn overrides_deny(&self, deny: &Path) -> bool {
        self.base.is_under(deny)
    }
}

impl OverridesDeny<GlobPattern> for GlobPattern {
    fn overrides_deny(&self, deny: &GlobPattern) -> bool {
        if self.base.is_strictly_under(&deny.base) {
            return true;
        }
        if self.base != deny.base {
            return false;
        }
        let allow_tail = self.suffix();
        let deny_tail = deny.suffix();
        self.pattern == deny.pattern
            || (!allow_tail.contains("**") && deny_tail.contains("**"))
            || self.pattern.len() >= deny.pattern.len()
    }
}

impl OverridesDeny<PathBuf> for Path {
    fn overrides_deny(&self, deny: &PathBuf) -> bool {
        self.overrides_deny(deny.as_path())
    }
}

impl OverridesDeny<PathBuf> for GlobPattern {
    fn overrides_deny(&self, deny: &PathBuf) -> bool {
        self.overrides_deny(deny.as_path())
    }
}

impl<Rhs: ?Sized> OverridesDeny<Rhs> for PathBuf
where
    Path: OverridesDeny<Rhs>,
{
    fn overrides_deny(&self, deny: &Rhs) -> bool {
        self.as_path().overrides_deny(deny)
    }
}
