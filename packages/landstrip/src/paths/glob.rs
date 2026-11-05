// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::PathExt;
use crate::error::{Error, PathIo, PolicyViolation, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Serialize;
use std::borrow::Cow;
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{MAIN_SEPARATOR, MAIN_SEPARATOR_STR, Path, PathBuf};

const MAX_PATTERN_BYTES: usize = 4096;

fn compile_pattern(pattern: &str) -> Result<(GlobSet, String)> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(PolicyViolation::GlobTooLong.into());
    }
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

pub(crate) struct GlobPattern<'a> {
    pattern: &'a str,
    matcher: Cow<'a, GlobSet>,
}

impl<'a> GlobPattern<'a> {
    pub(crate) fn new(pattern: &'a str) -> Result<Self> {
        let (matcher, _) = compile_pattern(pattern)?;
        Ok(Self {
            pattern,
            matcher: Cow::Owned(matcher),
        })
    }

    pub(crate) fn is_glob_byte(byte: u8) -> bool {
        matches!(byte, b'*' | b'?' | b'[' | b']')
    }

    pub(crate) fn is_glob_str(s: &str) -> bool {
        s.bytes().any(Self::is_glob_byte)
    }

    #[allow(dead_code)]
    pub(crate) fn is_recursive(&self) -> bool {
        self.pattern.contains("**")
    }

    pub(crate) fn base(&self) -> PathBuf {
        let (prefix, tail) = self.split_literal_prefix();
        if tail.is_empty() {
            return PathBuf::from(prefix);
        }
        let mut base = if prefix.ends_with(MAIN_SEPARATOR) {
            PathBuf::from(prefix)
        } else {
            Path::new(prefix)
                .parent()
                .map_or_else(|| PathBuf::from(prefix), Path::to_path_buf)
        };

        if base.as_os_str().is_empty() {
            base.push(MAIN_SEPARATOR_STR);
        }

        base
    }

    fn split_literal_prefix(&self) -> (&'a str, &'a [u8]) {
        let at = self
            .pattern
            .bytes()
            .position(Self::is_glob_byte)
            .unwrap_or(self.pattern.len());
        (&self.pattern[..at], &self.pattern.as_bytes()[at..])
    }

    pub(crate) fn matches_path(&self, path: &Path) -> bool {
        self.matcher.is_match(path.to_string_lossy().as_ref())
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
        let base = self.base();
        if base.is_under(root) {
            return true;
        }
        if !root.is_under(&base) {
            return false;
        }
        let mut matches = Vec::new();
        self.collect_matches(root, &mut matches, 0).is_err()
            || matches.iter().any(|candidate| is_denied(candidate))
    }

    pub(crate) fn expand(&self) -> Result<Vec<PathBuf>> {
        let base = self.base();
        let mut matches = Vec::new();

        match fs::symlink_metadata(&base) {
            Ok(_) => self.collect_matches(&base, &mut matches, 0)?,
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

        let candidate = path.clean_lexically();
        if self.matches_path(&candidate) {
            matches.push(candidate);
        }

        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.is_opaque() => return Ok(()),
            Err(source) => return Err(Error::policy_io(source)),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Ok(());
        }

        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || error.is_transport_failed() =>
            {
                return Ok(());
            }
            Err(source) => return Err(Error::policy_io(source)),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.is_transport_failed() => continue,
                Err(source) => return Err(Error::policy_io(source)),
            };
            self.collect_matches(&entry.path(), matches, depth + 1)?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub(crate) struct GlobPatternBuf {
    pattern: String,
    #[serde(skip)]
    matcher: GlobSet,
    #[serde(skip)]
    #[cfg(target_os = "macos")]
    regex: String,
}

impl PartialEq for GlobPatternBuf {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for GlobPatternBuf {}

impl Hash for GlobPatternBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
    }
}

impl GlobPatternBuf {
    pub(crate) fn new(pattern: impl Into<String>) -> Result<Self> {
        let pattern = pattern.into();
        let (matcher, regex) = compile_pattern(&pattern)?;
        #[cfg(not(target_os = "macos"))]
        drop(regex);
        Ok(Self {
            pattern,
            matcher,
            #[cfg(target_os = "macos")]
            regex,
        })
    }

    pub(crate) fn as_glob(&self) -> GlobPattern<'_> {
        GlobPattern {
            pattern: &self.pattern,
            matcher: Cow::Borrowed(&self.matcher),
        }
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

    pub(crate) fn base(&self) -> PathBuf {
        self.as_glob().base()
    }

    #[allow(dead_code)]
    pub(crate) fn is_recursive(&self) -> bool {
        self.as_glob().is_recursive()
    }

    pub(crate) fn matches_tree(&self, path: &Path) -> bool {
        self.as_glob().matches_tree(path)
    }

    pub(crate) fn spellings(&self) -> Result<impl Iterator<Item = Self> + use<'_>> {
        let base = self.base();
        let lexical = base.clean_lexically();
        let canonical = base.canonicalize_existing_prefix().clean_lexically();
        let lexical_str = lexical.to_string_lossy();
        let canonical_str = canonical.to_string_lossy();
        let alias = if canonical == lexical {
            None
        } else {
            self.pattern
                .strip_prefix(lexical_str.as_ref())
                .map(|suffix| {
                    let sep = if !suffix.starts_with(MAIN_SEPARATOR) && lexical_str.as_ref() != "/"
                    {
                        MAIN_SEPARATOR_STR
                    } else {
                        ""
                    };
                    Self::new(format!("{canonical_str}{sep}{suffix}"))
                })
                .transpose()?
        };
        Ok(std::iter::once(self.clone()).chain(alias))
    }
}

impl AsRef<str> for GlobPatternBuf {
    fn as_ref(&self) -> &str {
        &self.pattern
    }
}

impl fmt::Display for GlobPatternBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pattern)
    }
}

pub(crate) trait NormalizePatterns {
    fn normalize_patterns(&mut self);
}

impl NormalizePatterns for Vec<GlobPatternBuf> {
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

impl OverridesDeny<GlobPattern<'_>> for Path {
    fn overrides_deny(&self, deny: &GlobPattern<'_>) -> bool {
        deny.matches_tree(self)
    }
}

impl OverridesDeny<Path> for GlobPattern<'_> {
    fn overrides_deny(&self, deny: &Path) -> bool {
        self.base().is_under(deny)
    }
}

impl OverridesDeny<GlobPattern<'_>> for GlobPattern<'_> {
    fn overrides_deny(&self, deny: &GlobPattern<'_>) -> bool {
        let allow_base = self.base();
        let deny_base = deny.base();
        if allow_base.is_strictly_under(&deny_base) {
            return true;
        }
        if allow_base != deny_base {
            return false;
        }
        let base_str = allow_base.to_string_lossy();
        let allow_tail = self
            .pattern
            .strip_prefix(base_str.as_ref())
            .unwrap_or(self.pattern);
        let deny_tail = deny
            .pattern
            .strip_prefix(base_str.as_ref())
            .unwrap_or(deny.pattern);
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

impl OverridesDeny<GlobPatternBuf> for Path {
    fn overrides_deny(&self, deny: &GlobPatternBuf) -> bool {
        self.overrides_deny(&deny.as_glob())
    }
}

impl OverridesDeny<PathBuf> for GlobPattern<'_> {
    fn overrides_deny(&self, deny: &PathBuf) -> bool {
        self.overrides_deny(deny.as_path())
    }
}

impl OverridesDeny<GlobPatternBuf> for GlobPattern<'_> {
    fn overrides_deny(&self, deny: &GlobPatternBuf) -> bool {
        self.overrides_deny(&deny.as_glob())
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

impl<Rhs: ?Sized> OverridesDeny<Rhs> for GlobPatternBuf
where
    for<'a> GlobPattern<'a>: OverridesDeny<Rhs>,
{
    fn overrides_deny(&self, deny: &Rhs) -> bool {
        self.as_glob().overrides_deny(deny)
    }
}
