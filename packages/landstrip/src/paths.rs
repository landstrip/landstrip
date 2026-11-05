// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::fs;
use std::path::{Path, PathBuf};

pub(crate) mod glob;

pub(crate) use glob::{GlobPattern, GlobPatternBuf, NormalizePatterns, OverridesDeny};

pub(crate) trait PathExt {
    fn is_under(&self, root: impl AsRef<Path>) -> bool;
    fn is_strictly_under(&self, root: impl AsRef<Path>) -> bool;

    fn is_under_any<I>(&self, roots: I) -> bool
    where
        I: IntoIterator,
        I::Item: AsRef<Path>,
    {
        roots.into_iter().any(|root| self.is_under(root))
    }

    fn normalize(&self) -> PathBuf;
    fn clean_lexically(&self) -> PathBuf;
    fn canonicalize_existing_prefix(&self) -> PathBuf;
    fn spellings(&self) -> impl Iterator<Item = PathBuf>;
}

impl PathExt for Path {
    fn is_under(&self, root: impl AsRef<Path>) -> bool {
        self.starts_with(root)
    }

    fn is_strictly_under(&self, root: impl AsRef<Path>) -> bool {
        let root = root.as_ref();
        self.starts_with(root) && self != root
    }

    fn canonicalize_existing_prefix(&self) -> PathBuf {
        if let Ok(canonical) = fs::canonicalize(self) {
            return canonical;
        }

        let mut existing = self;
        let mut missing = Vec::new();
        while let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) {
            missing.push(name);
            existing = parent;
            if existing.as_os_str().is_empty() {
                break;
            }
            if let Ok(mut canonical) = fs::canonicalize(existing) {
                canonical.extend(missing.into_iter().rev());
                return canonical;
            }
        }

        self.clean_lexically()
    }

    fn normalize(&self) -> PathBuf {
        if cfg!(not(target_os = "macos")) {
            return self.canonicalize_existing_prefix();
        }

        self.clean_lexically()
    }

    fn clean_lexically(&self) -> PathBuf {
        let cleaned = path_clean::clean(self);
        if cleaned == Path::new(".") {
            PathBuf::new()
        } else {
            cleaned
        }
    }

    fn spellings(&self) -> impl Iterator<Item = PathBuf> {
        #[cfg(target_os = "macos")]
        {
            let lexical = self.clean_lexically();
            let canonical = self.canonicalize_existing_prefix().clean_lexically();
            let alias = (canonical != lexical).then_some(canonical);
            std::iter::once(lexical).chain(alias)
        }
        #[cfg(not(target_os = "macos"))]
        {
            std::iter::once(self.normalize()).chain(None)
        }
    }
}

pub(crate) trait NormalizeRoots {
    fn normalize_roots(&mut self);

    #[cfg(target_os = "windows")]
    fn retain_windows_allow_roots(&mut self);

    #[cfg(target_os = "windows")]
    fn retain_windows_deny_roots(&mut self);
}

impl NormalizeRoots for Vec<PathBuf> {
    fn normalize_roots(&mut self) {
        for path in self.iter_mut() {
            *path = path.clean_lexically();
        }
        self.sort_unstable();
        self.dedup();
    }

    #[cfg(target_os = "windows")]
    fn retain_windows_allow_roots(&mut self) {
        self.retain(|path| path.try_exists().unwrap_or(false));
    }

    #[cfg(target_os = "windows")]
    fn retain_windows_deny_roots(&mut self) {
        self.retain(|path| path.parent().is_some() && path.try_exists().unwrap_or(true));
    }
}
