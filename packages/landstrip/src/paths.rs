// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::fs;
use std::path::{Component, Path, PathBuf};

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

        let mut existing = self.to_path_buf();
        let mut missing = Vec::new();
        while !existing.as_os_str().is_empty() {
            if let Ok(canonical) = fs::canonicalize(&existing) {
                let mut result = canonical;
                result.extend(missing.into_iter().rev());
                return result;
            }
            if let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) {
                missing.push(name.to_os_string());
                existing = parent.to_path_buf();
            } else {
                break;
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
        let mut normalized = PathBuf::new();

        for component in self.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => match normalized.components().next_back() {
                    Some(Component::Normal(_) | Component::CurDir) => {
                        normalized.pop();
                    }
                    Some(Component::RootDir | Component::Prefix(_)) => {}
                    Some(Component::ParentDir) | None => {
                        if !self.has_root() {
                            normalized.push(Component::ParentDir.as_os_str());
                        }
                    }
                },
                _ => normalized.push(component.as_os_str()),
            }
        }

        normalized
    }
}

pub(crate) trait NormalizeRoots {
    fn normalize_roots(&mut self);
}

impl NormalizeRoots for Vec<PathBuf> {
    fn normalize_roots(&mut self) {
        for path in self.iter_mut() {
            *path = path.clean_lexically();
        }
        self.sort_unstable();
        self.dedup();
    }
}
