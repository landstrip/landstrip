// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::fs;
use std::path::{Component, Path, PathBuf};

pub(crate) trait PathCoverage {
    fn is_under(&self, root: impl AsRef<Path>) -> bool;
    fn is_strictly_under(&self, root: impl AsRef<Path>) -> bool;

    fn is_under_any<I>(&self, roots: I) -> bool
    where
        I: IntoIterator,
        I::Item: AsRef<Path>,
    {
        roots.into_iter().any(|root| self.is_under(root))
    }
}

impl PathCoverage for Path {
    fn is_under(&self, root: impl AsRef<Path>) -> bool {
        self.starts_with(root)
    }

    fn is_strictly_under(&self, root: impl AsRef<Path>) -> bool {
        let root = root.as_ref();
        self.starts_with(root) && self != root
    }
}

pub(crate) fn normalize_roots(paths: &mut Vec<PathBuf>) {
    for path in paths.iter_mut() {
        *path = normalize_path_lexically(path);
    }

    paths.sort_unstable();
    paths.dedup();
}

pub(crate) fn normalize_path(path: &Path) -> PathBuf {
    if cfg!(not(target_os = "macos")) {
        if let Ok(canonical) = fs::canonicalize(path) {
            return canonical;
        }

        let mut existing = path.to_path_buf();
        let mut missing = Vec::new();
        while !existing.as_os_str().is_empty() {
            if let Ok(canonical) = fs::canonicalize(&existing) {
                let mut result = canonical;
                for component in missing.into_iter().rev() {
                    result.push(component);
                }
                return result;
            }
            if let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) {
                missing.push(name.to_os_string());
                existing = parent.to_path_buf();
            } else {
                break;
            }
        }
    }

    normalize_path_lexically(path)
}

/// Like [`normalize_path`] but never follows a terminal symlink: the parent is
/// canonicalized while the final component is kept verbatim. Used for no-follow
/// metadata syscalls (`lchown`, `fchownat`/`utimensat` with `AT_SYMLINK_NOFOLLOW`)
/// so the policy decision and broker target the symlink itself, not what it
/// points to.
#[cfg(target_os = "linux")]
pub(crate) fn normalize_path_nofollow(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => normalize_path(parent).join(name),
        _ => normalize_path(path),
    }
}

pub(crate) fn normalize_path_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match normalized.components().next_back() {
                Some(Component::Normal(_) | Component::CurDir) => {
                    normalized.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                Some(Component::ParentDir) | None => {
                    if !path.has_root() {
                        normalized.push(Component::ParentDir.as_os_str());
                    }
                }
            },
            _ => normalized.push(component.as_os_str()),
        }
    }

    normalized
}
