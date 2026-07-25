// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::fs;
use std::path::{Component, Path, PathBuf};

pub(crate) fn normalize_roots(paths: &mut Vec<PathBuf>) {
    for path in paths.iter_mut() {
        *path = normalize_path(path);
    }

    paths.sort_unstable();
    paths.dedup();
}

pub(crate) fn normalize_path(path: &Path) -> PathBuf {
    if cfg!(not(target_os = "macos"))
        && let Ok(canonical) = fs::canonicalize(path)
    {
        return canonical;
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
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }

    normalized
}
