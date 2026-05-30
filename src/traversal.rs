// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use crate::paths::normalize_roots;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) fn subtract_denied_roots(
    mut allowed: Vec<PathBuf>,
    denied: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    normalize_roots(&mut allowed);
    let mut denied = denied.to_vec();
    normalize_roots(&mut denied);
    let mut roots = Vec::new();

    for root in allowed {
        roots.extend(scan_allowed_root(&root, &denied, true)?);
    }

    normalize_roots(&mut roots);

    Ok(roots)
}

fn scan_allowed_root(
    root: &Path,
    denied: &[PathBuf],
    is_explicit_root: bool,
) -> Result<Vec<PathBuf>> {
    if denied
        .iter()
        .any(|denied_root| root == denied_root || root.starts_with(denied_root))
    {
        return Ok(Vec::new());
    }

    let has_denied_descendant = denied
        .iter()
        .any(|denied_root| denied_root.starts_with(root));

    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(vec![root.to_path_buf()]);
        }
        Err(source) => {
            return Err(Error::with_source(
                format!("traversal: {}", root.display()),
                source,
            ));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() && !is_explicit_root {
        return Ok(Vec::new());
    }
    if !has_denied_descendant {
        return Ok(vec![root.to_path_buf()]);
    }
    if !file_type.is_dir() {
        return Ok(vec![root.to_path_buf()]);
    }

    let mut roots = Vec::new();
    let entries = fs::read_dir(root)
        .map_err(|source| Error::with_source(format!("traversal: {}", root.display()), source))?;

    for entry in entries {
        let entry = entry.map_err(|source| {
            Error::with_source(format!("traversal: {}", root.display()), source)
        })?;
        let child = entry.path();
        roots.extend(scan_allowed_root(&child, denied, false)?);
    }

    Ok(roots)
}
