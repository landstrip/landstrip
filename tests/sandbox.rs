// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use duct::{Expression, cmd};
use std::path::{Path, PathBuf};

#[test]
fn sandbox_script() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let landstrip = env!("CARGO_BIN_EXE_landstrip");

    sandbox_command(&repo_root)
        .dir(&repo_root)
        .env("LANDSTRIP_BIN", landstrip)
        .run()
        .expect("sandbox script failed");
}

#[cfg(windows)]
fn sandbox_command(repo_root: &Path) -> Expression {
    cmd(
        "pwsh",
        [
            "-NoProfile".to_owned(),
            "-File".to_owned(),
            repo_root
                .join("tests")
                .join("sandbox.ps1")
                .to_string_lossy()
                .into_owned(),
        ],
    )
}

#[cfg(not(windows))]
fn sandbox_command(repo_root: &Path) -> Expression {
    cmd(
        "sh",
        [repo_root
            .join("tests")
            .join("sandbox.sh")
            .to_string_lossy()
            .into_owned()],
    )
}
