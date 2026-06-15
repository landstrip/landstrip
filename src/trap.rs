// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) type Result<T> = std::result::Result<T, Trap>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TrapOperation {
    Read,
    Write,
}

#[derive(Debug, Serialize)]
pub(crate) enum Trap {
    Filesystem(TrapOperation, PathBuf, String),
    Network(String, String, String),
    Launch(String, String),
    Usage(String),
    Internal(BTreeMap<String, String>),
}

impl Trap {
    pub(crate) fn internal() -> Self {
        Self::Internal(BTreeMap::new())
    }

    pub(crate) fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        if let Self::Internal(detail) = &mut self {
            detail.insert(key.into(), value.into());
        }
        self
    }

    pub(crate) fn emit(&self) {
        eprintln!("{}", serde_json::to_string(self).unwrap_or_default());
    }

    pub(crate) fn is_usage(&self) -> bool {
        matches!(self, Self::Usage(_))
    }

    pub(crate) fn tool_exec(program: Option<OsString>, error: &io::Error) -> Self {
        let program = program
            .map(|program| program.to_string_lossy().into_owned())
            .unwrap_or_default();
        if error.kind() == io::ErrorKind::NotFound {
            Self::Launch(program, error.to_string())
        } else {
            Self::internal()
                .with_detail("program", program)
                .with_detail("source", error.to_string())
        }
    }

    pub(crate) fn policy_stdin_source(source: impl fmt::Display) -> Self {
        Self::internal().with_detail("source", source.to_string())
    }

    pub(crate) fn policy_file_source(path: &Path, source: impl fmt::Display) -> Self {
        Self::internal()
            .with_detail("file", path.to_string_lossy())
            .with_detail("source", source.to_string())
    }
}

impl fmt::Display for Trap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&serde_json::to_string(self).unwrap_or_default())
    }
}

impl From<io::Error> for Trap {
    fn from(error: io::Error) -> Self {
        Self::internal().with_detail("source", error.to_string())
    }
}
