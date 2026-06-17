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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum TrapOperation {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum NetworkOperation {
    Connect,
    Bind,
}

impl NetworkOperation {
    fn code(self) -> &'static str {
        match self {
            Self::Connect => "NET_CONNECT_DENIED",
            Self::Bind => "NET_BIND_DENIED",
        }
    }

    fn syscall(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Bind => "bind",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct ProcessContext {
    pub(crate) pid: u32,
    pub(crate) exe: Option<PathBuf>,
    pub(crate) cwd: Option<PathBuf>,
}
#[derive(Debug, Serialize)]
pub(crate) struct FilesystemTrap {
    pub(crate) code: &'static str,
    pub(crate) operation: TrapOperation,
    pub(crate) path: PathBuf,
    pub(crate) requested_path: PathBuf,
    pub(crate) syscall: &'static str,
    pub(crate) errno: &'static str,
    pub(crate) flags: Vec<&'static str>,
    pub(crate) reason: &'static str,
    pub(crate) suggested_grant: BTreeMap<&'static str, PathBuf>,
    pub(crate) process: ProcessContext,
    pub(crate) mechanism: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct NetworkTrap {
    pub(crate) code: &'static str,
    pub(crate) operation: &'static str,
    pub(crate) target: String,
    pub(crate) syscall: &'static str,
    pub(crate) errno: &'static str,
    pub(crate) mechanism: &'static str,
    pub(crate) process: ProcessContext,
}

#[derive(Debug, Serialize)]
pub(crate) enum Trap {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Filesystem(Box<FilesystemTrap>),
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Network(Box<NetworkTrap>),
    Launch(String, String),
    Usage(String),
    Internal(BTreeMap<String, String>),
}

impl Trap {
    pub(crate) fn internal() -> Self {
        Self::Internal(BTreeMap::new())
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn filesystem(
        operation: TrapOperation,
        path: PathBuf,
        requested_path: PathBuf,
        syscall: &'static str,
        flags: Vec<&'static str>,
        reason: &'static str,
        process: ProcessContext,
    ) -> Self {
        let code = match operation {
            TrapOperation::Read => "FS_READ_DENIED",
            TrapOperation::Write => "FS_WRITE_DENIED",
        };
        let grant_key = match operation {
            TrapOperation::Read => "allowRead",
            TrapOperation::Write => "allowWrite",
        };
        let mut suggested_grant = BTreeMap::new();
        suggested_grant.insert(grant_key, path.clone());
        Self::Filesystem(Box::new(FilesystemTrap {
            code,
            operation,
            path,
            requested_path,
            syscall,
            errno: "EACCES",
            flags,
            reason,
            suggested_grant,
            process,
            mechanism: "seccomp",
        }))
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn network(
        operation: NetworkOperation,
        target: String,
        process: ProcessContext,
    ) -> Self {
        Self::Network(Box::new(NetworkTrap {
            code: operation.code(),
            operation: operation.syscall(),
            target,
            syscall: operation.syscall(),
            errno: "EACCES",
            mechanism: "seccomp",
            process,
        }))
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

    #[cfg_attr(not(unix), allow(dead_code))]
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
