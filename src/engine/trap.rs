// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::engine::error::Error;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TrapOperation {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, strum_macros::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum NetworkOperation {
    Connect,
    Bind,
}

impl NetworkOperation {
    fn syscall(self) -> &'static str {
        self.into()
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
    pub(crate) code: Error,
    pub(crate) state: &'static str,
    pub(crate) query_id: u64,
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

/// A denied filesystem access, shared by the immediate query trap and the
/// deferred denial record so both describe the event with the same fields.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FilesystemDenial {
    pub(crate) operation: TrapOperation,
    pub(crate) path: PathBuf,
    pub(crate) requested_path: PathBuf,
    pub(crate) syscall: &'static str,
    pub(crate) flags: Vec<&'static str>,
    pub(crate) reason: &'static str,
    pub(crate) process: ProcessContext,
}

#[derive(Debug, Serialize)]
pub(crate) struct NetworkTrap {
    pub(crate) code: Error,
    pub(crate) state: &'static str,
    pub(crate) query_id: u64,
    pub(crate) operation: &'static str,
    pub(crate) target: String,
    pub(crate) syscall: &'static str,
    pub(crate) errno: &'static str,
    pub(crate) mechanism: &'static str,
    pub(crate) process: ProcessContext,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(crate) enum Trap {
    Filesystem(Box<FilesystemTrap>),
    Network(Box<NetworkTrap>),
}

impl Trap {
    pub(crate) fn filesystem(denial: FilesystemDenial, query_id: Option<u64>) -> Self {
        let FilesystemDenial {
            operation,
            path,
            requested_path,
            syscall,
            flags,
            reason,
            process,
        } = denial;
        let grant_key = match operation {
            TrapOperation::Read => "allowRead",
            TrapOperation::Write => "allowWrite",
        };
        let mut suggested_grant = BTreeMap::new();
        suggested_grant.insert(grant_key, path.clone());
        Self::Filesystem(Box::new(FilesystemTrap {
            code: Error::FilesystemDenied,
            state: if query_id.is_some() { "query" } else { "info" },
            query_id: query_id.unwrap_or(0),
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

    pub(crate) fn network(
        operation: NetworkOperation,
        target: String,
        process: ProcessContext,
        query_id: Option<u64>,
    ) -> Self {
        let syscall = operation.syscall();
        Self::Network(Box::new(NetworkTrap {
            code: Error::NetworkDenied,
            state: if query_id.is_some() { "query" } else { "info" },
            query_id: query_id.unwrap_or(0),
            operation: syscall,
            target,
            syscall,
            errno: "EACCES",
            mechanism: "seccomp",
            process,
        }))
    }

    pub(crate) fn emit(&self) {
        eprintln!("{}", serde_json::to_string(self).unwrap_or_default());
    }
}
