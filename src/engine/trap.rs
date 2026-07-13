// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! The trap record: one JSON object per landstrip event, tagged by `kind` and
//! carrying the stable [`Error`] code of the event it reports.

use crate::engine::error::{Error, Mechanism, errno_name};
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::error::Error as StdError;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// The code reported for an error the landstrip code space cannot name.
const INTERNAL_ERROR: &str = "INTERNAL_ERROR";

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TrapOperation {
    Read,
    Write,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, strum_macros::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum NetworkOperation {
    Connect,
    Bind,
}

#[cfg(target_os = "linux")]
impl NetworkOperation {
    fn syscall(self) -> &'static str {
        self.into()
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct ProcessContext {
    pub(crate) pid: u32,
    pub(crate) exe: Option<String>,
    pub(crate) cwd: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
pub(crate) struct FilesystemTrap {
    pub(crate) code: &'static str,
    pub(crate) state: &'static str,
    pub(crate) query_id: String,
    pub(crate) operation: TrapOperation,
    pub(crate) path: String,
    pub(crate) requested_path: String,
    pub(crate) syscall: &'static str,
    pub(crate) errno: &'static str,
    pub(crate) flags: Vec<&'static str>,
    pub(crate) reason: &'static str,
    pub(crate) suggested_grant: BTreeMap<&'static str, String>,
    pub(crate) process: ProcessContext,
    pub(crate) mechanism: Mechanism,
}

/// A denied filesystem access, shared by the immediate query trap and the
/// deferred denial record so both describe the event with the same fields.
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
pub(crate) struct NetworkTrap {
    pub(crate) code: &'static str,
    pub(crate) state: &'static str,
    pub(crate) query_id: String,
    pub(crate) operation: &'static str,
    pub(crate) target: String,
    pub(crate) syscall: &'static str,
    pub(crate) errno: &'static str,
    pub(crate) mechanism: Mechanism,
    pub(crate) process: ProcessContext,
}

/// The tool did not start.
#[derive(Debug, Serialize)]
pub(crate) struct LaunchTrap {
    pub(crate) code: &'static str,
    pub(crate) program: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) errno: Option<&'static str>,
    pub(crate) message: String,
}

/// The command line was rejected.
#[derive(Debug, Serialize)]
pub(crate) struct UsageTrap {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

/// Everything that fails before the tool runs: a policy landstrip cannot parse,
/// resolve, or enforce, and any sandbox it cannot install.
#[derive(Debug, Serialize)]
pub(crate) struct InternalTrap {
    pub(crate) code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mechanism: Option<Mechanism>,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(crate) enum Trap {
    #[cfg(target_os = "linux")]
    Filesystem(Box<FilesystemTrap>),
    #[cfg(target_os = "linux")]
    Network(Box<NetworkTrap>),
    Launch(Box<LaunchTrap>),
    Usage(Box<UsageTrap>),
    Internal(Box<InternalTrap>),
}

impl Trap {
    #[cfg(target_os = "linux")]
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
        let path = path.to_string_lossy().into_owned();
        let requested_path = requested_path.to_string_lossy().into_owned();
        let mut suggested_grant = BTreeMap::new();
        suggested_grant.insert(grant_key, path.clone());
        Self::Filesystem(Box::new(FilesystemTrap {
            code: Error::FilesystemDenied.code(),
            state: if query_id.is_some() { "query" } else { "info" },
            query_id: query_id.unwrap_or(0).to_string(),
            operation,
            path,
            requested_path,
            syscall,
            errno: denial_errno(),
            flags,
            reason,
            suggested_grant,
            process,
            mechanism: Mechanism::Seccomp,
        }))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn network(
        operation: NetworkOperation,
        target: String,
        process: ProcessContext,
        query_id: Option<u64>,
    ) -> Self {
        let syscall = operation.syscall();
        Self::Network(Box::new(NetworkTrap {
            code: Error::NetworkDenied.code(),
            state: if query_id.is_some() { "query" } else { "info" },
            query_id: query_id.unwrap_or(0).to_string(),
            operation: syscall,
            target,
            syscall,
            errno: denial_errno(),
            mechanism: Mechanism::Seccomp,
            process,
        }))
    }

    /// The trap that reports `error`, routed by the stage the code names.
    pub(crate) fn from_error(error: &Error) -> Self {
        match error {
            Error::Usage { message } => Self::Usage(Box::new(UsageTrap {
                code: error.code(),
                message: message.clone(),
            })),
            Error::LaunchFailed { tool, source } => Self::Launch(Box::new(LaunchTrap {
                code: error.code(),
                program: tool.to_string_lossy().into_owned(),
                errno: error.errno().and_then(errno_name),
                message: source.to_string(),
            })),
            Error::SandboxSetupFailed { mechanism, .. } => Self::Internal(Box::new(InternalTrap {
                code: error.code(),
                mechanism: Some(*mechanism),
                message: message(error),
            })),
            _ => Self::Internal(Box::new(InternalTrap {
                code: error.code(),
                mechanism: None,
                message: message(error),
            })),
        }
    }

    /// The trap for a failure the landstrip code space does not name.
    pub(crate) fn internal(message: String) -> Self {
        Self::Internal(Box::new(InternalTrap {
            code: INTERNAL_ERROR,
            mechanism: None,
            message,
        }))
    }

    pub(crate) fn json_line(&self) -> String {
        match serde_json::to_string(self) {
            Ok(line) => line,
            Err(error) => {
                log::error!("trap: serialize: {error}");
                r#"{"kind":"internal","code":"INTERNAL_ERROR","message":"failed to serialize trap"}"#
                    .to_owned()
            }
        }
    }

    pub(crate) fn emit_json(line: &str) {
        eprintln!("{line}");
    }

    pub(crate) fn emit(&self) {
        Self::emit_json(&self.json_line());
    }
}

/// The symbolic errno a denial surfaces in the sandboxed child.
#[cfg(target_os = "linux")]
fn denial_errno() -> &'static str {
    errno_name(Error::DENIAL_ERRNO).unwrap_or("EACCES")
}

/// The detail behind the code: the variant's data and its causes as one line,
/// for a human reading the trap. The code itself is the `code` field.
fn message(error: &Error) -> String {
    let mut message = error.detail().unwrap_or_default();
    let mut cause = StdError::source(error);

    while let Some(source) = cause {
        if !message.is_empty() {
            message.push_str(": ");
        }
        message.push_str(&source.to_string());
        cause = source.source();
    }

    if message.is_empty() {
        return error.code().to_owned();
    }

    message
}
