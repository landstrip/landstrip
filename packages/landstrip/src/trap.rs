// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! The trap record: one JSON object per landstrip event, tagged by `kind` and
//! carrying the stable [`Error`] code of the event it reports.

use crate::error::{Error, Mechanism};
#[cfg(target_os = "linux")]
use crate::policy::DenialReason;
#[cfg(unix)]
use crate::trap_fd::TrapFd;
use serde::Serialize;
use std::fmt;
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// The code reported for an error the landstrip code space cannot name.
const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
#[cfg(target_os = "linux")]
const FILESYSTEM_DENIED: &str = "FILESYSTEM_DENIED";
#[cfg(target_os = "linux")]
const NETWORK_DENIED: &str = "NETWORK_DENIED";
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TrapState {
    Query,
    Info,
}

#[cfg(target_os = "linux")]
impl TrapState {
    fn from_query_id(query_id: Option<u64>) -> (Self, String) {
        match query_id {
            Some(id) => (Self::Query, id.to_string()),
            None => (Self::Info, "0".to_owned()),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TrapOperation {
    Read,
    Write,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SuggestedGrant {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) allow_read: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) allow_write: Option<String>,
}

#[cfg(target_os = "linux")]
impl TrapOperation {
    fn suggested_grant(self, path: &str) -> SuggestedGrant {
        match self {
            Self::Read => SuggestedGrant {
                allow_read: Some(path.to_owned()),
                allow_write: None,
            },
            Self::Write => SuggestedGrant {
                allow_read: None,
                allow_write: Some(path.to_owned()),
            },
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, strum::IntoStaticStr)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "snake_case")]
pub(crate) enum NetworkOperation {
    Connect,
    Bind,
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
    pub(crate) state: TrapState,
    pub(crate) query_id: String,
    pub(crate) operation: TrapOperation,
    pub(crate) path: String,
    pub(crate) requested_path: String,
    pub(crate) syscall: &'static str,
    pub(crate) errno: &'static str,
    pub(crate) flags: Vec<&'static str>,
    pub(crate) reason: DenialReason,
    pub(crate) suggested_grant: SuggestedGrant,
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
    pub(crate) reason: DenialReason,
    pub(crate) process: ProcessContext,
}

#[cfg(target_os = "linux")]
impl FilesystemDenial {
    pub(crate) fn into_trap(self, query_id: Option<u64>) -> Trap {
        let path = self.path.to_string_lossy();
        let suggested_grant = self.operation.suggested_grant(&path);
        let (state, query_id) = TrapState::from_query_id(query_id);
        Trap::Filesystem(Box::new(FilesystemTrap {
            code: FILESYSTEM_DENIED,
            state,
            query_id,
            operation: self.operation,
            path: path.into_owned(),
            requested_path: self.requested_path.to_string_lossy().into_owned(),
            syscall: self.syscall,
            errno: Error::DENIAL_ERRNO_NAME,
            flags: self.flags,
            reason: self.reason,
            suggested_grant,
            process: self.process,
            mechanism: Mechanism::Seccomp,
        }))
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
pub(crate) struct NetworkTrap {
    pub(crate) code: &'static str,
    pub(crate) state: TrapState,
    pub(crate) query_id: String,
    pub(crate) operation: NetworkOperation,
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
    Launch(LaunchTrap),
    Usage(UsageTrap),
    Internal(InternalTrap),
}

impl Trap {
    #[cfg(target_os = "linux")]
    pub(crate) fn filesystem(denial: FilesystemDenial, query_id: Option<u64>) -> Self {
        denial.into_trap(query_id)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn network(
        operation: NetworkOperation,
        target: String,
        process: ProcessContext,
        query_id: Option<u64>,
    ) -> Self {
        let syscall = operation.into();
        let (state, query_id) = TrapState::from_query_id(query_id);
        Self::Network(Box::new(NetworkTrap {
            code: NETWORK_DENIED,
            state,
            query_id,
            operation,
            target,
            syscall,
            errno: Error::DENIAL_ERRNO_NAME,
            mechanism: Mechanism::Seccomp,
            process,
        }))
    }

    /// The trap for a failure the landstrip code space does not name.
    pub(crate) fn internal(message: String) -> Self {
        Self::Internal(InternalTrap {
            code: INTERNAL_ERROR,
            mechanism: None,
            message,
        })
    }

    pub(crate) fn to_json(&self) -> String {
        match serde_json::to_string(self) {
            Ok(line) => line,
            Err(error) => {
                log::error!("trap: serialize: {error}");
                r#"{"kind":"internal","code":"INTERNAL_ERROR","message":"failed to serialize trap"}"#
                    .to_owned()
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn emit_with_fd(&self, trap_fd: Option<&TrapFd>) {
        if let Some(trap_fd) = trap_fd
            && let Err(error) = trap_fd.write(self)
        {
            log::debug!("trap fd write failed: {error}");
        }
        self.emit();
    }

    pub(crate) fn emit(&self) {
        let _ = writeln!(io::stderr().lock(), "{self}");
    }
}

impl From<Error> for Trap {
    fn from(error: Error) -> Self {
        Self::from(&error)
    }
}

impl From<&Error> for Trap {
    fn from(error: &Error) -> Self {
        match error {
            Error::Usage { message } => Self::Usage(UsageTrap {
                code: error.code(),
                message: message.clone(),
            }),
            Error::LaunchFailed { tool, source } => Self::Launch(LaunchTrap {
                code: error.code(),
                program: tool.to_string_lossy().into_owned(),
                errno: error.errno_name(),
                message: source.to_string(),
            }),
            Error::SandboxSetupFailed { mechanism, .. } => Self::Internal(InternalTrap {
                code: error.code(),
                mechanism: Some(*mechanism),
                message: error.message(),
            }),
            _ => Self::Internal(InternalTrap {
                code: error.code(),
                mechanism: None,
                message: error.message(),
            }),
        }
    }
}

impl From<&anyhow::Error> for Trap {
    fn from(error: &anyhow::Error) -> Self {
        Error::find_in(error).map_or_else(|| Self::internal(format!("{error:#}")), Self::from)
    }
}

impl fmt::Display for Trap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_json())
    }
}
