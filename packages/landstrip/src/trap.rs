// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! The trap stanza: one blank-line-terminated `key=value` block per landstrip
//! event, carrying `kind` and the stable [`Error`] code of the event.

use crate::error::{Error, Mechanism};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::policy::DenialReason;
#[cfg(unix)]
use crate::trap_fd::TrapFd;
use std::fmt::{self, Write as _};
use std::io::{self, Write};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::path::PathBuf;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::str::FromStr;

/// The code reported for an error the landstrip code space cannot name.
const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const FILESYSTEM_DENIED: &str = "FILESYSTEM_DENIED";
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const NETWORK_DENIED: &str = "NETWORK_DENIED";

struct Stanza<'a, 'b>(&'a mut fmt::Formatter<'b>);

impl Stanza<'_, '_> {
    fn field(&mut self, key: &str, value: &str) -> fmt::Result {
        self.0.write_str(key)?;
        self.0.write_char('=')?;
        for ch in value.chars() {
            match ch {
                '\\' => self.0.write_str(r"\\")?,
                '\n' => self.0.write_str(r"\n")?,
                '\r' => self.0.write_str(r"\r")?,
                other => self.0.write_char(other)?,
            }
        }
        self.0.write_char('\n')
    }

    fn optional(&mut self, key: &str, value: Option<&str>) -> fmt::Result {
        if let Some(value) = value {
            self.field(key, value)?;
        }
        Ok(())
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn display(&mut self, key: &str, value: impl fmt::Display) -> fmt::Result {
        self.0.write_str(key)?;
        self.0.write_char('=')?;
        write!(self.0, "{value}")?;
        self.0.write_char('\n')
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn list(&mut self, key: &str, items: &[&str]) -> fmt::Result {
        if let Some((first, rest)) = items.split_first() {
            self.0.write_str(key)?;
            self.0.write_char('=')?;
            self.0.write_str(first)?;
            for item in rest {
                self.0.write_char(',')?;
                self.0.write_str(item)?;
            }
            self.0.write_char('\n')?;
        }
        Ok(())
    }

    fn finish(self) -> fmt::Result {
        self.0.write_char('\n')
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum TrapState {
    Query(u64),
    Info,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl From<Option<u64>> for TrapState {
    fn from(query_id: Option<u64>) -> Self {
        query_id.map_or(Self::Info, Self::Query)
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl TrapState {
    fn write_fields(self, stanza: &mut Stanza<'_, '_>) -> fmt::Result {
        match self {
            Self::Query(query_id) => {
                stanza.field("state", "query")?;
                stanza.display("query_id", query_id)
            }
            Self::Info => stanza.field("state", "info"),
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, strum::IntoStaticStr)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum TrapOperation {
    Read,
    Write,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, strum::IntoStaticStr)]
#[strum(serialize_all = "lowercase")]
pub(crate) enum NetworkOperation {
    Connect,
    Bind,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ProcessContext {
    pub(crate) pid: u32,
    pub(crate) exe: Option<String>,
    pub(crate) cwd: Option<String>,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl ProcessContext {
    fn write_fields(&self, stanza: &mut Stanza<'_, '_>) -> fmt::Result {
        stanza.display("pid", self.pid)?;
        stanza.optional("exe", self.exe.as_deref())?;
        stanza.optional("cwd", self.cwd.as_deref())
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[derive(Debug)]
pub(crate) struct FilesystemTrap {
    pub(crate) code: &'static str,
    pub(crate) state: TrapState,
    pub(crate) operation: TrapOperation,
    pub(crate) path: String,
    pub(crate) requested_path: Option<String>,
    pub(crate) syscall: &'static str,
    pub(crate) errno: &'static str,
    pub(crate) flags: Vec<&'static str>,
    pub(crate) reason: DenialReason,
    pub(crate) mechanism: Mechanism,
    pub(crate) process: ProcessContext,
}

/// The answer a responder writes back for a query trap.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplyAction {
    Allow,
    Deny,
}

/// One responder answer stanza.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Reply {
    pub(crate) query_id: u64,
    pub(crate) action: ReplyAction,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl Reply {
    fn unescape(raw: &str) -> Result<String, &'static str> {
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    _ => return Err("invalid escape sequence"),
                }
            } else {
                out.push(ch);
            }
        }
        Ok(out)
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl FromStr for Reply {
    type Err = &'static str;

    fn from_str(stanza: &str) -> Result<Self, Self::Err> {
        let mut query_id = None;
        let mut action = None;
        for line in stanza.lines() {
            if line.is_empty() {
                continue;
            }
            let (key, raw_value) = line.split_once('=').ok_or("missing '=' in reply")?;
            let value = Self::unescape(raw_value)?;
            match key {
                "query_id" => {
                    if query_id.is_some() {
                        return Err("duplicate query_id");
                    }
                    let parsed = value.parse::<u64>().map_err(|_| "invalid query_id")?;
                    if parsed == 0 {
                        return Err("zero query_id");
                    }
                    query_id = Some(parsed);
                }
                "action" => {
                    if action.is_some() {
                        return Err("duplicate action");
                    }
                    action = Some(if value == "allow" {
                        ReplyAction::Allow
                    } else {
                        ReplyAction::Deny
                    });
                }
                _ => {}
            }
        }
        Ok(Self {
            query_id: query_id.ok_or("missing query_id")?,
            action: action.ok_or("missing action")?,
        })
    }
}

/// A denied filesystem access, shared by the immediate query trap and the
/// deferred denial record so both describe the event with the same fields.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
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

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl FilesystemDenial {
    pub(crate) fn into_trap(self, query_id: Option<u64>) -> Trap {
        let path = self.path.to_string_lossy().into_owned();
        let requested = self.requested_path.to_string_lossy();
        let requested_path = (requested.as_ref() != path).then(|| requested.into_owned());
        Trap::Filesystem(Box::new(FilesystemTrap {
            code: FILESYSTEM_DENIED,
            state: TrapState::from(query_id),
            operation: self.operation,
            path,
            requested_path,
            syscall: self.syscall,
            errno: "EACCES",
            flags: self.flags,
            reason: self.reason,
            mechanism: Mechanism::Kvm,
            process: self.process,
        }))
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[derive(Debug)]
pub(crate) struct NetworkTrap {
    pub(crate) code: &'static str,
    pub(crate) state: TrapState,
    pub(crate) operation: NetworkOperation,
    pub(crate) target: String,
    pub(crate) syscall: &'static str,
    pub(crate) errno: &'static str,
    pub(crate) mechanism: Mechanism,
    pub(crate) process: ProcessContext,
}

/// The tool did not start.
#[derive(Debug)]
pub(crate) struct LaunchTrap {
    pub(crate) code: &'static str,
    pub(crate) program: String,
    pub(crate) errno: Option<String>,
    pub(crate) message: String,
}

/// The command line was rejected.
#[derive(Debug)]
pub(crate) struct UsageTrap {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

/// Everything that fails before the tool runs: a policy landstrip cannot parse,
/// resolve, or enforce, and any sandbox it cannot install.
#[derive(Debug)]
pub(crate) struct InternalTrap {
    pub(crate) code: &'static str,
    pub(crate) mechanism: Option<Mechanism>,
    pub(crate) message: String,
}

#[derive(Debug)]
pub(crate) enum Trap {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    Filesystem(Box<FilesystemTrap>),
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    Network(Box<NetworkTrap>),
    Launch(LaunchTrap),
    Usage(UsageTrap),
    Internal(InternalTrap),
}

impl Trap {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) fn network(
        operation: NetworkOperation,
        target: String,
        process: ProcessContext,
        query_id: Option<u64>,
    ) -> Self {
        let syscall = operation.into();
        Self::Network(Box::new(NetworkTrap {
            code: NETWORK_DENIED,
            state: TrapState::from(query_id),
            operation,
            target,
            syscall,
            errno: "EACCES",
            mechanism: Mechanism::Kvm,
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

    #[cfg(unix)]
    pub(crate) fn emit_with_fd(&self, trap_fd: Option<&TrapFd>) {
        let stanza = self.to_string();
        if let Some(trap_fd) = trap_fd
            && let Err(error) = trap_fd.write_stanza(&stanza)
        {
            log::debug!("trap fd write failed: {error}");
        }
        Self::write_stderr(&stanza);
    }

    /// Writes a stanza that was formatted by another process of the payload.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) fn emit_record(stanza: &str, trap_fd: Option<&TrapFd>) {
        if let Some(trap_fd) = trap_fd
            && let Err(error) = trap_fd.write_stanza(stanza)
        {
            log::debug!("trap fd write failed: {error}");
        }
        Self::write_stderr(stanza);
    }

    #[cfg(not(unix))]
    pub(crate) fn emit(&self) {
        Self::write_stderr(&self.to_string());
    }

    fn write_stderr(stanza: &str) {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(stanza.as_bytes());
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
        let mut stanza = Stanza(f);
        match self {
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            Self::Filesystem(trap) => {
                stanza.field("kind", "filesystem")?;
                stanza.field("code", trap.code)?;
                trap.state.write_fields(&mut stanza)?;
                stanza.field("operation", trap.operation.into())?;
                stanza.field("path", &trap.path)?;
                stanza.optional("requested_path", trap.requested_path.as_deref())?;
                stanza.field("syscall", trap.syscall)?;
                stanza.field("errno", trap.errno)?;
                stanza.list("flags", &trap.flags)?;
                stanza.field("reason", trap.reason.into())?;
                stanza.field("mechanism", trap.mechanism.into())?;
                trap.process.write_fields(&mut stanza)?;
            }
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            Self::Network(trap) => {
                stanza.field("kind", "network")?;
                stanza.field("code", trap.code)?;
                trap.state.write_fields(&mut stanza)?;
                stanza.field("operation", trap.operation.into())?;
                stanza.field("target", &trap.target)?;
                stanza.field("syscall", trap.syscall)?;
                stanza.field("errno", trap.errno)?;
                stanza.field("mechanism", trap.mechanism.into())?;
                trap.process.write_fields(&mut stanza)?;
            }
            Self::Launch(trap) => {
                stanza.field("kind", "launch")?;
                stanza.field("code", trap.code)?;
                stanza.field("program", &trap.program)?;
                stanza.optional("errno", trap.errno.as_deref())?;
                stanza.field("message", &trap.message)?;
            }
            Self::Usage(trap) => {
                stanza.field("kind", "usage")?;
                stanza.field("code", trap.code)?;
                stanza.field("message", &trap.message)?;
            }
            Self::Internal(trap) => {
                stanza.field("kind", "internal")?;
                stanza.field("code", trap.code)?;
                stanza.optional("mechanism", trap.mechanism.map(Into::into))?;
                stanza.field("message", &trap.message)?;
            }
        }
        stanza.finish()
    }
}
