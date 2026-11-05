// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use serde::{Serialize, Serializer};
use std::error::Error as StdError;
use std::fmt::{self, Write as _};
use std::io;
use std::path::PathBuf;

/// What went wrong underneath a landstrip error: an [`io::Error`] from a
/// syscall, an OS sandbox library's own error, or a message where the platform
/// reports no structured cause. An errno is recovered from it by
/// [`Error::errno`] when the cause carries one.
pub(crate) type Cause = Box<dyn StdError + Send + Sync>;
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// The OS enforcement layer an error or a denial is attributed to.
///
/// `Display` and `Serialize` render the lowercase name used on the trap wire.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, strum::Display)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mechanism {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Landlock,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Seccomp,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Namespace,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Seatbelt,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Appcontainer,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Windowsuser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, strum::IntoStaticStr)]
#[strum(prefix = "POLICY_", serialize_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PolicyViolation {
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    UnrestrictedRead,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    DenyReadAlwaysUnsupported,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    DenyWriteAlwaysUnsupported,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    LocalBindingUnsupported,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    UnixSocketUnsupported,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    UnixSocketPath,
    InvalidPort,
    EmptyPath,
    InvalidMachLookup,
    InvalidLogTag,
    HomeUnavailable,
    TraversalDepth,
    GlobTooLong,
    SelectorLimit,
}

impl PolicyViolation {
    pub(crate) fn code(self) -> &'static str {
        self.into()
    }

    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::UnrestrictedRead => {
                "unrestricted reads are unsupported by the active Windows sandbox"
            }
            Self::DenyReadAlwaysUnsupported => "denyReadAlways is unsupported on Windows",
            Self::DenyWriteAlwaysUnsupported => "denyWriteAlways is unsupported on Windows",
            Self::LocalBindingUnsupported => {
                "local binding is unsupported by the active Windows sandbox"
            }
            Self::UnixSocketUnsupported => {
                "Unix socket policy is unsupported by the active Windows sandbox"
            }
            Self::UnixSocketPath => "an allowed Unix socket path exists but is not a socket",
            Self::InvalidPort => "proxy ports must be between 1 and 65535",
            Self::EmptyPath => "policy paths must not be empty",
            Self::InvalidMachLookup => {
                "Mach service lookup names must not be empty or bare wildcards"
            }
            Self::InvalidLogTag => {
                "Darwin logTag must not be empty or contain quotes, backslashes, or control characters"
            }
            Self::HomeUnavailable => {
                "the home directory is unavailable for a tilde-prefixed policy path"
            }
            Self::TraversalDepth => "policy path traversal exceeded its maximum depth",
            Self::GlobTooLong => "glob patterns must not exceed 4096 bytes",
            Self::SelectorLimit => "write-deny anchoring must not exceed 65536 selectors",
        }
    }
}

/// A landstrip error identified by a stable, machine-routable code.
#[derive(Debug, strum::IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Error {
    #[strum(serialize = "USAGE_ERROR")]
    Usage {
        message: String,
    },
    PolicyParseFailed {
        context: Option<String>,
        source: Cause,
    },
    PolicyIoFailed {
        context: Option<String>,
        source: io::Error,
    },
    Policy(PolicyViolation),
    SandboxSetupFailed {
        mechanism: Mechanism,
        source: Cause,
    },
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    SuperviseFailed {
        source: Cause,
    },
    LaunchFailed {
        tool: PathBuf,
        source: Cause,
    },
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    HostJobIncompatible {
        source: Cause,
    },
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    IntegerTooLarge,
    #[cfg_attr(
        any(target_os = "linux", target_os = "macos", target_os = "windows"),
        allow(dead_code)
    )]
    PlatformUnsupported,
}

impl From<PolicyViolation> for Error {
    fn from(violation: PolicyViolation) -> Self {
        Self::Policy(violation)
    }
}

impl Error {
    pub(crate) fn sandbox_setup(mechanism: Mechanism, source: impl Into<Cause>) -> Self {
        Self::SandboxSetupFailed {
            mechanism,
            source: source.into(),
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn seatbelt(source: impl Into<Cause>) -> Self {
        Self::sandbox_setup(Mechanism::Seatbelt, source)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn landlock(source: impl Into<Cause>) -> Self {
        Self::sandbox_setup(Mechanism::Landlock, source)
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    pub(crate) fn supervise(source: impl Into<Cause>) -> Self {
        Self::SuperviseFailed {
            source: source.into(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn supervise_errno(errno: nix::errno::Errno) -> Self {
        Self::supervise(io::Error::from_raw_os_error(errno as i32))
    }

    pub(crate) fn launch(tool: impl Into<PathBuf>, source: impl Into<Cause>) -> Self {
        Self::LaunchFailed {
            tool: tool.into(),
            source: source.into(),
        }
    }

    pub(crate) fn parse_failed(source: impl StdError + Send + Sync + 'static) -> Self {
        Self::PolicyParseFailed {
            context: None,
            source: Box::new(source),
        }
    }

    pub(crate) fn policy_io(source: io::Error) -> Self {
        Self::PolicyIoFailed {
            context: None,
            source,
        }
    }

    pub(crate) fn with_context(self, context: impl Into<String>) -> Self {
        match self {
            Self::PolicyParseFailed { source, .. } => Self::PolicyParseFailed {
                context: Some(context.into()),
                source,
            },
            Self::PolicyIoFailed { source, .. } => Self::PolicyIoFailed {
                context: Some(context.into()),
                source,
            },
            other => other,
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Policy(violation) => violation.code(),
            other => other.into(),
        }
    }

    pub(crate) fn validation_message(&self) -> Option<String> {
        match self {
            Self::PolicyParseFailed { .. } => {
                let rendered = self.message();
                if rendered == self.code() {
                    Some("policy document is not valid JSON or YAML".to_owned())
                } else {
                    Some(rendered)
                }
            }
            Self::Policy(violation) => Some(violation.message().to_owned()),
            Self::SandboxSetupFailed {
                mechanism: Mechanism::Namespace,
                ..
            } => {
                let rendered = self.message();
                if rendered == self.code() {
                    Some("requested namespace isolation is unavailable".to_owned())
                } else {
                    Some(rendered)
                }
            }
            Self::SandboxSetupFailed {
                mechanism: Mechanism::Windowsuser,
                ..
            } => Some(self.message()),
            Self::PlatformUnsupported => Some("the current platform is unsupported".to_owned()),
            _ => None,
        }
    }

    #[cfg(unix)]
    pub(crate) fn errno(&self) -> Option<i32> {
        StdError::source(self)?
            .downcast_ref::<io::Error>()?
            .raw_os_error()
    }

    #[cfg(not(unix))]
    pub(crate) fn errno(&self) -> Option<i32> {
        let _ = self;
        None
    }

    pub(crate) fn detail(&self) -> Option<String> {
        match self {
            Self::Usage { message } => Some(message.clone()),
            Self::PolicyParseFailed { context, .. } | Self::PolicyIoFailed { context, .. } => {
                context.clone()
            }
            Self::Policy(violation) => Some(violation.message().to_owned()),
            Self::LaunchFailed { tool, .. } => Some(tool.display().to_string()),
            Self::HostJobIncompatible { .. } => Some(
                "Landstrip is running inside a Job Object that prevents creating the sandbox job; start the host process outside the debugger or configure it to permit child-process breakaway"
                    .to_owned(),
            ),
            _ => None,
        }
    }

    pub(crate) fn errno_name(&self) -> Option<String> {
        self.errno().and_then(|errno| {
            #[cfg(unix)]
            {
                let errno = nix::errno::Errno::from_raw(errno);
                (errno != nix::errno::Errno::UnknownErrno).then(|| format!("{errno:?}"))
            }
            #[cfg(not(unix))]
            {
                let _ = errno;
                None
            }
        })
    }

    pub(crate) fn message(&self) -> String {
        let mut message = self.detail().unwrap_or_default();
        let mut cause = StdError::source(self);

        while let Some(source) = cause {
            if !message.is_empty() {
                message.push_str(": ");
            }
            let _ = write!(message, "{source}");
            cause = source.source();
        }

        if message.is_empty() {
            return self.code().to_owned();
        }

        message
    }

    pub(crate) fn find_in(error: &anyhow::Error) -> Option<&Self> {
        error
            .chain()
            .find_map(<dyn StdError + 'static>::downcast_ref::<Self>)
    }
}

pub(crate) trait PathIo {
    fn is_opaque(&self) -> bool;
    fn is_transport_failed(&self) -> bool;
}

impl PathIo for io::Error {
    fn is_transport_failed(&self) -> bool {
        self.kind() == io::ErrorKind::NotConnected || self.raw_os_error() == Some(libc::EIO)
    }

    fn is_opaque(&self) -> bool {
        matches!(
            self.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
        ) || self.is_transport_failed()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())?;

        match self.detail() {
            Some(detail) => write!(f, ": {detail}"),
            None => Ok(()),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::PolicyIoFailed { source, .. } => Some(source),
            Self::PolicyParseFailed { source, .. }
            | Self::SandboxSetupFailed { source, .. }
            | Self::SuperviseFailed { source }
            | Self::LaunchFailed { source, .. }
            | Self::HostJobIncompatible { source } => Some(&**source),
            _ => None,
        }
    }
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.code())
    }
}
