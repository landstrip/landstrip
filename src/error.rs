// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use serde::Serialize;
use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;
use strum_macros::Display;

pub(crate) type Result<T> = std::result::Result<T, Error>;
type Cause = Box<dyn StdError + Send + Sync + 'static>;

#[derive(Debug)]
pub(crate) enum Error {
    Usage(String),
    Policy {
        source: PolicySource,
        target: PolicyTarget,
        message: String,
        cause: Option<Cause>,
    },
    ToolLaunch {
        program: Option<OsString>,
        message: String,
        cause: Option<Cause>,
    },
    ToolEncoding {
        program: Option<OsString>,
        message: String,
        cause: Option<Cause>,
    },
    Platform {
        message: String,
    },
    System {
        message: String,
        cause: Option<Cause>,
    },
}

#[derive(Debug)]
pub(crate) enum PolicySource {
    Stdin,
    File(PathBuf),
}

#[derive(Debug)]
pub(crate) enum PolicyTarget {
    Filesystem,
    Network,
    Platform,
}

impl Error {
    pub(crate) fn response(&self) -> Option<Response<'_>> {
        match self {
            Self::Usage(_) => None,
            Self::Policy {
                source,
                target,
                message,
                ..
            } => Some(Response {
                category: "policy",
                file: match source {
                    PolicySource::File(file) => Some(file.display().to_string()),
                    PolicySource::Stdin => None,
                },
                program: None,
                target: Some(match target {
                    PolicyTarget::Filesystem => "filesystem",
                    PolicyTarget::Network => "network",
                    PolicyTarget::Platform => "platform",
                }),
                kind: None,
                message,
            }),
            Self::ToolLaunch {
                program, message, ..
            } => Some(Response {
                category: "tool",
                file: None,
                program: program
                    .as_ref()
                    .map(|program| program.to_string_lossy().into_owned()),
                target: None,
                kind: Some("launch"),
                message,
            }),
            Self::ToolEncoding {
                program, message, ..
            } => Some(Response {
                category: "tool",
                file: None,
                program: program
                    .as_ref()
                    .map(|program| program.to_string_lossy().into_owned()),
                target: None,
                kind: Some("encoding"),
                message,
            }),
            Self::Platform { message } => Some(Response {
                category: "platform",
                file: None,
                program: None,
                target: None,
                kind: None,
                message,
            }),
            Self::System { message, .. } => Some(Response {
                category: "system",
                file: None,
                program: None,
                target: None,
                kind: None,
                message,
            }),
        }
    }

    pub(crate) fn policy(target: PolicyTarget, message: impl Into<String>) -> Self {
        Self::Policy {
            source: PolicySource::Stdin,
            target,
            message: message.into(),
            cause: None,
        }
    }

    pub(crate) fn policy_stdin_source(
        target: PolicyTarget,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        let (message, cause) = Self::cause(source);
        Self::Policy {
            source: PolicySource::Stdin,
            target,
            message,
            cause: Some(cause),
        }
    }

    pub(crate) fn policy_file_source(
        path: PathBuf,
        target: PolicyTarget,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        let (message, cause) = Self::cause(source);
        Self::Policy {
            source: PolicySource::File(path),
            target,
            message,
            cause: Some(cause),
        }
    }

    pub(crate) fn tool_exec(program: Option<OsString>, error: io::Error) -> Self {
        let kind = error.kind();
        let (message, cause) = Self::cause(error);
        if kind == io::ErrorKind::InvalidInput {
            Self::ToolEncoding {
                program,
                message,
                cause: Some(cause),
            }
        } else {
            Self::ToolLaunch {
                program,
                message,
                cause: Some(cause),
            }
        }
    }

    pub(crate) fn system(message: impl Into<String>) -> Self {
        Self::System {
            message: message.into(),
            cause: None,
        }
    }

    pub(crate) fn system_source(source: impl StdError + Send + Sync + 'static) -> Self {
        let (message, cause) = Self::cause(source);
        Self::System {
            message,
            cause: Some(cause),
        }
    }

    fn cause(source: impl StdError + Send + Sync + 'static) -> (String, Cause) {
        let message = source.to_string();
        (message, Box::new(source))
    }
}

#[derive(Serialize)]
pub(crate) struct Response<'a> {
    category: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    message: &'a str,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message)
            | Self::Policy {
                source: PolicySource::Stdin,
                message,
                ..
            }
            | Self::Platform { message }
            | Self::System { message, .. }
            | Self::ToolLaunch {
                program: None,
                message,
                ..
            }
            | Self::ToolEncoding {
                program: None,
                message,
                ..
            } => f.write_str(message),
            Self::Policy {
                source: PolicySource::File(file),
                message,
                ..
            } => write!(f, "{}: {message}", file.display()),
            Self::ToolLaunch {
                program: Some(program),
                message,
                ..
            }
            | Self::ToolEncoding {
                program: Some(program),
                message,
                ..
            } => write!(f, "{}: {message}", program.to_string_lossy()),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Policy { cause, .. }
            | Self::ToolLaunch { cause, .. }
            | Self::ToolEncoding { cause, .. }
            | Self::System { cause, .. } => cause
                .as_deref()
                .map(|source| source as &(dyn StdError + 'static)),
            Self::Usage(_) | Self::Platform { .. } => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        let (message, cause) = Self::cause(error);
        Self::System {
            message,
            cause: Some(cause),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        let (message, cause) = Self::cause(error);
        Self::Policy {
            source: PolicySource::Stdin,
            target: PolicyTarget::Platform,
            message,
            cause: Some(cause),
        }
    }
}

#[derive(Clone, Copy, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum PolicyPort {
    HttpProxyPolicy,
    SocksProxyPolicy,
}
