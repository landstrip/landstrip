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
        r#type: PolicyType,
        message: String,
        cause: Option<Cause>,
    },
    Tool {
        program: Option<OsString>,
        r#type: ToolType,
        message: String,
        cause: Option<Cause>,
    },
    #[allow(dead_code)]
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
pub(crate) enum PolicyType {
    Filesystem,
    Network,
    Platform,
}

#[derive(Debug)]
pub(crate) enum ToolType {
    Launch,
    Encoding,
}

impl Error {
    pub(crate) fn response(&self) -> Option<Response<'_>> {
        match self {
            Self::Usage(_) => None,
            Self::Policy {
                source,
                r#type,
                message,
                ..
            } => Some(Response {
                category: "policy",
                file: match source {
                    PolicySource::File(file) => Some(file.display().to_string()),
                    PolicySource::Stdin => None,
                },
                program: None,
                r#type: Some(match r#type {
                    PolicyType::Filesystem => "filesystem",
                    PolicyType::Network => "network",
                    PolicyType::Platform => "platform",
                }),
                message,
            }),
            Self::Tool {
                program,
                r#type,
                message,
                ..
            } => Some(Response {
                category: "tool",
                file: None,
                program: program
                    .as_ref()
                    .map(|program| program.to_string_lossy().into_owned()),
                r#type: Some(match r#type {
                    ToolType::Launch => "launch",
                    ToolType::Encoding => "encoding",
                }),
                message,
            }),
            Self::Platform { message } => Some(Response {
                category: "platform",
                file: None,
                program: None,
                r#type: None,
                message,
            }),
            Self::System { message, .. } => Some(Response {
                category: "system",
                file: None,
                program: None,
                r#type: None,
                message,
            }),
        }
    }

    pub(crate) fn policy(r#type: PolicyType, message: impl Into<String>) -> Self {
        Self::Policy {
            source: PolicySource::Stdin,
            r#type,
            message: message.into(),
            cause: None,
        }
    }

    pub(crate) fn policy_stdin_source(
        r#type: PolicyType,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        let (message, cause) = Self::cause(source);
        Self::Policy {
            source: PolicySource::Stdin,
            r#type,
            message,
            cause: Some(cause),
        }
    }

    pub(crate) fn policy_file_source(
        path: PathBuf,
        r#type: PolicyType,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        let (message, cause) = Self::cause(source);
        Self::Policy {
            source: PolicySource::File(path),
            r#type,
            message,
            cause: Some(cause),
        }
    }

    pub(crate) fn tool_exec(program: Option<OsString>, error: io::Error) -> Self {
        let r#type = if error.kind() == io::ErrorKind::NotFound {
            ToolType::Launch
        } else {
            ToolType::Encoding
        };
        Self::Tool {
            program,
            r#type,
            message: error.to_string(),
            cause: Some(Box::new(error)),
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
    r#type: Option<&'a str>,
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
            | Self::Tool {
                program: None,
                message,
                ..
            } => f.write_str(message),
            Self::Policy {
                source: PolicySource::File(file),
                message,
                ..
            } => write!(f, "{}: {message}", file.display()),
            Self::Tool {
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
            Self::Policy { cause, .. } | Self::Tool { cause, .. } | Self::System { cause, .. } => {
                cause
                    .as_deref()
                    .map(|source| source as &(dyn StdError + 'static))
            }
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


#[derive(Clone, Copy, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum PolicyPort {
    HttpProxyPolicy,
    SocksProxyPolicy,
}
