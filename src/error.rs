// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;
use strum_macros::Display;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum Error {
    Usage(String),
    Policy {
        file: Option<PathBuf>,
        message: String,
    },
    Tool {
        program: Option<OsString>,
        message: String,
    },
    Capability {
        message: String,
    },
    System {
        message: String,
    },
}

impl Error {
    pub(crate) fn policy(message: impl Into<String>) -> Self {
        Self::Policy {
            file: None,
            message: message.into(),
        }
    }

    pub(crate) fn policy_file(path: PathBuf, message: impl Into<String>) -> Self {
        Self::Policy {
            file: Some(path),
            message: message.into(),
        }
    }

    pub(crate) fn tool(program: Option<OsString>, message: impl Into<String>) -> Self {
        Self::Tool {
            program,
            message: message.into(),
        }
    }

    pub(crate) fn system(message: impl Into<String>) -> Self {
        Self::System {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message)
            | Self::Policy {
                file: None,
                message,
            }
            | Self::Capability { message }
            | Self::System { message }
            | Self::Tool {
                program: None,
                message,
            } => f.write_str(message),
            Self::Policy {
                file: Some(file),
                message,
            } => write!(f, "{}: {message}", file.display()),
            Self::Tool {
                program: Some(program),
                message,
            } => write!(f, "{}: {message}", program.to_string_lossy()),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::system(error.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::policy(error.to_string())
    }
}

#[derive(Clone, Copy, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum PolicyPort {
    HttpProxyPolicy,
    SocksProxyPolicy,
}
