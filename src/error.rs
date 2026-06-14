// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;
use strum_macros::Display;

pub(crate) type Result<T> = std::result::Result<T, Error>;
type Cause = Box<dyn StdError + Send + Sync + 'static>;

#[derive(Debug, Display)]
pub(crate) enum ErrorKind {
    AccessDenied,
    ArchitectureNotSupported,
    ConnectionClosed,
    FeatureNotAvailable,
    #[allow(dead_code)]
    FeatureNotSupported,
    FileDescriptorNotFound,
    HomeNotAvailable,
    InvalidEncoding,
    InvalidPath,
    InvalidPort,
    InvalidProfile,
    InvalidResponse,
    LaunchFailed,
    Other,
    #[allow(dead_code)]
    SetupFailed,
    SystemCallFailed,
    #[allow(dead_code)]
    Unsupported,
    Usage,
}

#[derive(Debug)]
pub(crate) struct Error {
    pub(crate) kind: ErrorKind,
    pub(crate) r#type: Option<&'static str>,
    pub(crate) file: Option<PathBuf>,
    pub(crate) operation: Option<&'static str>,
    pub(crate) program: Option<OsString>,
    pub(crate) source: Option<String>,
    pub(crate) cause: Option<Cause>,
    pub(crate) api: Option<String>,
    pub(crate) code: Option<String>,
    pub(crate) errno: Option<String>,
    pub(crate) mechanism: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) offset: Option<String>,
    pub(crate) port: Option<String>,
    pub(crate) arch: Option<String>,
    pub(crate) feature: Option<String>,
    pub(crate) cause_desc: Option<String>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            r#type: None,
            file: None,
            operation: None,
            program: None,
            source: None,
            cause: None,
            api: None,
            code: None,
            errno: None,
            mechanism: None,
            action: None,
            offset: None,
            port: None,
            arch: None,
            feature: None,
            cause_desc: None,
        }
    }

    pub(crate) fn emit(&self) {
        eprintln!("reason: {}", self.kind);
        if let Some(value) = self.r#type {
            eprintln!("type: {value}");
        }
        if let Some(ref value) = self.file {
            eprintln!("file: {}", value.display());
        }
        if let Some(value) = self.operation {
            eprintln!("operation: {value}");
        }
        if let Some(ref value) = self.program {
            eprintln!("program: {}", value.to_string_lossy());
        }
        if let Some(ref value) = self.source {
            eprintln!("source: {value}");
        }
        if let Some(ref value) = self.api {
            eprintln!("api: {value}");
        }
        if let Some(ref value) = self.code {
            eprintln!("code: {value}");
        }
        if let Some(ref value) = self.errno {
            eprintln!("errno: {value}");
        }
        if let Some(ref value) = self.mechanism {
            eprintln!("mechanism: {value}");
        }
        if let Some(ref value) = self.action {
            eprintln!("action: {value}");
        }
        if let Some(ref value) = self.offset {
            eprintln!("offset: {value}");
        }
        if let Some(ref value) = self.port {
            eprintln!("port: {value}");
        }
        if let Some(ref value) = self.arch {
            eprintln!("arch: {value}");
        }
        if let Some(ref value) = self.feature {
            eprintln!("feature: {value}");
        }
        if let Some(ref value) = self.cause_desc {
            eprintln!("cause: {value}");
        }
    }

    pub(crate) fn with_type(mut self, r#type: &'static str) -> Self {
        self.r#type = Some(r#type);
        self
    }

    pub(crate) fn with_file(mut self, file: PathBuf) -> Self {
        self.file = Some(file);
        self
    }

    pub(crate) fn with_operation(mut self, operation: &'static str) -> Self {
        self.operation = Some(operation);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_program(mut self, program: OsString) -> Self {
        self.program = Some(program);
        self
    }

    pub(crate) fn with_source(mut self, source: String) -> Self {
        self.source = Some(source);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_api(mut self, api: impl Into<String>) -> Self {
        self.api = Some(api.into());
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_code(mut self, code: impl fmt::Display) -> Self {
        self.code = Some(code.to_string());
        self
    }

    pub(crate) fn with_errno(mut self, errno: impl fmt::Display) -> Self {
        self.errno = Some(errno.to_string());
        self
    }

    pub(crate) fn with_mechanism(mut self, mechanism: &'static str) -> Self {
        self.mechanism = Some(mechanism.to_owned());
        self
    }

    pub(crate) fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_offset(mut self, offset: impl fmt::Display) -> Self {
        self.offset = Some(offset.to_string());
        self
    }

    pub(crate) fn with_port(mut self, port: impl fmt::Display) -> Self {
        self.port = Some(port.to_string());
        self
    }

    pub(crate) fn with_arch(mut self, arch: &str) -> Self {
        self.arch = Some(arch.to_owned());
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_feature(mut self, feature: &'static str) -> Self {
        self.feature = Some(feature.to_owned());
        self
    }

    pub(crate) fn with_cause_desc(mut self, cause_desc: &'static str) -> Self {
        self.cause_desc = Some(cause_desc.to_owned());
        self
    }

    pub(crate) fn tool_exec(program: Option<OsString>, error: io::Error) -> Self {
        let kind = if error.kind() == io::ErrorKind::NotFound {
            ErrorKind::LaunchFailed
        } else {
            ErrorKind::InvalidEncoding
        };
        Self {
            program,
            r#type: if error.kind() == io::ErrorKind::NotFound {
                Some("launch")
            } else {
                Some("encoding")
            },
            source: Some(error.to_string()),
            cause: Some(Box::new(error)),
            ..Self::new(kind)
        }
    }

    pub(crate) fn policy_stdin_source(source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            source: Some(source.to_string()),
            cause: Some(Box::new(source)),
            ..Self::new(ErrorKind::Other)
        }
    }

    pub(crate) fn policy_file_source(
        path: PathBuf,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            file: Some(path),
            source: Some(source.to_string()),
            cause: Some(Box::new(source)),
            ..Self::new(ErrorKind::Other)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let ErrorKind::Usage = self.kind {
            if let Some(ref source) = self.source {
                f.write_str(source)
            } else {
                f.write_str("landstrip: usage error")
            }
        } else {
            write!(f, "{}", self.kind)?;
            if let Some(ref file) = self.file {
                write!(f, ": {}", file.display())?;
            } else if let Some(ref program) = self.program {
                write!(f, ": {}", program.to_string_lossy())?;
            }
            if let Some(ref source) = self.source {
                write!(f, ": {source}")?;
            }
            Ok(())
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self.kind {
            ErrorKind::Other
            | ErrorKind::LaunchFailed
            | ErrorKind::SystemCallFailed
            | ErrorKind::SetupFailed => self
                .cause
                .as_deref()
                .map(|source| source as &(dyn StdError + 'static)),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        let source = error.to_string();
        Self {
            source: Some(source),
            cause: Some(Box::new(error)),
            ..Self::new(ErrorKind::Other)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PolicyPort {
    HttpProxyPolicy,
    SocksProxyPolicy,
}

impl fmt::Display for PolicyPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpProxyPolicy => f.write_str("http_proxy_port"),
            Self::SocksProxyPolicy => f.write_str("socks_proxy_port"),
        }
    }
}
