// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#[cfg(target_os = "linux")]
use landlock::PathFdError;
#[cfg(target_os = "linux")]
use libseccomp::error::SeccompError;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use strum_macros::Display;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[cfg(target_os = "linux")]
    #[error("address family not supported")]
    AddressFamilyNotSupported,
    #[cfg(target_os = "linux")]
    #[error("bad address")]
    BadAddress,
    #[cfg(target_os = "linux")]
    #[error("bad file descriptor")]
    BadFileDescriptor,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("failed to execute {command}: {source}", command = command.to_string_lossy())]
    Exec {
        command: OsString,
        source: io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("invalid address")]
    InvalidAddress,
    #[error(transparent)]
    Io(io::Error),
    #[error(transparent)]
    Json(serde_json::Error),
    #[cfg(target_os = "linux")]
    #[error("landlock ruleset not enforced")]
    LandlockNone,
    #[cfg(target_os = "linux")]
    #[error("landlock ruleset partially enforced")]
    LandlockPartial,
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    LandlockPathFd(PathFdError),
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    LandlockRuleset(landlock::RulesetError),
    #[cfg(target_os = "linux")]
    #[error("missing file descriptor")]
    MissingFileDescriptor,
    #[cfg(target_os = "linux")]
    #[error("name too long")]
    NameTooLong,
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Nix(nix::errno::Errno),
    #[cfg(target_os = "linux")]
    #[error("seccomp notify API {version} is too old: required {required}, current {current}")]
    NotSupportedNotifyApi {
        required: u32,
        current: u32,
        version: String,
    },
    #[cfg(target_os = "linux")]
    #[error("peer closed connection")]
    PeerClosed,
    #[cfg(target_os = "linux")]
    #[error("policy denied operation")]
    PolicyDenied,
    #[error("policy file {file}: {source}", file = path.display())]
    PolicyFile { path: PathBuf, source: io::Error },
    #[error("policy file {file}: {source}", file = path.display())]
    PolicyFileJson {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("policy home unavailable")]
    PolicyHomeUnavailable,
    #[error("policy path empty")]
    PolicyPathEmpty,
    #[error("{0} port out of range")]
    PolicyPortOutOfRange(PolicyPort),
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Seccomp(SeccompError),
    #[cfg(target_os = "macos")]
    #[error("seatbelt initialization failed: {0}")]
    SeatbeltInit(String),
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[error("unsupported platform")]
    UnsupportedPlatform,
    #[error("{0}")]
    Usage(String),
    #[cfg(target_os = "windows")]
    #[error("windows API call {function} failed with error code {code}")]
    WindowsApi { function: &'static str, code: u32 },
    #[cfg(target_os = "windows")]
    #[error("windows command line contains an interior NUL byte")]
    WindowsCommandLine,
    #[cfg(target_os = "windows")]
    #[error("unsupported windows policy: {0}")]
    WindowsUnsupportedPolicy(&'static str),
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<serde_json::Error> for Error {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

#[cfg(target_os = "linux")]
impl From<nix::errno::Errno> for Error {
    fn from(source: nix::errno::Errno) -> Self {
        Self::Nix(source)
    }
}

#[cfg(target_os = "linux")]
impl From<SeccompError> for Error {
    fn from(source: SeccompError) -> Self {
        Self::Seccomp(source)
    }
}

#[cfg(target_os = "linux")]
impl From<landlock::RulesetError> for Error {
    fn from(source: landlock::RulesetError) -> Self {
        Self::LandlockRuleset(source)
    }
}

#[cfg(target_os = "linux")]
impl From<PathFdError> for Error {
    fn from(source: PathFdError) -> Self {
        Self::LandlockPathFd(source)
    }
}

#[derive(Clone, Copy, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum PolicyPort {
    HttpProxyPolicy,
    SocksProxyPolicy,
}
