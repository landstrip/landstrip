// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use strum_macros::Display;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("address family not supported")]
    AddressFamilyNotSupported,

    #[error("backend call failed with {code}")]
    BackendCall { code: u32 },

    #[error("backend setup failed: {0}")]
    BackendSetup(String),

    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("bad address")]
    BadAddress,

    #[error("bad file descriptor")]
    BadFileDescriptor,

    #[error("{command} failed with {error}", command = command.to_string_lossy())]
    Exec {
        command: OsString,
        #[source]
        error: io::Error,
    },

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid command: {0}")]
    InvalidCommand(&'static str),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("missing file descriptor")]
    MissingFileDescriptor,

    #[error("name too long")]
    NameTooLong,

    #[error("peer closed connection")]
    PeerClosed,

    #[error("policy denied operation")]
    PolicyDenied,

    #[error("policy: {file}: {error}", file = path.display())]
    PolicyFile {
        path: PathBuf,
        #[source]
        error: io::Error,
    },

    #[error("policy: {file}: {error}", file = path.display())]
    PolicyFileJson {
        path: PathBuf,
        #[source]
        error: serde_json::Error,
    },

    #[error("policy: home unavailable")]
    PolicyHomeUnavailable,

    #[error("policy: path empty")]
    PolicyPathEmpty,

    #[error("policy: {0} port out of range")]
    PolicyPortOutOfRange(PolicyPort),

    #[error("failed with {errno}")]
    SystemCall { errno: i32 },

    #[error("unsupported platform")]
    UnsupportedPlatform,

    #[error("policy: unsupported: {0}")]
    UnsupportedPolicy(&'static str),

    #[error("{0}")]
    Usage(String),
}

#[derive(Clone, Copy, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum PolicyPort {
    HttpProxyPolicy,
    SocksProxyPolicy,
}
