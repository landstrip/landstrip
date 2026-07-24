// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use serde::{Serialize, Serializer};
use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::path::PathBuf;

/// What went wrong underneath a landstrip error: an [`io::Error`] from a
/// syscall, an OS sandbox library's own error, or a message where the platform
/// reports no structured cause. An errno is recovered from it by
/// [`Error::errno`] when the cause carries one.
pub(crate) type Cause = Box<dyn StdError + Send + Sync>;

/// The OS enforcement layer an error or a denial is attributed to.
///
/// `Display` and `Serialize` render the lowercase name used on the trap wire.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, strum_macros::Display)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mechanism {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Landlock,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Seccomp,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Seatbelt,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Appcontainer,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Windowsuser,
}

/// A landstrip error identified by a stable, machine-routable code.
///
/// Variants name the stage that failed, not the operating system that reported
/// it: the same code is raised by every backend that has the same stage, and the
/// platform detail rides along as data (`mechanism`, `source`) instead of
/// multiplying the code space.
///
/// `Display` renders the `SCREAMING_SNAKE_CASE` code followed by the variant's
/// discriminating data, and [`StdError::source`] exposes the underlying cause so
/// `anyhow`'s alternate format appends it.
#[derive(Debug, strum_macros::IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Error {
    /// A filesystem access the policy denies. Only the Linux broker mediates
    /// individual accesses, so only it raises this.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    FilesystemDenied,
    /// A network access the policy denies. Linux broker only, as above.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    NetworkDenied,
    /// Command line arguments landstrip cannot act on.
    #[strum(serialize = "USAGE_ERROR")]
    Usage {
        message: String,
    },
    /// A policy document that is not well-formed JSON or YAML.
    PolicyParseFailed {
        source: Cause,
    },
    /// The filesystem refused a read the policy resolution needs.
    PolicyIoFailed {
        source: io::Error,
    },
    /// A policy the platform sandbox cannot enforce, rejected before launch.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    PolicyUnrestrictedRead,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    PolicyTcpBindUnsupported,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    PolicyUnixSocketUnsupported,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    PolicyUnixSocketPath,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    PolicyDenyWriteSymlinkAncestor,
    PolicyInvalidPort,
    PolicyEmptyPath,
    PolicyHomeUnavailable,
    PolicyTraversalDepth,
    /// The sandbox could not be installed on the process.
    SandboxSetupFailed {
        mechanism: Mechanism,
        source: Cause,
    },
    /// Supervising the sandboxed child failed: the broker loop, a wait, or the
    /// descriptor handoff.
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    SuperviseFailed {
        source: Cause,
    },
    /// The sandbox was installed but the tool did not start.
    LaunchFailed {
        tool: PathBuf,
        source: Cause,
    },
    /// The host Job Object rejected both nested assignment and safe breakaway.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    HostJobIncompatible {
        source: Cause,
    },
    /// A value the kernel interface cannot represent.
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    IntegerTooLarge,
    /// An operating system landstrip has no sandbox backend for.
    #[cfg_attr(
        any(target_os = "linux", target_os = "macos", target_os = "windows"),
        allow(dead_code)
    )]
    PlatformUnsupported,
}

impl Error {
    /// The errno a policy denial surfaces inside the sandboxed child. The single
    /// source of truth for the broker deny response and the trap `errno` field.
    /// Only the Linux broker mediates individual accesses; the static-profile
    /// platforms leave the errno to the kernel.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) const DENIAL_ERRNO: i32 = libc::EACCES;

    /// The stable, machine-routable code.
    pub(crate) fn code(&self) -> &'static str {
        self.into()
    }

    /// The errno the cause carries, or `None` when it carries none.
    #[cfg(unix)]
    pub(crate) fn errno(&self) -> Option<i32> {
        StdError::source(self)?
            .downcast_ref::<io::Error>()?
            .raw_os_error()
    }

    /// Windows reports Win32 status codes. They share the numeric space of POSIX
    /// errnos without sharing their meaning — `ERROR_ACCESS_DENIED` is 5, which
    /// is `EIO`, and `ERROR_INVALID_DATA` is 13, which is `EACCES`, landstrip's
    /// own denial errno — so nothing is mapped here rather than mapped wrongly.
    #[cfg(not(unix))]
    pub(crate) fn errno(&self) -> Option<i32> {
        let _ = self;
        None
    }

    /// The variant's discriminating data, or `None` when the code says it all.
    /// The cause, where there is one, is reached through [`StdError::source`].
    pub(crate) fn detail(&self) -> Option<String> {
        match self {
            Self::Usage { message } => Some(message.clone()),
            Self::LaunchFailed { tool, .. } => Some(tool.display().to_string()),
            Self::HostJobIncompatible { .. } => Some(
                "Landstrip is running inside a Job Object that prevents creating the sandbox job; start Pi outside the debugger or configure it to permit child-process breakaway"
                    .to_owned(),
            ),
            _ => None,
        }
    }
}

/// The symbolic name of `errno`, or `None` when it has no POSIX name (a Win32
/// status, say).
pub(crate) fn errno_name(errno: i32) -> Option<&'static str> {
    match errno {
        libc::E2BIG => Some("E2BIG"),
        libc::EACCES => Some("EACCES"),
        libc::EAGAIN => Some("EAGAIN"),
        libc::EBADF => Some("EBADF"),
        libc::EFAULT => Some("EFAULT"),
        libc::EINVAL => Some("EINVAL"),
        libc::EIO => Some("EIO"),
        libc::EISDIR => Some("EISDIR"),
        libc::ELOOP => Some("ELOOP"),
        libc::ENAMETOOLONG => Some("ENAMETOOLONG"),
        libc::ENOENT => Some("ENOENT"),
        libc::ENOEXEC => Some("ENOEXEC"),
        libc::ENOMEM => Some("ENOMEM"),
        libc::ENOTDIR => Some("ENOTDIR"),
        libc::EPERM => Some("EPERM"),
        _ => None,
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
            Self::PolicyIoFailed { source } => Some(source),
            Self::PolicyParseFailed { source }
            | Self::SandboxSetupFailed { source, .. }
            | Self::SuperviseFailed { source }
            | Self::LaunchFailed { source, .. }
            | Self::HostJobIncompatible { source } => Some(&**source),
            _ => None,
        }
    }
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.code())
    }
}
