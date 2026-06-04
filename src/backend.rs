// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! OS-specific sandbox execution backends.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::error::Error;
use crate::error::Result;
use crate::policy::AccessPolicy;
use std::ffi::{OsStr, OsString};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::process::CommandExt;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

/// Trait for platform-specific sandbox backends.
pub(crate) trait Backend {
    /// Execute `command` with `args` under the given access policy.
    ///
    /// On success this function replaces the current process image and
    /// therefore never returns. On error a [`Result`] is returned.
    fn execute(
        &self,
        policy: &AccessPolicy,
        policy_base: &Path,
        command: &OsStr,
        args: &[OsString],
    ) -> Result<()>;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn exec_unix_command(command: &OsStr, args: &[OsString]) -> Result<()> {
    let error = Command::new(command).args(args).exec();
    Err(Error::Exec {
        command: command.to_os_string(),
        source: error,
    })
}

/// Compile-time platform backend selection.
#[cfg(target_os = "linux")]
pub(crate) use crate::linux::LinuxBackend as PlatformBackend;

#[cfg(target_os = "macos")]
pub(crate) use crate::macos::MacosBackend as PlatformBackend;

#[cfg(target_os = "windows")]
pub(crate) use crate::windows::WindowsBackend as PlatformBackend;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) use crate::fallback::FallbackBackend as PlatformBackend;
