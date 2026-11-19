// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Fallback platform implementation for unsupported platforms.
//!
//! Returns an error to communicate that the current operating system is not yet
//! supported by landstrip.

use crate::error::Error;
use crate::policy::AccessPolicy;
#[cfg(unix)]
use crate::trap_fd::TrapFd;
use anyhow::Result;
use std::ffi::{OsStr, OsString};
use std::path::Path;

#[cfg(unix)]
pub(crate) fn execute(
    _policy: &AccessPolicy,
    _cwd: &Path,
    _tool: &OsStr,
    _args: &[OsString],
    _trap_fd: Option<&mut TrapFd>,
    _inherited_fds: &[std::os::fd::RawFd],
) -> Result<i32> {
    Err(Error::PlatformUnsupported.into())
}

#[cfg(not(unix))]
pub(crate) fn execute(
    _policy: &AccessPolicy,
    _cwd: &Path,
    _tool: &OsStr,
    _args: &[OsString],
) -> Result<i32> {
    Err(Error::PlatformUnsupported.into())
}
