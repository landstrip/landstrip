// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Fallback platform implementation for unsupported platforms.
//!
//! Returns [`ErrorKind::Unsupported`] to communicate that the current
//! operating system is not yet supported by landstrip.

use crate::error::{Error, ErrorKind, Result};
use crate::error_fd::ErrorFd;
use crate::policy::AccessPolicy;
use std::ffi::{OsStr, OsString};

pub(crate) fn execute(
    _policy: &AccessPolicy,
    _tool: &OsStr,
    _args: &[OsString],
    _error_fd: ErrorFd,
) -> Result<()> {
    Err(Error::new(ErrorKind::Unsupported))
}
