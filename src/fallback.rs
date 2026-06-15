// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Fallback platform implementation for unsupported platforms.
//!
//! Returns [`Trap::Internal`] to communicate that the current
//! operating system is not yet supported by landstrip.

use crate::policy::AccessPolicy;
use crate::trap::{Result, Trap};
use crate::trap_fd::TrapFd;
use std::ffi::{OsStr, OsString};

pub(crate) fn execute(
    _policy: &AccessPolicy,
    _tool: &OsStr,
    _args: &[OsString],
    _trap_fd: TrapFd,
) -> Result<()> {
    Err(Trap::internal())
}
