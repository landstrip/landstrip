// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Fallback backend for unsupported platforms.
//!
//! Returns [`Error::Capability`] to communicate that the current
//! operating system is not yet supported by landstrip.

use crate::error::{Error, Result};
use crate::policy::AccessPolicy;
use std::ffi::{OsStr, OsString};
use std::path::Path;

pub(crate) fn execute(
    _policy: &AccessPolicy,
    _policy_base: &Path,
    _tool: &OsStr,
    _args: &[OsString],
) -> Result<()> {
    Err(Error::Capability {
        message: "platform sandbox support is missing".to_owned(),
    })
}
