// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Sandbox engine: policy loading and lowering, platform enforcement, and
//! structured outcomes and traps.

pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod outcome;
pub(crate) mod paths;
pub(crate) mod platform;
pub(crate) mod policy;
pub(crate) mod trap;
#[cfg(unix)]
pub(crate) mod trap_fd;
