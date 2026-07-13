// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Platform-independent sandbox engine: policy lowering, path resolution, and
//! the trap reporting channel shared by the OS backends.

pub(crate) mod error;
pub(crate) mod paths;
pub(crate) mod policy;
pub(crate) mod trap;
pub(crate) mod trap_fd;
