// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Linux sandbox platform using a KVM guest and namespaces.

pub(crate) mod kvm;
mod namespace;
mod signals;

use crate::policy::AccessPolicy;
use crate::trap_fd::TrapFd;
use anyhow::Result;
use std::ffi::{OsStr, OsString};
use std::path::Path;

pub(crate) fn resume_if_requested() -> Option<Result<i32>> {
    kvm::Sandbox::resume_if_requested()
}

pub(crate) fn doctor() -> Result<()> {
    kvm::Sandbox::probe()?;
    namespace::probe()
}

pub(crate) fn check_host() -> crate::error::Result<()> {
    kvm::Sandbox::probe().map_err(|error| {
        crate::error::Error::sandbox_setup(
            crate::error::Mechanism::Kvm,
            error.into_boxed_dyn_error(),
        )
    })?;
    namespace::probe().map_err(|error| {
        crate::error::Error::sandbox_setup(
            crate::error::Mechanism::Namespace,
            error.into_boxed_dyn_error(),
        )
    })
}

pub(crate) fn execute(
    policy: &AccessPolicy,
    cwd: &Path,
    tool: &OsStr,
    args: &[OsString],
    trap_fd: Option<&mut TrapFd>,
    inherited_fds: &[std::os::fd::RawFd],
) -> Result<i32> {
    kvm::Sandbox::execute(policy, cwd, tool, args, trap_fd, inherited_fds)
}
