// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

mod container;
pub(crate) mod kvm;
mod namespace;
mod signals;

use crate::policy::AccessPolicy;
use crate::trap_fd::TrapFd;
use anyhow::Result;
use clap::ValueEnum;
use clap::builder::PossibleValue;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::fd::RawFd;
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum Backend {
    #[default]
    Auto,
    Container,
    Machine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolvedBackend {
    Container,
    Machine,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_possible_value()
            .as_ref()
            .map_or("", PossibleValue::get_name)
            .fmt(f)
    }
}

impl Backend {
    fn resolve(self) -> ResolvedBackend {
        match self {
            Self::Auto => {
                if kvm::Sandbox::is_available() {
                    ResolvedBackend::Machine
                } else {
                    ResolvedBackend::Container
                }
            }
            Self::Container => ResolvedBackend::Container,
            Self::Machine => ResolvedBackend::Machine,
        }
    }

    pub(crate) fn doctor(self) -> Result<()> {
        match self.resolve() {
            ResolvedBackend::Container => {
                container::Sandbox::probe()?;
                namespace::probe()
            }
            ResolvedBackend::Machine => {
                kvm::Sandbox::probe()?;
                namespace::probe()
            }
        }
    }

    pub(crate) fn check_host(self) -> crate::error::Result<()> {
        match self.resolve() {
            ResolvedBackend::Container => {
                container::Sandbox::check_host()?;
                namespace::probe().map_err(|error| {
                    crate::error::Error::sandbox_setup(
                        crate::error::Mechanism::Namespace,
                        error.into_boxed_dyn_error(),
                    )
                })
            }
            ResolvedBackend::Machine => {
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
        }
    }

    pub(crate) fn execute(
        self,
        policy: &AccessPolicy,
        cwd: &Path,
        tool: &OsStr,
        args: &[OsString],
        trap_fd: Option<&mut TrapFd>,
        inherited_fds: &[RawFd],
    ) -> Result<i32> {
        match self.resolve() {
            ResolvedBackend::Container => container::Sandbox::execute(
                policy,
                cwd,
                tool,
                args,
                trap_fd.as_deref(),
                inherited_fds,
            ),
            ResolvedBackend::Machine => {
                kvm::Sandbox::execute(policy, cwd, tool, args, trap_fd, inherited_fds)
            }
        }
    }
}

pub(crate) fn resume_if_requested() -> Option<Result<i32>> {
    kvm::Sandbox::resume_if_requested()
}
