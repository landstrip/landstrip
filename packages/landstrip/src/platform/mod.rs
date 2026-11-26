// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! OS-specific sandbox implementations that enforce a lowered policy.
//!
//! Each target selects its implementation and re-exports its [`execute`] entry
//! point, so callers use this module without naming an OS.

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows"
)))]
mod fallback;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
mod unix;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use linux::{Backend as LinuxBackend, resume_if_requested};

use crate::outcome::DoctorReport;
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows"
))]
use crate::outcome::SandboxPlatform;

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(crate) enum WindowsCommand {
    Install {
        restricted_accounts: u16,
        unrestricted_accounts: u16,
        proxy_port_low: u16,
        proxy_port_high: u16,
    },
    PrepareAppContainer,
    Status,
    Uninstall,
}

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows"
)))]
pub(crate) use fallback::execute;
#[cfg(target_os = "macos")]
pub(crate) use macos::execute;
#[cfg(target_os = "windows")]
pub(crate) use windows::{RESTRICTED_USER_RUNNER, execute, manage as manage_windows, run_worker};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(clippy::unnecessary_wraps, reason = "uniform platform validate API")]
pub(crate) fn validate(_policy: &crate::policy::AccessPolicy) -> crate::error::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn validate(policy: &crate::policy::AccessPolicy) -> crate::error::Result<()> {
    macos::validate(policy)
}

#[cfg(target_os = "windows")]
pub(crate) fn validate(policy: &crate::policy::AccessPolicy) -> crate::error::Result<()> {
    windows::validate(policy)
}

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows"
)))]
pub(crate) fn validate(_policy: &crate::policy::AccessPolicy) -> crate::error::Result<()> {
    Err(crate::error::Error::PlatformUnsupported)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn check(
    policy: &crate::policy::AccessPolicy,
    backend: LinuxBackend,
) -> crate::error::Result<()> {
    validate(policy)?;
    backend.check_host()
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub(crate) fn check(policy: &crate::policy::AccessPolicy) -> crate::error::Result<()> {
    validate(policy)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(clippy::unnecessary_wraps, reason = "uniform platform doctor API")]
pub(crate) fn doctor(backend: LinuxBackend) -> anyhow::Result<DoctorReport> {
    Ok(doctor_report(SandboxPlatform::Linux, backend.doctor()))
}

#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_wraps, reason = "uniform platform doctor API")]
pub(crate) fn doctor() -> anyhow::Result<DoctorReport> {
    Ok(doctor_report(SandboxPlatform::Macos, macos::doctor()))
}

#[cfg(target_os = "windows")]
pub(crate) fn doctor() -> anyhow::Result<DoctorReport> {
    let status = windows::status()?;
    Ok(DoctorReport::new(SandboxPlatform::Windows, status.error))
}

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    target_os = "windows"
)))]
pub(crate) fn doctor() -> anyhow::Result<DoctorReport> {
    Err(crate::error::Error::PlatformUnsupported.into())
}

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
fn doctor_report(platform: SandboxPlatform, result: anyhow::Result<()>) -> DoctorReport {
    DoctorReport::new(platform, result.err().map(|error| format!("{error:#}")))
}
