// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! OS-specific sandbox implementations that enforce a lowered policy.
//!
//! Each target selects its implementation and re-exports its [`execute`] entry
//! point, so callers use this module without naming an OS.

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod fallback;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(target_os = "windows")]
mod windows;

use crate::outcome::DoctorReport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::outcome::SandboxImplementation;
#[cfg(target_os = "windows")]
use crate::outcome::WindowsStatusReport;

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(crate) enum WindowsCommand {
    Install {
        restricted_accounts: u16,
        unrestricted_accounts: u16,
        proxy_port_low: u16,
        proxy_port_high: u16,
    },
    Status,
    Uninstall,
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) use fallback::execute;
#[cfg(target_os = "linux")]
pub(crate) use linux::execute;
#[cfg(target_os = "macos")]
pub(crate) use macos::execute;
#[cfg(target_os = "windows")]
pub(crate) use windows::execute;

#[cfg(target_os = "linux")]
pub(crate) use linux::fd;

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps, reason = "uniform platform validation API")]
pub(crate) fn validate(_policy: &crate::policy::AccessPolicy) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn validate(policy: &crate::policy::AccessPolicy) -> anyhow::Result<()> {
    policy.validate()?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn validate(policy: &crate::policy::AccessPolicy) -> anyhow::Result<()> {
    windows::validate(policy)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn validate(_policy: &crate::policy::AccessPolicy) -> anyhow::Result<()> {
    Err(crate::error::Error::PlatformUnsupported.into())
}

#[cfg(target_os = "windows")]
pub(crate) fn manage_windows(command: &WindowsCommand) -> anyhow::Result<WindowsStatusReport> {
    windows::manage(command)
}

#[cfg(target_os = "windows")]
pub(crate) fn run_worker(request: &std::path::Path) -> anyhow::Result<i32> {
    windows::run_worker(request)
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps, reason = "uniform platform doctor API")]
pub(crate) fn doctor() -> anyhow::Result<DoctorReport> {
    Ok(doctor_report(
        SandboxImplementation::LandlockSeccomp,
        linux::doctor(),
    ))
}

#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_wraps, reason = "uniform platform doctor API")]
pub(crate) fn doctor() -> anyhow::Result<DoctorReport> {
    Ok(doctor_report(
        SandboxImplementation::Seatbelt,
        macos::doctor(),
    ))
}

#[cfg(target_os = "windows")]
pub(crate) fn doctor() -> anyhow::Result<DoctorReport> {
    let status = windows::status()?;
    let error = (!status.healthy).then(|| "restricted-user installation is unhealthy".to_owned());
    Ok(DoctorReport {
        ok: status.healthy,
        platform: std::env::consts::OS,
        implementation: status.active,
        error,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn doctor() -> anyhow::Result<DoctorReport> {
    Err(crate::error::Error::PlatformUnsupported.into())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn doctor_report(
    implementation: SandboxImplementation,
    result: anyhow::Result<()>,
) -> DoctorReport {
    let error = result.err().map(|error| format!("{error:#}"));
    DoctorReport {
        ok: error.is_none(),
        platform: std::env::consts::OS,
        implementation,
        error,
    }
}
