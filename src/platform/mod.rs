// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! OS-specific sandbox implementations that enforce a lowered engine policy.
//!
//! Each target selects its implementation and re-exports its [`execute`] entry
//! point, so callers depend on `crate::platform::execute` without naming an OS.

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod fallback;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

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
pub(crate) fn validate(_policy: &crate::engine::policy::AccessPolicy) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn validate(policy: &crate::engine::policy::AccessPolicy) -> anyhow::Result<()> {
    policy.validate()?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn validate(policy: &crate::engine::policy::AccessPolicy) -> anyhow::Result<()> {
    windows::validate(policy)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn validate(_policy: &crate::engine::policy::AccessPolicy) -> anyhow::Result<()> {
    Err(crate::engine::error::Error::PlatformUnsupported.into())
}

#[cfg(target_os = "windows")]
pub(crate) fn manage_windows(command: &crate::cli::WindowsCommand) -> anyhow::Result<()> {
    windows::manage(command)
}

#[cfg(target_os = "windows")]
pub(crate) fn run_worker(request: &std::path::Path) -> anyhow::Result<()> {
    windows::run_worker(request)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn run_worker(_request: &std::path::Path) -> anyhow::Result<()> {
    Err(crate::engine::error::Error::PlatformUnsupported.into())
}

pub(crate) fn doctor() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let implementation = {
        linux::doctor()?;
        "landlock+seccomp"
    };
    #[cfg(target_os = "macos")]
    let implementation = {
        macos::doctor()?;
        "seatbelt"
    };
    #[cfg(target_os = "windows")]
    let implementation = windows::doctor()?;
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return Err(crate::engine::error::Error::PlatformUnsupported.into());

    println!(
        "{}",
        serde_json::to_string(&DoctorReport {
            ok: true,
            platform: std::env::consts::OS,
            implementation,
        })?
    );
    Ok(())
}

#[derive(serde::Serialize)]
struct DoctorReport {
    ok: bool,
    platform: &'static str,
    implementation: &'static str,
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn manage_windows(_command: &crate::cli::WindowsCommand) -> anyhow::Result<()> {
    Err(crate::engine::error::Error::PlatformUnsupported.into())
}
