// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! OS-specific sandbox backends that enforce a lowered engine policy.
//!
//! Each target selects exactly one backend and re-exports its [`execute`]
//! entry point, so callers depend on `crate::platform::execute` without naming
//! an operating system.

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

#[cfg(target_os = "windows")]
pub(crate) fn manage_windows(command: &crate::cli::WindowsCommand) -> anyhow::Result<()> {
    windows::manage(command)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn manage_windows(_command: &crate::cli::WindowsCommand) -> anyhow::Result<()> {
    Err(crate::engine::error::Error::PlatformUnsupported.into())
}
