// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::engine::policy::AccessPolicy;
use serde::Serialize;
use std::io::{self, Write};
use std::fmt;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum SandboxImplementation {
    #[cfg(target_os = "linux")]
    #[serde(rename = "landlock+seccomp")]
    LandlockSeccomp,
    #[cfg(target_os = "macos")]
    #[serde(rename = "seatbelt")]
    Seatbelt,
    #[cfg(target_os = "windows")]
    #[serde(rename = "appContainer")]
    AppContainer,
    #[cfg(target_os = "windows")]
    #[serde(rename = "restrictedUser")]
    RestrictedUser,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyValidationError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyValidationReport {
    pub(crate) valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<PolicyValidationError>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DoctorReport {
    pub(crate) ok: bool,
    pub(crate) platform: &'static str,
    pub(crate) implementation: SandboxImplementation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WindowsStatusReport {
    pub(crate) active: SandboxImplementation,
    pub(crate) installed: bool,
    pub(crate) healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) restricted_accounts: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unrestricted_accounts: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proxy_port_low: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proxy_port_high: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) runner: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) runner_healthy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) accounts_healthy: Option<bool>,
}

#[cfg(target_os = "windows")]
impl WindowsStatusReport {
    pub(crate) fn app_container() -> Self {
        Self {
            active: SandboxImplementation::AppContainer,
            installed: false,
            healthy: true,
            version: None,
            complete: None,
            restricted_accounts: None,
            unrestricted_accounts: None,
            proxy_port_low: None,
            proxy_port_high: None,
            runner: None,
            runner_healthy: None,
            accounts_healthy: None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum CommandOutcome {
    Exit(i32),
    PolicyValidated(PolicyValidationReport),
    PolicyResolved(AccessPolicy),
    Doctor(DoctorReport),
    #[cfg(target_os = "windows")]
    Windows(WindowsStatusReport),
}

impl CommandOutcome {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Exit(code) => *code,
            Self::PolicyValidated(report) => i32::from(!report.valid),
            Self::Doctor(report) => i32::from(!report.ok),
            #[cfg(target_os = "windows")]
            Self::Windows(report) => i32::from(!report.healthy),
            Self::PolicyResolved(_) => 0,
        }
    }

    pub(crate) fn write_to(&self, mut output: impl Write) -> io::Result<()> {
        match self {
            Self::Exit(_) => Ok(()),
            _ => writeln!(output, "{self}"),
        }
    }
}

impl fmt::Display for CommandOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exit(_) => Ok(()),
            Self::PolicyValidated(report) => match serde_json::to_string(report) {
                Ok(json) => f.write_str(&json),
                Err(_) => Err(fmt::Error),
            },
            Self::PolicyResolved(policy) => match serde_json::to_string(policy) {
                Ok(json) => f.write_str(&json),
                Err(_) => Err(fmt::Error),
            },
            Self::Doctor(report) => match serde_json::to_string(report) {
                Ok(json) => f.write_str(&json),
                Err(_) => Err(fmt::Error),
            },
            #[cfg(target_os = "windows")]
            Self::Windows(report) => match serde_json::to_string(report) {
                Ok(json) => f.write_str(&json),
                Err(_) => Err(fmt::Error),
            },
        }
    }
}
