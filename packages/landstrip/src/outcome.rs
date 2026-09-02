// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::policy::AccessPolicy;
use serde::Serialize;
use std::io::{self, Write};
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct PolicyValidationError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct PolicyValidationReport {
    pub(crate) valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<PolicyValidationError>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct DoctorReport {
    pub(crate) ok: bool,
    pub(crate) platform: &'static str,
    pub(crate) implementation: SandboxImplementation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[cfg(target_os = "windows")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

    pub(crate) fn restricted_user(
        version: u32,
        complete: bool,
        restricted_accounts: usize,
        unrestricted_accounts: usize,
        proxy_port_low: u16,
        proxy_port_high: u16,
        runner: PathBuf,
        runner_healthy: bool,
        accounts_healthy: bool,
    ) -> Self {
        Self {
            active: SandboxImplementation::RestrictedUser,
            installed: true,
            healthy: complete && accounts_healthy && runner_healthy,
            version: Some(version),
            complete: Some(complete),
            restricted_accounts: Some(restricted_accounts),
            unrestricted_accounts: Some(unrestricted_accounts),
            proxy_port_low: Some(proxy_port_low),
            proxy_port_high: Some(proxy_port_high),
            runner: Some(runner),
            runner_healthy: Some(runner_healthy),
            accounts_healthy: Some(accounts_healthy),
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
            Self::PolicyValidated(report) => write_json(&mut output, report),
            Self::PolicyResolved(policy) => write_json(&mut output, policy),
            Self::Doctor(report) => write_json(&mut output, report),
            #[cfg(target_os = "windows")]
            Self::Windows(report) => write_json(&mut output, report),
        }
    }
}

fn write_json(output: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    writeln!(output)
}
