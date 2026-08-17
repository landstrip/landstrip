// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::policy::AccessPolicy;
use serde::{Serialize, Serializer};
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

#[derive(Debug, Serialize)]
pub(crate) struct PolicyValidationError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Debug)]
pub(crate) enum PolicyValidationReport {
    Valid,
    Invalid(PolicyValidationError),
}

impl Serialize for PolicyValidationReport {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Report<'a> {
            valid: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<&'a PolicyValidationError>,
        }

        let (valid, error) = match self {
            Self::Valid => (true, None),
            Self::Invalid(error) => (false, Some(error)),
        };
        Report { valid, error }.serialize(serializer)
    }
}

#[derive(Debug)]
pub(crate) enum DoctorReport {
    Healthy {
        platform: &'static str,
        implementation: SandboxImplementation,
    },
    Unhealthy {
        platform: &'static str,
        implementation: SandboxImplementation,
        error: String,
    },
}

impl Serialize for DoctorReport {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Report<'a> {
            ok: bool,
            platform: &'static str,
            implementation: SandboxImplementation,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<&'a str>,
        }

        let report = match self {
            Self::Healthy {
                platform,
                implementation,
            } => Report {
                ok: true,
                platform,
                implementation: *implementation,
                error: None,
            },
            Self::Unhealthy {
                platform,
                implementation,
                error,
            } => Report {
                ok: false,
                platform,
                implementation: *implementation,
                error: Some(error),
            },
        };
        report.serialize(serializer)
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(crate) enum WindowsStatusReport {
    AppContainer,
    RestrictedUser {
        version: u32,
        complete: bool,
        restricted_accounts: usize,
        unrestricted_accounts: usize,
        proxy_port_low: u16,
        proxy_port_high: u16,
        runner: PathBuf,
        runner_healthy: bool,
        accounts_healthy: bool,
    },
}

#[cfg(target_os = "windows")]
impl WindowsStatusReport {
    pub(crate) fn app_container() -> Self {
        Self::AppContainer
    }

    pub(crate) fn active(&self) -> SandboxImplementation {
        match self {
            Self::AppContainer => SandboxImplementation::AppContainer,
            Self::RestrictedUser { .. } => SandboxImplementation::RestrictedUser,
        }
    }

    pub(crate) fn healthy(&self) -> bool {
        match self {
            Self::AppContainer => true,
            Self::RestrictedUser {
                complete,
                runner_healthy,
                accounts_healthy,
                ..
            } => *complete && *accounts_healthy && *runner_healthy,
        }
    }
}

#[cfg(target_os = "windows")]
impl Serialize for WindowsStatusReport {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Report<'a> {
            active: SandboxImplementation,
            installed: bool,
            healthy: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            version: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            complete: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            restricted_accounts: Option<usize>,
            #[serde(skip_serializing_if = "Option::is_none")]
            unrestricted_accounts: Option<usize>,
            #[serde(skip_serializing_if = "Option::is_none")]
            proxy_port_low: Option<u16>,
            #[serde(skip_serializing_if = "Option::is_none")]
            proxy_port_high: Option<u16>,
            #[serde(skip_serializing_if = "Option::is_none")]
            runner: Option<&'a PathBuf>,
            #[serde(skip_serializing_if = "Option::is_none")]
            runner_healthy: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            accounts_healthy: Option<bool>,
        }

        let report = match self {
            Self::AppContainer => Report {
                active: self.active(),
                installed: false,
                healthy: self.healthy(),
                version: None,
                complete: None,
                restricted_accounts: None,
                unrestricted_accounts: None,
                proxy_port_low: None,
                proxy_port_high: None,
                runner: None,
                runner_healthy: None,
                accounts_healthy: None,
            },
            Self::RestrictedUser {
                version,
                complete,
                restricted_accounts,
                unrestricted_accounts,
                proxy_port_low,
                proxy_port_high,
                runner,
                runner_healthy,
                accounts_healthy,
            } => Report {
                active: self.active(),
                installed: true,
                healthy: self.healthy(),
                version: Some(*version),
                complete: Some(*complete),
                restricted_accounts: Some(*restricted_accounts),
                unrestricted_accounts: Some(*unrestricted_accounts),
                proxy_port_low: Some(*proxy_port_low),
                proxy_port_high: Some(*proxy_port_high),
                runner: Some(runner),
                runner_healthy: Some(*runner_healthy),
                accounts_healthy: Some(*accounts_healthy),
            },
        };
        report.serialize(serializer)
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
            Self::PolicyValidated(report) => {
                i32::from(!matches!(report, PolicyValidationReport::Valid))
            }
            Self::Doctor(report) => i32::from(!matches!(report, DoctorReport::Healthy { .. })),
            #[cfg(target_os = "windows")]
            Self::Windows(report) => i32::from(!report.healthy()),
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
