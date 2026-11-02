// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
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

impl SandboxImplementation {
    fn capabilities(self) -> FeatureCapabilities {
        let capabilities = FeatureCapabilities {
            filesystem_tiers: &[
                "allowWrite",
                "denyWrite",
                "allowRead",
                "denyRead",
                "denyReadAlways",
                "denyWriteAlways",
            ],
            network_mediation: true,
            unix_socket_filtering: false,
            process_isolation: false,
        };
        match self {
            #[cfg(target_os = "linux")]
            Self::LandlockSeccomp => FeatureCapabilities {
                unix_socket_filtering: true,
                process_isolation: true,
                ..capabilities
            },
            #[cfg(target_os = "macos")]
            Self::Seatbelt => FeatureCapabilities {
                unix_socket_filtering: true,
                ..capabilities
            },
            #[cfg(target_os = "windows")]
            Self::AppContainer | Self::RestrictedUser => FeatureCapabilities {
                filesystem_tiers: &["allowWrite", "denyWrite", "allowRead", "denyRead"],
                ..capabilities
            },
        }
    }
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

impl TryFrom<Result<()>> for PolicyValidationReport {
    type Error = Error;

    fn try_from(result: Result<()>) -> Result<Self> {
        match result {
            Ok(()) => Ok(Self {
                valid: true,
                error: None,
            }),
            Err(error) => {
                let Some(message) = error.validation_message() else {
                    return Err(error);
                };
                Ok(Self {
                    valid: false,
                    error: Some(PolicyValidationError {
                        code: error.code(),
                        message,
                    }),
                })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct DoctorReport {
    pub(crate) ok: bool,
    pub(crate) platform: &'static str,
    pub(crate) implementation: SandboxImplementation,
    pub(crate) supported: FeatureCapabilities,
    pub(crate) available: FeatureCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

impl DoctorReport {
    pub(crate) fn new(implementation: SandboxImplementation, error: Option<String>) -> Self {
        let ok = error.is_none();
        let supported = implementation.capabilities();
        let available = if ok {
            supported
        } else {
            FeatureCapabilities::default()
        };
        Self {
            ok,
            platform: std::env::consts::OS,
            implementation,
            supported,
            available,
            error,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct FeatureCapabilities {
    pub(crate) filesystem_tiers: &'static [&'static str],
    pub(crate) network_mediation: bool,
    pub(crate) unix_socket_filtering: bool,
    pub(crate) process_isolation: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[cfg(target_os = "windows")]
impl WindowsStatusReport {
    pub(crate) fn app_container(error: Option<String>) -> Self {
        Self {
            active: SandboxImplementation::AppContainer,
            installed: false,
            healthy: error.is_none(),
            version: None,
            complete: None,
            restricted_accounts: None,
            unrestricted_accounts: None,
            proxy_port_low: None,
            proxy_port_high: None,
            runner: None,
            runner_healthy: None,
            accounts_healthy: None,
            error,
        }
    }
}

#[derive(Debug)]
pub(crate) enum CommandOutcome {
    Exit(i32),
    Json {
        exit_code: i32,
        value: serde_json::Value,
    },
}

impl CommandOutcome {
    pub(crate) fn json(ok: bool, value: impl Serialize) -> serde_json::Result<Self> {
        Ok(Self::Json {
            exit_code: i32::from(!ok),
            value: serde_json::to_value(value)?,
        })
    }

    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Exit(code) => *code,
            Self::Json { exit_code, .. } => *exit_code,
        }
    }

    pub(crate) fn write_to(&self, mut output: impl Write) -> io::Result<()> {
        if let Self::Json { value, .. } = self {
            serde_json::to_writer(&mut output, value)?;
            writeln!(output)?;
        }
        Ok(())
    }
}
