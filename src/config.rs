// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::cli::PolicyFormat;
use crate::engine::error::Error;
use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::error::Error as StdError;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct Settings {
    pub(crate) filesystem: SandboxFilesystem,
    pub(crate) network: SandboxNetwork,
    pub(crate) windows: SandboxWindows,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct SandboxFilesystem {
    #[serde(deserialize_with = "deserialize_paths")]
    pub(crate) allow_write: Vec<String>,
    #[serde(deserialize_with = "deserialize_paths")]
    pub(crate) deny_write: Vec<String>,
    #[serde(deserialize_with = "deserialize_paths")]
    pub(crate) allow_read: Vec<String>,
    #[serde(deserialize_with = "deserialize_paths")]
    pub(crate) deny_read: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct SandboxNetwork {
    pub(crate) allow_network: bool,
    pub(crate) allow_local_binding: bool,
    pub(crate) allow_all_unix_sockets: bool,
    #[serde(deserialize_with = "deserialize_paths")]
    pub(crate) allow_unix_sockets: Vec<String>,
    pub(crate) http_proxy_port: Option<u16>,
    pub(crate) socks_proxy_port: Option<u16>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AppContainerMode {
    #[default]
    Lpac,
    Standard,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum WindowsBackend {
    #[default]
    AppContainer,
    RestrictedUser,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct SandboxWindows {
    pub(crate) backend: WindowsBackend,
    pub(crate) app_container_mode: AppContainerMode,
    pub(crate) allow_loopback: bool,
}

pub(crate) fn load_settings(policy_paths: &[PathBuf], format: PolicyFormat) -> Result<Settings> {
    let mut merged = Value::Object(Map::new());

    if policy_paths.is_empty() {
        let mut document = String::new();
        io::stdin()
            .read_to_string(&mut document)
            .map_err(|source| Error::PolicyIoFailed { source })
            .context("policy stdin")?;
        let value = parse_policy_document(&document, format).context("policy stdin")?;
        merge_json(&mut merged, value);
        parse_settings(merged).context("policy stdin")
    } else {
        let mut last_path = &policy_paths[0];
        for path in policy_paths {
            log::debug!("config: {}", path.display());

            let document = fs::read_to_string(path)
                .map_err(|source| Error::PolicyIoFailed { source })
                .with_context(|| format!("policy file {}", path.display()))?;
            let value = parse_policy_document(&document, format)
                .with_context(|| format!("policy file {}", path.display()))?;
            merge_json(&mut merged, value);
            last_path = path;
        }
        parse_settings(merged).with_context(|| format!("policy file {}", last_path.display()))
    }
}

fn parse_policy_document(
    document: &str,
    format: PolicyFormat,
) -> std::result::Result<Value, Error> {
    match format {
        PolicyFormat::Json => serde_json::from_str(document).map_err(parse_failed),
        PolicyFormat::Yaml => serde_yml::from_str(document).map_err(parse_failed),
    }
}

fn parse_settings(document: Value) -> std::result::Result<Settings, Error> {
    serde_json::from_value(document).map_err(parse_failed)
}

fn parse_failed(source: impl StdError + Send + Sync + 'static) -> Error {
    Error::PolicyParseFailed {
        source: Box::new(source),
    }
}

fn deserialize_paths<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let input = Option::<PathInput>::deserialize(deserializer)?;

    Ok(match input {
        Some(PathInput::List(paths)) => paths,
        Some(PathInput::Lines(lines)) => lines
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        None => Vec::new(),
    })
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PathInput {
    List(Vec<String>),
    Lines(String),
}

fn merge_json(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                merge_json(base.entry(key).or_insert(Value::Null), value);
            }
        }
        (Value::Array(base), Value::Array(overlay)) => {
            for value in overlay {
                if !base.contains(&value) {
                    base.push(value);
                }
            }
        }
        (base, overlay) => {
            *base = overlay;
        }
    }
}
