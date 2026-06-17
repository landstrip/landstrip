// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::cli::PolicyFormat;
use crate::trap::{Result, Trap};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::error::Error as StdError;
use std::fmt;
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

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct SandboxWindows {
    pub(crate) disable_win32k: bool,
    pub(crate) disable_extension_points: bool,
    pub(crate) strict_handle_checks: bool,
    pub(crate) image_load_no_remote: bool,
    pub(crate) image_load_no_low_label: bool,
    pub(crate) image_load_prefer_system32: bool,
}

pub(crate) fn load_settings(policy_paths: &[PathBuf], format: PolicyFormat) -> Result<Settings> {
    let mut merged = Value::Object(Map::new());

    if policy_paths.is_empty() {
        let mut document = String::new();
        io::stdin()
            .read_to_string(&mut document)
            .map_err(Trap::policy_stdin_source)?;
        let value = parse_policy_document(&document, format).map_err(Trap::policy_stdin_source)?;
        merge_json(&mut merged, value);
        serde_json::from_value(merged).map_err(Trap::policy_stdin_source)
    } else {
        for path in policy_paths {
            log::debug!("config: {}", path.display());

            let document = fs::read_to_string(path)
                .map_err(|source| Trap::policy_file_source(path, source))?;
            let value = parse_policy_document(&document, format)
                .map_err(|source| Trap::policy_file_source(path, source))?;
            merge_json(&mut merged, value);
        }
        serde_json::from_value(merged)
            .map_err(|source| Trap::policy_file_source(&policy_paths[0], source))
    }
}

fn parse_policy_document(
    document: &str,
    format: PolicyFormat,
) -> std::result::Result<Value, PolicyDocumentError> {
    match format {
        PolicyFormat::Json => serde_json::from_str(document).map_err(PolicyDocumentError::Json),
        PolicyFormat::Yaml => serde_yml::from_str(document).map_err(PolicyDocumentError::Yaml),
    }
}

#[derive(Debug)]
enum PolicyDocumentError {
    Json(serde_json::Error),
    Yaml(serde_yml::Error),
}

impl fmt::Display for PolicyDocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => error.fmt(f),
            Self::Yaml(error) => error.fmt(f),
        }
    }
}

impl StdError for PolicyDocumentError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Yaml(error) => Some(error),
        }
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
