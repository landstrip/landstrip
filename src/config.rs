// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct Settings {
    pub(crate) sandbox: Option<Sandbox>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Sandbox {
    pub(crate) enabled: bool,
    pub(crate) fail_if_unavailable: bool,
    pub(crate) filesystem: Option<SandboxFilesystem>,
    pub(crate) network: Option<SandboxNetwork>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SandboxFilesystem {
    pub(crate) allow_write: Vec<String>,
    pub(crate) deny_write: Vec<String>,
    pub(crate) allow_read: Vec<String>,
    pub(crate) deny_read: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SandboxNetwork {
    pub(crate) allow_local_binding: bool,
    pub(crate) http_proxy_port: Option<u16>,
    pub(crate) socks_proxy_port: Option<u16>,
    pub(crate) allowed_domains: Vec<String>,
    pub(crate) denied_domains: Vec<String>,
}

pub(crate) fn load_settings(policy_paths: &[PathBuf]) -> Result<Settings> {
    let mut merged = Value::Object(Map::new());

    if policy_paths.is_empty() {
        let mut json = String::new();
        io::stdin()
            .read_to_string(&mut json)
            .map_err(|source| Error::with_source("stdin", source))?;
        let value: Value =
            serde_json::from_str(&json).map_err(|source| Error::with_source("stdin", source))?;
        merge_json(&mut merged, value);
    } else {
        for path in policy_paths {
            log::debug!("policy document: {}", path.display());

            let context = path.display().to_string();
            let json = fs::read_to_string(path)
                .map_err(|source| Error::with_source(context.clone(), source))?;
            let value: Value = serde_json::from_str(&json)
                .map_err(|source| Error::with_source(context, source))?;
            merge_json(&mut merged, value);
        }
    }

    serde_json::from_value(merged).map_err(|source| Error::with_source("policy", source))
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
