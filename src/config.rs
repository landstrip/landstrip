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
    pub(crate) filesystem: SandboxFilesystem,
    pub(crate) network: SandboxNetwork,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct SandboxFilesystem {
    pub(crate) allow_write: Vec<String>,
    pub(crate) deny_write: Vec<String>,
    pub(crate) allow_read: Vec<String>,
    pub(crate) deny_read: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct SandboxNetwork {
    pub(crate) allow_network: bool,
    pub(crate) allow_local_binding: bool,
    pub(crate) allow_all_unix_sockets: bool,
    pub(crate) allow_unix_sockets: Vec<String>,
    pub(crate) http_proxy_port: Option<u16>,
    pub(crate) socks_proxy_port: Option<u16>,
}

pub(crate) fn load_settings(policy_paths: &[PathBuf]) -> Result<Settings> {
    let mut merged = Value::Object(Map::new());

    if policy_paths.is_empty() {
        let mut json = String::new();
        io::stdin()
            .read_to_string(&mut json)
            .map_err(|error| Error::policy(error.to_string()))?;
        let value: Value = serde_json::from_str(&json)?;
        merge_json(&mut merged, value);
    } else {
        for path in policy_paths {
            log::debug!("policy: file {}", path.display());

            let json = fs::read_to_string(path)
                .map_err(|source| Error::policy_file(path.clone(), source.to_string()))?;
            let value: Value = serde_json::from_str(&json)
                .map_err(|source| Error::policy_file(path.clone(), source.to_string()))?;
            merge_json(&mut merged, value);
        }
    }

    serde_json::from_value(merged).map_err(Error::from)
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
