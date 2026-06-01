// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

const HTTP_PROXY: &str = "HTTP_PROXY";
const SOCKS_PROXY: &str = "SOCKS_PROXY";

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
    pub(crate) allow_local_binding: bool,
    pub(crate) allow_all_unix_sockets: bool,
    pub(crate) allow_unix_sockets: Vec<String>,
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
            .map_err(|source| Error::with_source("policy: stdin", source))?;
        let value: Value = serde_json::from_str(&json)
            .map_err(|source| Error::with_source("policy: stdin", source))?;
        merge_json(&mut merged, value);
    } else {
        for path in policy_paths {
            log::debug!("policy: file {}", path.display());

            let context = format!("policy: file {}", path.display());
            let json = fs::read_to_string(path)
                .map_err(|source| Error::with_source(context.clone(), source))?;
            let value: Value = serde_json::from_str(&json)
                .map_err(|source| Error::with_source(context, source))?;
            merge_json(&mut merged, value);
        }
    }

    apply_proxy_env_defaults(&mut merged, |name| env::var(name).ok())?;

    serde_json::from_value(merged).map_err(|source| Error::with_source("policy: decode", source))
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

fn apply_proxy_env_defaults(
    settings: &mut Value,
    env_var: impl Fn(&str) -> Option<String>,
) -> Result<()> {
    let Some(settings) = settings.as_object_mut() else {
        return Ok(());
    };

    if settings
        .get("network")
        .is_some_and(|network| !network.is_object())
    {
        return Ok(());
    }

    let http_proxy_port = env_var(HTTP_PROXY)
        .map(|value| proxy_port(HTTP_PROXY, &value, 80))
        .transpose()?;
    let socks_proxy_port = env_var(SOCKS_PROXY)
        .map(|value| proxy_port(SOCKS_PROXY, &value, 1080))
        .transpose()?;
    if http_proxy_port.is_none() && socks_proxy_port.is_none() {
        return Ok(());
    }

    let network = settings
        .entry("network")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("network object created above");

    if !network.contains_key("httpProxyPort") {
        if let Some(port) = http_proxy_port {
            network.insert("httpProxyPort".to_owned(), Value::from(port));
        }
    }

    if !network.contains_key("socksProxyPort") {
        if let Some(port) = socks_proxy_port {
            network.insert("socksProxyPort".to_owned(), Value::from(port));
        }
    }

    Ok(())
}

fn proxy_port(name: &str, value: &str, default_port: u16) -> Result<Option<u16>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }

    let authority = value
        .split_once("://")
        .map_or(value, |(_, authority)| authority);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    if authority.is_empty() {
        return Ok(None);
    }

    let port = authority_port(name, authority)?.unwrap_or(default_port);

    if port == 0 {
        return Err(Error::message(format!(
            "policy: net {name} range 1..=65535",
        )));
    }

    Ok(Some(port))
}

fn authority_port(name: &str, authority: &str) -> Result<Option<u16>> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((_, rest)) = rest.split_once(']') else {
            return Ok(None);
        };
        let Some(port) = rest.strip_prefix(':') else {
            return Ok(None);
        };

        return parse_port(name, port).map(Some);
    }

    let Some((_, port)) = authority.rsplit_once(':') else {
        return Ok(None);
    };

    parse_port(name, port).map(Some)
}

fn parse_port(name: &str, port: &str) -> Result<u16> {
    if port.is_empty() {
        return Err(Error::message(format!("policy: net {name} port empty")));
    }

    port.parse::<u16>()
        .map_err(|source| Error::with_source(format!("policy: net {name} port"), source))
}
