// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::Error;
use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::error::Error as StdError;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub(crate) enum PolicyFormat {
    #[default]
    Json,
    Yaml,
}

impl PolicyFormat {
    pub(crate) fn parse_document(self, document: &str) -> std::result::Result<Value, Error> {
        match self {
            Self::Json => serde_json::from_str(document).map_err(parse_failed),
            Self::Yaml => serde_yml::from_str(document).map_err(parse_failed),
        }
    }
}

impl std::fmt::Display for PolicyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => f.write_str("json"),
            Self::Yaml => f.write_str("yaml"),
        }
    }
}

impl std::str::FromStr for PolicyFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "yaml" | "yml" => Ok(Self::Yaml),
            _ => Err(Error::Usage {
                message: format!("unsupported policy format: {s}"),
            }),
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Settings {
    pub(crate) filesystem: SandboxFilesystem,
    pub(crate) network: SandboxNetwork,
    pub(crate) windows: SandboxWindows,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SandboxNetwork {
    pub(crate) allow_network: bool,
    pub(crate) allow_local_binding: bool,
    pub(crate) allow_all_unix_sockets: bool,
    #[serde(deserialize_with = "deserialize_paths")]
    pub(crate) allow_unix_sockets: Vec<String>,
    pub(crate) http_proxy_port: Option<u16>,
    pub(crate) socks_proxy_port: Option<u16>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AppContainerMode {
    #[default]
    Lpac,
    Standard,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SandboxWindows {
    pub(crate) app_container_mode: AppContainerMode,
    pub(crate) allow_loopback: bool,
    #[serde(
        rename = "backend",
        deserialize_with = "reject_windows_backend",
        skip_serializing
    )]
    _removed_backend: (),
}

pub(crate) fn load_settings(
    policy_paths: &[PathBuf],
    format: PolicyFormat,
    tool: Option<&OsStr>,
) -> Result<Settings> {
    let mut merged = Value::Object(Map::new());

    for path in policy_paths {
        let (document, source_name) = if path.as_path() == Path::new("-") {
            let mut document = String::new();
            io::stdin()
                .read_to_string(&mut document)
                .context("policy stdin")?;
            (document, "policy stdin".to_owned())
        } else {
            log::debug!("config: {}", path.display());
            let document = fs::read_to_string(path)
                .with_context(|| format!("policy file {}", path.display()))?;
            (document, format!("policy file {}", path.display()))
        };
        let value = format
            .parse_document(&document)
            .with_context(|| source_name)?;
        merge_json(&mut merged, value);
    }

    if let Some(tool) = tool
        && let Some(value) = read_executable_policy(tool, format)?
    {
        merge_json(&mut merged, value);
    }

    serde_json::from_value(merged)
        .map_err(parse_failed)
        .context("policy")
}

/// Extra policy a sysadmin attaches to a specific tool's executable: a Unix
/// extended attribute or a Windows alternate data stream, merged over the
/// `--policy` documents.
///
/// The executable is resolved the same way the shell would find it (`PATH`
/// search unless the name already names a location) and then canonicalized,
/// so the attribute is always read from the real executable inode a `PATH`
/// trick cannot relocate.
fn read_executable_policy(tool: &OsStr, format: PolicyFormat) -> Result<Option<Value>> {
    let Some(exe) = resolve_executable(tool) else {
        return Ok(None);
    };

    let Some(bytes) =
        read_policy_bytes(&exe).with_context(|| format!("executable policy {}", exe.display()))?
    else {
        return Ok(None);
    };

    let document = String::from_utf8(bytes)
        .map_err(parse_failed)
        .with_context(|| format!("executable policy {}", exe.display()))?;
    let value = format
        .parse_document(&document)
        .with_context(|| format!("executable policy {}", exe.display()))?;
    Ok(Some(value))
}

fn resolve_executable(tool: &OsStr) -> Option<PathBuf> {
    let tool_path = Path::new(tool);
    let has_location = tool_path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());

    let candidate = if has_location {
        locate_executable(tool_path)?
    } else {
        let path_var = std::env::var_os("PATH")?;
        std::env::split_paths(&path_var).find_map(|dir| locate_executable(&dir.join(tool_path)))?
    };

    candidate.canonicalize().ok()
}

/// The extended attribute carrying a supplementary policy, in the
/// unprivileged `user` namespace: unlike `trusted.*` or `security.*`, it
/// needs no capability to read, matching the portable file-based policy it
/// supplements. A sysadmin who wants it root-only protects the executable
/// itself, the same way they would protect a `sandbox.json`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const EXECUTABLE_POLICY_XATTR: &str = "user.landstrip.policy";

/// The alternate data stream carrying the same policy on Windows.
#[cfg(target_os = "windows")]
const EXECUTABLE_POLICY_STREAM: &str = "landstrip.policy";

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn locate_executable(path: &Path) -> Option<PathBuf> {
    is_executable_file(path).then(|| path.to_path_buf())
}

#[cfg(target_os = "windows")]
fn locate_executable(path: &Path) -> Option<PathBuf> {
    resolve_with_extensions(path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn locate_executable(_path: &Path) -> Option<PathBuf> {
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_policy_bytes(exe: &Path) -> Result<Option<Vec<u8>>> {
    Ok(read_xattr(exe, EXECUTABLE_POLICY_XATTR)?)
}

#[cfg(target_os = "windows")]
fn read_policy_bytes(exe: &Path) -> Result<Option<Vec<u8>>> {
    let mut stream = exe.as_os_str().to_os_string();
    stream.push(":");
    stream.push(EXECUTABLE_POLICY_STREAM);
    match fs::read(PathBuf::from(stream)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::PolicyIoFailed { source }.into()),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn read_policy_bytes(_exe: &Path) -> Result<Option<Vec<u8>>> {
    Ok(None)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(target_os = "windows")]
fn resolve_with_extensions(base: &Path) -> Option<PathBuf> {
    if base.extension().is_some() {
        return base.is_file().then(|| base.to_path_buf());
    }

    let pathext = std::env::var_os("PATHEXT")
        .unwrap_or_else(|| std::ffi::OsString::from(".COM;.EXE;.BAT;.CMD"));
    std::env::split_paths(&pathext).find_map(|ext| {
        let mut candidate = base.as_os_str().to_os_string();
        candidate.push(ext);
        let candidate = PathBuf::from(candidate);
        candidate.is_file().then_some(candidate)
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_xattr(path: &Path, name: &str) -> std::result::Result<Option<Vec<u8>>, Error> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|source| Error::PolicyIoFailed {
            source: io::Error::new(io::ErrorKind::InvalidInput, source),
        })?;
    let c_name = CString::new(name).map_err(|source| Error::PolicyIoFailed {
        source: io::Error::new(io::ErrorKind::InvalidInput, source),
    })?;

    // SAFETY: c_path and c_name are live NUL-terminated C strings; a null
    // value pointer with size 0 only queries the attribute's length.
    let needed =
        unsafe { platform_getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
    if needed < 0 {
        return classify_xattr_error();
    }
    if needed == 0 {
        return Ok(Some(Vec::new()));
    }

    let needed = usize::try_from(needed).map_err(|_| Error::PolicyIoFailed {
        source: io::Error::new(io::ErrorKind::InvalidData, "xattr size does not fit usize"),
    })?;
    let mut buffer = vec![0u8; needed];
    // SAFETY: buffer is valid for writes of its own length, which is passed
    // as the size bound alongside it.
    let got = unsafe {
        platform_getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if got < 0 {
        return classify_xattr_error();
    }

    let got = usize::try_from(got).map_err(|_| Error::PolicyIoFailed {
        source: io::Error::new(io::ErrorKind::InvalidData, "xattr size does not fit usize"),
    })?;
    buffer.truncate(got);
    Ok(Some(buffer))
}

/// `ENODATA` (Linux) or `ENOATTR` (macOS) means the attribute is absent:
/// nothing to merge. Anything else — `ENOTSUP`, `EACCES`, `ERANGE`, a vanished
/// file — fails the invocation instead of silently skipping a policy that
/// might have tightened access.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn classify_xattr_error() -> std::result::Result<Option<Vec<u8>>, Error> {
    #[cfg(target_os = "linux")]
    let missing = libc::ENODATA;
    #[cfg(target_os = "macos")]
    let missing = libc::ENOATTR;

    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == missing || code == libc::ENOENT => Ok(None),
        _ => Err(Error::PolicyIoFailed { source: error }),
    }
}

#[cfg(target_os = "linux")]
unsafe fn platform_getxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *mut libc::c_void,
    size: libc::size_t,
) -> libc::ssize_t {
    unsafe { libc::getxattr(path, name, value, size) }
}

#[cfg(target_os = "macos")]
unsafe fn platform_getxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *mut libc::c_void,
    size: libc::size_t,
) -> libc::ssize_t {
    unsafe { libc::getxattr(path, name, value, size, 0, 0) }
}

fn parse_failed(source: impl StdError + Send + Sync + 'static) -> Error {
    Error::PolicyParseFailed {
        source: Box::new(source),
    }
}

fn reject_windows_backend<'de, D>(deserializer: D) -> std::result::Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    let _ = serde::de::IgnoredAny::deserialize(deserializer)?;

    Err(serde::de::Error::custom(
        "windows.backend was removed; use `landstrip windows install` or \
         `landstrip windows uninstall` to select the Windows implementation",
    ))
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
