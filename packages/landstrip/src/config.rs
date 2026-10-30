// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::Error;
use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
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
        let mut value: Value = match self {
            Self::Json => serde_json::from_str(document).map_err(Error::parse_failed)?,
            Self::Yaml => serde_yml::from_str(document).map_err(Error::parse_failed)?,
        };
        if !value.is_object()
            || value
                .get("filesystem")
                .is_some_and(|filesystem| !filesystem.is_object())
        {
            return Err(Error::parse_failed(io::Error::new(
                io::ErrorKind::InvalidData,
                "policy root and filesystem must be objects",
            )));
        }
        for pointer in [
            "/filesystem/allowWrite",
            "/filesystem/denyWrite",
            "/filesystem/allowRead",
            "/filesystem/denyRead",
            "/filesystem/denyReadAlways",
            "/filesystem/denyWriteAlways",
            "/network/allowUnixSockets",
        ] {
            if let Some(paths) = value.pointer_mut(pointer) {
                let resolved = deserialize_paths(paths.take()).map_err(Error::parse_failed)?;
                *paths = serde_json::to_value(resolved).map_err(Error::parse_failed)?;
            }
        }
        if let Some(services) = value.pointer_mut("/macos/allowMachLookup") {
            let resolved = deserialize_strings(services.take()).map_err(Error::parse_failed)?;
            *services = serde_json::to_value(resolved).map_err(Error::parse_failed)?;
        }
        serde_json::from_value::<Settings>(value.clone()).map_err(Error::parse_failed)?;
        Ok(value)
    }

    fn read_executable_policy(self, tool: &OsStr, cwd: &Path) -> Result<Option<Value>> {
        let Some(exe) = resolve_executable(tool, cwd) else {
            return Ok(None);
        };
        let context = format!("executable policy {}", exe.display());

        let Some(bytes) = read_policy_bytes(&exe).with_context(|| context.clone())? else {
            return Ok(None);
        };

        let document = String::from_utf8(bytes)
            .map_err(Error::parse_failed)
            .with_context(|| context.clone())?;
        let value = self.parse_document(&document).with_context(|| context)?;
        Ok(Some(value))
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Settings {
    pub(crate) filesystem: SandboxFilesystem,
    pub(crate) network: SandboxNetwork,
    pub(crate) macos: SandboxDarwin,
    pub(crate) windows: SandboxWindows,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum PathSelector {
    Literal { literal: String },
    Glob { glob: String },
    Bare(String),
}

impl PathSelector {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Literal { literal } | Self::Glob { glob: literal } | Self::Bare(literal) => {
                literal
            }
        }
    }

    pub(crate) fn is_literal(&self) -> bool {
        matches!(self, Self::Literal { .. })
    }

    /// True when the entry resolves against the policy base rather than naming
    /// an absolute path or home-relative scope.
    pub(crate) fn is_base_relative(&self) -> bool {
        let raw = self.as_str();
        !Path::new(raw).has_root() && raw != "~" && !raw.starts_with("~/")
    }

    pub(crate) fn literal_path(path: &Path) -> Self {
        Self::Literal {
            literal: path.to_string_lossy().into_owned(),
        }
    }

    pub(crate) fn join_under(&self, root: &Path) -> Self {
        let joined = root.join(self.as_str()).to_string_lossy().into_owned();
        match self {
            Self::Literal { .. } => Self::Literal { literal: joined },
            Self::Glob { .. } => Self::Glob { glob: joined },
            Self::Bare(_) => Self::Bare(joined),
        }
    }
}

impl AsRef<str> for PathSelector {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SandboxFilesystem {
    pub(crate) allow_write: Vec<PathSelector>,
    pub(crate) deny_write: Vec<PathSelector>,
    pub(crate) allow_read: Vec<PathSelector>,
    pub(crate) deny_read: Vec<PathSelector>,
    pub(crate) deny_read_always: Vec<PathSelector>,
    pub(crate) deny_write_always: Vec<PathSelector>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SandboxNetwork {
    pub(crate) allow_network: bool,
    pub(crate) allow_local_binding: bool,
    pub(crate) allow_all_unix_sockets: bool,
    pub(crate) allow_unix_sockets: Vec<PathSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) supervisor_sockets: Option<Vec<PathSelector>>,
    pub(crate) http_proxy_port: Option<u16>,
    pub(crate) socks_proxy_port: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[allow(
    clippy::struct_field_names,
    reason = "field names match the JSON policy schema"
)]
pub(crate) struct SandboxDarwin {
    pub(crate) allow_trustd: bool,
    pub(crate) allow_mach_lookup: Vec<String>,
    pub(crate) allow_apple_events: bool,
    pub(crate) allow_pty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) log_tag: Option<String>,
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
    /// Accept the additive grants the restricted-user backend applies on top of
    /// the sandbox account's own rights. Without this the backend refuses to run
    /// an allowlist policy it cannot enforce.
    pub(crate) allow_additive_grants: bool,
}

impl Settings {
    pub(crate) fn load(
        policy_paths: &[PathBuf],
        format: PolicyFormat,
        tool: Option<&OsStr>,
        cwd: &Path,
    ) -> Result<Self> {
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
            && let Some(value) = format.read_executable_policy(tool, cwd)?
        {
            merge_json(&mut merged, value);
        }

        serde_json::from_value(merged)
            .map_err(Error::parse_failed)
            .context("policy")
    }
}

fn resolve_executable(tool: &OsStr, cwd: &Path) -> Option<PathBuf> {
    let base = if cfg!(unix) { cwd } else { Path::new("") };
    let tool_path = Path::new(tool);
    let has_location = tool_path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());

    let candidate = if has_location {
        locate_executable(&base.join(tool_path))?
    } else {
        let path_var = std::env::var_os("PATH")?;
        std::env::split_paths(&path_var)
            .find_map(|dir| locate_executable(&base.join(dir).join(tool_path)))?
    };

    candidate.canonicalize().ok()
}

/// The extended attribute carrying a supplementary policy, in the
/// unprivileged `user` namespace: unlike `trusted.*` or `security.*`, it
/// needs no capability to read, matching the portable file-based policy it
/// supplements. A sysadmin who wants it root-only protects the executable
/// itself, the same way they would protect a `sandbox.json`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const EXECUTABLE_POLICY_XATTR: &std::ffi::CStr = c"user.landstrip.policy";

/// The alternate data stream carrying the same policy on Windows.
#[cfg(target_os = "windows")]
const EXECUTABLE_POLICY_STREAM: &str = "landstrip.policy";

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn locate_executable(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .then(|| path.to_path_buf())
}

#[cfg(target_os = "windows")]
fn locate_executable(base: &Path) -> Option<PathBuf> {
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

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn locate_executable(_path: &Path) -> Option<PathBuf> {
    None
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
fn read_policy_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|source| Error::PolicyIoFailed {
            source: io::Error::new(io::ErrorKind::InvalidInput, source),
        })?;

    // SAFETY: c_path and EXECUTABLE_POLICY_XATTR are live NUL-terminated C strings;
    // a null value pointer with size 0 only queries the attribute's length.
    let needed = unsafe {
        platform_getxattr(
            c_path.as_ptr(),
            EXECUTABLE_POLICY_XATTR.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
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
            EXECUTABLE_POLICY_XATTR.as_ptr(),
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
fn classify_xattr_error() -> Result<Option<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    let missing = libc::ENODATA;
    #[cfg(target_os = "macos")]
    let missing = libc::ENOATTR;

    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == missing || code == libc::ENOENT => Ok(None),
        _ => Err(Error::PolicyIoFailed { source: error }.into()),
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

fn deserialize_paths<'de, D>(deserializer: D) -> std::result::Result<Vec<PathSelector>, D::Error>
where
    D: Deserializer<'de>,
{
    let input = Option::<PathInput>::deserialize(deserializer)?;
    Ok(input.map_or_else(Vec::new, Vec::from))
}

fn deserialize_strings<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PathInput {
    List(Vec<PathSelector>),
    Lines(String),
}

impl From<PathInput> for Vec<PathSelector> {
    fn from(input: PathInput) -> Self {
        match input {
            PathInput::List(paths) => paths,
            PathInput::Lines(lines) => lines
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(|line| PathSelector::Bare(line.to_owned()))
                .collect(),
        }
    }
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
