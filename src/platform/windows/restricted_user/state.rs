// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Persistent installation state and DPAPI-protected account credentials.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::{OsStr, c_void};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SetFileSecurityW, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use zeroize::Zeroize;

pub(super) const INSTALLATION_VERSION: u32 = 1;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const STATE_DIRECTORY: &str = "Landstrip/windows-restricted-user-v1";
const STATE_FILE: &str = "state.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum NetworkMode {
    Restricted,
    Unrestricted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Account {
    pub(super) name: String,
    pub(super) sid: String,
    pub(super) encrypted_password: String,
    pub(super) network_mode: NetworkMode,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Installation {
    pub(super) version: u32,
    pub(super) id: String,
    pub(super) proxy_port_low: u16,
    pub(super) proxy_port_high: u16,
    pub(super) wfp_provider: String,
    pub(super) wfp_sublayer: String,
    pub(super) wfp_filters: Vec<String>,
    pub(super) complete: bool,
    pub(super) runner_path: PathBuf,
    pub(super) accounts: Vec<Account>,
}

pub(super) struct SecretWide(Vec<u16>);

impl SecretWide {
    pub(super) fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

impl Drop for SecretWide {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(super) fn state_path() -> Result<PathBuf> {
    let base = env::var_os("ProgramData").context("Windows ProgramData is unavailable")?;
    Ok(PathBuf::from(base).join(STATE_DIRECTORY).join(STATE_FILE))
}

pub(super) fn initialize_runtime_directories() -> Result<()> {
    let path = state_path()?;
    let directory = path
        .parent()
        .context("restricted-user state path has no parent")?;
    for name in ["leases", "runs"] {
        let runtime_directory = directory.join(name);
        fs::create_dir_all(&runtime_directory).with_context(|| {
            format!(
                "create restricted-user runtime directory {}",
                runtime_directory.display()
            )
        })?;
        protect_path(&runtime_directory)?;
    }
    Ok(())
}

pub(super) fn load() -> Result<Installation> {
    let path = state_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("restricted-user installation state {}", path.display()))?;
    let installation: Installation = serde_json::from_slice(&bytes)
        .with_context(|| format!("restricted-user installation state {}", path.display()))?;
    if installation.version != INSTALLATION_VERSION {
        bail!(
            "restricted-user installation version {} is unsupported; expected {}",
            installation.version,
            INSTALLATION_VERSION
        );
    }
    Ok(installation)
}

pub(super) fn load_optional() -> Result<Option<Installation>> {
    match load() {
        Ok(installation) => Ok(Some(installation)),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|source| source.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn save(installation: &Installation) -> Result<()> {
    let path = state_path()?;
    let directory = path
        .parent()
        .context("restricted-user state path has no parent")?;
    fs::create_dir_all(directory).with_context(|| {
        format!(
            "create restricted-user state directory {}",
            directory.display()
        )
    })?;
    protect_path(directory)?;

    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(installation)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("create restricted-user state {}", temporary.display()))?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        protect_path(&temporary)?;
        drop(file);

        replace_file(&temporary, &path)?;
        protect_path(&path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(super) fn replace_file(temporary: &Path, path: &Path) -> Result<()> {
    let temporary_wide = wide_string(temporary.as_os_str());
    let path_wide = wide_string(path.as_os_str());
    if unsafe {
        MoveFileExW(
            temporary_wide.as_ptr(),
            path_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("replace restricted-user file {}", path.display()));
    }
    Ok(())
}

pub(super) fn remove() -> Result<()> {
    let path = state_path()?;
    if let Some(directory) = path.parent() {
        for name in ["leases", "runs"] {
            let runtime_directory = directory.join(name);
            match fs::remove_dir_all(&runtime_directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "remove restricted-user runtime directory {}",
                            runtime_directory.display()
                        )
                    });
                }
            }
        }
    }

    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("remove restricted-user installation state"),
    }

    if let Some(directory) = path.parent() {
        let _ = fs::remove_dir(directory);
    }
    Ok(())
}

pub(super) fn protect_password(password: &str) -> Result<String> {
    let mut clear = password.as_bytes().to_vec();
    let clear_len = u32::try_from(clear.len()).context("password is too long")?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: clear_len,
        pbData: clear.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    clear.zeroize();
    if result == 0 {
        return Err(io::Error::last_os_error()).context("protect sandbox account credential");
    }

    let protected = unsafe {
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let encoded = encode_hex(bytes);
        LocalFree(output.pbData.cast::<c_void>());
        encoded
    };
    Ok(protected)
}

pub(super) fn unprotect_password(protected: &str) -> Result<SecretWide> {
    let mut protected = decode_hex(protected)?;
    let protected_len = u32::try_from(protected.len()).context("protected password is too long")?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: protected_len,
        pbData: protected.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    protected.zeroize();
    if result == 0 {
        return Err(io::Error::last_os_error()).context("unprotect sandbox account credential");
    }

    let mut clear = unsafe {
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let clear = bytes.to_vec();
        LocalFree(output.pbData.cast::<c_void>());
        clear
    };
    let password = String::from_utf8(clear.clone()).context("sandbox password is not UTF-8")?;
    clear.zeroize();
    let mut wide = OsStr::new(&password).encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let mut password = password;
    password.zeroize();
    Ok(SecretWide(wide))
}

pub(super) fn protect_path(path: &Path) -> Result<()> {
    let owner_sid = current_user_sid_string()?;
    let descriptor = format!("D:P(A;;FA;;;SY)(A;;FA;;;{owner_sid})");
    let descriptor = wide_string(OsStr::new(&descriptor));
    let mut security_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor.as_ptr(),
            SECURITY_DESCRIPTOR_REVISION,
            &mut security_descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error()).context("build restricted-user state DACL");
    }

    let path = wide_string(path.as_os_str());
    let result = unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            security_descriptor,
        )
    };
    unsafe {
        LocalFree(security_descriptor.cast::<c_void>());
    }
    if result == 0 {
        return Err(io::Error::last_os_error()).context("protect restricted-user state DACL");
    }
    Ok(())
}

fn current_user_sid_string() -> Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error()).context("open current process token");
    }
    let token = Handle(token);

    let mut required = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(i32::from_ne_bytes(ERROR_INSUFFICIENT_BUFFER.to_ne_bytes())) {
        return Err(error).context("query current user SID size");
    }
    let word_size = std::mem::size_of::<usize>();
    let word_count = usize::try_from(required)?.div_ceil(word_size);
    let mut buffer = vec![0_usize; word_count];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("query current user SID");
    }
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_string = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) } == 0 {
        return Err(io::Error::last_os_error()).context("format current user SID");
    }
    let value = unsafe { wide_ptr_to_string(sid_string) };
    unsafe {
        LocalFree(sid_string.cast::<c_void>());
    }
    value.context("current user SID is not valid UTF-16")
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("protected password has an invalid length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => bail!("protected password contains non-hexadecimal data"),
    }
}

fn wide_string(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

unsafe fn wide_ptr_to_string(value: *const u16) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) }).ok()
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
