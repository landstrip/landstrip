// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Local sandbox account provisioning.

use super::state::{self, Account, NetworkMode};
use anyhow::{Context, Result, bail};
use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, LocalFree};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetUserAdd, NetUserDel, UF_DONT_EXPIRE_PASSWD, UF_NORMAL_ACCOUNT,
    UF_PASSWD_CANT_CHANGE, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};
use zeroize::Zeroize;

const ACCOUNT_COMMENT: &str = "Landstrip restricted-user sandbox account";
const PASSWORD_BYTES: usize = 32;

pub(super) fn provision(name: &str, network_mode: NetworkMode) -> Result<Account> {
    let mut password = random_password()?;
    if let Err(error) = create(name, &password) {
        password.zeroize();
        return Err(error);
    }

    let result = (|| {
        let sid = lookup_sid(name)?;
        let encrypted_password = state::protect_password(&password)?;
        Ok(Account {
            name: name.to_owned(),
            sid,
            encrypted_password,
            network_mode,
        })
    })();
    password.zeroize();

    match result {
        Ok(account) => Ok(account),
        Err(error) => match remove(name) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(error.context(format!(
                "remove incomplete sandbox account: {cleanup_error:#}"
            ))),
        },
    }
}

pub(super) fn remove(name: &str) -> Result<()> {
    let name = wide(name);
    let status = unsafe { NetUserDel(ptr::null(), name.as_ptr()) };
    if status == NERR_Success || status == 2221 {
        return Ok(());
    }
    Err(net_error(status))
        .with_context(|| format!("delete sandbox account {}", display_wide(&name)))
}

pub(super) fn lookup_sid(name: &str) -> Result<String> {
    let name = wide(name);
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut sid_use: SID_NAME_USE = 0;
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            ptr::null_mut(),
            &mut sid_size,
            ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(i32::from_ne_bytes(ERROR_INSUFFICIENT_BUFFER.to_ne_bytes())) {
        return Err(error).context("query sandbox account SID size");
    }

    let mut sid = vec![0_u8; sid_size as usize];
    let mut domain = vec![0_u16; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("query sandbox account SID");
    }

    let mut sid_string = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut sid_string) } == 0 {
        return Err(io::Error::last_os_error()).context("format sandbox account SID");
    }
    let value = unsafe { nul_terminated_to_string(sid_string) };
    unsafe {
        LocalFree(sid_string.cast::<c_void>());
    }
    value.context("sandbox account SID is not valid UTF-16")
}

pub(super) fn random_identifier(bytes: usize) -> Result<String> {
    let mut random = vec![0_u8; bytes];
    let length = u32::try_from(random.len()).context("random identifier is too long")?;
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            random.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        bail!("BCryptGenRandom failed with NTSTATUS 0x{status:08x}");
    }
    Ok(hex(&random))
}

fn create(name: &str, password: &str) -> Result<()> {
    let mut name_wide = wide(name);
    let mut password_wide = wide(password);
    let mut comment = wide(ACCOUNT_COMMENT);
    let mut user = USER_INFO_1 {
        usri1_name: name_wide.as_mut_ptr(),
        usri1_password: password_wide.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: ptr::null_mut(),
        usri1_comment: comment.as_mut_ptr(),
        usri1_flags: UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE,
        usri1_script_path: ptr::null_mut(),
    };
    let mut parameter_error = 0;
    let status =
        unsafe { NetUserAdd(ptr::null(), 1, (&raw mut user).cast(), &mut parameter_error) };
    password_wide.zeroize();
    if status != NERR_Success {
        return Err(net_error(status))
            .with_context(|| format!("create sandbox account (field {parameter_error})"));
    }
    Ok(())
}

fn random_password() -> Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_+";
    let mut random = vec![0_u8; PASSWORD_BYTES];
    let length = u32::try_from(random.len()).context("password is too long")?;
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            random.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(anyhow::anyhow!(
            "BCryptGenRandom failed with NTSTATUS 0x{status:08x}"
        ));
    }

    let mut password = String::with_capacity(PASSWORD_BYTES + 4);
    password.push('a');
    password.push('A');
    password.push('7');
    password.push('!');
    for byte in &random {
        password.push(char::from(ALPHABET[*byte as usize % ALPHABET.len()]));
    }
    random.zeroize();
    Ok(password)
}

fn net_error(status: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::from_ne_bytes(status.to_ne_bytes()))
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn display_wide(value: &[u16]) -> String {
    String::from_utf16_lossy(&value[..value.len().saturating_sub(1)])
}

unsafe fn nul_terminated_to_string(value: *const u16) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) }).ok()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}
