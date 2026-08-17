// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox implementations.

use super::WindowsCommand;

mod appcontainer;
mod restricted_user;

use crate::engine::error::{Error, Mechanism};
use crate::engine::outcome::WindowsStatusReport;
use crate::engine::policy::AccessPolicy;
use anyhow::Result;
use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_PATH_NOT_FOUND,
    ERROR_SHARING_VIOLATION, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, REVOKE_ACCESS,
    SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetTokenInformation, InitializeSecurityDescriptor,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    SetFileSecurityW, SetSecurityDescriptorDacl, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Take ownership of a live Win32 handle.
///
/// # Safety
/// `handle` must be a unique, closeable handle.
pub(crate) unsafe fn own_handle(handle: HANDLE) -> OwnedHandle {
    unsafe { OwnedHandle::from_raw_handle(handle) }
}

/// Open the current process token with `desired_access`.
pub(crate) fn current_process_token(desired_access: u32) -> io::Result<OwnedHandle> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), desired_access, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { own_handle(token) })
}

/// A Win32 C string: UTF-16 units plus a trailing NUL.
pub(crate) trait ToWideNul {
    fn to_wide_nul(&self) -> Vec<u16>;
}

impl<T: AsRef<OsStr> + ?Sized> ToWideNul for T {
    fn to_wide_nul(&self) -> Vec<u16> {
        self.as_ref().encode_wide().chain(Some(0)).collect()
    }
}

/// A NUL-terminated UTF-16 C string as a slice, without the terminator.
///
/// # Safety
/// `value` must be null or a valid pointer to a NUL-terminated UTF-16 string.
pub(crate) unsafe fn from_wide_nul<'a>(value: *const u16) -> Option<&'a [u16]> {
    if value.is_null() {
        return None;
    }
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    Some(unsafe { std::slice::from_raw_parts(value, length) })
}

/// Format `sid` as an SDDL SID string.
///
/// # Safety
/// `sid` must be a valid, readable SID.
pub(crate) unsafe fn sid_string(sid: PSID) -> io::Result<String> {
    let mut wide = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &raw mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let wide = unsafe { OwnedLocal::from_raw(wide) };
    unsafe { from_wide_nul(wide.as_ptr()) }
        .and_then(|wide| String::from_utf16(wide).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SID is not valid UTF-16"))
}

/// Aligned `TOKEN_USER` query buffer.
pub(crate) struct TokenUserBuffer {
    words: Vec<usize>,
}

impl std::ops::Deref for TokenUserBuffer {
    type Target = TOKEN_USER;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.words.as_ptr().cast() }
    }
}

/// Query the user SID from `token`.
pub(crate) fn token_user(token: HANDLE) -> io::Result<TokenUserBuffer> {
    let mut size = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut size);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER.cast_signed()) {
        return Err(error);
    }
    let word_size = mem::size_of::<usize>();
    let word_count = usize::try_from(size)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "token user information is too large",
            )
        })?
        .div_ceil(word_size);
    let mut words = vec![0_usize; word_count];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            words.as_mut_ptr().cast(),
            size,
            &raw mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(TokenUserBuffer { words })
}

/// A `LocalAlloc`'d security descriptor parsed from SDDL.
pub(crate) struct OwnedSecurityDescriptor {
    descriptor: OwnedLocal,
    size: u32,
}

impl OwnedSecurityDescriptor {
    pub(crate) fn from_sddl(sddl: impl AsRef<OsStr>) -> io::Result<Self> {
        let sddl = sddl.to_wide_nul();
        let mut descriptor = ptr::null_mut();
        let mut size = 0;
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &raw mut descriptor,
                &raw mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptor: unsafe { OwnedLocal::from_raw(descriptor) },
            size,
        })
    }

    pub(crate) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.descriptor.as_ptr()
    }

    pub(crate) fn size(&self) -> u32 {
        self.size
    }
}

/// Lowercase hexadecimal encoding of `bytes`.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

/// Decode lowercase or uppercase hexadecimal `value`.
pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if !value.len().is_multiple_of(2) {
        return Err("hex string has an invalid length");
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

fn hex_digit(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("hex string contains non-hexadecimal data"),
    }
}

/// Quote one argument for `CreateProcessW` / `CommandLineToArgvW`.
///
/// `arg` must not contain an interior NUL.
pub(crate) fn quote_command_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_owned();
    }
    if !arg
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\"'))
    {
        return arg.to_owned();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(ch);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

/// Quote one already-decoded argument. `arg` must not contain an interior NUL.
pub(crate) fn quote_command_text(arg: &str) -> Result<String, &'static str> {
    if arg.contains('\0') {
        return Err("command line contains an interior NUL byte");
    }
    Ok(quote_command_arg(arg))
}

/// Join a tool and arguments into a `CreateProcessW` command line.
pub(crate) fn join_command_line<E>(
    tool: &OsStr,
    args: &[OsString],
    mut quote: impl FnMut(&OsStr) -> Result<String, E>,
) -> Result<String, E> {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(quote(tool)?);
    for arg in args {
        parts.push(quote(arg)?);
    }
    Ok(parts.join(" "))
}

pub(crate) const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

type Win32CallResult<T> = std::result::Result<T, (&'static str, io::Error)>;

/// A Win32 or `NET_API` status code, as reported by APIs that return one
/// instead of setting the last error.
pub(crate) fn win32_error(status: u32) -> io::Error {
    io::Error::from_raw_os_error(status.cast_signed())
}

/// The Win32 status carried by `error`, when it carries one.
pub(crate) fn win32_status(error: &io::Error) -> Option<u32> {
    error.raw_os_error().map(i32::cast_unsigned)
}

pub(crate) fn is_missing_status(status: u32) -> bool {
    status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
}

pub(crate) fn is_locked_status(status: u32) -> bool {
    status == ERROR_SHARING_VIOLATION || status == ERROR_ACCESS_DENIED
}

pub(crate) fn is_missing_error(error: &io::Error) -> bool {
    win32_status(error).is_some_and(is_missing_status)
}

pub(crate) fn is_locked_error(error: &io::Error) -> bool {
    win32_status(error).is_some_and(is_locked_status)
}

/// Format an ACL apply failure for `path`.
pub(crate) fn path_access_failed(
    mechanism: Mechanism,
    path: &Path,
    mode: ACCESS_MODE,
    api: &str,
    source: &io::Error,
) -> Error {
    Error::sandbox_setup(
        mechanism,
        format!(
            "{api} failed to {} ACL for {}: {source}",
            acl_action(mode),
            path.display()
        ),
    )
}

fn acl_action(mode: ACCESS_MODE) -> &'static str {
    match mode {
        GRANT_ACCESS => "grant",
        DENY_ACCESS => "deny",
        REVOKE_ACCESS => "revoke",
        _ => "update",
    }
}

/// A `LocalAlloc`'d buffer.
pub(crate) struct OwnedLocal(*mut c_void);

impl OwnedLocal {
    /// Take ownership of a `LocalAlloc`'d pointer.
    ///
    /// # Safety
    /// `ptr` must be null or a unique `LocalAlloc` allocation.
    pub(crate) unsafe fn from_raw<T>(ptr: *mut T) -> Self {
        Self(ptr.cast())
    }

    pub(crate) fn as_ptr<T>(&self) -> *mut T {
        self.0.cast()
    }
}

impl Drop for OwnedLocal {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// Edit a path DACL for `sid`.
pub(crate) fn set_path_access(
    path: &Path,
    sid: PSID,
    access: u32,
    mode: ACCESS_MODE,
    inherit: bool,
    propagate: bool,
) -> Win32CallResult<()> {
    let path_wide = path.to_wide_nul();
    let mut old_dacl: *mut ACL = ptr::null_mut();
    let mut security_descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut old_dacl,
            ptr::null_mut(),
            &raw mut security_descriptor,
        )
    };
    if status != 0 {
        return Err(("GetNamedSecurityInfoW", win32_error(status)));
    }
    let _security_descriptor = unsafe { OwnedLocal::from_raw(security_descriptor) };

    let explicit_access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: mode,
        grfInheritance: if inherit {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            0
        },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let mut new_dacl: *mut ACL = ptr::null_mut();
    let status =
        unsafe { SetEntriesInAclW(1, &raw const explicit_access, old_dacl, &raw mut new_dacl) };
    if status != 0 {
        return Err(("SetEntriesInAclW", win32_error(status)));
    }
    let _new_dacl = unsafe { OwnedLocal::from_raw(new_dacl) };
    apply_path_dacl(&path_wide, new_dacl, propagate)
}

/// Apply a constructed DACL to a path.
///
/// Propagating updates use `SetNamedSecurityInfoW`. Non-propagating updates
/// write the DACL with `SetFileSecurityW` so descendants stay unchanged.
fn apply_path_dacl(path: &[u16], dacl: *mut ACL, propagate: bool) -> Win32CallResult<()> {
    if propagate {
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr().cast_mut(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(("SetNamedSecurityInfoW", win32_error(status)));
        }
        return Ok(());
    }

    let mut descriptor = unsafe { mem::zeroed::<SECURITY_DESCRIPTOR>() };
    if unsafe {
        InitializeSecurityDescriptor((&raw mut descriptor).cast(), SECURITY_DESCRIPTOR_REVISION)
    } == 0
    {
        return Err(("InitializeSecurityDescriptor", io::Error::last_os_error()));
    }
    if unsafe { SetSecurityDescriptorDacl((&raw mut descriptor).cast(), 1, dacl, 0) } == 0 {
        return Err(("SetSecurityDescriptorDacl", io::Error::last_os_error()));
    }
    if unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            (&raw mut descriptor).cast(),
        )
    } == 0
    {
        return Err(("SetFileSecurityW", io::Error::last_os_error()));
    }
    Ok(())
}

pub(crate) fn execute(policy: &AccessPolicy, tool: &OsStr, args: &[OsString]) -> Result<i32> {
    if restricted_user::is_installed()? {
        restricted_user::execute(policy, tool, args)
    } else {
        appcontainer::execute(policy, tool, args)
    }
}

pub(crate) fn validate(policy: &AccessPolicy) -> Result<()> {
    policy.validate()?;
    if restricted_user::is_installed()? {
        restricted_user::active_implementation()?;
        restricted_user::validate(policy)?;
    }
    Ok(())
}

pub(crate) fn manage(command: &WindowsCommand) -> Result<WindowsStatusReport> {
    restricted_user::manage(command)
}

pub(crate) fn run_worker(request: &std::path::Path) -> Result<i32> {
    restricted_user::run_worker(request)
}

pub(crate) fn status() -> Result<WindowsStatusReport> {
    restricted_user::status()
}
