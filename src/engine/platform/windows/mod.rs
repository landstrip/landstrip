// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox implementations.

use super::WindowsCommand;

mod appcontainer;
mod restricted_user;

use crate::engine::outcome::WindowsStatusReport;
use crate::engine::policy::AccessPolicy;
use anyhow::Result;
use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, TOKEN_USER, TokenUser,
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

pub(crate) const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

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
