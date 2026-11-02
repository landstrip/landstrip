// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use anyhow::{Context, Result};
use std::ffi::{OsStr, c_void};
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_PATH_NOT_FOUND,
    ERROR_SHARING_VIOLATION, HANDLE, LocalFree, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW,
};
use windows_sys::Win32::Security::{
    ACL, GetSecurityDescriptorDacl, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID,
    TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, INFINITE, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
};

const APP_CONTAINER_GROUP_SIDS: [&str; 2] = ["S-1-15-2-1", "S-1-15-2-2"];

pub(super) trait ToWideNul {
    fn to_wide_nul(&self) -> Vec<u16>;
}

impl<T: AsRef<OsStr> + ?Sized> ToWideNul for T {
    fn to_wide_nul(&self) -> Vec<u16> {
        self.as_ref().encode_wide().chain(Some(0)).collect()
    }
}

pub(super) struct OsStatus;

impl OsStatus {
    pub(super) fn from_code(status: u32) -> io::Error {
        io::Error::from_raw_os_error(status.cast_signed())
    }

    pub(super) fn code(error: &io::Error) -> Option<u32> {
        error.raw_os_error().map(i32::cast_unsigned)
    }

    pub(super) fn is_missing(error: &io::Error) -> bool {
        matches!(
            Self::code(error),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
        )
    }

    pub(super) fn is_locked(error: &io::Error) -> bool {
        matches!(
            Self::code(error),
            Some(ERROR_SHARING_VIOLATION | ERROR_ACCESS_DENIED)
        )
    }
}

pub(super) struct OwnedLocal(*mut c_void);

impl OwnedLocal {
    pub(super) unsafe fn from_raw<T>(ptr: *mut T) -> Self {
        Self(ptr.cast())
    }

    pub(super) fn as_ptr<T>(&self) -> *mut T {
        self.0.cast()
    }

    unsafe fn wide_slice(&self) -> Option<&[u16]> {
        let value = self.as_ptr::<u16>().cast_const();
        if value.is_null() {
            return None;
        }
        let mut length = 0;
        while unsafe { *value.add(length) } != 0 {
            length += 1;
        }
        Some(unsafe { std::slice::from_raw_parts(value, length) })
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

pub(super) struct LocalSid(OwnedLocal);

impl TryFrom<&str> for LocalSid {
    type Error = io::Error;

    fn try_from(sid: &str) -> io::Result<Self> {
        let wide = sid.to_wide_nul();
        let mut raw = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(unsafe { OwnedLocal::from_raw(raw) }))
    }
}

impl LocalSid {
    pub(super) fn as_ptr(&self) -> PSID {
        self.0.as_ptr()
    }

    pub(super) fn app_container_groups() -> Result<Vec<Self>> {
        APP_CONTAINER_GROUP_SIDS
            .into_iter()
            .map(|sid| {
                Self::try_from(sid).with_context(|| format!("convert AppContainer group SID {sid}"))
            })
            .collect()
    }

    pub(super) unsafe fn format(sid: PSID) -> io::Result<String> {
        let mut wide = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &raw mut wide) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let wide = unsafe { OwnedLocal::from_raw(wide) };
        unsafe { wide.wide_slice() }
            .and_then(|units| String::from_utf16(units).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SID is not valid UTF-16"))
    }
}

pub(super) struct OwnedSecurityDescriptor {
    descriptor: OwnedLocal,
    size: u32,
}

impl OwnedSecurityDescriptor {
    pub(super) const REVISION: u32 = 1;

    pub(super) fn from_sddl(sddl: impl AsRef<OsStr>) -> io::Result<Self> {
        let sddl = sddl.to_wide_nul();
        let mut descriptor = ptr::null_mut();
        let mut size = 0;
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                Self::REVISION,
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

    pub(super) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.descriptor.as_ptr()
    }

    pub(super) fn size(&self) -> u32 {
        self.size
    }

    pub(super) fn dacl(&self) -> io::Result<*mut ACL> {
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut dacl_present: i32 = 0;
        let mut dacl_defaulted: i32 = 0;
        if unsafe {
            GetSecurityDescriptorDacl(
                self.as_ptr(),
                &raw mut dacl_present,
                &raw mut dacl,
                &raw mut dacl_defaulted,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(dacl)
    }
}

struct TokenUserBuffer {
    words: Vec<usize>,
}

impl std::ops::Deref for TokenUserBuffer {
    type Target = TOKEN_USER;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.words.as_ptr().cast() }
    }
}

pub(super) struct ProcessToken(OwnedHandle);

impl ProcessToken {
    pub(super) fn current(desired_access: u32) -> io::Result<Self> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), desired_access, &raw mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(token) }))
    }

    pub(super) fn is_current_elevated() -> Result<bool> {
        let token = Self::current(TOKEN_QUERY).context("open current process token")?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0;
        let size = u32::try_from(mem::size_of::<TOKEN_ELEVATION>())
            .context("token elevation structure is too large")?;
        if unsafe {
            GetTokenInformation(
                token.as_raw(),
                TokenElevation,
                (&raw mut elevation).cast(),
                size,
                &raw mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("query process elevation");
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    pub(super) fn as_raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }

    pub(super) fn user_sid_string(&self) -> io::Result<String> {
        let user = self.user()?;
        unsafe { LocalSid::format(user.User.Sid) }
    }

    fn user(&self) -> io::Result<TokenUserBuffer> {
        let mut size = 0;
        unsafe {
            GetTokenInformation(self.as_raw(), TokenUser, ptr::null_mut(), 0, &raw mut size);
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
                self.as_raw(),
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
}

pub(super) struct NamedMutex {
    handle: OwnedHandle,
}

impl NamedMutex {
    pub(super) fn lock(name: impl AsRef<OsStr>) -> io::Result<Self> {
        Self::acquire(name, INFINITE)?.ok_or_else(|| io::Error::other("named mutex wait timed out"))
    }

    pub(super) fn acquire(name: impl AsRef<OsStr>, timeout_ms: u32) -> io::Result<Option<Self>> {
        let name = name.as_ref().to_wide_nul();
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        match unsafe { WaitForSingleObject(handle.as_raw_handle(), timeout_ms) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Some(Self { handle })),
            WAIT_TIMEOUT => Ok(None),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            status => Err(io::Error::other(format!(
                "unexpected mutex wait status {status}"
            ))),
        }
    }
}

impl Drop for NamedMutex {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle.as_raw_handle());
        }
    }
}

pub(super) struct AtomicFile;

impl AtomicFile {
    pub(super) fn replace(temporary: &Path, destination: &Path) -> io::Result<()> {
        let temporary_wide = temporary.to_wide_nul();
        let destination_wide = destination.to_wide_nul();
        if unsafe {
            MoveFileExW(
                temporary_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
