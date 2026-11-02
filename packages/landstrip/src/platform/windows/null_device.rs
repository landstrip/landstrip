// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::win32::{LocalSid, NamedMutex, OsStatus, OwnedLocal, ToWideNul};
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, SE_FILE_OBJECT, SetEntriesInAclW,
    SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TYPE_CHAR, GetFileType, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};

const NULL_DEVICE: &str = r"\\?\GLOBALROOT\Device\Null";

fn open(path: &str, desired_access: u32) -> io::Result<OwnedHandle> {
    let path = path.to_wide_nul();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(super) fn prepare() -> Result<()> {
    let _lock = NamedMutex::lock("Global\\LandstripNullDevicePreparation")
        .context("acquire null-device preparation mutex")?;
    let handle =
        open(NULL_DEVICE, READ_CONTROL | WRITE_DAC).context("open Device Null for DACL update")?;
    let mut old_dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut old_dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(OsStatus::from_code(status)).context("GetSecurityInfo for Device Null");
    }
    let _descriptor = unsafe { OwnedLocal::from_raw(descriptor) };
    if old_dacl.is_null() {
        return Ok(());
    }

    let sids = LocalSid::app_container_groups()?;
    let entries = sids
        .iter()
        .map(|sid| EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: sid.as_ptr().cast(),
            },
        })
        .collect::<Vec<_>>();
    let mut new_dacl = ptr::null_mut();
    let status = unsafe {
        SetEntriesInAclW(
            u32::try_from(entries.len()).context("too many null-device ACL entries")?,
            entries.as_ptr(),
            old_dacl,
            &raw mut new_dacl,
        )
    };
    if status != 0 {
        return Err(OsStatus::from_code(status)).context("SetEntriesInAclW for Device Null");
    }
    let new_dacl = unsafe { OwnedLocal::from_raw(new_dacl) };
    if new_dacl.as_ptr::<std::ffi::c_void>().is_null() {
        bail!("null-device ACL merge returned no DACL");
    }
    let status = unsafe {
        SetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_dacl.as_ptr(),
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(OsStatus::from_code(status)).context("SetSecurityInfo for Device Null");
    }
    Ok(())
}

pub(super) fn probe() -> Result<()> {
    let handle = open(r"\\.\NUL", GENERIC_READ | GENERIC_WRITE).context(
        "open NUL for reading and writing; run landstrip windows prepare-appcontainer after each reboot",
    )?;
    if unsafe { GetFileType(handle.as_raw_handle()) } != FILE_TYPE_CHAR {
        bail!("NUL is not a character device");
    }
    let mut file = File::from(handle);
    let mut byte = [0];
    if file.read(&mut byte).context("read NUL")? != 0 {
        bail!("NUL did not return end-of-file");
    }
    file.write_all(b"x").context("write NUL")?;
    Ok(())
}
