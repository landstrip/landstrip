// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Temporary filesystem grants for a leased sandbox account.

use crate::engine::error::{Error as LandstripError, Mechanism};
use crate::engine::policy::{AccessPolicy, ReadAccess};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, c_void};
use std::io;
use std::iter;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, ConvertStringSidToSidW, DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    GetNamedSecurityInfoW, REVOKE_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, InitializeSecurityDescriptor, PSID, SECURITY_DESCRIPTOR,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, SetFileSecurityW, SetSecurityDescriptorDacl,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
type Win32CallResult<T> = std::result::Result<T, (&'static str, io::Error)>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GrantPlan {
    entries: Vec<GrantEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantEntry {
    access_mode: ACCESS_MODE,
    path: PathBuf,
    access: u32,
    inherit: bool,
    propagate: bool,
}

impl GrantPlan {
    pub(super) fn new(policy: &AccessPolicy, request_path: &Path) -> Result<Self> {
        let read_roots = match &policy.read_access {
            ReadAccess::AllowRoots(read_roots) => read_roots,
            ReadAccess::Unrestricted => {
                return Err(LandstripError::PolicyUnrestrictedRead.into());
            }
        };
        let mut plan = Self {
            entries: Vec::new(),
        };
        for path in read_roots {
            plan.add_root(path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, GRANT_ACCESS);
        }
        for path in &policy.write_roots {
            plan.add_root(
                path,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
                GRANT_ACCESS,
            );
        }
        // Placed after grant entries so the resulting DACL has DENY before
        // GRANT in access-evaluation order.
        for path in &policy.write_denied_roots {
            plan.add_subtree_deny(
                path,
                FILE_GENERIC_WRITE | FILE_DELETE_CHILD | DELETE,
                DENY_ACCESS,
            );
        }
        for path in &policy.read_denied_roots {
            plan.add_subtree_deny(path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, DENY_ACCESS);
        }
        plan.add_local(request_path, FILE_GENERIC_READ, GRANT_ACCESS);
        Ok(plan)
    }

    fn add_root(&mut self, path: &Path, access: u32, access_mode: ACCESS_MODE) {
        let ancestor_access = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        for ancestor in path.ancestors().skip(1) {
            self.entries.push(GrantEntry {
                access_mode,
                path: ancestor.to_path_buf(),
                access: ancestor_access,
                inherit: false,
                propagate: false,
            });
        }
        self.entries.push(GrantEntry {
            access_mode,
            path: path.to_path_buf(),
            access,
            inherit: true,
            propagate: true,
        });
    }

    fn add_subtree_deny(&mut self, path: &Path, access: u32, access_mode: ACCESS_MODE) {
        self.entries.push(GrantEntry {
            access_mode,
            path: path.to_path_buf(),
            access,
            inherit: true,
            propagate: true,
        });
    }

    fn add_local(&mut self, path: &Path, access: u32, access_mode: ACCESS_MODE) {
        let ancestor_access = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        for ancestor in path.ancestors().skip(1) {
            self.entries.push(GrantEntry {
                access_mode,
                path: ancestor.to_path_buf(),
                access: ancestor_access,
                inherit: false,
                propagate: false,
            });
        }
        self.entries.push(GrantEntry {
            access_mode,
            path: path.to_path_buf(),
            access,
            inherit: false,
            propagate: false,
        });
    }

    pub(super) fn apply(&self, sid: &str) -> Result<Self> {
        let sid = OwnedSid::parse(sid)?;
        let mut applied = Self {
            entries: Vec::with_capacity(self.entries.len()),
        };
        for entry in &self.entries {
            match set_path_access(
                &entry.path,
                sid.0,
                entry.access,
                entry.access_mode,
                entry.inherit,
                entry.propagate,
                false,
            ) {
                Ok(true) => applied.entries.push(entry.clone()),
                Ok(false) => {}
                Err(error) => {
                    for applied_entry in applied.entries.iter().rev() {
                        let _ = set_path_access(
                            &applied_entry.path,
                            sid.0,
                            0,
                            REVOKE_ACCESS,
                            false,
                            applied_entry.propagate,
                            true,
                        );
                    }
                    return Err(error);
                }
            }
        }
        Ok(applied)
    }

    pub(super) fn revoke(&self, sid: &str) -> Result<()> {
        let sid = OwnedSid::parse(sid)?;
        let mut first_error = None;
        for entry in self.entries.iter().rev() {
            let error = set_path_access(
                &entry.path,
                sid.0,
                0,
                REVOKE_ACCESS,
                false,
                entry.propagate,
                true,
            )
            .err();
            if first_error.is_none() {
                first_error = error;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

struct OwnedSid(PSID);

impl OwnedSid {
    fn parse(value: &str) -> Result<Self> {
        let value = wide(value);
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(value.as_ptr(), &raw mut sid) } == 0 {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Windowsuser,
                io::Error::last_os_error(),
            )
            .into());
        }
        Ok(Self(sid))
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0.cast::<c_void>());
            }
        }
    }
}

fn set_path_access(
    path: &Path,
    sid: PSID,
    access: u32,
    mode: ACCESS_MODE,
    inherit: bool,
    propagate: bool,
    ignore_missing: bool,
) -> Result<bool> {
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
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
        if should_skip_before_apply(mode, status, ignore_missing) {
            return Ok(false);
        }
        return Err(
            path_access_failed(path, mode, "GetNamedSecurityInfoW", &win32_error(status)).into(),
        );
    }

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
        unsafe { LocalFree(security_descriptor) };
        return Err(
            path_access_failed(path, mode, "SetEntriesInAclW", &win32_error(status)).into(),
        );
    }

    let result = apply_path_dacl(&path_wide, new_dacl, propagate);
    unsafe {
        LocalFree(new_dacl.cast());
        LocalFree(security_descriptor);
    }
    if let Err((api, error)) = result {
        if ignore_missing && is_missing_error(&error) {
            return Ok(false);
        }
        // A failed non-propagating grant did not alter descendants and leaves
        // the target inaccessible. Propagating failures may be partial, so they
        // remain hard errors and the full journal is retained for recovery.
        if mode == GRANT_ACCESS && !propagate && is_locked_error(&error) {
            return Ok(false);
        }
        return Err(path_access_failed(path, mode, api, &error).into());
    }
    Ok(true)
}

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

fn path_access_failed(
    path: &Path,
    mode: ACCESS_MODE,
    api: &str,
    source: &io::Error,
) -> LandstripError {
    LandstripError::sandbox_setup(
        Mechanism::Windowsuser,
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

fn win32_error(status: u32) -> io::Error {
    io::Error::from_raw_os_error(status.cast_signed())
}

fn is_missing_status(status: u32) -> bool {
    status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
}

fn is_missing_error(error: &io::Error) -> bool {
    error
        .raw_os_error()
        .is_some_and(|status| is_missing_status(status.cast_unsigned()))
}

/// Return whether an ACL target is inaccessible.
fn is_locked_status(status: u32) -> bool {
    status == ERROR_SHARING_VIOLATION || status == ERROR_ACCESS_DENIED
}

fn is_locked_error(error: &io::Error) -> bool {
    error
        .raw_os_error()
        .is_some_and(|status| is_locked_status(status.cast_unsigned()))
}

fn should_skip_before_apply(mode: ACCESS_MODE, status: u32, ignore_missing: bool) -> bool {
    (ignore_missing && is_missing_status(status))
        || (mode == GRANT_ACCESS && is_locked_status(status))
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}
