// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Temporary filesystem grants for a leased sandbox account.

use crate::engine::error::{Cause, Error as LandstripError, Mechanism};
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
use windows_sys::Win32::Foundation::LocalFree;
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
    FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

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
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
                GRANT_ACCESS,
            );
        }
        // Placed after grant entries so the resulting DACL has DENY before
        // GRANT in access-evaluation order.
        for path in &policy.write_denied_roots {
            plan.add_subtree_deny(path, FILE_GENERIC_WRITE | FILE_DELETE_CHILD, DENY_ACCESS);
        }
        for path in &policy.read_denied_roots {
            plan.add_subtree_deny(path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, DENY_ACCESS);
        }
        plan.add_local(request_path, FILE_GENERIC_READ, GRANT_ACCESS);
        Ok(plan)
    }

    fn add_root(&mut self, path: &Path, access: u32, access_mode: ACCESS_MODE) {
        for ancestor in path.ancestors().skip(1) {
            self.entries.push(GrantEntry {
                access_mode,
                path: ancestor.to_path_buf(),
                access: FILE_GENERIC_EXECUTE,
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
        for ancestor in path.ancestors().skip(1) {
            self.entries.push(GrantEntry {
                access_mode,
                path: ancestor.to_path_buf(),
                access: FILE_GENERIC_EXECUTE,
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

    pub(super) fn apply(&self, sid: &str) -> Result<()> {
        let sid = OwnedSid::parse(sid)?;
        let mut applied: Vec<&GrantEntry> = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            if let Err(error) = set_path_access(
                &entry.path,
                sid.0,
                entry.access,
                entry.access_mode,
                entry.inherit,
                entry.propagate,
            ) {
                for applied_entry in applied.iter().rev() {
                    let _ = set_path_access(
                        &applied_entry.path,
                        sid.0,
                        0,
                        REVOKE_ACCESS,
                        false,
                        applied_entry.propagate,
                    );
                }
                return Err(error);
            }
            applied.push(entry);
        }
        Ok(())
    }

    pub(super) fn revoke(&self, sid: &str) -> Result<()> {
        let sid = OwnedSid::parse(sid)?;
        for entry in self.entries.iter().rev() {
            set_path_access(&entry.path, sid.0, 0, REVOKE_ACCESS, false, entry.propagate)?;
        }
        Ok(())
    }
}

struct OwnedSid(PSID);

impl OwnedSid {
    fn parse(value: &str) -> Result<Self> {
        let value = wide(value);
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut sid) } == 0 {
            return Err(setup_failed(io::Error::last_os_error()).into());
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
) -> Result<()> {
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let mut old_dacl: *mut ACL = ptr::null_mut();
    let mut security_descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return Err(setup_failed(win32_error(status)).into());
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
    let status = unsafe { SetEntriesInAclW(1, &explicit_access, old_dacl, &mut new_dacl) };
    if status != 0 {
        unsafe { LocalFree(security_descriptor) };
        return Err(setup_failed(win32_error(status)).into());
    }

    let result = apply_path_dacl(&path, new_dacl, propagate);
    unsafe {
        LocalFree(new_dacl.cast());
        LocalFree(security_descriptor);
    }
    result.map_err(|e| setup_failed(format!("apply_path_dacl: {e}")))?;
    Ok(())
}

fn apply_path_dacl(path: &[u16], dacl: *mut ACL, propagate: bool) -> io::Result<()> {
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
            return Err(win32_error(status));
        }
        return Ok(());
    }

    let mut descriptor = unsafe { mem::zeroed::<SECURITY_DESCRIPTOR>() };
    if unsafe {
        InitializeSecurityDescriptor((&raw mut descriptor).cast(), SECURITY_DESCRIPTOR_REVISION)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { SetSecurityDescriptorDacl((&raw mut descriptor).cast(), 1, dacl, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            (&raw mut descriptor).cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn setup_failed(source: impl Into<Cause>) -> LandstripError {
    LandstripError::SandboxSetupFailed {
        mechanism: Mechanism::Windowsuser,
        source: source.into(),
    }
}

fn win32_error(status: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::from_ne_bytes(status.to_ne_bytes()))
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}
