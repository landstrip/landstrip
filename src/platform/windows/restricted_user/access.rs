// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Temporary filesystem grants for a leased sandbox account.

use super::{
    OwnedLocal, ToWideNul, is_locked_error, is_missing_error, path_access_failed, set_path_access,
};
use crate::error::{Error as LandstripError, Mechanism};
use crate::policy::{AccessPolicy, ReadAccess};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, ConvertStringSidToSidW, DENY_ACCESS, GRANT_ACCESS, REVOKE_ACCESS,
};
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

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
            match set_restricted_path_access(
                &entry.path,
                sid.as_psid(),
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
                        let _ = set_restricted_path_access(
                            &applied_entry.path,
                            sid.as_psid(),
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
            let error = set_restricted_path_access(
                &entry.path,
                sid.as_psid(),
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

struct OwnedSid(OwnedLocal);

impl OwnedSid {
    fn parse(value: &str) -> Result<Self> {
        let value = value.to_wide_nul();
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(value.as_ptr(), &raw mut sid) } == 0 {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Windowsuser,
                io::Error::last_os_error(),
            )
            .into());
        }
        Ok(Self(unsafe { OwnedLocal::from_raw(sid) }))
    }

    fn as_psid(&self) -> PSID {
        self.0.as_ptr()
    }
}

fn set_restricted_path_access(
    path: &Path,
    sid: PSID,
    access: u32,
    mode: ACCESS_MODE,
    inherit: bool,
    propagate: bool,
    ignore_missing: bool,
) -> Result<bool> {
    match set_path_access(path, sid, access, mode, inherit, propagate) {
        Ok(()) => Ok(true),
        Err(("GetNamedSecurityInfoW", error))
            if (ignore_missing && is_missing_error(&error))
                || (mode == GRANT_ACCESS && is_locked_error(&error)) =>
        {
            Ok(false)
        }
        Err(("SetEntriesInAclW", error)) => Err(path_access_failed(
            Mechanism::Windowsuser,
            path,
            mode,
            "SetEntriesInAclW",
            &error,
        )
        .into()),
        Err((api, error)) => {
            if ignore_missing && is_missing_error(&error) {
                return Ok(false);
            }
            // A failed non-propagating grant did not alter descendants and leaves
            // the target inaccessible. Propagating failures may be partial, so they
            // remain hard errors and the full journal is retained for recovery.
            if mode == GRANT_ACCESS && !propagate && is_locked_error(&error) {
                return Ok(false);
            }
            Err(path_access_failed(Mechanism::Windowsuser, path, mode, api, &error).into())
        }
    }
}
