// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::win32::{OsStatus, OwnedLocal, OwnedSecurityDescriptor, ToWideNul};
use crate::error::{Error, Mechanism, PolicyViolation};
use crate::paths::PathExt;
use crate::policy::{AccessPolicy, ReadAccess};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    REVOKE_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, InitializeSecurityDescriptor, PSID, SECURITY_DESCRIPTOR,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, SetFileSecurityW, SetSecurityDescriptorDacl,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

pub(super) type Win32CallResult<T> = std::result::Result<T, (&'static str, io::Error)>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PathAccessEntry {
    pub(super) access_mode: ACCESS_MODE,
    pub(super) path: PathBuf,
    pub(super) access: u32,
    pub(super) inherit: bool,
    pub(super) propagate: bool,
}

impl PathAccessEntry {
    pub(super) fn policy_entries(policy: &AccessPolicy) -> crate::error::Result<Vec<Self>> {
        let read_roots = match &policy.read_access {
            ReadAccess::AllowRoots(read_roots) => read_roots,
            ReadAccess::Unrestricted => {
                return Err(PolicyViolation::UnrestrictedRead.into());
            }
        };
        let mut entries = Vec::new();
        for path in read_roots {
            Self::push_grant(
                &mut entries,
                path,
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                true,
            );
        }
        for path in &policy.write_roots {
            Self::push_grant(
                &mut entries,
                path,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
                true,
            );
        }
        for path in &policy.write_denials.roots {
            let carved: Vec<&Path> = policy
                .write_denials
                .carveouts
                .roots
                .iter()
                .map(PathBuf::as_path)
                .filter(|carveout| carveout.is_strictly_under(path))
                .collect();
            if carved.is_empty() {
                entries.push(Self::subtree_deny(
                    path,
                    FILE_GENERIC_WRITE | FILE_DELETE_CHILD | DELETE,
                ));
            } else if policy
                .write_roots
                .iter()
                .any(|root| path.is_strictly_under(root))
            {
                Self::push_carved_write_deny(
                    &mut entries,
                    path,
                    &carved,
                    FILE_GENERIC_WRITE | FILE_DELETE_CHILD | DELETE,
                )?;
            }
        }
        for path in &policy.read_denials.roots {
            entries.push(Self::subtree_deny(path, FILE_GENERIC_READ | DELETE));
        }
        Ok(entries)
    }

    pub(super) fn push_grant(
        entries: &mut Vec<Self>,
        path: &Path,
        access: u32,
        inherit_and_propagate: bool,
    ) {
        let ancestor_access = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        for ancestor in path.ancestors().skip(1) {
            Self::insert_or_merge_grant(entries, ancestor, ancestor_access, false);
        }
        Self::insert_or_merge_grant(entries, path, access, inherit_and_propagate);
    }

    fn insert_or_merge_grant(
        entries: &mut Vec<Self>,
        path: &Path,
        access: u32,
        inherit_and_propagate: bool,
    ) {
        if let Some(existing) = entries
            .iter_mut()
            .find(|entry| entry.access_mode == GRANT_ACCESS && entry.path == path)
        {
            existing.access |= access;
            existing.inherit |= inherit_and_propagate;
            existing.propagate |= inherit_and_propagate;
            return;
        }
        entries.push(Self::grant(path, access, inherit_and_propagate));
    }

    pub(super) fn grant(path: &Path, access: u32, inherit_and_propagate: bool) -> Self {
        Self {
            access_mode: GRANT_ACCESS,
            path: path.to_path_buf(),
            access,
            inherit: inherit_and_propagate,
            propagate: inherit_and_propagate,
        }
    }

    fn subtree_deny(path: &Path, access: u32) -> Self {
        Self {
            access_mode: DENY_ACCESS,
            path: path.to_path_buf(),
            access,
            inherit: true,
            propagate: true,
        }
    }

    fn push_carved_write_deny(
        entries: &mut Vec<Self>,
        root: &Path,
        carved: &[&Path],
        access: u32,
    ) -> crate::error::Result<()> {
        let mut stack = vec![root.to_path_buf()];
        while let Some(current) = stack.pop() {
            if current.is_under_any(carved) {
                continue;
            }
            let has_carved_descendant = carved
                .iter()
                .any(|carveout| carveout.is_strictly_under(&current));
            let is_dir = fs::symlink_metadata(&current).is_ok_and(|md| md.file_type().is_dir());
            if !has_carved_descendant || !is_dir {
                entries.push(Self::subtree_deny(&current, access));
                continue;
            }
            entries.push(Self {
                access_mode: DENY_ACCESS,
                path: current.clone(),
                access,
                inherit: false,
                propagate: false,
            });
            for entry in fs::read_dir(&current).map_err(Error::policy_io)? {
                let entry = entry.map_err(Error::policy_io)?;
                stack.push(entry.path());
            }
        }
        Ok(())
    }

    pub(super) fn apply(&self, sid: PSID) -> Win32CallResult<()> {
        PathDacl::set_access(
            &self.path,
            sid,
            self.access,
            self.access_mode,
            self.inherit,
            self.propagate,
        )
    }

    pub(super) fn revoke(&self, sid: PSID) -> Win32CallResult<()> {
        PathDacl::set_access(&self.path, sid, 0, REVOKE_ACCESS, false, self.propagate)
    }

    pub(super) fn format_error(
        mechanism: Mechanism,
        path: &Path,
        mode: ACCESS_MODE,
        api: &str,
        source: &io::Error,
    ) -> Error {
        let action = match mode {
            GRANT_ACCESS => "grant",
            DENY_ACCESS => "deny",
            REVOKE_ACCESS => "revoke",
            _ => "update",
        };
        Error::sandbox_setup(
            mechanism,
            format!(
                "{api} failed to {action} ACL for {}: {source}",
                path.display()
            ),
        )
    }
}

struct PathDacl;

impl PathDacl {
    fn set_access(
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
            return Err(("GetNamedSecurityInfoW", OsStatus::from_code(status)));
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
            return Err(("SetEntriesInAclW", OsStatus::from_code(status)));
        }
        let _new_dacl = unsafe { OwnedLocal::from_raw(new_dacl) };
        Self::apply_dacl(&path_wide, new_dacl, propagate)
    }

    fn apply_dacl(path: &[u16], dacl: *mut ACL, propagate: bool) -> Win32CallResult<()> {
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
                return Err(("SetNamedSecurityInfoW", OsStatus::from_code(status)));
            }
            return Ok(());
        }

        let mut descriptor = unsafe { mem::zeroed::<SECURITY_DESCRIPTOR>() };
        if unsafe {
            InitializeSecurityDescriptor(
                (&raw mut descriptor).cast(),
                OwnedSecurityDescriptor::REVISION,
            )
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
}
