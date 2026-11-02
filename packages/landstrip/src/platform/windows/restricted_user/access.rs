// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Temporary filesystem grants for a leased sandbox account.

use super::super::acl::PathAccessEntry;
use super::super::win32::{LocalSid, OsStatus};
use crate::error::{Error as LandstripError, Mechanism};
use crate::policy::AccessPolicy;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use windows_sys::Win32::Security::Authorization::{GRANT_ACCESS, REVOKE_ACCESS};
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GrantPlan {
    entries: Vec<PathAccessEntry>,
}

impl GrantPlan {
    pub(super) fn new(policy: &AccessPolicy, request_path: &Path) -> Result<Self> {
        let mut entries = PathAccessEntry::policy_entries(policy)?;
        PathAccessEntry::push_grant(&mut entries, request_path, FILE_GENERIC_READ, false);
        Ok(Self { entries })
    }

    pub(super) fn apply(&self, sid: &str) -> Result<Self> {
        let sid = LocalSid::try_from(sid)
            .map_err(|source| LandstripError::sandbox_setup(Mechanism::Windowsuser, source))?;
        let mut applied = Self {
            entries: Vec::with_capacity(self.entries.len()),
        };
        for entry in &self.entries {
            match apply_restricted_entry(entry, sid.as_ptr()) {
                Ok(true) => applied.entries.push(entry.clone()),
                Ok(false) => {}
                Err(error) => {
                    for applied_entry in applied.entries.iter().rev() {
                        let _ = revoke_restricted_entry(applied_entry, sid.as_ptr());
                    }
                    return Err(error);
                }
            }
        }
        Ok(applied)
    }

    pub(super) fn revoke(&self, sid: &str) -> Result<()> {
        let sid = LocalSid::try_from(sid)
            .map_err(|source| LandstripError::sandbox_setup(Mechanism::Windowsuser, source))?;
        let mut first_error = None;
        for entry in self.entries.iter().rev() {
            let error = revoke_restricted_entry(entry, sid.as_ptr()).err();
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

fn apply_restricted_entry(entry: &PathAccessEntry, sid: PSID) -> Result<bool> {
    match entry.apply(sid) {
        Ok(()) => Ok(true),
        // A failed non-propagating grant did not alter descendants and leaves
        // the target inaccessible. Propagating failures may be partial, so they
        // remain hard errors and the full journal is retained for recovery.
        Err((api, error))
            if (api == "GetNamedSecurityInfoW" || !entry.propagate)
                && entry.access_mode == GRANT_ACCESS
                && OsStatus::is_locked(&error) =>
        {
            Ok(false)
        }
        Err((api, error)) => Err(PathAccessEntry::format_error(
            Mechanism::Windowsuser,
            &entry.path,
            entry.access_mode,
            api,
            &error,
        )
        .into()),
    }
}

fn revoke_restricted_entry(entry: &PathAccessEntry, sid: PSID) -> Result<()> {
    match entry.revoke(sid) {
        Ok(()) => Ok(()),
        Err((api, error)) if api != "SetEntriesInAclW" && OsStatus::is_missing(&error) => Ok(()),
        Err((api, error)) => Err(PathAccessEntry::format_error(
            Mechanism::Windowsuser,
            &entry.path,
            REVOKE_ACCESS,
            api,
            &error,
        )
        .into()),
    }
}
