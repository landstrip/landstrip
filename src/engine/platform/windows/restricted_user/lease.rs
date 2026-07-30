// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Exclusive account leasing and crash-recovery journals.

use super::access::GrantPlan;
use super::state::{self, Account, Installation, NetworkMode};
use crate::engine::error::{Error as LandstripError, Mechanism};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Journal {
    account_sid: String,
    grants: GrantPlan,
}

pub(super) struct Lease<'a> {
    account: &'a Account,
    handle: HANDLE,
    journal_path: PathBuf,
}

impl<'a> Lease<'a> {
    pub(super) fn acquire(
        installation: &'a Installation,
        network_mode: NetworkMode,
    ) -> Result<Self> {
        for account in installation
            .accounts
            .iter()
            .filter(|account| account.network_mode == network_mode)
        {
            if let Some(lease) = Self::try_account(installation, account)? {
                lease.recover_stale()?;
                return Ok(lease);
            }
        }
        Err(LandstripError::SandboxSetupFailed {
            mechanism: Mechanism::Windowsuser,
            source: io::Error::new(
                io::ErrorKind::WouldBlock,
                "all matching restricted-user accounts are busy",
            )
            .into(),
        }
        .into())
    }

    pub(super) fn account(&self) -> &Account {
        self.account
    }

    pub(super) fn write_journal(&self, grants: &GrantPlan) -> Result<()> {
        let journal = Journal {
            account_sid: self.account.sid.clone(),
            grants: grants.clone(),
        };
        let directory = self
            .journal_path
            .parent()
            .context("restricted-user journal path has no parent")?;
        fs::create_dir_all(directory)
            .with_context(|| format!("create lease journal directory {}", directory.display()))?;
        state::protect_path(directory)?;
        let temporary = self
            .journal_path
            .with_extension(format!("tmp-{}", std::process::id()));
        let bytes = serde_json::to_vec_pretty(&journal)?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)
                .with_context(|| format!("create lease journal {}", temporary.display()))?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            state::protect_path(&temporary)?;
            drop(file);

            state::replace_file(&temporary, &self.journal_path)?;
            state::protect_path(&self.journal_path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub(super) fn clear_journal(&self) -> Result<()> {
        match fs::remove_file(&self.journal_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("remove restricted-user lease journal"),
        }
    }

    fn try_account(installation: &Installation, account: &'a Account) -> Result<Option<Self>> {
        let name = format!(
            "Global\\LandstripRestrictedUser-{}-{}",
            installation.id, account.name
        );
        let name = wide(&name);
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error()).context("create restricted-user lease mutex");
        }
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        if wait == WAIT_TIMEOUT {
            unsafe {
                CloseHandle(handle);
            }
            return Ok(None);
        }
        if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
            unsafe {
                CloseHandle(handle);
            }
            return Err(io::Error::last_os_error()).context("acquire restricted-user lease mutex");
        }
        let state_path = state::state_path()?;
        let journal_path = state_path
            .parent()
            .context("restricted-user state path has no parent")?
            .join("leases")
            .join(format!("{}.json", account.name));
        Ok(Some(Self {
            account,
            handle,
            journal_path,
        }))
    }

    fn recover_stale(&self) -> Result<()> {
        let bytes = match fs::read(&self.journal_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("read restricted-user lease journal"),
        };
        let journal: Journal =
            serde_json::from_slice(&bytes).context("parse restricted-user lease journal")?;
        if !journal.account_sid.eq_ignore_ascii_case(&self.account.sid) {
            return Err(LandstripError::SandboxSetupFailed {
                mechanism: Mechanism::Windowsuser,
                source: "lease journal account SID does not match installation state".into(),
            }
            .into());
        }
        journal
            .grants
            .revoke(&journal.account_sid)
            .context("recover stale restricted-user filesystem grants")?;
        self.clear_journal()
    }
}

pub(super) fn recover_all(installation: &Installation) -> Result<()> {
    let mut leases = Vec::with_capacity(installation.accounts.len());
    for account in &installation.accounts {
        let lease = Lease::try_account(installation, account)?.ok_or_else(|| {
            LandstripError::SandboxSetupFailed {
                mechanism: Mechanism::Windowsuser,
                source: io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("restricted-user account {} is busy", account.name),
                )
                .into(),
            }
        })?;
        lease.recover_stale()?;
        leases.push(lease);
    }
    Ok(())
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                ReleaseMutex(self.handle);
                CloseHandle(self.handle);
            }
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}
