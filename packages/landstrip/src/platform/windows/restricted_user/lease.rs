// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Exclusive account leasing and crash-recovery journals.

use super::super::win32::NamedMutex;
use super::access::GrantPlan;
use super::state::{Account, Installation, NetworkMode, StateStore};
use crate::error::{Error as LandstripError, Mechanism};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Journal {
    account_sid: String,
    grants: GrantPlan,
}
pub(super) struct Lease<'a> {
    account: &'a Account,
    _mutex: NamedMutex,
    journal_path: PathBuf,
}

impl<'a> Lease<'a> {
    pub(super) fn acquire(
        store: &StateStore,
        installation: &'a Installation,
        network_mode: NetworkMode,
    ) -> Result<Self> {
        for account in installation
            .accounts
            .iter()
            .filter(|account| account.network_mode == network_mode)
        {
            if let Some(lease) = Self::try_account(store, installation, account)? {
                lease.recover_stale()?;
                return Ok(lease);
            }
        }
        Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "all matching restricted-user accounts are busy",
            ),
        )
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
        StateStore::write_json(&self.journal_path, &journal, "lease journal")
    }

    pub(super) fn clear_journal(&self) -> Result<()> {
        match fs::remove_file(&self.journal_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("remove restricted-user lease journal"),
        }
    }

    fn try_account(
        store: &StateStore,
        installation: &Installation,
        account: &'a Account,
    ) -> Result<Option<Self>> {
        let journal_path = store.leases_dir().join(format!("{}.json", account.name));
        let name = format!(
            "Global\\LandstripRestrictedUser-{}-{}",
            installation.id, account.name
        );
        let Some(mutex) =
            NamedMutex::acquire(name, 0).context("acquire restricted-user lease mutex")?
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            account,
            _mutex: mutex,
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
            return Err(LandstripError::sandbox_setup(
                Mechanism::Windowsuser,
                "lease journal account SID does not match installation state",
            )
            .into());
        }
        journal
            .grants
            .revoke(&journal.account_sid)
            .context("recover stale restricted-user filesystem grants")?;
        self.clear_journal()
    }

    pub(super) fn recover_all(store: &StateStore, installation: &'a Installation) -> Result<()> {
        let mut leases = Vec::with_capacity(installation.accounts.len());
        for account in &installation.accounts {
            let lease = Self::try_account(store, installation, account)?.ok_or_else(|| {
                LandstripError::sandbox_setup(
                    Mechanism::Windowsuser,
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!("restricted-user account {} is busy", account.name),
                    ),
                )
            })?;
            lease.recover_stale()?;
            leases.push(lease);
        }
        Ok(())
    }
}
