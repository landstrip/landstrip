// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Elevated restricted-user installation lifecycle.

use super::super::RESTRICTED_USER_RUNNER;
use super::super::process::SpawnedProcess;
use super::super::win32::{AtomicFile, NamedMutex, ProcessToken};
use super::account;
use super::lease::Lease;
use super::state::{INSTALLATION_VERSION, Installation, NetworkMode, StateStore};
use super::wfp;
use crate::outcome::{SandboxImplementation, WindowsStatusReport};
use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const FILTERS_PER_RESTRICTED_ACCOUNT: usize = 6;
const INSTALL_DIRECTORY: &str = "Landstrip";
const MANAGEMENT_MUTEX: &str = "Global\\LandstripRestrictedUserManagement";

pub(in crate::platform::windows) fn install(
    restricted_accounts: u16,
    unrestricted_accounts: u16,
    proxy_port_low: u16,
    proxy_port_high: u16,
) -> Result<()> {
    if !ProcessToken::is_current_elevated()? {
        return SpawnedProcess::elevate(&format!(
            "windows install --restricted-accounts {restricted_accounts} --unrestricted-accounts {unrestricted_accounts} --proxy-port-range {proxy_port_low}-{proxy_port_high}"
        ));
    }
    let _management_lock =
        NamedMutex::lock(MANAGEMENT_MUTEX).context("acquire restricted-user management mutex")?;
    setup(
        restricted_accounts,
        unrestricted_accounts,
        proxy_port_low,
        proxy_port_high,
    )
}

pub(in crate::platform::windows) fn uninstall() -> Result<()> {
    if !ProcessToken::is_current_elevated()? {
        return SpawnedProcess::elevate("windows uninstall");
    }
    let _management_lock =
        NamedMutex::lock(MANAGEMENT_MUTEX).context("acquire restricted-user management mutex")?;
    let store = StateStore::locate()?;
    remove_installation(&store)
}

pub(in crate::platform::windows) fn status() -> Result<Option<WindowsStatusReport>> {
    let Some(installation) = Installation::load_optional()? else {
        return Ok(None);
    };

    let (accounts_healthy, runner_healthy) = installation.health();
    let healthy = installation.complete && accounts_healthy && runner_healthy;
    Ok(Some(WindowsStatusReport {
        active: SandboxImplementation::RestrictedUser,
        installed: true,
        healthy,
        version: Some(installation.version),
        complete: Some(installation.complete),
        restricted_accounts: Some(
            installation
                .accounts
                .iter()
                .filter(|account| account.network_mode == NetworkMode::Restricted)
                .count(),
        ),
        unrestricted_accounts: Some(
            installation
                .accounts
                .iter()
                .filter(|account| account.network_mode == NetworkMode::Unrestricted)
                .count(),
        ),
        proxy_port_low: Some(installation.proxy_port_low),
        proxy_port_high: Some(installation.proxy_port_high),
        runner: Some(installation.runner_path),
        runner_healthy: Some(runner_healthy),
        accounts_healthy: Some(accounts_healthy),
        error: (!healthy).then(|| "restricted-user installation is unhealthy".to_owned()),
    }))
}

fn setup(
    restricted_accounts: u16,
    unrestricted_accounts: u16,
    proxy_port_low: u16,
    proxy_port_high: u16,
) -> Result<()> {
    let store = StateStore::locate()?;
    if Installation::load_optional_from(&store)?.is_some() {
        remove_installation(&store).context("remove previous restricted-user installation")?;
    }
    let id = account::random_identifier(8)?;
    let restricted_count = usize::from(restricted_accounts);
    let filter_count = restricted_count
        .checked_mul(FILTERS_PER_RESTRICTED_ACCOUNT)
        .context("WFP filter count overflow")?;
    let mut wfp_filters = Vec::with_capacity(filter_count);
    for _ in 0..filter_count {
        wfp_filters.push(account::random_identifier(16)?);
    }
    let runner_path = install_runner()?;

    let mut installation = Installation {
        version: INSTALLATION_VERSION,
        id,
        proxy_port_low,
        proxy_port_high,
        wfp_provider: account::random_identifier(16)?,
        wfp_sublayer: account::random_identifier(16)?,
        wfp_filters,
        complete: false,
        runner_path,
        accounts: Vec::with_capacity(restricted_count + usize::from(unrestricted_accounts)),
    };
    if let Err(error) = installation.save(&store) {
        return match remove_runner(&installation.runner_path) {
            Ok(()) => Err(error),
            Err(cleanup_error) => {
                Err(error.context(format!("automatic cleanup also failed: {cleanup_error:#}")))
            }
        };
    }

    let setup_result = (|| {
        store.init_runtime_dirs()?;
        provision_accounts(
            &store,
            &mut installation,
            restricted_accounts,
            NetworkMode::Restricted,
            "r",
        )?;
        provision_accounts(
            &store,
            &mut installation,
            unrestricted_accounts,
            NetworkMode::Unrestricted,
            "u",
        )?;
        wfp::install(&installation)?;
        installation.complete = true;
        installation.save(&store)?;
        Ok(())
    })();

    if let Err(error) = setup_result {
        return match remove_installation(&store) {
            Ok(()) => Err(error),
            Err(cleanup_error) => {
                Err(error.context(format!("automatic cleanup also failed: {cleanup_error:#}")))
            }
        };
    }

    Ok(())
}

fn provision_accounts(
    store: &StateStore,
    installation: &mut Installation,
    count: u16,
    network_mode: NetworkMode,
    mode_tag: &str,
) -> Result<()> {
    let prefix = &installation.id[..installation.id.len().min(8)];
    for index in 0..count {
        let name = format!("ls_{prefix}_{mode_tag}{index:02}");
        let provisioned = account::provision(&name, network_mode)
            .with_context(|| format!("provision restricted-user account {name}"))?;
        installation.accounts.push(provisioned);
        if let Err(error) = installation.save(store) {
            let provisioned = installation
                .accounts
                .pop()
                .context("newly provisioned account disappeared from installation state")?;
            return match account::remove(&provisioned.name) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(error.context(format!(
                    "remove unrecorded restricted-user account also failed: {cleanup_error:#}"
                ))),
            };
        }
    }
    Ok(())
}

fn remove_installation(store: &StateStore) -> Result<()> {
    let Some(mut installation) = Installation::load_optional_from(store)? else {
        return Ok(());
    };

    installation.complete = false;
    installation
        .save(store)
        .context("mark restricted-user installation unavailable")?;

    Lease::recover_all(store, &installation)
        .context("recover restricted-user filesystem grants before uninstall")?;
    wfp::uninstall(&installation).context("remove restricted-user WFP policy")?;
    for provisioned in &installation.accounts {
        account::remove(&provisioned.name)
            .with_context(|| format!("remove restricted-user account {}", provisioned.name))?;
    }
    remove_runner(&installation.runner_path)?;
    store.remove()
}

fn install_runner() -> Result<PathBuf> {
    let program_files = env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .context("ProgramFiles is unavailable")?;
    let directory = program_files.join(INSTALL_DIRECTORY);
    fs::create_dir_all(&directory)
        .with_context(|| format!("create runner directory {}", directory.display()))?;
    let source = env::current_exe().context("locate current landstrip executable")?;
    let destination = directory.join(RESTRICTED_USER_RUNNER);
    let temporary = directory.join(format!(
        "{RESTRICTED_USER_RUNNER}.tmp-{}",
        std::process::id()
    ));
    fs::copy(&source, &temporary).with_context(|| {
        format!(
            "copy restricted-user runner from {} to {}",
            source.display(),
            temporary.display()
        )
    })?;
    if let Err(error) = AtomicFile::replace(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("install restricted-user runner {}", destination.display()));
    }
    Ok(destination)
}

fn remove_runner(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("remove restricted-user runner {}", path.display()));
        }
    }
    if let Some(directory) = path.parent() {
        let _ = fs::remove_dir(directory);
    }
    Ok(())
}
