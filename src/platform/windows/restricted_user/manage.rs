// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Elevated installation lifecycle for restricted-user isolation.

use super::account;
use super::lease;
use super::state::{self, INSTALLATION_VERSION, Installation, NetworkMode};
use super::wfp;
use super::{ToWideNul, current_process_token, own_handle};
use crate::outcome::{SandboxImplementation, WindowsStatusReport};
use crate::platform::WindowsCommand;
use anyhow::{Context, Result, bail};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::mem;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetExitCodeProcess, INFINITE, ReleaseMutex, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, SHELLEXECUTEINFOW_0,
    ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const FILTERS_PER_RESTRICTED_ACCOUNT: usize = 8;
const INSTALL_DIRECTORY: &str = "Landstrip";
const RUNNER_FILE: &str = "landstrip-restricted-user-runner.exe";
const MANAGEMENT_MUTEX: &str = "Global\\LandstripRestrictedUserManagement";

pub(crate) fn manage(command: &WindowsCommand) -> Result<WindowsStatusReport> {
    match command {
        WindowsCommand::Install {
            restricted_accounts,
            unrestricted_accounts,
            proxy_port_low,
            proxy_port_high,
        } => {
            if !is_elevated()? {
                elevate_install(
                    *restricted_accounts,
                    *unrestricted_accounts,
                    *proxy_port_low,
                    *proxy_port_high,
                )?;
                return status();
            }
            let _management_lock = ManagementLock::acquire()?;
            setup(
                *restricted_accounts,
                *unrestricted_accounts,
                *proxy_port_low,
                *proxy_port_high,
            )
        }
        WindowsCommand::Status => status(),
        WindowsCommand::Uninstall => {
            if !is_elevated()? {
                elevate_uninstall()?;
                return status();
            }
            let _management_lock = ManagementLock::acquire()?;
            uninstall()
        }
    }
}

fn setup(
    restricted_accounts: u16,
    unrestricted_accounts: u16,
    proxy_port_low: u16,
    proxy_port_high: u16,
) -> Result<WindowsStatusReport> {
    if state::load_optional()?.is_some() {
        uninstall().context("remove previous restricted-user installation")?;
    }

    let id = account::random_identifier(8)?;
    let restricted_count = usize::from(restricted_accounts);
    let filter_count = restricted_count
        .checked_mul(FILTERS_PER_RESTRICTED_ACCOUNT)
        .context("WFP filter count overflow")?;
    let mut wfp_filters = Vec::with_capacity(filter_count);
    for _ in 0..filter_count {
        wfp_filters.push(wfp::generate_key()?);
    }
    let runner_path = install_runner()?;

    let mut installation = Installation {
        version: INSTALLATION_VERSION,
        id,
        proxy_port_low,
        proxy_port_high,
        wfp_provider: wfp::generate_key()?,
        wfp_sublayer: wfp::generate_key()?,
        wfp_filters,
        complete: false,
        runner_path,
        accounts: Vec::with_capacity(restricted_count + usize::from(unrestricted_accounts)),
    };
    if let Err(error) = state::save(&installation) {
        let cleanup = remove_runner(&installation.runner_path);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => {
                Err(error.context(format!("automatic cleanup also failed: {cleanup_error:#}")))
            }
        };
    }

    let setup_result = (|| {
        state::initialize_runtime_directories()?;
        provision_accounts(
            &mut installation,
            restricted_accounts,
            NetworkMode::Restricted,
            "r",
        )?;
        provision_accounts(
            &mut installation,
            unrestricted_accounts,
            NetworkMode::Unrestricted,
            "u",
        )?;
        wfp::install(&installation)?;
        installation.complete = true;
        state::save(&installation)?;
        Ok(())
    })();

    if let Err(error) = setup_result {
        let cleanup = uninstall();
        return match cleanup {
            Ok(_) => Err(error),
            Err(cleanup_error) => {
                Err(error.context(format!("automatic cleanup also failed: {cleanup_error:#}")))
            }
        };
    }

    status()
}

fn provision_accounts(
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
        if let Err(error) = state::save(installation) {
            let provisioned = installation
                .accounts
                .pop()
                .context("newly provisioned account disappeared from installation state")?;
            let cleanup = account::remove(&provisioned.name);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(error.context(format!(
                    "remove unrecorded restricted-user account also failed: {cleanup_error:#}"
                ))),
            };
        }
    }
    Ok(())
}

fn uninstall() -> Result<WindowsStatusReport> {
    let Some(mut installation) = state::load_optional()? else {
        return Ok(WindowsStatusReport::app_container());
    };

    installation.complete = false;
    state::save(&installation).context("mark restricted-user installation unavailable")?;

    lease::recover_all(&installation)
        .context("recover restricted-user filesystem grants before uninstall")?;
    wfp::uninstall(&installation).context("remove restricted-user WFP policy")?;
    for provisioned in &installation.accounts {
        account::remove(&provisioned.name)
            .with_context(|| format!("remove restricted-user account {}", provisioned.name))?;
    }
    remove_runner(&installation.runner_path)?;
    state::remove()?;
    Ok(WindowsStatusReport::app_container())
}

pub(in crate::platform::windows) fn status() -> Result<WindowsStatusReport> {
    let Some(installation) = state::load_optional()? else {
        return Ok(WindowsStatusReport::app_container());
    };

    let (accounts_healthy, runner_healthy) = installation_health(&installation);
    let healthy = installation.complete && accounts_healthy && runner_healthy;
    Ok(WindowsStatusReport {
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
    })
}

pub(in crate::platform::windows) fn active_implementation() -> Result<&'static str> {
    let Some(installation) = state::load_optional()? else {
        return Ok("appContainer");
    };
    let (accounts_healthy, runner_healthy) = installation_health(&installation);
    if !installation.complete || !accounts_healthy || !runner_healthy {
        bail!("restricted-user installation is unhealthy");
    }
    Ok("restrictedUser")
}

fn installation_health(installation: &Installation) -> (bool, bool) {
    let accounts_healthy = installation.accounts.iter().all(|provisioned| {
        account::lookup_sid(&provisioned.name)
            .is_ok_and(|sid| sid.eq_ignore_ascii_case(&provisioned.sid))
    });
    (accounts_healthy, installation.runner_path.is_file())
}

fn install_runner() -> Result<PathBuf> {
    let program_files = env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .context("ProgramFiles is unavailable")?;
    let directory = program_files.join(INSTALL_DIRECTORY);
    fs::create_dir_all(&directory)
        .with_context(|| format!("create runner directory {}", directory.display()))?;
    let source = env::current_exe().context("locate current landstrip executable")?;
    let destination = directory.join(RUNNER_FILE);
    let temporary = directory.join(format!("{RUNNER_FILE}.tmp-{}", std::process::id()));
    fs::copy(&source, &temporary).with_context(|| {
        format!(
            "copy restricted-user runner from {} to {}",
            source.display(),
            temporary.display()
        )
    })?;
    if destination.exists() {
        fs::remove_file(&destination)
            .with_context(|| format!("replace restricted-user runner {}", destination.display()))?;
    }
    fs::rename(&temporary, &destination)
        .with_context(|| format!("install restricted-user runner {}", destination.display()))?;
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

fn elevate_install(
    restricted_accounts: u16,
    unrestricted_accounts: u16,
    proxy_port_low: u16,
    proxy_port_high: u16,
) -> Result<()> {
    elevate(&format!(
        "windows install --restricted-accounts {restricted_accounts} --unrestricted-accounts {unrestricted_accounts} --proxy-port-range {proxy_port_low}-{proxy_port_high}"
    ))
}

fn elevate_uninstall() -> Result<()> {
    elevate("windows uninstall")
}

fn elevate(parameters: &str) -> Result<()> {
    let executable = env::current_exe().context("locate current landstrip executable")?;
    let executable = executable.to_wide_nul();
    let parameters = parameters.to_wide_nul();
    let verb = OsStr::new("runas").to_wide_nul();
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(mem::size_of::<SHELLEXECUTEINFOW>())
            .context("ShellExecute structure is too large")?,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
        hwnd: ptr::null_mut(),
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: ptr::null(),
        nShow: SW_SHOWNORMAL,
        hInstApp: ptr::null_mut(),
        lpIDList: ptr::null_mut(),
        lpClass: ptr::null(),
        hkeyClass: ptr::null_mut(),
        dwHotKey: 0,
        Anonymous: SHELLEXECUTEINFOW_0::default(),
        hProcess: ptr::null_mut(),
    };
    if unsafe { ShellExecuteExW(&raw mut execute) } == 0 {
        return Err(io::Error::last_os_error()).context("request Windows elevation");
    }
    if execute.hProcess.is_null() {
        bail!("Windows elevation returned no process handle");
    }
    let process = unsafe { own_handle(execute.hProcess) };
    if unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
        return Err(io::Error::last_os_error()).context("wait for elevated landstrip");
    }
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &raw mut exit_code) } == 0 {
        return Err(io::Error::last_os_error()).context("query elevated landstrip exit code");
    }
    if exit_code != 0 {
        bail!("elevated landstrip exited with status {exit_code}");
    }
    Ok(())
}

fn is_elevated() -> Result<bool> {
    let token = current_process_token(TOKEN_QUERY).context("open current process token")?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&raw mut elevation).cast(),
            u32::try_from(mem::size_of::<TOKEN_ELEVATION>())
                .context("token elevation structure is too large")?,
            &raw mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("query process elevation");
    }
    Ok(elevation.TokenIsElevated != 0)
}

struct ManagementLock(HANDLE);

impl ManagementLock {
    fn acquire() -> Result<Self> {
        let name = MANAGEMENT_MUTEX.to_wide_nul();
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error())
                .context("create restricted-user management mutex");
        }
        let wait = unsafe { WaitForSingleObject(handle, INFINITE) };
        if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
            unsafe { CloseHandle(handle) };
            let error = if wait == WAIT_FAILED {
                io::Error::last_os_error()
            } else {
                io::Error::other(format!("unexpected mutex wait result {wait}"))
            };
            return Err(error).context("acquire restricted-user management mutex");
        }
        Ok(Self(handle))
    }
}

impl Drop for ManagementLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
