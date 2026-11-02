// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Elevated broker that starts a worker under a leased local account.

use super::super::process::{CommandLine, SandboxJob, SpawnedProcess};
use super::super::win32::ToWideNul;
use super::state::{Account, SecretWide};
use crate::error::{Error as LandstripError, Mechanism};
use anyhow::Result;
use std::io;
use std::mem;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessWithLogonW, LOGON_WITH_PROFILE, PROCESS_INFORMATION,
};

pub(super) fn launch(account: &Account, runner_path: &Path, request_path: &Path) -> Result<u32> {
    if !runner_path.is_file() {
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            "restricted-user runner is missing",
        )
        .into());
    }
    let executable = runner_path.to_wide_nul();
    let mut command_line = CommandLine::encode(runner_path.as_os_str(), [request_path.as_os_str()])
        .map_err(|msg| LandstripError::sandbox_setup(Mechanism::Windowsuser, msg))?;
    let username = account.name.to_wide_nul();
    let domain = [0_u16];
    let password = SecretWide::decrypt(&account.encrypted_password)?;
    let current_directory = std::env::current_dir()?.to_wide_nul();
    let job = SandboxJob::new(Mechanism::Windowsuser)?;
    let startup = SpawnedProcess::std_startup_info()?;

    let mut process_info = unsafe { mem::zeroed::<PROCESS_INFORMATION>() };
    let ok = unsafe {
        CreateProcessWithLogonW(
            username.as_ptr(),
            domain.as_ptr(),
            password.as_ptr(),
            LOGON_WITH_PROFILE,
            executable.as_ptr(),
            command_line.as_mut_ptr(),
            CREATE_SUSPENDED,
            ptr::null(),
            current_directory.as_ptr(),
            &raw const startup,
            &raw mut process_info,
        )
    };
    if ok == 0 {
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("CreateProcessWithLogonW: {}", io::Error::last_os_error()),
        )
        .into());
    }
    let spawned = unsafe { SpawnedProcess::from_raw(process_info) };
    spawned.assign_to_job(&job, Mechanism::Windowsuser)?;
    spawned.resume_and_wait(Mechanism::Windowsuser)
}
