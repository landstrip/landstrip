// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Elevated broker that starts a worker under a leased local account.

use super::state::{self, Account};
use super::{ToWideNul, own_handle, quote_command_arg};
use crate::error::{Error as LandstripError, Mechanism};
use anyhow::{Context, Result};
use std::ffi::{OsStr, c_void};
use std::io;
use std::mem;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::WAIT_FAILED;
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessWithLogonW, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
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
    let command_line = format!(
        "{} {}",
        quote(runner_path.as_os_str())?,
        quote(request_path.as_os_str())?
    );
    let mut command_line = command_line.to_wide_nul();
    let username = account.name.to_wide_nul();
    let domain = "".to_wide_nul();
    let password = state::unprotect_password(&account.encrypted_password)?;
    let current_directory = std::env::current_dir()?;
    let current_directory = current_directory.to_wide_nul();
    let job = create_job()?;

    let mut startup = unsafe { mem::zeroed::<STARTUPINFOW>() };
    startup.cb = u32::try_from(mem::size_of::<STARTUPINFOW>())?;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    startup.hStdOutput = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    startup.hStdError = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    let mut process_info = unsafe { mem::zeroed::<PROCESS_INFORMATION>() };
    let ok = unsafe {
        CreateProcessWithLogonW(
            username.as_ptr(),
            domain.as_ptr(),
            password.as_ptr(),
            0,
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
    let process = unsafe { own_handle(process_info.hProcess) };
    let thread = unsafe { own_handle(process_info.hThread) };
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
        let error = io::Error::last_os_error();
        unsafe {
            TerminateProcess(process.as_raw_handle(), 1);
        }
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("AssignProcessToJobObject: {error}"),
        )
        .into());
    }
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("ResumeThread: {}", io::Error::last_os_error()),
        )
        .into());
    }
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) };
    if wait == WAIT_FAILED {
        return Err(LandstripError::supervise(io::Error::last_os_error()).into());
    }
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &raw mut exit_code) } == 0 {
        return Err(LandstripError::supervise(io::Error::last_os_error()).into());
    }
    Ok(exit_code)
}

fn create_job() -> Result<OwnedHandle> {
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("CreateJobObjectW: {}", io::Error::last_os_error()),
        )
        .into());
    }
    let job = unsafe { own_handle(job) };
    let mut limits = unsafe { mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast::<c_void>(),
            u32::try_from(mem::size_of_val(&limits))?,
        )
    } == 0
    {
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("SetInformationJobObject: {}", io::Error::last_os_error()),
        )
        .into());
    }
    Ok(job)
}

fn quote(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("restricted-user worker path is not valid Unicode")?;
    if value.contains('\0') {
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            "restricted-user worker path contains an interior NUL",
        )
        .into());
    }
    Ok(quote_command_arg(value))
}
