// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Elevated broker that starts a worker under a leased local account.

use super::state::{self, Account};
use crate::engine::error::{Error as LandstripError, Mechanism};
use anyhow::{Context, Result};
use std::ffi::{OsStr, c_void};
use std::io;
use std::iter;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED};
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
        return Err(setup_failed("restricted-user runner is missing").into());
    }
    let executable = wide_os(runner_path.as_os_str());
    let command_line = format!(
        "{} windows worker {}",
        quote(runner_path.as_os_str())?,
        quote(request_path.as_os_str())?
    );
    let mut command_line = wide(&command_line);
    let username = wide(&account.name);
    let domain = wide(".");
    let password = state::unprotect_password(&account.encrypted_password)?;
    let current_directory = std::env::current_dir()?;
    let current_directory = wide_os(current_directory.as_os_str());
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
            &startup,
            &mut process_info,
        )
    };
    if ok == 0 {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    let process = Handle(process_info.hProcess);
    let thread = Handle(process_info.hThread);
    if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
        let error = io::Error::last_os_error();
        unsafe {
            TerminateProcess(process.0, 1);
        }
        return Err(setup_failed(error).into());
    }
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    let wait = unsafe { WaitForSingleObject(process.0, INFINITE) };
    if wait == WAIT_FAILED {
        return Err(LandstripError::SuperviseFailed {
            source: io::Error::last_os_error().into(),
        }
        .into());
    }
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 {
        return Err(LandstripError::SuperviseFailed {
            source: io::Error::last_os_error().into(),
        }
        .into());
    }
    Ok(exit_code)
}

fn create_job() -> Result<Handle> {
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    let job = Handle(job);
    let mut limits = unsafe { mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast::<c_void>(),
            u32::try_from(mem::size_of_val(&limits))?,
        )
    } == 0
    {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    Ok(job)
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn quote(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("restricted-user worker path is not valid Unicode")?;
    if value.contains('\0') {
        return Err(setup_failed("restricted-user worker path contains an interior NUL").into());
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in value.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(iter::repeat_n('\\', backslashes));
                quoted.push(ch);
                backslashes = 0;
            }
        }
    }
    quoted.extend(iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    Ok(quoted)
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn setup_failed(source: impl Into<crate::engine::error::Cause>) -> LandstripError {
    LandstripError::SandboxSetupFailed {
        mechanism: Mechanism::Windowsuser,
        source: source.into(),
    }
}
