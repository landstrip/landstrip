// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Restricted-account worker process.

use super::state;
use super::{
    OwnedSecurityDescriptor, ToWideNul, current_process_token, join_command_line, own_handle,
    quote_command_text, sid_string, token_user,
};
use crate::error::{Error as LandstripError, Mechanism};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::WAIT_FAILED;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE,
    PROTECTED_DACL_SECURITY_INFORMATION, SetKernelObjectSecurity, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess,
    GetCurrentThread, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};

const REQUEST_VERSION: u32 = 2;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    version: u32,
    account_sid: String,
    tool: Vec<u16>,
    args: Vec<Vec<u16>>,
    cwd: Vec<u16>,
    environment: Vec<u16>,
}

pub(super) fn write_request(
    path: &Path,
    account_sid: &str,
    tool: &OsStr,
    args: &[OsString],
    cwd: &Path,
) -> Result<()> {
    let request = Request {
        version: REQUEST_VERSION,
        account_sid: account_sid.to_owned(),
        tool: tool.encode_wide().collect(),
        args: args.iter().map(|arg| arg.encode_wide().collect()).collect(),
        cwd: cwd.as_os_str().encode_wide().collect(),
        environment: current_environment()?,
    };
    let parent = path
        .parent()
        .context("restricted-user request path has no parent")?;
    if !parent.is_dir() {
        bail!("restricted-user runtime directory is missing");
    }
    let bytes = serde_json::to_vec(&request)?;
    let result = (|| {
        let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        state::protect_path(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

pub(super) fn run(path: &Path) -> Result<i32> {
    let bytes = fs::read(path).context("read restricted-user worker request")?;
    let request: Request =
        serde_json::from_slice(&bytes).context("parse restricted-user worker request")?;
    if request.version != REQUEST_VERSION {
        bail!("unsupported restricted-user worker request version");
    }
    verify_current_sid(&request.account_sid)?;

    let tool = OsString::from_wide(&request.tool);
    let args = request
        .args
        .iter()
        .map(|arg| OsString::from_wide(arg))
        .collect::<Vec<_>>();
    let cwd = OsString::from_wide(&request.cwd);
    let exit_code = launch(&tool, &args, &cwd, &request.environment)?;
    Ok(exit_code.cast_signed())
}

fn launch(tool: &OsStr, args: &[OsString], cwd: &OsStr, environment: &[u16]) -> Result<u32> {
    harden_worker_objects()?;
    let restricted_token = create_restricted_token()?;

    let command_line = command_line(tool, args)?;
    let mut command_line = command_line.to_wide_nul();
    let cwd = cwd.to_wide_nul();
    validate_environment(environment)?;
    let mut startup = unsafe { mem::zeroed::<STARTUPINFOW>() };
    startup.cb = u32::try_from(mem::size_of::<STARTUPINFOW>())?;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    startup.hStdOutput = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    startup.hStdError = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    let mut process_info = unsafe { mem::zeroed::<PROCESS_INFORMATION>() };
    let ok = unsafe {
        CreateProcessAsUserW(
            restricted_token.as_raw_handle(),
            ptr::null(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            cwd.as_ptr(),
            &raw const startup,
            &raw mut process_info,
        )
    };
    if ok == 0 {
        return Err(LandstripError::launch(tool, io::Error::last_os_error()).into());
    }
    let process = unsafe { own_handle(process_info.hProcess) };
    let thread = unsafe { own_handle(process_info.hThread) };
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

fn create_restricted_token() -> Result<OwnedHandle> {
    // Strip all privileges from the worker's own primary token. landstrip's
    // filesystem write boundary is the dedicated SAM user's DACL (apply() in
    // access.rs), not the token's restricting-SID list: the DACL grants the
    // user, so restricting SIDs would deny the worker its own workspace under
    // DISABLE_MAX_PRIVILEGE (which gates reads as well as writes). Keep only
    // the privilege-stripping, which defends the DACL against
    // SeBackupPrivilege / SeRestorePrivilege bypass. An empty restricting-SID
    // list (count 0, pointer NULL) is the textbook-valid minimal call.
    let process_token = worker_process_token()?;
    let mut restricted_token = ptr::null_mut();
    let ok = unsafe {
        CreateRestrictedToken(
            process_token.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            &raw mut restricted_token,
        )
    };
    if ok == 0 {
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("CreateRestrictedToken: {}", io::Error::last_os_error()),
        )
        .into());
    }
    Ok(unsafe { own_handle(restricted_token) })
}

fn harden_worker_objects() -> Result<()> {
    let descriptor = OwnedSecurityDescriptor::from_sddl("D:P(A;;GA;;;SY)").map_err(|source| {
        LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("ConvertStringSecurityDescriptorToSecurityDescriptorW: {source}"),
        )
    })?;

    for (handle, object) in [
        (unsafe { GetCurrentProcess() }, "worker process"),
        (unsafe { GetCurrentThread() }, "worker thread"),
    ] {
        if unsafe {
            SetKernelObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.as_ptr(),
            )
        } == 0
        {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Windowsuser,
                format!(
                    "SetKernelObjectSecurity ({object}): {}",
                    io::Error::last_os_error()
                ),
            )
            .into());
        }
    }
    Ok(())
}

fn current_environment() -> Result<Vec<u16>> {
    let environment = unsafe { GetEnvironmentStringsW() };
    if environment.is_null() {
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("GetEnvironmentStringsW: {}", io::Error::last_os_error()),
        )
        .into());
    }
    let mut length = 0;
    while unsafe { *environment.add(length) } != 0 || unsafe { *environment.add(length + 1) } != 0 {
        length += 1;
    }
    length += 2;
    let result = unsafe { std::slice::from_raw_parts(environment, length) }.to_vec();
    if unsafe { FreeEnvironmentStringsW(environment) } == 0 {
        return Err(LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("FreeEnvironmentStringsW: {}", io::Error::last_os_error()),
        )
        .into());
    }
    Ok(result)
}

fn validate_environment(environment: &[u16]) -> Result<()> {
    let Some(terminator) = environment.windows(2).position(|pair| pair == [0, 0]) else {
        bail!("restricted-user worker environment is not terminated");
    };
    if terminator + 2 != environment.len() {
        bail!("restricted-user worker environment contains trailing data");
    }
    Ok(())
}

fn worker_process_token() -> Result<OwnedHandle> {
    current_process_token(TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY).map_err(|source| {
        LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("OpenProcessToken: {source}"),
        )
        .into()
    })
}

fn verify_current_sid(expected: &str) -> Result<()> {
    let token = worker_process_token()?;
    let user = token_user(token.as_raw_handle()).map_err(|source| {
        LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("GetTokenInformation: {source}"),
        )
    })?;
    let actual = unsafe { sid_string(user.User.Sid) }.map_err(|source| {
        LandstripError::sandbox_setup(
            Mechanism::Windowsuser,
            format!("ConvertSidToStringSidW: {source}"),
        )
    })?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("restricted-user worker account SID does not match request");
    }
    Ok(())
}

fn command_line(tool: &OsStr, args: &[OsString]) -> Result<String> {
    join_command_line(tool, args, |arg| {
        let arg = arg
            .to_str()
            .context("restricted-user command line is not valid Unicode")?;
        quote_command_text(arg)
            .map_err(|_| anyhow::anyhow!("restricted-user command line contains an interior NUL"))
    })
}
