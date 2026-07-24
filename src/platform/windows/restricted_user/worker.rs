// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Restricted-account worker process.

use super::state;
use crate::engine::error::{Error as LandstripError, Mechanism};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString, c_void};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::iter;
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree, WAIT_FAILED};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE,
    GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, SetKernelObjectSecurity, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAnyPackageSid,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess,
    GetCurrentThread, GetExitCodeProcess, INFINITE, OpenProcessToken, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};

const REQUEST_VERSION: u32 = 2;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

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
        state::protect_path(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

pub(super) fn run(path: &Path) -> Result<()> {
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
    std::process::exit(i32::from_ne_bytes(exit_code.to_ne_bytes()));
}

fn launch(tool: &OsStr, args: &[OsString], cwd: &OsStr, environment: &[u16]) -> Result<u32> {
    harden_worker_objects()?;
    let process_token = current_process_token()?;
    let token_user = token_user(process_token.0)?;
    let mut application_package_sid = [0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut application_package_sid_size = SECURITY_MAX_SID_SIZE;
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAnyPackageSid,
            ptr::null_mut(),
            application_package_sid.as_mut_ptr().cast(),
            &mut application_package_sid_size,
        )
    } == 0
    {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    let restricted_sids = [
        SID_AND_ATTRIBUTES {
            Sid: token_user.User.Sid,
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: application_package_sid.as_mut_ptr().cast(),
            Attributes: 0,
        },
    ];
    let mut restricted_token = ptr::null_mut();
    let ok = unsafe {
        CreateRestrictedToken(
            process_token.0,
            DISABLE_MAX_PRIVILEGE,
            0,
            ptr::null(),
            0,
            ptr::null(),
            u32::try_from(restricted_sids.len())?,
            restricted_sids.as_ptr(),
            &mut restricted_token,
        )
    };
    if ok == 0 {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    let restricted_token = Handle(restricted_token);

    let command_line = command_line(tool, args)?;
    let mut command_line = wide(&command_line);
    let cwd = cwd.encode_wide().chain(Some(0)).collect::<Vec<_>>();
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
            restricted_token.0,
            ptr::null(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            cwd.as_ptr(),
            &startup,
            &mut process_info,
        )
    };
    if ok == 0 {
        return Err(LandstripError::LaunchFailed {
            tool: tool.into(),
            source: io::Error::last_os_error().into(),
        }
        .into());
    }
    let process = Handle(process_info.hProcess);
    let thread = Handle(process_info.hThread);
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

fn harden_worker_objects() -> Result<()> {
    let descriptor = wide("D:P(A;;GA;;;SY)");
    let mut security_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor.as_ptr(),
            SECURITY_DESCRIPTOR_REVISION,
            &mut security_descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }

    let result = (|| {
        for (handle, object) in [
            (unsafe { GetCurrentProcess() }, "worker process"),
            (unsafe { GetCurrentThread() }, "worker thread"),
        ] {
            if unsafe {
                SetKernelObjectSecurity(
                    handle,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    security_descriptor,
                )
            } == 0
            {
                return Err(setup_failed(io::Error::last_os_error()))
                    .with_context(|| format!("protect restricted-user {object}"));
            }
        }
        Ok(())
    })();
    unsafe {
        LocalFree(security_descriptor.cast::<c_void>());
    }
    result
}

fn current_environment() -> Result<Vec<u16>> {
    let environment = unsafe { GetEnvironmentStringsW() };
    if environment.is_null() {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    let mut length = 0;
    while unsafe { *environment.add(length) } != 0 || unsafe { *environment.add(length + 1) } != 0 {
        length += 1;
    }
    length += 2;
    let result = unsafe { std::slice::from_raw_parts(environment, length) }.to_vec();
    if unsafe { FreeEnvironmentStringsW(environment) } == 0 {
        return Err(setup_failed(io::Error::last_os_error()).into());
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

fn current_process_token() -> Result<Handle> {
    let mut token = ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut token,
        )
    } == 0
    {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    Ok(Handle(token))
}

fn token_user(token: HANDLE) -> Result<TokenUserBuffer> {
    let mut size = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
    }
    if size == 0 {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    let word_size = mem::size_of::<usize>();
    let word_count = usize::try_from(size)?.div_ceil(word_size);
    let mut words = vec![0_usize; word_count];
    if unsafe { GetTokenInformation(token, TokenUser, words.as_mut_ptr().cast(), size, &mut size) }
        == 0
    {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    Ok(TokenUserBuffer { words })
}

struct TokenUserBuffer {
    words: Vec<usize>,
}

impl std::ops::Deref for TokenUserBuffer {
    type Target = TOKEN_USER;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.words.as_ptr().cast() }
    }
}

fn verify_current_sid(expected: &str) -> Result<()> {
    let token = current_process_token()?;
    let user = token_user(token.0)?;
    let mut sid_string = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_string) } == 0 {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    let actual = wide_ptr_to_string(sid_string);
    unsafe {
        LocalFree(sid_string.cast::<c_void>());
    }
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("restricted-user worker account SID does not match request");
    }
    Ok(())
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

fn command_line(tool: &OsStr, args: &[OsString]) -> Result<String> {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(quote_command_arg(tool)?);
    for arg in args {
        parts.push(quote_command_arg(arg)?);
    }
    Ok(parts.join(" "))
}

fn quote_command_arg(arg: &OsStr) -> Result<String> {
    let arg = arg
        .to_str()
        .context("restricted-user command line is not valid Unicode")?;
    if arg.contains('\0') {
        bail!("restricted-user command line contains an interior NUL");
    }
    if arg.is_empty() {
        return Ok("\"\"".to_owned());
    }
    if !arg
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\"'))
    {
        return Ok(arg.to_owned());
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in arg.chars() {
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

fn wide_ptr_to_string(value: *const u16) -> String {
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) })
}

fn setup_failed(source: impl Into<crate::engine::error::Cause>) -> LandstripError {
    LandstripError::SandboxSetupFailed {
        mechanism: Mechanism::Windowsuser,
        source: source.into(),
    }
}
