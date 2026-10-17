// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::{
    AppContainerProfile, ProcThreadAttributeList, current_process_in_job, update_attribute,
};
use crate::config::AppContainerMode;
use crate::error::Mechanism;
use crate::outcome::WindowsStatusReport;
use crate::platform::windows::{SandboxJob, ToWideNul, null_device, own_handle, wait_process_exit};
use anyhow::{Context, Result, anyhow, bail};
use std::ffi::c_void;
use std::io;
use std::mem;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, HANDLE, UNICODE_STRING,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, ImpersonateLoggedOnUser, RevertToSelf, SECURITY_CAPABILITIES,
    TOKEN_DUPLICATE, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenIsAppContainer,
    TokenIsLessPrivilegedAppContainer, TokenSecurityAttributes,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW,
    EXTENDED_STARTUPINFO_PRESENT, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, PROC_THREAD_ATTRIBUTE_JOB_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTUPINFOEXW,
};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

pub(in crate::platform::windows) fn status() -> WindowsStatusReport {
    WindowsStatusReport::app_container(probe_null_device().err().map(|error| format!("{error:#}")))
}

pub(in crate::platform::windows) fn probe_null_device() -> Result<()> {
    let errors = [
        ("standard", AppContainerMode::Standard),
        ("lpac", AppContainerMode::Lpac),
    ]
    .into_iter()
    .filter_map(|(name, mode)| probe(mode).err().map(|error| format!("{name}: {error:#}")))
    .collect::<Vec<_>>();
    if !errors.is_empty() {
        bail!("{}", errors.join("; "));
    }
    Ok(())
}

fn probe(mode: AppContainerMode) -> Result<()> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let moniker = format!("landstrip.doctor.{}.{timestamp}", std::process::id());
    let profile = AppContainerProfile::new(&moniker, true)?;
    let job = SandboxJob::new(Mechanism::Appcontainer)?;
    let mut job_handle = job.as_raw();
    let mut attributes =
        ProcThreadAttributeList::new(if mode == AppContainerMode::Lpac { 3 } else { 2 })?;
    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid(),
        Capabilities: ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    update_attribute(
        attributes.as_mut_ptr(),
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        (&raw mut capabilities).cast(),
        mem::size_of_val(&capabilities),
    )?;
    update_attribute(
        attributes.as_mut_ptr(),
        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
        (&raw mut job_handle).cast(),
        mem::size_of_val(&job_handle),
    )?;
    let mut all_packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    if mode == AppContainerMode::Lpac {
        update_attribute(
            attributes.as_mut_ptr(),
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
            (&raw mut all_packages_policy).cast(),
            mem::size_of_val(&all_packages_policy),
        )?;
    }
    let mut startup = STARTUPINFOEXW {
        StartupInfo: unsafe { mem::zeroed() },
        lpAttributeList: attributes.as_mut_ptr(),
    };
    startup.StartupInfo.cb = u32::try_from(mem::size_of_val(&startup))?;
    let executable = std::env::current_exe()
        .context("locate executable for suspended AppContainer probe")?
        .to_wide_nul();
    let mut create = |flags| -> io::Result<PROCESS_INFORMATION> {
        let mut info = unsafe { mem::zeroed::<PROCESS_INFORMATION>() };
        if unsafe {
            CreateProcessW(
                executable.as_ptr(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                0,
                flags,
                ptr::null(),
                ptr::null(),
                (&raw mut startup).cast(),
                &raw mut info,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    };
    let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW;
    let info = match create(flags) {
        Err(error)
            if error.raw_os_error() == Some(ERROR_ACCESS_DENIED.cast_signed())
                && current_process_in_job()? =>
        {
            create(flags | CREATE_BREAKAWAY_FROM_JOB)
        }
        result => result,
    }
    .context("create suspended AppContainer probe")?;
    let process = unsafe { own_handle(info.hProcess) };
    let _thread = unsafe { own_handle(info.hThread) };
    let result = probe_process_token(&process, mode);
    drop(job);
    let cleanup = wait_process_exit(&process)
        .map(|_| ())
        .context("reap suspended AppContainer probe");
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("probe cleanup also failed: {cleanup:#}")))
        }
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn probe_process_token(process: &OwnedHandle, mode: AppContainerMode) -> Result<()> {
    let mut token = ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            process.as_raw_handle(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("open AppContainer probe token");
    }
    let token = unsafe { own_handle(token) };
    std::thread::Builder::new()
        .name("landstrip-null-probe".to_owned())
        .spawn(move || {
            let app_container = token_u32(token.as_raw_handle(), TokenIsAppContainer)
                .context("query AppContainer probe token identity")?;
            if app_container != 1 {
                bail!("probe token has unexpected AppContainer identity");
            }
            let lpac =
                token_is_lpac(token.as_raw_handle()).context("query LPAC probe token identity")?;
            if lpac != (mode == AppContainerMode::Lpac) {
                bail!("probe token has unexpected LPAC identity");
            }
            if unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) } == 0 {
                return Err(io::Error::last_os_error())
                    .context("impersonate AppContainer probe token");
            }
            let result = null_device::probe();
            if unsafe { RevertToSelf() } == 0 {
                return Err(io::Error::last_os_error())
                    .context("restore null-device probe thread token");
            }
            result
        })
        .context("spawn null-device probe thread")?
        .join()
        .map_err(|_| anyhow!("null-device probe thread panicked"))?
}

/// Query a `u32`-valued token information class.
fn token_u32(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<u32> {
    let mut value = 0_u32;
    let mut returned = 0;
    let size = u32::try_from(mem::size_of_val(&value)).map_err(io::Error::other)?;
    if unsafe {
        GetTokenInformation(
            token,
            class,
            (&raw mut value).cast(),
            size,
            &raw mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("token information class {class} returned {returned} bytes"),
        ));
    }
    Ok(value)
}

/// Whether `token` is a less privileged `AppContainer`.
///
/// Some Windows builds (Windows 11 24H2, 26100) reject `TokenIsLessPrivilegedAppContainer`
/// with `ERROR_INVALID_PARAMETER` for every token. There, the `WIN://NOALLAPPPKG` security
/// attribute that Windows sets on a token created with
/// `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT` answers instead.
fn token_is_lpac(token: HANDLE) -> io::Result<bool> {
    match token_u32(token, TokenIsLessPrivilegedAppContainer) {
        Ok(value) => Ok(value != 0),
        Err(error) if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER.cast_signed()) => {
            token_has_security_attribute(token, "WIN://NOALLAPPPKG")
        }
        Err(error) => Err(error),
    }
}

/// `TOKEN_SECURITY_ATTRIBUTES_INFORMATION`, the layout `GetTokenInformation` returns for
/// `TokenSecurityAttributes`. Unlike `CLAIM_SECURITY_ATTRIBUTES_INFORMATION`, its attribute
/// names are `UNICODE_STRING`s.
#[repr(C)]
struct TokenSecurityAttributesInformation {
    version: u16,
    reserved: u16,
    attribute_count: u32,
    attributes: *const TokenSecurityAttributeV1,
}

/// `TOKEN_SECURITY_ATTRIBUTE_V1`.
#[repr(C)]
struct TokenSecurityAttributeV1 {
    name: UNICODE_STRING,
    value_type: u16,
    reserved: u16,
    flags: u32,
    value_count: u32,
    values: *const c_void,
}

/// Whether `token` carries the security attribute `name` (compared case-insensitively).
fn token_has_security_attribute(token: HANDLE, name: &str) -> io::Result<bool> {
    let mut size = 0;
    unsafe {
        GetTokenInformation(
            token,
            TokenSecurityAttributes,
            ptr::null_mut(),
            0,
            &raw mut size,
        );
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER.cast_signed()) {
        return Err(error);
    }
    let word_size = mem::size_of::<u64>();
    let word_count = usize::try_from(size)
        .map_err(io::Error::other)?
        .div_ceil(word_size);
    let mut words = vec![0_u64; word_count];
    if unsafe {
        GetTokenInformation(
            token,
            TokenSecurityAttributes,
            words.as_mut_ptr().cast(),
            size,
            &raw mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { &*words.as_ptr().cast::<TokenSecurityAttributesInformation>() };
    let count = usize::try_from(information.attribute_count).map_err(io::Error::other)?;
    if count == 0 || information.attributes.is_null() {
        return Ok(false);
    }
    let attributes = unsafe { std::slice::from_raw_parts(information.attributes, count) };
    Ok(attributes.iter().any(|attribute| {
        let name_units = usize::from(attribute.name.Length) / mem::size_of::<u16>();
        !attribute.name.Buffer.is_null()
            && String::from_utf16_lossy(unsafe {
                std::slice::from_raw_parts(attribute.name.Buffer, name_units)
            })
            .eq_ignore_ascii_case(name)
    }))
}
