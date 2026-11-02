// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::{AppContainerProfile, LookupRoots, ProcThreadAttributeList};
use crate::config::AppContainerMode;
use crate::error::Mechanism;
use crate::outcome::WindowsStatusReport;
use crate::platform::windows::null_device;
use crate::platform::windows::process::{BreakawayError, SandboxJob, SpawnedProcess};
use crate::platform::windows::win32::{OwnedSecurityDescriptor, ToWideNul};
use anyhow::{Context, Result, anyhow, bail};
use std::io;
use std::mem;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Security::{
    AccessCheck, DuplicateToken, GENERIC_MAPPING, GetTokenInformation, ImpersonateLoggedOnUser,
    PRIVILEGE_SET, RevertToSelf, SECURITY_CAPABILITIES, SecurityImpersonation, TOKEN_DUPLICATE,
    TOKEN_QUERY, TokenIsAppContainer,
};
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, PROC_THREAD_ATTRIBUTE_JOB_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
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
    attributes.update(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &mut capabilities,
    )?;
    attributes.update(PROC_THREAD_ATTRIBUTE_JOB_LIST, &mut job_handle)?;
    let mut all_packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    if mode == AppContainerMode::Lpac {
        attributes.update(
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            &mut all_packages_policy,
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
    let spawned = SpawnedProcess::create_extended(
        Some(&executable),
        None,
        false,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        None,
        &mut startup,
    )
    .map_err(BreakawayError::into_io)
    .context("create suspended AppContainer probe")?;
    let SpawnedProcess {
        process,
        thread: _thread,
    } = spawned;
    let result = ProbeToken::try_from(&process).and_then(|token| token.spawn_probe(mode));
    drop(job);
    let cleanup = SpawnedProcess::wait_exit(&process)
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

/// A verified `AppContainer` impersonation token, owned by the probe thread.
struct ProbeToken(OwnedHandle);

impl<'a> TryFrom<BorrowedHandle<'a>> for ProbeToken {
    type Error = anyhow::Error;

    fn try_from(process: BorrowedHandle<'a>) -> Result<Self> {
        let mut primary = ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                process.as_raw_handle(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &raw mut primary,
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("open AppContainer probe token");
        }
        let primary = unsafe { OwnedHandle::from_raw_handle(primary) };
        let mut token = ptr::null_mut();
        if unsafe {
            DuplicateToken(
                primary.as_raw_handle(),
                SecurityImpersonation,
                &raw mut token,
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("duplicate AppContainer probe token");
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut is_app_container = 0_u32;
        let mut returned = 0;
        let size = u32::try_from(mem::size_of_val(&is_app_container))?;
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenIsAppContainer,
                (&raw mut is_app_container).cast(),
                size,
                &raw mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("query AppContainer probe token");
        }
        if returned != size || is_app_container != 1 {
            bail!("probe token is not an AppContainer");
        }
        Ok(Self(token))
    }
}

impl TryFrom<&OwnedHandle> for ProbeToken {
    type Error = anyhow::Error;

    fn try_from(process: &OwnedHandle) -> Result<Self> {
        Self::try_from(process.as_handle())
    }
}

impl AsHandle for ProbeToken {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}

impl AsRawHandle for ProbeToken {
    fn as_raw_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0.as_raw_handle()
    }
}

impl TryFrom<&ProbeToken> for AppContainerMode {
    type Error = anyhow::Error;

    fn try_from(token: &ProbeToken) -> Result<Self> {
        const APP_CONTAINER_ACCESS: u32 = 0x1;
        const LPAC_ACCESS: u32 = 0x2;
        const PROBE_ACCESS: u32 = APP_CONTAINER_ACCESS | LPAC_ACCESS;

        // Give everyone both rights, then let the AppContainer access check
        // distinguish All Application Packages from All Restricted Application Packages.
        let descriptor = OwnedSecurityDescriptor::from_sddl(
            "O:SYG:SYD:(A;;0x3;;;WD)(A;;0x1;;;AC)(A;;0x2;;;S-1-15-2-2)",
        )
        .context("create AppContainer mode probe security descriptor")?;
        let mapping = GENERIC_MAPPING::default();
        let mut privileges = vec![PRIVILEGE_SET::default()];
        let mut granted = 0;
        let mut allowed = 0;
        loop {
            let capacity = u32::try_from(mem::size_of_val(privileges.as_slice()))?;
            let mut size = capacity;
            if unsafe {
                AccessCheck(
                    descriptor.as_ptr(),
                    token.as_raw_handle(),
                    MAXIMUM_ALLOWED,
                    &raw const mapping,
                    privileges.as_mut_ptr(),
                    &raw mut size,
                    &raw mut granted,
                    &raw mut allowed,
                )
            } != 0
            {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER.cast_signed())
                || size <= capacity
            {
                return Err(error).context("check AppContainer probe token access");
            }
            privileges.resize(
                usize::try_from(size)?.div_ceil(mem::size_of::<PRIVILEGE_SET>()),
                PRIVILEGE_SET::default(),
            );
        }
        if allowed == 0 {
            bail!("AppContainer probe token was denied both test rights");
        }
        match granted & PROBE_ACCESS {
            APP_CONTAINER_ACCESS | PROBE_ACCESS => Ok(AppContainerMode::Standard),
            LPAC_ACCESS => Ok(AppContainerMode::Lpac),
            access => bail!("AppContainer probe token has unexpected access mask {access:#x}"),
        }
    }
}

struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        unsafe {
            RevertToSelf();
        }
    }
}

impl ProbeToken {
    fn impersonate(&self) -> Result<ImpersonationGuard> {
        if unsafe { ImpersonateLoggedOnUser(self.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error()).context("impersonate AppContainer probe token");
        }
        Ok(ImpersonationGuard)
    }

    fn spawn_probe(self, mode: AppContainerMode) -> Result<()> {
        std::thread::Builder::new()
            .name("landstrip-null-probe".to_owned())
            .spawn(move || {
                let token_mode = AppContainerMode::try_from(&self)?;
                if token_mode != mode {
                    bail!("probe token does not have the requested AppContainer mode");
                }
                let _impersonation = self.impersonate()?;
                null_device::probe()?;
                LookupRoots::discover().probe()
            })
            .context("spawn AppContainer probe thread")?
            .join()
            .map_err(|_| anyhow!("AppContainer probe thread panicked"))?
    }
}
