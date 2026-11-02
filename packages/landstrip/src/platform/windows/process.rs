// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::win32::{OsStatus, ToWideNul};
use crate::error::{Error, Mechanism};
use anyhow::{Context, Result, bail};
use std::env;
use std::ffi::OsStr;
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE, WAIT_FAILED};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, SHELLEXECUTEINFOW_0,
    ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub(super) struct SandboxJob {
    handle: OwnedHandle,
}

impl SandboxJob {
    pub(super) fn new(mechanism: Mechanism) -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(Error::sandbox_setup(mechanism, io::Error::last_os_error()).into());
        }

        let job = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(handle) },
        };
        let mut limits = unsafe { mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let size = u32::try_from(mem::size_of_val(&limits)).map_err(|_| Error::IntegerTooLarge)?;
        let ok = unsafe {
            SetInformationJobObject(
                job.handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size,
            )
        };
        if ok == 0 {
            return Err(Error::sandbox_setup(mechanism, io::Error::last_os_error()).into());
        }

        Ok(job)
    }

    pub(super) fn as_raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }
}

pub(super) struct CommandLine(Vec<u16>);

impl CommandLine {
    pub(super) fn encode<'a>(
        program: &OsStr,
        args: impl IntoIterator<Item = &'a OsStr>,
    ) -> std::result::Result<Self, &'static str> {
        let mut out = Vec::new();
        Self::push_quoted(&mut out, program)?;
        for arg in args {
            out.push(u16::from(b' '));
            Self::push_quoted(&mut out, arg)?;
        }
        out.push(0);
        Ok(Self(out))
    }

    pub(super) fn as_mut_slice(&mut self) -> &mut [u16] {
        &mut self.0
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut u16 {
        self.0.as_mut_ptr()
    }

    fn push_quoted(out: &mut Vec<u16>, arg: &OsStr) -> std::result::Result<(), &'static str> {
        let mut empty = true;
        let mut needs_quotes = false;
        for unit in arg.encode_wide() {
            if unit == 0 {
                return Err("command line contains an interior NUL");
            }
            empty = false;
            if matches!(unit, 0x20 | 0x09 | 0x0a | 0x22) {
                needs_quotes = true;
            }
        }
        if empty {
            out.extend_from_slice(&[u16::from(b'"'), u16::from(b'"')]);
            return Ok(());
        }
        if !needs_quotes {
            out.extend(arg.encode_wide());
            return Ok(());
        }

        out.push(u16::from(b'"'));
        let mut backslashes = 0;
        for unit in arg.encode_wide() {
            match unit {
                0x5c => backslashes += 1,
                0x22 => {
                    out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
                    out.push(u16::from(b'"'));
                    backslashes = 0;
                }
                _ => {
                    out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
                    out.push(unit);
                    backslashes = 0;
                }
            }
        }
        out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
        out.push(u16::from(b'"'));
        Ok(())
    }
}

pub(super) enum BreakawayError {
    IncompatibleJob(io::Error),
    JobQuery(io::Error),
    Os(io::Error),
}

impl BreakawayError {
    pub(super) fn into_io(self) -> io::Error {
        match self {
            Self::IncompatibleJob(error) | Self::JobQuery(error) | Self::Os(error) => error,
        }
    }
}

pub(super) struct SpawnedProcess {
    pub(super) process: OwnedHandle,
    pub(super) thread: OwnedHandle,
}

impl SpawnedProcess {
    pub(super) unsafe fn from_raw(info: PROCESS_INFORMATION) -> Self {
        Self {
            process: unsafe { OwnedHandle::from_raw_handle(info.hProcess) },
            thread: unsafe { OwnedHandle::from_raw_handle(info.hThread) },
        }
    }

    pub(super) fn std_startup_info() -> Result<STARTUPINFOW> {
        let mut startup = unsafe { mem::zeroed::<STARTUPINFOW>() };
        startup.cb = u32::try_from(mem::size_of::<STARTUPINFOW>())?;
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        startup.hStdOutput = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        startup.hStdError = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        Ok(startup)
    }

    pub(super) fn create_extended(
        application: Option<&[u16]>,
        command_line: Option<&mut [u16]>,
        inherit_handles: bool,
        creation_flags: u32,
        cwd: Option<&[u16]>,
        startup_info: &mut STARTUPINFOEXW,
    ) -> std::result::Result<Self, BreakawayError> {
        let app_ptr = application.map_or(ptr::null(), <[u16]>::as_ptr);
        let command_ptr = command_line.map_or(ptr::null_mut(), <[u16]>::as_mut_ptr);
        let cwd_ptr = cwd.map_or(ptr::null(), <[u16]>::as_ptr);
        let inherit = i32::from(inherit_handles);
        let mut spawn = |flags: u32| -> io::Result<Self> {
            let mut info = unsafe { mem::zeroed::<PROCESS_INFORMATION>() };
            let created = unsafe {
                CreateProcessW(
                    app_ptr,
                    command_ptr,
                    ptr::null(),
                    ptr::null(),
                    inherit,
                    flags,
                    ptr::null(),
                    cwd_ptr,
                    (&raw mut *startup_info).cast(),
                    &raw mut info,
                )
            };
            if created == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { Self::from_raw(info) })
        };

        let flags = EXTENDED_STARTUPINFO_PRESENT | creation_flags;
        match spawn(flags) {
            Ok(process) => Ok(process),
            Err(source) if OsStatus::code(&source) == Some(ERROR_ACCESS_DENIED) => {
                match Self::current_in_job() {
                    Ok(true) => spawn(flags | CREATE_BREAKAWAY_FROM_JOB).map_err(|retry| {
                        if OsStatus::code(&retry) == Some(ERROR_ACCESS_DENIED) {
                            BreakawayError::IncompatibleJob(retry)
                        } else {
                            BreakawayError::Os(retry)
                        }
                    }),
                    Ok(false) => Err(BreakawayError::Os(source)),
                    Err(query_error) => Err(BreakawayError::JobQuery(query_error)),
                }
            }
            Err(source) => Err(BreakawayError::Os(source)),
        }
    }

    pub(super) fn assign_to_job(&self, job: &SandboxJob, mechanism: Mechanism) -> Result<()> {
        if unsafe { AssignProcessToJobObject(job.as_raw(), self.process.as_raw_handle()) } == 0 {
            let error = io::Error::last_os_error();
            unsafe {
                TerminateProcess(self.process.as_raw_handle(), 1);
            }
            return Err(Error::sandbox_setup(
                mechanism,
                format!("AssignProcessToJobObject: {error}"),
            )
            .into());
        }
        Ok(())
    }

    pub(super) fn resume_and_wait(self, mechanism: Mechanism) -> Result<u32> {
        if unsafe { ResumeThread(self.thread.as_raw_handle()) } == u32::MAX {
            let error = io::Error::last_os_error();
            unsafe {
                TerminateProcess(self.process.as_raw_handle(), 1);
            }
            return Err(Error::sandbox_setup(mechanism, format!("ResumeThread: {error}")).into());
        }
        drop(self.thread);
        Self::wait_exit(&self.process)
    }

    pub(super) fn wait_exit(process: &impl AsRawHandle) -> Result<u32> {
        let handle = process.as_raw_handle();
        if unsafe { WaitForSingleObject(handle, INFINITE) } == WAIT_FAILED {
            return Err(Error::supervise(io::Error::last_os_error()).into());
        }

        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(handle, &raw mut exit_code) } == 0 {
            return Err(Error::supervise(io::Error::last_os_error()).into());
        }

        Ok(exit_code)
    }

    pub(super) fn elevate(parameters: &str) -> Result<()> {
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
        let process = unsafe { OwnedHandle::from_raw_handle(execute.hProcess) };
        let exit_code = Self::wait_exit(&process).context("wait for elevated landstrip")?;
        if exit_code != 0 {
            bail!("elevated landstrip exited with status {exit_code}");
        }
        Ok(())
    }

    fn current_in_job() -> io::Result<bool> {
        let mut in_job = 0;
        if unsafe { IsProcessInJob(GetCurrentProcess(), ptr::null_mut(), &raw mut in_job) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(in_job != 0)
    }
}
