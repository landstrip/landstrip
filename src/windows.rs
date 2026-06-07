// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox backend using LPAC `AppContainer`.

use crate::error::{Error, Result};
use crate::policy::{AccessPolicy, ReadAccess, UnixSocketAccess};
use std::collections::hash_map::DefaultHasher;
use std::ffi::{OsStr, OsString, c_void};
use std::hash::{Hash, Hasher};
use std::iter;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, LocalFree,
    WAIT_FAILED,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, FreeSid, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTUPINFOEXW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

const INFINITE: u32 = 0xffff_ffff;

pub(crate) fn execute(
    policy: &AccessPolicy,
    policy_base: &Path,
    command: &OsStr,
    args: &[OsString],
) -> Result<()> {
    reject_unsupported_policy(policy)?;

    let moniker = appcontainer_moniker(policy_base, command, policy);
    let mut profile = AppContainerProfile::new(&moniker)?;
    grant_policy_access(policy, profile.sid())?;

    let exit_code = create_process_in_appcontainer(profile.sid(), command, args)?;
    std::process::exit(i32::from_ne_bytes(exit_code.to_ne_bytes()));
}

fn reject_unsupported_policy(policy: &AccessPolicy) -> Result<()> {
    if matches!(policy.read_access, ReadAccess::Unrestricted) {
        return Err(Error::Capability {
            message: "read access must use explicit allow roots".to_owned(),
        });
    }

    let network = &policy.network_access;

    if network.is_unrestricted() {
        return Err(Error::Capability {
            message: "unrestricted network is not supported yet".to_owned(),
        });
    }

    if network.local_tcp_bind || !network.connect_tcp_ports.is_empty() {
        return Err(Error::Capability {
            message: "TCP policies are not supported yet".to_owned(),
        });
    }

    if !matches!(&network.unix_socket_access, UnixSocketAccess::AllowPaths(paths) if paths.is_empty())
    {
        return Err(Error::Capability {
            message: "Unix socket policies are not supported".to_owned(),
        });
    }

    Ok(())
}

fn appcontainer_moniker(policy_base: &Path, command: &OsStr, policy: &AccessPolicy) -> String {
    let mut hasher = DefaultHasher::new();
    policy_base.hash(&mut hasher);
    PathBuf::from(command).hash(&mut hasher);
    policy.hash(&mut hasher);
    format!("landstrip.{:016x}", hasher.finish())
}

struct AppContainerProfile {
    sid: PSID,
}

impl AppContainerProfile {
    fn new(moniker: &str) -> Result<Self> {
        let moniker = wide_string(moniker);
        let display = wide_string("landstrip");
        let description = wide_string("landstrip sandbox");
        let mut sid = ptr::null_mut();
        let hr = unsafe {
            CreateAppContainerProfile(
                moniker.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                ptr::null_mut(),
                0,
                &mut sid,
            )
        };

        if hr == 0 {
            return Ok(Self { sid });
        }

        if hresult_value(hr) & 0xffff != ERROR_ALREADY_EXISTS {
            let code = hresult_value(hr);
            return Err(Error::system(format!(
                "CreateAppContainerProfile failed: HRESULT {code}"
            )));
        }

        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(moniker.as_ptr(), &mut sid) };
        if hr != 0 {
            let code = hresult_value(hr);
            return Err(Error::system(format!(
                "DeriveAppContainerSidFromAppContainerName failed: HRESULT {code}"
            )));
        }

        Ok(Self { sid })
    }

    fn sid(&mut self) -> PSID {
        self.sid
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if !self.sid.is_null() {
            unsafe { FreeSid(self.sid) };
        }
    }
}

fn grant_policy_access(policy: &AccessPolicy, sid: PSID) -> Result<()> {
    let read_roots = match &policy.read_access {
        ReadAccess::AllowRoots(read_roots) => read_roots,
        ReadAccess::Unrestricted => {
            return Err(Error::Capability {
                message: "read access must use explicit allow roots".to_owned(),
            });
        }
    };

    for path in read_roots {
        grant_path_access(path, sid, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)?;
    }

    for path in &policy.write_roots {
        grant_path_access(
            path,
            sid,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
        )?;
    }

    Ok(())
}

fn grant_path_access(path: &Path, sid: PSID, access: u32) -> Result<()> {
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let mut old_dacl: *mut ACL = ptr::null_mut();
    let mut security_descriptor = ptr::null_mut();

    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return Err(Error::system(format!(
            "GetNamedSecurityInfoW failed: status {status}"
        )));
    }

    let explicit_access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let mut new_dacl: *mut ACL = ptr::null_mut();

    let status = unsafe { SetEntriesInAclW(1, &explicit_access, old_dacl, &mut new_dacl) };
    if status != 0 {
        unsafe { LocalFree(security_descriptor) };
        return Err(Error::system(format!(
            "SetEntriesInAclW failed: status {status}"
        )));
    }

    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr().cast_mut(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_dacl,
            ptr::null_mut(),
        )
    };

    unsafe {
        LocalFree(new_dacl.cast());
        LocalFree(security_descriptor);
    }

    if status != 0 {
        return Err(Error::system(format!(
            "SetNamedSecurityInfoW failed: status {status}"
        )));
    }

    Ok(())
}

fn create_process_in_appcontainer(sid: PSID, command: &OsStr, args: &[OsString]) -> Result<u32> {
    let command_line = command_line(command, args)?;
    let mut command_line = wide_string(&command_line);
    let mut startup_info = unsafe { mem::zeroed::<STARTUPINFOEXW>() };
    startup_info.StartupInfo.cb = u32::try_from(mem::size_of::<STARTUPINFOEXW>())
        .map_err(|_| Error::system("startup info size exceeds u32"))?;

    let mut attribute_list = ProcThreadAttributeList::new(2)?;
    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: ptr::null_mut::<SID_AND_ATTRIBUTES>(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut all_packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

    update_attribute(
        attribute_list.as_mut_ptr(),
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        (&raw mut capabilities).cast(),
        mem::size_of::<SECURITY_CAPABILITIES>(),
    )?;
    update_attribute(
        attribute_list.as_mut_ptr(),
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
        (&raw mut all_packages_policy).cast(),
        mem::size_of::<u32>(),
    )?;

    startup_info.lpAttributeList = attribute_list.as_mut_ptr();
    let mut process_info = unsafe { mem::zeroed::<PROCESS_INFORMATION>() };
    let created = unsafe {
        CreateProcessW(
            ptr::null(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null(),
            ptr::null(),
            (&raw mut startup_info).cast(),
            &mut process_info,
        )
    };

    if created == 0 {
        let code = unsafe { GetLastError() };
        return Err(Error::command(
            Some(command.to_os_string()),
            format!("CreateProcessW failed: error {code}"),
        ));
    }

    let process = Handle(process_info.hProcess);
    let thread = Handle(process_info.hThread);
    let wait = unsafe { WaitForSingleObject(process.0, INFINITE) };
    if wait == WAIT_FAILED {
        let code = unsafe { GetLastError() };
        return Err(Error::system(format!(
            "WaitForSingleObject failed: error {code}"
        )));
    }

    let mut exit_code = 0;
    let ok = unsafe { GetExitCodeProcess(process.0, &mut exit_code) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(Error::system(format!(
            "GetExitCodeProcess failed: error {code}"
        )));
    }

    drop(thread);
    drop(process);
    Ok(exit_code)
}

fn update_attribute(
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    attribute: usize,
    value: *mut c_void,
    size: usize,
) -> Result<()> {
    let ok = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            attribute,
            value,
            size,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(Error::system(format!(
            "UpdateProcThreadAttribute failed: error {code}"
        )));
    }
    Ok(())
}

struct ProcThreadAttributeList {
    storage: Vec<u8>,
}

impl ProcThreadAttributeList {
    fn new(count: u32) -> Result<Self> {
        let mut size = 0;
        let ok = unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut size) };
        let code = unsafe { GetLastError() };
        if ok != 0 || code != ERROR_INSUFFICIENT_BUFFER {
            return Err(Error::system(format!(
                "InitializeProcThreadAttributeList failed: error {code}"
            )));
        }

        let mut storage = vec![0_u8; size];
        let list = storage.as_mut_ptr().cast();
        let ok = unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut size) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(Error::system(format!(
                "InitializeProcThreadAttributeList failed: error {code}"
            )));
        }

        Ok(Self { storage })
    }

    fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.as_mut_ptr()) };
    }
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn command_line(command: &OsStr, args: &[OsString]) -> Result<String> {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(
        quote_command_arg(command)
            .map_err(|message| Error::command(Some(command.to_os_string()), message))?,
    );
    for arg in args {
        parts.push(
            quote_command_arg(arg)
                .map_err(|message| Error::command(Some(command.to_os_string()), message))?,
        );
    }
    Ok(parts.join(" "))
}

fn quote_command_arg(arg: &OsStr) -> std::result::Result<String, &'static str> {
    let arg = arg.to_string_lossy();
    if arg.contains('\0') {
        return Err("command line contains an interior NUL byte");
    }

    if arg.is_empty() {
        return Ok("\"\"".to_owned());
    }

    if !arg
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\"'))
    {
        return Ok(arg.into_owned());
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(iter::repeat('\\').take(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(iter::repeat('\\').take(backslashes));
                quoted.push(ch);
                backslashes = 0;
            }
        }
    }
    quoted.extend(iter::repeat('\\').take(backslashes * 2));
    quoted.push('"');
    Ok(quoted)
}

fn wide_string(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(iter::once(0))
        .collect()
}

fn hresult_value(hr: i32) -> u32 {
    u32::from_ne_bytes(hr.to_ne_bytes())
}
