// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox platform using LPAC `AppContainer`.

use crate::policy::{AccessPolicy, ReadAccess, UnixSocketAccess};
use crate::trap::{Result, Trap};
use crate::trap_fd::TrapFd;
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
    ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, FreeSid, PSID, SECURITY_CAPABILITIES,
    SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
    WinCapabilityPrivateNetworkClientServerSid,
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
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

const NETWORK_CAPABILITY_SIDS: [WELL_KNOWN_SID_TYPE; 3] = [
    WinCapabilityInternetClientSid,
    WinCapabilityInternetClientServerSid,
    WinCapabilityPrivateNetworkClientServerSid,
];

pub(crate) fn execute(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    _trap_fd: TrapFd,
) -> Result<()> {
    reject_unsupported_policy(policy)?;

    let moniker = appcontainer_moniker(tool, policy);
    let profile = AppContainerProfile::new(&moniker)?;
    grant_policy_access(policy, profile.sid())?;

    let grant_network = policy.network_access.is_unrestricted();
    let exit_code = create_process_in_appcontainer(profile.sid(), tool, args, grant_network)?;
    std::process::exit(i32::from_ne_bytes(exit_code.to_ne_bytes()));
}

fn reject_unsupported_policy(policy: &AccessPolicy) -> Result<()> {
    if matches!(policy.read_access, ReadAccess::Unrestricted) {
        return Err(Trap::internal().with_detail("feature", "read access"));
    }

    let network = &policy.network_access;

    if network.is_unrestricted() {
        return Ok(());
    }

    if network.local_tcp_bind || !network.connect_tcp_ports.is_empty() {
        return Err(Trap::internal().with_detail("feature", "TCP policies"));
    }

    if !matches!(&network.unix_socket_access, UnixSocketAccess::AllowPaths(paths) if paths.is_empty())
    {
        return Err(Trap::internal().with_detail("feature", "Unix socket policies"));
    }

    Ok(())
}

fn appcontainer_moniker(tool: &OsStr, policy: &AccessPolicy) -> String {
    let mut hasher = DefaultHasher::new();
    PathBuf::from(tool).hash(&mut hasher);
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
            return Err(Trap::internal()
                .with_detail("api", "CreateAppContainerProfile")
                .with_detail("code", code.to_string()));
        }

        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(moniker.as_ptr(), &mut sid) };
        if hr != 0 {
            let code = hresult_value(hr);
            return Err(Trap::internal()
                .with_detail("api", "DeriveAppContainerSidFromAppContainerName")
                .with_detail("code", code.to_string()));
        }

        Ok(Self { sid })
    }

    fn sid(&self) -> PSID {
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
            return Err(Trap::internal().with_detail("feature", "read access"));
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
        return Err(Trap::internal()
            .with_detail("api", "GetNamedSecurityInfoW")
            .with_detail("code", status.to_string()));
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
        return Err(Trap::internal()
            .with_detail("api", "SetEntriesInAclW")
            .with_detail("code", status.to_string()));
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
        return Err(Trap::internal()
            .with_detail("api", "SetNamedSecurityInfoW")
            .with_detail("code", status.to_string()));
    }

    Ok(())
}

fn create_process_in_appcontainer(
    sid: PSID,
    tool: &OsStr,
    args: &[OsString],
    grant_network: bool,
) -> Result<u32> {
    let command_line = command_line(tool, args)?;
    let mut command_line = wide_string(&command_line);
    let mut startup_info = unsafe { mem::zeroed::<STARTUPINFOEXW>() };
    startup_info.StartupInfo.cb =
        u32::try_from(mem::size_of::<STARTUPINFOEXW>()).map_err(|_| Trap::internal())?;

    let mut attribute_list = ProcThreadAttributeList::new(2)?;
    let mut network_capabilities = NetworkCapabilities::new(grant_network)?;
    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: network_capabilities.as_mut_ptr(),
        CapabilityCount: network_capabilities.count(),
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
        return Err(Trap::Launch(
            tool.to_string_lossy().into_owned(),
            format!("CreateProcessW failed: {code}"),
        ));
    }

    let process = Handle(process_info.hProcess);
    let thread = Handle(process_info.hThread);
    let wait = unsafe { WaitForSingleObject(process.0, INFINITE) };
    if wait == WAIT_FAILED {
        let code = unsafe { GetLastError() };
        return Err(Trap::internal()
            .with_detail("api", "WaitForSingleObject")
            .with_detail("code", code.to_string()));
    }

    let mut exit_code = 0;
    let ok = unsafe { GetExitCodeProcess(process.0, &mut exit_code) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(Trap::internal()
            .with_detail("api", "GetExitCodeProcess")
            .with_detail("code", code.to_string()));
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
        return Err(Trap::internal()
            .with_detail("api", "UpdateProcThreadAttribute")
            .with_detail("code", code.to_string()));
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
            return Err(Trap::internal()
                .with_detail("api", "InitializeProcThreadAttributeList")
                .with_detail("code", code.to_string()));
        }

        let mut storage = vec![0_u8; size];
        let list = storage.as_mut_ptr().cast();
        let ok = unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut size) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(Trap::internal()
                .with_detail("api", "InitializeProcThreadAttributeList")
                .with_detail("code", code.to_string()));
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

struct NetworkCapabilities {
    /// Backing storage for the capability SIDs referenced by `entries`.
    #[allow(dead_code)]
    sids: Vec<[u8; SECURITY_MAX_SID_SIZE as usize]>,
    entries: Vec<SID_AND_ATTRIBUTES>,
}

impl NetworkCapabilities {
    fn new(grant_network: bool) -> Result<Self> {
        if !grant_network {
            return Ok(Self {
                sids: Vec::new(),
                entries: Vec::new(),
            });
        }

        let mut sids = Vec::with_capacity(NETWORK_CAPABILITY_SIDS.len());
        for kind in NETWORK_CAPABILITY_SIDS {
            let mut sid = [0_u8; SECURITY_MAX_SID_SIZE as usize];
            let mut size = SECURITY_MAX_SID_SIZE;
            let ok = unsafe {
                CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &mut size)
            };
            if ok == 0 {
                let code = unsafe { GetLastError() };
                return Err(Trap::internal()
                    .with_detail("api", "CreateWellKnownSid")
                    .with_detail("code", code.to_string()));
            }
            sids.push(sid);
        }

        let entries = sids
            .iter_mut()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid.as_mut_ptr().cast(),
                Attributes: SE_GROUP_ENABLED,
            })
            .collect();

        Ok(Self { sids, entries })
    }

    fn as_mut_ptr(&mut self) -> *mut SID_AND_ATTRIBUTES {
        if self.entries.is_empty() {
            ptr::null_mut()
        } else {
            self.entries.as_mut_ptr()
        }
    }

    fn count(&self) -> u32 {
        u32::try_from(self.entries.len()).unwrap_or(0)
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

fn command_line(tool: &OsStr, args: &[OsString]) -> Result<String> {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(quote_command_arg(tool).map_err(|message| tool_encoding_error(tool, message))?);
    for arg in args {
        parts.push(quote_command_arg(arg).map_err(|message| tool_encoding_error(tool, message))?);
    }
    Ok(parts.join(" "))
}

fn tool_encoding_error(tool: &OsStr, message: &str) -> Trap {
    Trap::internal()
        .with_detail("program", tool.to_string_lossy())
        .with_detail("source", message)
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
