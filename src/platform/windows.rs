// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox platform using `AppContainer`.

use crate::config::AppContainerMode;
use crate::engine::error::{Cause, Error as LandstripError, Mechanism};
use crate::engine::policy::{AccessPolicy, ReadAccess};
use crate::engine::trap_fd::TrapFd;
use anyhow::Result;
use std::collections::hash_map::DefaultHasher;
use std::ffi::{OsStr, OsString, c_void};
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io;
use std::iter;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_ABANDONED,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::WindowsFirewall::{
    NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig,
};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, REVOKE_ACCESS,
    SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, FreeSid,
    InitializeSecurityDescriptor, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES,
    SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, SetFileSecurityW, SetSecurityDescriptorDacl,
    WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
    WinCapabilityPrivateNetworkClientServerSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, GetFileType, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapFree};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CreateMutexW, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, PROCESS_SYNCHRONIZE,
    ReleaseMutex, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

const INFINITE: u32 = 0xffff_ffff;
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
/// The `HRESULT` facility that wraps a Win32 error code.
const FACILITY_WIN32: u32 = 7;
const LOOPBACK_MUTEX_NAME: &str = "Global\\landstrip-loopback-config";
const LOOPBACK_PROFILE_PREFIX: &str = "landstrip.loopback.";
static NEXT_PROFILE_ID: AtomicU64 = AtomicU64::new(0);

const NETWORK_CAPABILITY_SIDS: [WELL_KNOWN_SID_TYPE; 3] = [
    WinCapabilityInternetClientSid,
    WinCapabilityInternetClientServerSid,
    WinCapabilityPrivateNetworkClientServerSid,
];

/// An `AppContainer` landstrip could not create, grant, or launch into.
fn setup_failed(source: impl Into<Cause>) -> LandstripError {
    LandstripError::SandboxSetupFailed {
        mechanism: Mechanism::Appcontainer,
        source: source.into(),
    }
}

/// A Win32 status code, as reported by the ACL APIs that return one instead of
/// setting the last error.
fn win32_error(status: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::from_ne_bytes(status.to_ne_bytes()))
}

/// The Win32 error an `HRESULT` carries, when it carries one at all.
fn hresult_win32(hr: i32) -> Option<u16> {
    let hresult = hresult_value(hr);

    ((hresult >> 16) & 0x7ff == FACILITY_WIN32).then_some((hresult & 0xffff) as u16)
}

/// What an `HRESULT` failure means. The profile APIs report an `HRESULT`, not a
/// Win32 error code, and `io::Error` on Windows carries Win32 codes: handing it
/// the `HRESULT` verbatim (`0x800700b7`, say) makes it render a message for an
/// error nobody reported. Unwrap the Win32 error where the `HRESULT` wraps one,
/// and report the raw value where it does not.
fn hresult_cause(hr: i32) -> Cause {
    match hresult_win32(hr).map(|code| io::Error::from_raw_os_error(i32::from(code))) {
        Some(error) => error.into(),
        None => format!("HRESULT 0x{:08x}", hresult_value(hr)).into(),
    }
}

pub(crate) fn execute(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    _trap_fd: &TrapFd,
) -> Result<()> {
    let moniker = appcontainer_moniker(tool, policy, policy.allow_windows_loopback);
    let profile = AppContainerProfile::new(&moniker, !policy.allow_windows_loopback)?;
    let loopback = if policy.allow_windows_loopback {
        log::warn!("windows: AppContainer loopback exemption permits all local loopback services");
        Some(LoopbackExemption::new(&moniker, profile.sid())?)
    } else {
        None
    };
    let grants = grant_policy_access(policy, profile.sid())?;

    let grant_network = policy.network_access.is_unrestricted();
    if !grant_network && !policy.network_access.connect_tcp_ports.is_empty() {
        log::warn!(
            "windows: per-port TCP filtering is unavailable; running with no network access"
        );
    }
    let exit_code = create_process_in_appcontainer(
        profile.sid(),
        tool,
        args,
        grant_network,
        policy.app_container_mode,
    );

    // The tool has exited, so the container's access to the policy roots is
    // released here. std::process::exit runs no destructors, and this is the
    // path every successful run takes: leaving it to `Drop` leaves the
    // container's ACEs on the user's files and its profile on the machine.
    // Grants go first — revoking an ACE needs the SID the profile owns.
    drop(grants);
    drop(loopback);
    drop(profile);

    std::process::exit(i32::from_ne_bytes(exit_code?.to_ne_bytes()));
}

fn appcontainer_moniker(tool: &OsStr, policy: &AccessPolicy, loopback: bool) -> String {
    let mut hasher = DefaultHasher::new();
    PathBuf::from(tool).hash(&mut hasher);
    policy.hash(&mut hasher);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    NEXT_PROFILE_ID
        .fetch_add(1, Ordering::Relaxed)
        .hash(&mut hasher);
    let profile_id = hasher.finish();
    if loopback {
        format!(
            "{LOOPBACK_PROFILE_PREFIX}{:x}.{profile_id:016x}",
            std::process::id()
        )
    } else {
        format!("landstrip.{:x}.{profile_id:016x}", std::process::id())
    }
}

struct AppContainerProfile {
    sid: PSID,
    moniker: Vec<u16>,
    delete_on_drop: bool,
}

impl AppContainerProfile {
    fn new(moniker: &str, delete_on_drop: bool) -> Result<Self> {
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
            return Ok(Self {
                sid,
                moniker,
                delete_on_drop,
            });
        }

        if hresult_win32(hr).map(u32::from) != Some(ERROR_ALREADY_EXISTS) {
            return Err(setup_failed(hresult_cause(hr)).into());
        }

        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(moniker.as_ptr(), &mut sid) };
        if hr != 0 {
            return Err(setup_failed(hresult_cause(hr)).into());
        }

        Ok(Self {
            sid,
            moniker,
            delete_on_drop,
        })
    }

    fn sid(&self) -> PSID {
        self.sid
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if self.delete_on_drop && !self.moniker.is_empty() {
            unsafe { DeleteAppContainerProfile(self.moniker.as_ptr()) };
        }
        if !self.sid.is_null() {
            unsafe { FreeSid(self.sid) };
        }
    }
}

struct LoopbackExemption {
    marker: PathBuf,
    moniker: String,
    sid: PSID,
    active: bool,
}

impl LoopbackExemption {
    fn new(moniker: &str, sid: PSID) -> Result<Self> {
        let _mutex = LoopbackMutex::lock()?;
        let state_dir = dirs::data_local_dir()
            .ok_or_else(|| setup_failed("local data directory is unavailable"))?
            .join("landstrip")
            .join("loopback");
        fs::create_dir_all(&state_dir).map_err(setup_failed)?;
        cleanup_stale_loopback_profiles(&state_dir)?;

        let marker = state_dir.join(moniker);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
            .map_err(setup_failed)?;
        update_loopback_config(Some(sid), &[])?;

        Ok(Self {
            marker,
            moniker: moniker.to_owned(),
            sid,
            active: true,
        })
    }

    fn remove(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        let _mutex = LoopbackMutex::lock()?;
        update_loopback_config(None, &[self.sid])?;
        delete_appcontainer_profile(&self.moniker)?;
        remove_marker(&self.marker)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for LoopbackExemption {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            log::warn!("windows: could not remove AppContainer loopback exemption: {error:#}");
        }
    }
}

struct LoopbackMutex {
    handle: Handle,
}

impl LoopbackMutex {
    fn lock() -> Result<Self> {
        let name = wide_string(LOOPBACK_MUTEX_NAME);
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(setup_failed(io::Error::last_os_error()).into());
        }
        let mutex = Self {
            handle: Handle(handle),
        };
        match unsafe { WaitForSingleObject(mutex.handle.0, INFINITE) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(mutex),
            WAIT_FAILED => Err(setup_failed(io::Error::last_os_error()).into()),
            status => Err(setup_failed(format!("unexpected mutex wait status {status}")).into()),
        }
    }
}

impl Drop for LoopbackMutex {
    fn drop(&mut self) {
        unsafe { ReleaseMutex(self.handle.0) };
    }
}

struct StaleLoopbackProfile {
    marker: PathBuf,
    moniker: String,
    sid: OwnedSid,
}

fn cleanup_stale_loopback_profiles(state_dir: &Path) -> Result<()> {
    let mut stale = Vec::new();
    for entry in fs::read_dir(state_dir).map_err(setup_failed)? {
        let entry = entry.map_err(setup_failed)?;
        let Some(moniker) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(pid) = loopback_profile_pid(&moniker) else {
            continue;
        };
        if process_is_running(pid) {
            continue;
        }
        match derive_appcontainer_sid(&moniker) {
            Ok(Some(sid)) => stale.push(StaleLoopbackProfile {
                marker: entry.path(),
                moniker,
                sid,
            }),
            Ok(None) => remove_marker(&entry.path())?,
            Err(error) => {
                log::warn!("windows: could not inspect stale loopback profile: {error:#}");
            }
        }
    }

    if stale.is_empty() {
        return Ok(());
    }
    let stale_sids = stale
        .iter()
        .map(|profile| profile.sid.0)
        .collect::<Vec<_>>();
    update_loopback_config(None, &stale_sids)?;
    for profile in stale {
        if let Err(error) = delete_appcontainer_profile(&profile.moniker) {
            log::warn!("windows: could not delete stale loopback profile: {error:#}");
            continue;
        }
        remove_marker(&profile.marker)?;
    }
    Ok(())
}

fn loopback_profile_pid(moniker: &str) -> Option<u32> {
    let suffix = moniker.strip_prefix(LOOPBACK_PROFILE_PREFIX)?;
    let (pid, _) = suffix.split_once('.')?;
    u32::from_str_radix(pid, 16).ok()
}

fn process_is_running(pid: u32) -> bool {
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
    }
    let process = Handle(handle);
    matches!(
        unsafe { WaitForSingleObject(process.0, 0) },
        WAIT_TIMEOUT | WAIT_FAILED
    )
}

fn derive_appcontainer_sid(moniker: &str) -> Result<Option<OwnedSid>> {
    let moniker = wide_string(moniker);
    let mut sid = ptr::null_mut();
    let hr = unsafe { DeriveAppContainerSidFromAppContainerName(moniker.as_ptr(), &mut sid) };
    if hresult_win32(hr).map(u32::from) == Some(ERROR_NOT_FOUND) {
        return Ok(None);
    }
    if hr != 0 {
        return Err(setup_failed(hresult_cause(hr)).into());
    }
    Ok(Some(OwnedSid(sid)))
}

fn delete_appcontainer_profile(moniker: &str) -> Result<()> {
    let moniker = wide_string(moniker);
    let hr = unsafe { DeleteAppContainerProfile(moniker.as_ptr()) };
    if hr != 0 {
        return Err(setup_failed(hresult_cause(hr)).into());
    }
    Ok(())
}

fn remove_marker(marker: &Path) -> Result<()> {
    match fs::remove_file(marker) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(setup_failed(error).into()),
    }
}

fn update_loopback_config(add: Option<PSID>, remove: &[PSID]) -> Result<()> {
    if add.is_none() && remove.is_empty() {
        return Ok(());
    }
    let config = LoopbackConfig::get()?;
    let mut entries = config
        .entries()
        .iter()
        .filter(|entry| {
            !remove
                .iter()
                .any(|sid| unsafe { EqualSid(entry.Sid, *sid) != 0 })
        })
        .copied()
        .collect::<Vec<_>>();
    if let Some(sid) = add {
        if !entries
            .iter()
            .any(|entry| unsafe { EqualSid(entry.Sid, sid) != 0 })
        {
            entries.push(SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: 0,
            });
        }
    }
    let count = u32::try_from(entries.len()).map_err(|_| LandstripError::IntegerTooLarge)?;
    let entries_ptr = if entries.is_empty() {
        ptr::null()
    } else {
        entries.as_ptr()
    };
    let status = unsafe { NetworkIsolationSetAppContainerConfig(count, entries_ptr) };
    if status != 0 {
        return Err(setup_failed(win32_error(status)).into());
    }
    Ok(())
}

struct OwnedSid(PSID);

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeSid(self.0) };
        }
    }
}

struct LoopbackConfig {
    count: u32,
    entries: *mut SID_AND_ATTRIBUTES,
}

impl LoopbackConfig {
    fn get() -> Result<Self> {
        let mut count = 0;
        let mut entries = ptr::null_mut();
        let status = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut entries) };
        if status != 0 {
            return Err(setup_failed(win32_error(status)).into());
        }
        Ok(Self { count, entries })
    }

    fn entries(&self) -> &[SID_AND_ATTRIBUTES] {
        if self.entries.is_null() {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.entries, self.count as usize) }
    }
}

impl Drop for LoopbackConfig {
    fn drop(&mut self) {
        let heap = unsafe { GetProcessHeap() };
        for entry in self.entries() {
            if !entry.Sid.is_null() {
                unsafe { HeapFree(heap, 0, entry.Sid.cast()) };
            }
        }
        if !self.entries.is_null() {
            unsafe { HeapFree(heap, 0, self.entries.cast()) };
        }
    }
}

fn grant_policy_access(policy: &AccessPolicy, sid: PSID) -> Result<GrantedAccess> {
    let read_roots = match &policy.read_access {
        ReadAccess::AllowRoots(read_roots) => read_roots,
        ReadAccess::Unrestricted => {
            return Err(LandstripError::PolicyUnrestrictedRead.into());
        }
    };
    let mut granted = GrantedAccess {
        sid,
        paths: Vec::new(),
    };

    for path in read_roots {
        grant_root_access(&mut granted, path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)?;
    }

    for path in &policy.write_roots {
        grant_root_access(
            &mut granted,
            path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
        )?;
    }

    Ok(granted)
}

fn grant_root_access(granted: &mut GrantedAccess, path: &Path, access: u32) -> Result<()> {
    // Ancestors grant only traversal plus metadata on each directory itself.
    // SetFileSecurityW keeps these ACEs local: SetNamedSecurityInfoW would
    // re-propagate every existing inheritable ACE through each ancestor tree.
    for ancestor in path.ancestors().skip(1) {
        grant_path_access(ancestor, granted.sid, FILE_GENERIC_EXECUTE, false, false)?;
        granted.paths.push(GrantedPath {
            path: ancestor.to_path_buf(),
            propagate: false,
        });
    }

    grant_path_access(path, granted.sid, access, true, true)?;
    granted.paths.push(GrantedPath {
        path: path.to_path_buf(),
        propagate: true,
    });
    Ok(())
}

struct GrantedPath {
    path: PathBuf,
    propagate: bool,
}

struct GrantedAccess {
    sid: PSID,
    paths: Vec<GrantedPath>,
}

impl Drop for GrantedAccess {
    fn drop(&mut self) {
        for granted in self.paths.iter().rev() {
            let _ = revoke_path_access(&granted.path, self.sid, granted.propagate);
        }
    }
}

fn grant_path_access(
    path: &Path,
    sid: PSID,
    access: u32,
    inherit: bool,
    propagate: bool,
) -> Result<()> {
    set_path_access(path, sid, access, GRANT_ACCESS, inherit, propagate)
}

fn revoke_path_access(path: &Path, sid: PSID, propagate: bool) -> Result<()> {
    set_path_access(path, sid, 0, REVOKE_ACCESS, false, propagate)
}

fn set_path_access(
    path: &Path,
    sid: PSID,
    access: u32,
    mode: ACCESS_MODE,
    inherit: bool,
    propagate: bool,
) -> Result<()> {
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
        return Err(setup_failed(win32_error(status)).into());
    }

    let explicit_access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: mode,
        grfInheritance: if inherit {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            0
        },
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
        return Err(setup_failed(win32_error(status)).into());
    }

    let result = apply_path_dacl(&path, new_dacl, propagate);
    unsafe {
        LocalFree(new_dacl.cast());
        LocalFree(security_descriptor);
    }
    result.map_err(setup_failed)?;

    Ok(())
}

fn apply_path_dacl(path: &[u16], dacl: *mut ACL, propagate: bool) -> io::Result<()> {
    if propagate {
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr().cast_mut(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(win32_error(status));
        }
        return Ok(());
    }

    let mut descriptor = unsafe { mem::zeroed::<SECURITY_DESCRIPTOR>() };
    let initialized = unsafe {
        InitializeSecurityDescriptor((&raw mut descriptor).cast(), SECURITY_DESCRIPTOR_REVISION)
    };
    if initialized == 0 {
        return Err(io::Error::last_os_error());
    }
    let dacl_set = unsafe { SetSecurityDescriptorDacl((&raw mut descriptor).cast(), 1, dacl, 0) };
    if dacl_set == 0 {
        return Err(io::Error::last_os_error());
    }
    let applied = unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            (&raw mut descriptor).cast(),
        )
    };
    if applied == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

struct SandboxJob {
    handle: Handle,
}

impl SandboxJob {
    fn new() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(setup_failed(io::Error::last_os_error()).into());
        }

        let job = Self {
            handle: Handle(handle),
        };
        let mut limits = unsafe { mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                job.handle.0,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                u32::try_from(mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(|_| LandstripError::IntegerTooLarge)?,
            )
        };
        if ok == 0 {
            return Err(setup_failed(io::Error::last_os_error()).into());
        }

        Ok(job)
    }

    fn as_raw(&self) -> HANDLE {
        self.handle.0
    }
}

struct StandardHandles {
    stdin: Handle,
    stdout: Handle,
    stderr: Handle,
}

impl StandardHandles {
    fn duplicate() -> Result<Self> {
        Ok(Self {
            stdin: inheritable_standard_handle(
                io::stdin().as_raw_handle().cast(),
                StandardHandleDirection::Input,
            )?,
            stdout: inheritable_standard_handle(
                io::stdout().as_raw_handle().cast(),
                StandardHandleDirection::Output,
            )?,
            stderr: inheritable_standard_handle(
                io::stderr().as_raw_handle().cast(),
                StandardHandleDirection::Output,
            )?,
        })
    }

    fn raw(&self) -> [HANDLE; 3] {
        [self.stdin.0, self.stdout.0, self.stderr.0]
    }
}

#[derive(Clone, Copy)]
enum StandardHandleDirection {
    Input,
    Output,
}

impl StandardHandleDirection {
    fn desired_access(self) -> u32 {
        match self {
            Self::Input => GENERIC_READ,
            Self::Output => GENERIC_WRITE,
        }
    }
}

fn inheritable_standard_handle(
    source: HANDLE,
    direction: StandardHandleDirection,
) -> Result<Handle> {
    if !is_real_handle_value(source as isize) || !is_io_file_type(unsafe { GetFileType(source) }) {
        return inheritable_null_handle(direction);
    }

    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = ptr::null_mut();
    let ok = unsafe {
        DuplicateHandle(
            process,
            source,
            process,
            &mut duplicate,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    let duplicate = Handle(duplicate);
    if !is_real_handle_value(duplicate.0 as isize)
        || !is_io_file_type(unsafe { GetFileType(duplicate.0) })
    {
        return inheritable_null_handle(direction);
    }

    Ok(duplicate)
}

fn inheritable_null_handle(direction: StandardHandleDirection) -> Result<Handle> {
    const NUL: [u16; 4] = [b'N' as u16, b'U' as u16, b'L' as u16, 0];

    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| LandstripError::IntegerTooLarge)?,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let handle = unsafe {
        CreateFileW(
            NUL.as_ptr(),
            direction.desired_access(),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security_attributes,
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    if !is_io_file_type(unsafe { GetFileType(handle) }) {
        unsafe { CloseHandle(handle) };
        return Err(setup_failed("NUL did not produce an I/O handle").into());
    }

    Ok(Handle(handle))
}

fn is_real_handle_value(value: isize) -> bool {
    value > 0
}

fn is_io_file_type(file_type: u32) -> bool {
    matches!(file_type, FILE_TYPE_CHAR | FILE_TYPE_DISK | FILE_TYPE_PIPE)
}

fn create_process_in_appcontainer(
    sid: PSID,
    tool: &OsStr,
    args: &[OsString],
    grant_network: bool,
    app_container_mode: AppContainerMode,
) -> Result<u32> {
    // Process mitigation policies not enabled:
    //
    // - `IMAGE_LOAD_PREFER_SYSTEM32` (required for MinGW/Cygwin DLL resolution)
    // - `PROCESS_WIN32K_SYSCALL_DISABLE` (required for GUI tooling)
    const MITIGATION_POLICY: u64 = (1u64 << 32)  // DisableExtensionPoints
        | (1u64 << 48)  // FontDisable
        | (1u64 << 52)  // ImageLoadNoRemote
        | (1u64 << 56); // ImageLoadNoLowLabel
    let command_line = command_line(tool, args)?;
    let mut startup_info = unsafe { mem::zeroed::<STARTUPINFOEXW>() };
    startup_info.StartupInfo.cb = u32::try_from(mem::size_of::<STARTUPINFOEXW>())
        .map_err(|_| LandstripError::IntegerTooLarge)?;

    let standard_handles = StandardHandles::duplicate()?;
    let mut inherited_handles = standard_handles.raw();
    startup_info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup_info.StartupInfo.hStdInput = inherited_handles[0];
    startup_info.StartupInfo.hStdOutput = inherited_handles[1];
    startup_info.StartupInfo.hStdError = inherited_handles[2];

    let job = SandboxJob::new()?;
    let mut job_handle = job.as_raw();
    let mut mitigation_policy = MITIGATION_POLICY;
    let attribute_count = if app_container_mode == AppContainerMode::Lpac {
        5
    } else {
        4
    };
    let mut attribute_list = ProcThreadAttributeList::new(attribute_count)?;
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
    if app_container_mode == AppContainerMode::Lpac {
        update_attribute(
            attribute_list.as_mut_ptr(),
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
            (&raw mut all_packages_policy).cast(),
            mem::size_of::<u32>(),
        )?;
    }
    update_attribute(
        attribute_list.as_mut_ptr(),
        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
        (&raw mut job_handle).cast(),
        mem::size_of::<HANDLE>(),
    )?;
    update_attribute(
        attribute_list.as_mut_ptr(),
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        inherited_handles.as_mut_ptr().cast(),
        mem::size_of_val(&inherited_handles),
    )?;
    if mitigation_policy != 0 {
        update_attribute(
            attribute_list.as_mut_ptr(),
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            (&raw mut mitigation_policy).cast(),
            mem::size_of::<u64>(),
        )?;
    }

    startup_info.lpAttributeList = attribute_list.as_mut_ptr();
    let process_info = launch_process(
        &command_line,
        tool,
        &mut startup_info,
        current_process_in_job()?,
    )?;
    drop(standard_handles);

    supervise_process(process_info)
}

fn current_process_in_job() -> Result<bool> {
    let mut in_job = 0;
    let ok = unsafe { IsProcessInJob(GetCurrentProcess(), ptr::null_mut(), &mut in_job) };
    if ok == 0 {
        return Err(setup_failed(io::Error::last_os_error()).into());
    }
    Ok(in_job != 0)
}

fn launch_process(
    command_line: &str,
    tool: &OsStr,
    startup_info: &mut STARTUPINFOEXW,
    in_host_job: bool,
) -> Result<PROCESS_INFORMATION> {
    match create_process(command_line, startup_info, EXTENDED_STARTUPINFO_PRESENT) {
        Ok(process_info) => Ok(process_info),
        Err(source) if in_host_job && is_access_denied(&source) => create_process(
            command_line,
            startup_info,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_BREAKAWAY_FROM_JOB,
        )
        .map_err(|source| {
            if is_access_denied(&source) {
                LandstripError::HostJobIncompatible {
                    source: source.into(),
                }
                .into()
            } else {
                LandstripError::LaunchFailed {
                    tool: PathBuf::from(tool),
                    source: source.into(),
                }
                .into()
            }
        }),
        Err(source) => Err(LandstripError::LaunchFailed {
            tool: PathBuf::from(tool),
            source: source.into(),
        }
        .into()),
    }
}

fn create_process(
    command_line: &str,
    startup_info: &mut STARTUPINFOEXW,
    creation_flags: u32,
) -> io::Result<PROCESS_INFORMATION> {
    let mut command_line = wide_string(command_line);
    let mut process_info = unsafe { mem::zeroed::<PROCESS_INFORMATION>() };
    let created = unsafe {
        CreateProcessW(
            ptr::null(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            creation_flags,
            ptr::null(),
            ptr::null(),
            (&raw mut *startup_info).cast(),
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(process_info)
}

fn is_access_denied(error: &io::Error) -> bool {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        == Some(ERROR_ACCESS_DENIED)
}

fn supervise_process(process_info: PROCESS_INFORMATION) -> Result<u32> {
    let process = Handle(process_info.hProcess);
    let thread = Handle(process_info.hThread);
    let wait = unsafe { WaitForSingleObject(process.0, INFINITE) };
    if wait == WAIT_FAILED {
        return Err(LandstripError::SuperviseFailed {
            source: io::Error::last_os_error().into(),
        }
        .into());
    }

    let mut exit_code = 0;
    let ok = unsafe { GetExitCodeProcess(process.0, &mut exit_code) };
    if ok == 0 {
        return Err(LandstripError::SuperviseFailed {
            source: io::Error::last_os_error().into(),
        }
        .into());
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
        return Err(setup_failed(io::Error::last_os_error()).into());
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
            return Err(setup_failed(io::Error::last_os_error()).into());
        }

        let mut storage = vec![0_u8; size];
        let list = storage.as_mut_ptr().cast();
        let ok = unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut size) };
        if ok == 0 {
            return Err(setup_failed(io::Error::last_os_error()).into());
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
                return Err(setup_failed(io::Error::last_os_error()).into());
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

fn tool_encoding_error(tool: &OsStr, message: &'static str) -> LandstripError {
    LandstripError::LaunchFailed {
        tool: PathBuf::from(tool),
        source: message.into(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_positive_handle_values_are_real() {
        assert!(!is_real_handle_value(0));
        assert!(!is_real_handle_value(-1));
        assert!(!is_real_handle_value(-2));
        assert!(is_real_handle_value(1));
    }

    #[test]
    fn only_io_file_types_are_accepted() {
        assert!(is_io_file_type(FILE_TYPE_CHAR));
        assert!(is_io_file_type(FILE_TYPE_DISK));
        assert!(is_io_file_type(FILE_TYPE_PIPE));
        assert!(!is_io_file_type(0));
        assert!(!is_io_file_type(0x8000));
    }

    #[test]
    fn null_access_matches_standard_handle_direction() {
        assert_eq!(
            StandardHandleDirection::Input.desired_access(),
            GENERIC_READ
        );
        assert_eq!(
            StandardHandleDirection::Output.desired_access(),
            GENERIC_WRITE
        );
    }

    #[test]
    fn access_denied_detection_uses_the_win32_error_code() {
        assert!(is_access_denied(&io::Error::from_raw_os_error(5)));
        assert!(!is_access_denied(&io::Error::from_raw_os_error(2)));
    }
}
