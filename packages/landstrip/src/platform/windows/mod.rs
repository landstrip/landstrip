// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows sandbox implementations.

mod appcontainer;
mod null_device;
mod restricted_user;

pub(crate) use restricted_user::{manage, run_worker, status};

use crate::error::{Error, Mechanism};
use crate::paths::PathExt;
use crate::policy::{AccessPolicy, ReadAccess};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString, c_void};
use std::fs;
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_PATH_NOT_FOUND,
    ERROR_SHARING_VIOLATION, HANDLE, LocalFree, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    REVOKE_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetTokenInformation, InitializeSecurityDescriptor,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    SetFileSecurityW, SetSecurityDescriptorDacl, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, ReleaseMutex,
    WaitForSingleObject,
};

/// Take ownership of a live Win32 handle.
///
/// # Safety
/// `handle` must be a unique, closeable handle.
pub(crate) unsafe fn own_handle(handle: HANDLE) -> OwnedHandle {
    unsafe { OwnedHandle::from_raw_handle(handle) }
}

/// Open the current process token with `desired_access`.
pub(crate) fn current_process_token(desired_access: u32) -> io::Result<OwnedHandle> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), desired_access, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { own_handle(token) })
}

pub(crate) struct SandboxJob {
    handle: OwnedHandle,
}

impl SandboxJob {
    pub(crate) fn new(mechanism: Mechanism) -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(Error::sandbox_setup(mechanism, io::Error::last_os_error()).into());
        }

        let job = Self {
            handle: unsafe { own_handle(handle) },
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

    pub(crate) fn as_raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }
}

pub(crate) struct NamedMutex {
    handle: OwnedHandle,
}

impl NamedMutex {
    pub(crate) fn lock(name: impl AsRef<OsStr>) -> io::Result<Self> {
        Self::acquire(name, INFINITE)?.ok_or_else(|| io::Error::other("named mutex wait timed out"))
    }

    pub(crate) fn acquire(name: impl AsRef<OsStr>, timeout_ms: u32) -> io::Result<Option<Self>> {
        let name = name.as_ref().to_wide_nul();
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        let handle = unsafe { own_handle(handle) };
        match unsafe { WaitForSingleObject(handle.as_raw_handle(), timeout_ms) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Some(Self { handle })),
            WAIT_TIMEOUT => Ok(None),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            status => Err(io::Error::other(format!(
                "unexpected mutex wait status {status}"
            ))),
        }
    }
}

impl Drop for NamedMutex {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle.as_raw_handle());
        }
    }
}

pub(crate) fn wait_process_exit(process: &impl AsRawHandle) -> Result<u32> {
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

/// A Win32 C string: UTF-16 units plus a trailing NUL.
pub(crate) trait ToWideNul {
    fn to_wide_nul(&self) -> Vec<u16>;
}

impl<T: AsRef<OsStr> + ?Sized> ToWideNul for T {
    fn to_wide_nul(&self) -> Vec<u16> {
        self.as_ref().encode_wide().chain(Some(0)).collect()
    }
}

/// A NUL-terminated UTF-16 C string as a slice, without the terminator.
///
/// # Safety
/// `value` must be null or a valid pointer to a NUL-terminated UTF-16 string.
pub(crate) unsafe fn from_wide_nul<'a>(value: *const u16) -> Option<&'a [u16]> {
    if value.is_null() {
        return None;
    }
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    Some(unsafe { std::slice::from_raw_parts(value, length) })
}

/// Format `sid` as an SDDL SID string.
///
/// # Safety
/// `sid` must be a valid, readable SID.
pub(crate) unsafe fn sid_string(sid: PSID) -> io::Result<String> {
    let mut wide = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &raw mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let wide = unsafe { OwnedLocal::from_raw(wide) };
    unsafe { from_wide_nul(wide.as_ptr()) }
        .and_then(|wide| String::from_utf16(wide).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SID is not valid UTF-16"))
}

/// Aligned `TOKEN_USER` query buffer.
pub(crate) struct TokenUserBuffer {
    words: Vec<usize>,
}

impl std::ops::Deref for TokenUserBuffer {
    type Target = TOKEN_USER;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.words.as_ptr().cast() }
    }
}

/// Query the user SID from `token`.
pub(crate) fn token_user(token: HANDLE) -> io::Result<TokenUserBuffer> {
    let mut size = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut size);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER.cast_signed()) {
        return Err(error);
    }
    let word_size = mem::size_of::<usize>();
    let word_count = usize::try_from(size)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "token user information is too large",
            )
        })?
        .div_ceil(word_size);
    let mut words = vec![0_usize; word_count];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            words.as_mut_ptr().cast(),
            size,
            &raw mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(TokenUserBuffer { words })
}

/// A `LocalAlloc`'d security descriptor parsed from SDDL.
pub(crate) struct OwnedSecurityDescriptor {
    descriptor: OwnedLocal,
    size: u32,
}

impl OwnedSecurityDescriptor {
    pub(crate) fn from_sddl(sddl: impl AsRef<OsStr>) -> io::Result<Self> {
        let sddl = sddl.to_wide_nul();
        let mut descriptor = ptr::null_mut();
        let mut size = 0;
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &raw mut descriptor,
                &raw mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptor: unsafe { OwnedLocal::from_raw(descriptor) },
            size,
        })
    }

    pub(crate) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.descriptor.as_ptr()
    }

    pub(crate) fn size(&self) -> u32 {
        self.size
    }
}

/// Lowercase hexadecimal encoding of `bytes`.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

/// Decode lowercase or uppercase hexadecimal `value`.
pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if !value.len().is_multiple_of(2) {
        return Err("hex string has an invalid length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("hex string contains non-hexadecimal data"),
    }
}

/// Quote one argument for `CreateProcessW` / `CommandLineToArgvW`.
///
/// Quote one already-decoded argument. `arg` must not contain an interior NUL.
pub(crate) fn quote_command_arg(arg: &str) -> Result<String, &'static str> {
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
        return Ok(arg.to_owned());
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(ch);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    Ok(quoted)
}

/// Join a tool and arguments into a `CreateProcessW` command line.
pub(crate) fn join_command_line<E>(
    tool: &OsStr,
    args: &[OsString],
    mut quote: impl FnMut(&OsStr) -> Result<String, E>,
) -> Result<String, E> {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(quote(tool)?);
    for arg in args {
        parts.push(quote(arg)?);
    }
    Ok(parts.join(" "))
}

pub(crate) const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

type Win32CallResult<T> = std::result::Result<T, (&'static str, io::Error)>;

/// A Win32 or `NET_API` status code, as reported by APIs that return one
/// instead of setting the last error.
pub(crate) fn win32_error(status: u32) -> io::Error {
    io::Error::from_raw_os_error(status.cast_signed())
}

/// The Win32 status carried by `error`, when it carries one.
pub(crate) fn win32_status(error: &io::Error) -> Option<u32> {
    error.raw_os_error().map(i32::cast_unsigned)
}

pub(crate) fn is_missing_error(error: &io::Error) -> bool {
    matches!(
        win32_status(error),
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
    )
}

pub(crate) fn is_locked_error(error: &io::Error) -> bool {
    matches!(
        win32_status(error),
        Some(ERROR_SHARING_VIOLATION | ERROR_ACCESS_DENIED)
    )
}

/// Format an ACL apply failure for `path`.
pub(crate) fn path_access_failed(
    mechanism: Mechanism,
    path: &Path,
    mode: ACCESS_MODE,
    api: &str,
    source: &io::Error,
) -> Error {
    Error::sandbox_setup(
        mechanism,
        format!(
            "{api} failed to {} ACL for {}: {source}",
            acl_action(mode),
            path.display()
        ),
    )
}

fn acl_action(mode: ACCESS_MODE) -> &'static str {
    match mode {
        GRANT_ACCESS => "grant",
        DENY_ACCESS => "deny",
        REVOKE_ACCESS => "revoke",
        _ => "update",
    }
}

/// A `LocalAlloc`'d buffer.
pub(crate) struct OwnedLocal(*mut c_void);

impl OwnedLocal {
    /// Take ownership of a `LocalAlloc`'d pointer.
    ///
    /// # Safety
    /// `ptr` must be null or a unique `LocalAlloc` allocation.
    pub(crate) unsafe fn from_raw<T>(ptr: *mut T) -> Self {
        Self(ptr.cast())
    }

    pub(crate) fn as_ptr<T>(&self) -> *mut T {
        self.0.cast()
    }
}

impl Drop for OwnedLocal {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

const APP_CONTAINER_GROUP_SIDS: [&str; 2] = ["S-1-15-2-1", "S-1-15-2-2"];

pub(crate) struct LocalSid(OwnedLocal);

impl TryFrom<&str> for LocalSid {
    type Error = io::Error;

    fn try_from(sid: &str) -> io::Result<Self> {
        let wide = sid.to_wide_nul();
        let mut raw = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(unsafe { OwnedLocal::from_raw(raw) }))
    }
}

impl LocalSid {
    pub(crate) fn as_ptr(&self) -> PSID {
        self.0.as_ptr()
    }

    pub(crate) fn app_container_groups() -> Result<Vec<Self>> {
        APP_CONTAINER_GROUP_SIDS
            .into_iter()
            .map(|sid| {
                Self::try_from(sid).with_context(|| format!("convert AppContainer group SID {sid}"))
            })
            .collect()
    }
}

/// Edit a path DACL for `sid`.
pub(crate) fn set_path_access(
    path: &Path,
    sid: PSID,
    access: u32,
    mode: ACCESS_MODE,
    inherit: bool,
    propagate: bool,
) -> Win32CallResult<()> {
    let path_wide = path.to_wide_nul();
    let mut old_dacl: *mut ACL = ptr::null_mut();
    let mut security_descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut old_dacl,
            ptr::null_mut(),
            &raw mut security_descriptor,
        )
    };
    if status != 0 {
        return Err(("GetNamedSecurityInfoW", win32_error(status)));
    }
    let _security_descriptor = unsafe { OwnedLocal::from_raw(security_descriptor) };

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
    let status =
        unsafe { SetEntriesInAclW(1, &raw const explicit_access, old_dacl, &raw mut new_dacl) };
    if status != 0 {
        return Err(("SetEntriesInAclW", win32_error(status)));
    }
    let _new_dacl = unsafe { OwnedLocal::from_raw(new_dacl) };
    apply_path_dacl(&path_wide, new_dacl, propagate)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PathAccessEntry {
    pub(crate) access_mode: ACCESS_MODE,
    pub(crate) path: PathBuf,
    pub(crate) access: u32,
    pub(crate) inherit: bool,
    pub(crate) propagate: bool,
}

impl PathAccessEntry {
    pub(crate) fn policy_entries(policy: &AccessPolicy) -> Result<Vec<Self>> {
        let read_roots = match &policy.read_access {
            ReadAccess::AllowRoots(read_roots) => read_roots,
            ReadAccess::Unrestricted => {
                return Err(Error::PolicyUnrestrictedRead.into());
            }
        };
        let mut entries = Vec::new();
        for path in read_roots {
            Self::push_grant(
                &mut entries,
                path,
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                true,
            );
        }
        for path in &policy.write_roots {
            Self::push_grant(
                &mut entries,
                path,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
                true,
            );
        }
        // Placed after grant entries so the resulting DACL has DENY before
        // GRANT in access-evaluation order.
        for path in &policy.write_denied_roots {
            let carved: Vec<&Path> = policy
                .write_carveouts
                .iter()
                .map(PathBuf::as_path)
                .filter(|carveout| carveout.is_strictly_under(path))
                .collect();
            if carved.is_empty() {
                entries.push(Self::subtree_deny(
                    path,
                    FILE_GENERIC_WRITE | FILE_DELETE_CHILD | DELETE,
                ));
            } else if policy
                .write_roots
                .iter()
                .any(|root| path.is_strictly_under(root))
            {
                Self::push_carved_write_deny(
                    &mut entries,
                    path,
                    &carved,
                    FILE_GENERIC_WRITE | FILE_DELETE_CHILD | DELETE,
                )?;
            }
        }
        for path in &policy.read_denied_roots {
            // Traverse (`FILE_TRAVERSE`/`FILE_GENERIC_EXECUTE` on a directory) is
            // deliberately absent: a granted write root nested in a read-denied
            // subtree must stay writable, as it does under Seatbelt and Landlock.
            // Executing a binary in the subtree still needs read access to it.
            entries.push(Self::subtree_deny(path, FILE_GENERIC_READ | DELETE));
        }
        Ok(entries)
    }

    pub(crate) fn push_grant(
        entries: &mut Vec<Self>,
        path: &Path,
        access: u32,
        inherit_and_propagate: bool,
    ) {
        let ancestor_access = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        for ancestor in path.ancestors().skip(1) {
            entries.push(Self {
                access_mode: GRANT_ACCESS,
                path: ancestor.to_path_buf(),
                access: ancestor_access,
                inherit: false,
                propagate: false,
            });
        }
        entries.push(Self {
            access_mode: GRANT_ACCESS,
            path: path.to_path_buf(),
            access,
            inherit: inherit_and_propagate,
            propagate: inherit_and_propagate,
        });
    }

    fn subtree_deny(path: &Path, access: u32) -> Self {
        Self {
            access_mode: DENY_ACCESS,
            path: path.to_path_buf(),
            access,
            inherit: true,
            propagate: true,
        }
    }

    fn push_carved_write_deny(
        entries: &mut Vec<Self>,
        root: &Path,
        carved: &[&Path],
        access: u32,
    ) -> Result<()> {
        let mut stack = vec![root.to_path_buf()];
        while let Some(current) = stack.pop() {
            if current.is_under_any(carved) {
                continue;
            }
            let has_carved_descendant = carved
                .iter()
                .any(|carveout| carveout.is_strictly_under(&current));
            let is_dir = fs::symlink_metadata(&current).is_ok_and(|md| md.file_type().is_dir());
            if !has_carved_descendant || !is_dir {
                entries.push(Self::subtree_deny(&current, access));
                continue;
            }
            entries.push(Self {
                access_mode: DENY_ACCESS,
                path: current.clone(),
                access,
                inherit: false,
                propagate: false,
            });
            for entry in
                fs::read_dir(&current).map_err(|source| Error::PolicyIoFailed { source })?
            {
                let entry = entry.map_err(|source| Error::PolicyIoFailed { source })?;
                stack.push(entry.path());
            }
        }
        Ok(())
    }

    pub(crate) fn apply(&self, sid: PSID) -> Win32CallResult<()> {
        set_path_access(
            &self.path,
            sid,
            self.access,
            self.access_mode,
            self.inherit,
            self.propagate,
        )
    }

    pub(crate) fn revoke(&self, sid: PSID) -> Win32CallResult<()> {
        set_path_access(&self.path, sid, 0, REVOKE_ACCESS, false, self.propagate)
    }
}

/// Apply a constructed DACL to a path.
///
/// Propagating updates use `SetNamedSecurityInfoW`. Non-propagating updates
/// write the DACL with `SetFileSecurityW` so descendants stay unchanged.
fn apply_path_dacl(path: &[u16], dacl: *mut ACL, propagate: bool) -> Win32CallResult<()> {
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
            return Err(("SetNamedSecurityInfoW", win32_error(status)));
        }
        return Ok(());
    }

    let mut descriptor = unsafe { mem::zeroed::<SECURITY_DESCRIPTOR>() };
    if unsafe {
        InitializeSecurityDescriptor((&raw mut descriptor).cast(), SECURITY_DESCRIPTOR_REVISION)
    } == 0
    {
        return Err(("InitializeSecurityDescriptor", io::Error::last_os_error()));
    }
    if unsafe { SetSecurityDescriptorDacl((&raw mut descriptor).cast(), 1, dacl, 0) } == 0 {
        return Err(("SetSecurityDescriptorDacl", io::Error::last_os_error()));
    }
    if unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            (&raw mut descriptor).cast(),
        )
    } == 0
    {
        return Err(("SetFileSecurityW", io::Error::last_os_error()));
    }
    Ok(())
}

pub(crate) fn execute(
    policy: &AccessPolicy,
    cwd: &Path,
    tool: &OsStr,
    args: &[OsString],
) -> Result<i32> {
    if restricted_user::is_installed()? {
        restricted_user::execute(policy, cwd, tool, args)
    } else {
        appcontainer::execute(policy, cwd, tool, args)
    }
}

pub(crate) fn validate(policy: &AccessPolicy) -> Result<()> {
    if restricted_user::is_installed()? {
        restricted_user::active_implementation()?;
        restricted_user::validate(policy)?;
    }
    Ok(())
}
