// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::error::{BrokerError, SysResult};
use super::grant::{
    FdMutation, Grant, MutationGrant, MutationTarget, OPEN_HOW_SIZE, OpenGrant, OpenHow,
    PathMutation, open_path,
};
use super::notify::NotificationResult;
use super::process::{MissingTarget, ResolvedPath, TargetProcess, fd_label_under_root};
use super::supervise::{Denial, Denials};
use crate::paths::PathExt;
use crate::policy::{AccessPolicy, DenialReason};
use crate::trap::{FilesystemDenial, ProcessContext, TrapOperation};
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

pub(super) const SYS_FCHMODAT2: i64 = 452;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) mod legacy_syscall {
    pub const OPEN: Option<i64> = Some(libc::SYS_open);
    pub const ACCESS: Option<i64> = Some(libc::SYS_access);
    pub const RENAME: Option<i64> = Some(libc::SYS_rename);
    pub const LINK: Option<i64> = Some(libc::SYS_link);
    pub const SYMLINK: Option<i64> = Some(libc::SYS_symlink);
    pub const UNLINK: Option<i64> = Some(libc::SYS_unlink);
    pub const RMDIR: Option<i64> = Some(libc::SYS_rmdir);
    pub const MKDIR: Option<i64> = Some(libc::SYS_mkdir);
    pub const MKNOD: Option<i64> = Some(libc::SYS_mknod);
    pub const CREAT: Option<i64> = Some(libc::SYS_creat);
    pub const CHMOD: Option<i64> = Some(libc::SYS_chmod);
    pub const CHOWN: Option<i64> = Some(libc::SYS_chown);
    pub const LCHOWN: Option<i64> = Some(libc::SYS_lchown);
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub(super) mod legacy_syscall {
    pub const OPEN: Option<i64> = None;
    pub const ACCESS: Option<i64> = None;
    pub const RENAME: Option<i64> = None;
    pub const LINK: Option<i64> = None;
    pub const SYMLINK: Option<i64> = None;
    pub const UNLINK: Option<i64> = None;
    pub const RMDIR: Option<i64> = None;
    pub const MKDIR: Option<i64> = None;
    pub const MKNOD: Option<i64> = None;
    pub const CREAT: Option<i64> = None;
    pub const CHMOD: Option<i64> = None;
    pub const CHOWN: Option<i64> = None;
    pub const LCHOWN: Option<i64> = None;
}

trait SyscallArg {
    fn to_u32(self) -> u32;
    fn to_i32(self) -> i32;
}

impl SyscallArg for u64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "syscall argument registers are zero- or sign-extended u64 in seccomp_notif"
    )]
    fn to_u32(self) -> u32 {
        self as u32
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "syscall argument registers are zero- or sign-extended u64 in seccomp_notif"
    )]
    fn to_i32(self) -> i32 {
        (self as u32).cast_signed()
    }
}

fn open_flag_names(flags: i32) -> Vec<&'static str> {
    let mut names = Vec::new();
    match flags & libc::O_ACCMODE {
        libc::O_WRONLY => names.push("O_WRONLY"),
        libc::O_RDWR => names.push("O_RDWR"),
        _ => names.push("O_RDONLY"),
    }
    if flags & libc::O_CREAT != 0 {
        names.push("O_CREAT");
    }
    if flags & libc::O_TRUNC != 0 {
        names.push("O_TRUNC");
    }
    if flags & libc::O_APPEND != 0 {
        names.push("O_APPEND");
    }
    names
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(super) enum MutationSyscall {
    Renameat2,
    Renameat,
    Linkat,
    Symlinkat,
    Unlinkat,
    Mkdirat,
    Mknodat,
    Truncate,
    Fchmod,
    Fchmodat,
    Fchmodat2,
    Fchown,
    Fchownat,
    Utimensat,
    Fsetxattr,
    Setxattr,
    Lsetxattr,
    Fremovexattr,
    Removexattr,
    Lremovexattr,
    Rename,
    Link,
    Symlink,
    Unlink,
    Rmdir,
    Mkdir,
    Mknod,
    Creat,
    Chmod,
    Chown,
    Lchown,
}

impl MutationSyscall {
    pub(super) fn no_follow(self, args: &[u64; 6]) -> bool {
        let flag = |index: usize| args[index].to_i32() & libc::AT_SYMLINK_NOFOLLOW != 0;
        let follow = |index: usize| args[index].to_i32() & libc::AT_SYMLINK_FOLLOW != 0;
        match self {
            Self::Unlink
            | Self::Unlinkat
            | Self::Rmdir
            | Self::Lchown
            | Self::Lsetxattr
            | Self::Lremovexattr
            | Self::Link => true,
            Self::Fchownat => flag(4),
            Self::Fchmodat2 | Self::Utimensat => flag(3),
            Self::Linkat => !follow(4),
            Self::Renameat2
            | Self::Renameat
            | Self::Symlinkat
            | Self::Mkdirat
            | Self::Mknodat
            | Self::Truncate
            | Self::Fchmodat
            | Self::Fchmod
            | Self::Fchown
            | Self::Fsetxattr
            | Self::Fremovexattr
            | Self::Setxattr
            | Self::Removexattr
            | Self::Rename
            | Self::Symlink
            | Self::Mkdir
            | Self::Mknod
            | Self::Creat
            | Self::Chmod
            | Self::Chown => false,
        }
    }

    pub(super) fn is_mkdir(self) -> bool {
        matches!(self, Self::Mkdir | Self::Mkdirat)
    }

    pub(super) fn is_removal(self) -> bool {
        matches!(self, Self::Unlink | Self::Unlinkat | Self::Rmdir)
    }

    pub(super) fn is_reparent(self) -> bool {
        matches!(
            self,
            Self::Link | Self::Linkat | Self::Rename | Self::Renameat | Self::Renameat2
        )
    }
}

pub(super) struct Syscall {
    pub(super) nr: Option<i64>,
    pub(super) kind: MutationSyscall,
    pub(super) paths: &'static [(Option<usize>, usize)],
    pub(super) landlock_backed: bool,
}

pub(super) const MUTATION_SYSCALLS: &[Syscall] = &[
    Syscall {
        nr: Some(libc::SYS_renameat2),
        kind: MutationSyscall::Renameat2,
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_renameat),
        kind: MutationSyscall::Renameat,
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_linkat),
        kind: MutationSyscall::Linkat,
        paths: &[(Some(0), 1), (Some(2), 3)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_symlinkat),
        kind: MutationSyscall::Symlinkat,
        paths: &[(Some(1), 2)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_unlinkat),
        kind: MutationSyscall::Unlinkat,
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_mkdirat),
        kind: MutationSyscall::Mkdirat,
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_mknodat),
        kind: MutationSyscall::Mknodat,
        paths: &[(Some(0), 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_truncate),
        kind: MutationSyscall::Truncate,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: Some(libc::SYS_fchmod),
        kind: MutationSyscall::Fchmod,
        paths: &[],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fchown),
        kind: MutationSyscall::Fchown,
        paths: &[],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fchmodat),
        kind: MutationSyscall::Fchmodat,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(SYS_FCHMODAT2),
        kind: MutationSyscall::Fchmodat2,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fchownat),
        kind: MutationSyscall::Fchownat,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_utimensat),
        kind: MutationSyscall::Utimensat,
        paths: &[(Some(0), 1)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fsetxattr),
        kind: MutationSyscall::Fsetxattr,
        paths: &[],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_fremovexattr),
        kind: MutationSyscall::Fremovexattr,
        paths: &[],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_setxattr),
        kind: MutationSyscall::Setxattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_lsetxattr),
        kind: MutationSyscall::Lsetxattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_removexattr),
        kind: MutationSyscall::Removexattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: Some(libc::SYS_lremovexattr),
        kind: MutationSyscall::Lremovexattr,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::RENAME,
        kind: MutationSyscall::Rename,
        paths: &[(None, 0), (None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::LINK,
        kind: MutationSyscall::Link,
        paths: &[(None, 0), (None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::SYMLINK,
        kind: MutationSyscall::Symlink,
        paths: &[(None, 1)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::UNLINK,
        kind: MutationSyscall::Unlink,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::RMDIR,
        kind: MutationSyscall::Rmdir,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::MKDIR,
        kind: MutationSyscall::Mkdir,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::MKNOD,
        kind: MutationSyscall::Mknod,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::CREAT,
        kind: MutationSyscall::Creat,
        paths: &[(None, 0)],
        landlock_backed: true,
    },
    Syscall {
        nr: legacy_syscall::CHMOD,
        kind: MutationSyscall::Chmod,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::CHOWN,
        kind: MutationSyscall::Chown,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
    Syscall {
        nr: legacy_syscall::LCHOWN,
        kind: MutationSyscall::Lchown,
        paths: &[(None, 0)],
        landlock_backed: false,
    },
];

struct Open {
    flags: i32,
    mode: u32,
    resolve: u64,
}

impl Open {
    fn from_args(request: &libc::seccomp_notif, legacy_open: bool) -> SysResult<Self> {
        let args = &request.data.args;
        let flags_arg = if legacy_open { 1 } else { 2 };
        let mode_arg = if legacy_open { 2 } else { 3 };
        let flags = i32::try_from(args[flags_arg]).map_err(|_| BrokerError::InvalidAddress)?;
        Ok(Self {
            flags,
            mode: args[mode_arg].to_u32(),
            resolve: 0,
        })
    }

    fn from_how(request: &libc::seccomp_notif, process: &TargetProcess) -> SysResult<Self> {
        let args = &request.data.args;
        let addr = usize::try_from(args[2]).map_err(|_| BrokerError::BadAddress)?;
        let size = usize::try_from(args[3]).map_err(|_| BrokerError::InvalidAddress)?;
        if size < OPEN_HOW_SIZE {
            return Err(BrokerError::InvalidAddress);
        }
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| BrokerError::SystemCall { errno: libc::EIO })?;
        if size > page_size {
            return Err(BrokerError::SystemCall { errno: libc::E2BIG });
        }
        let buf = process.read_vec(addr, size)?;
        let how = OpenHow::try_from(buf.as_slice())?;
        Ok(Self {
            flags: i32::try_from(how.flags).map_err(|_| BrokerError::InvalidAddress)?,
            mode: u32::try_from(how.mode).map_err(|_| BrokerError::InvalidAddress)?,
            resolve: how.resolve,
        })
    }
}

struct OpenDenial {
    operation: TrapOperation,
    path: PathBuf,
    requested_path: PathBuf,
    syscall: &'static str,
    flags: i32,
    grant: Option<OpenGrant>,
    reason: DenialReason,
    pid: u32,
    report: bool,
}

impl OpenDenial {
    fn deny(self, denials: &mut Denials<'_>, allow_query: bool) -> SysResult<NotificationResult> {
        if !self.report {
            return Err(BrokerError::PolicyDenied);
        }
        // SECCOMP_IOCTL_NOTIF_ADDFD cannot inject O_PATH descriptors.
        let grant = if self.flags & libc::O_PATH != 0 {
            None
        } else {
            self.grant.map(Grant::Open)
        };
        denials.deny(
            Denial::Filesystem(FilesystemDenial {
                operation: self.operation,
                path: self.path,
                requested_path: self.requested_path,
                syscall: self.syscall,
                flags: open_flag_names(self.flags),
                reason: self.reason,
                process: TargetProcess::from_raw(self.pid).context(),
            }),
            allow_query,
            grant,
        )
    }
}

struct OpenRequest {
    process: TargetProcess,
    dirfd: RawFd,
    path: PathBuf,
    open: Open,
    syscall: &'static str,
}

impl TryFrom<&libc::seccomp_notif> for OpenRequest {
    type Error = BrokerError;

    fn try_from(request: &libc::seccomp_notif) -> SysResult<Self> {
        let nr = i64::from(request.data.nr);
        let openat2 = nr == libc::SYS_openat2;
        let legacy_open = matches!(legacy_syscall::OPEN, Some(open) if open == nr);
        let dirfd = if legacy_open {
            libc::AT_FDCWD
        } else {
            request.data.args[0].to_i32()
        };
        let path_arg = usize::from(!legacy_open);
        let path_ptr =
            usize::try_from(request.data.args[path_arg]).map_err(|_| BrokerError::BadAddress)?;
        let process = TargetProcess::from_raw(request.pid);
        let open = if openat2 {
            Open::from_how(request, &process)?
        } else {
            Open::from_args(request, legacy_open)?
        };
        let syscall = if openat2 {
            "openat2"
        } else if legacy_open {
            "open"
        } else {
            "openat"
        };
        Ok(Self {
            dirfd,
            path: process.read_nonempty_path(path_ptr)?,
            open,
            syscall,
            process,
        })
    }
}

impl OpenRequest {
    fn resolve(&self) -> SysResult<ResolvedPath> {
        let filesystem = self.process.filesystem()?;
        let follow = self.open.flags & libc::O_NOFOLLOW == 0
            && self.open.flags & (libc::O_CREAT | libc::O_EXCL) != (libc::O_CREAT | libc::O_EXCL);
        let missing = if self.open.flags & libc::O_CREAT != 0 {
            MissingTarget::File
        } else {
            MissingTarget::Disallow
        };
        filesystem.resolve(self.dirfd, &self.path, follow, missing, self.open.resolve)
    }
}

#[derive(Clone, Copy)]
struct AccessMode(i32);

impl AccessMode {
    fn reads(self) -> bool {
        self.0 & libc::R_OK != 0
    }

    fn writes(self) -> bool {
        self.0 & libc::W_OK != 0
    }

    fn is_supported(self) -> bool {
        self.0 & !(libc::R_OK | libc::W_OK | libc::X_OK) == 0
    }
}

impl TryFrom<u64> for AccessMode {
    type Error = BrokerError;

    fn try_from(mode: u64) -> SysResult<Self> {
        Ok(Self(
            i32::try_from(mode).map_err(|_| BrokerError::InvalidAddress)?,
        ))
    }
}

#[derive(Clone, Copy)]
struct AccessFlags(i32);

impl AccessFlags {
    const KNOWN: i32 = libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;

    fn parse(flags: i32) -> Option<Self> {
        (flags & !Self::KNOWN == 0).then_some(Self(flags))
    }

    fn follows(self) -> bool {
        self.0 & libc::AT_SYMLINK_NOFOLLOW == 0
    }

    fn empty_path(self) -> bool {
        self.0 & libc::AT_EMPTY_PATH != 0
    }
}

#[derive(Clone, Copy)]
enum AccessSyscall {
    Access,
    Faccessat,
    Faccessat2,
}

impl AccessSyscall {
    fn from_nr(nr: i64) -> Option<Self> {
        if legacy_syscall::ACCESS.is_some_and(|access| nr == access) {
            Some(Self::Access)
        } else if nr == libc::SYS_faccessat {
            Some(Self::Faccessat)
        } else if nr == libc::SYS_faccessat2 {
            Some(Self::Faccessat2)
        } else {
            None
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Faccessat => "faccessat",
            Self::Faccessat2 => "faccessat2",
        }
    }

    fn takes_dirfd(self) -> bool {
        !matches!(self, Self::Access)
    }

    fn flags(self, args: &[u64; 6]) -> Option<AccessFlags> {
        let flags = match self {
            Self::Faccessat2 => i32::try_from(args[3]).ok()?,
            Self::Access | Self::Faccessat => 0,
        };
        AccessFlags::parse(flags)
    }
}

struct AccessRequest {
    process: TargetProcess,
    dirfd: RawFd,
    path: PathBuf,
    mode: AccessMode,
    flags: AccessFlags,
    syscall: AccessSyscall,
}

impl AccessRequest {
    fn from_notification(request: &libc::seccomp_notif) -> SysResult<Option<Self>> {
        let Some(syscall) = AccessSyscall::from_nr(i64::from(request.data.nr)) else {
            return Ok(None);
        };
        let args = &request.data.args;
        let Some(flags) = syscall.flags(args) else {
            return Ok(None);
        };
        let path_arg = usize::from(syscall.takes_dirfd());
        let path_ptr = usize::try_from(args[path_arg]).map_err(|_| BrokerError::BadAddress)?;
        let process = TargetProcess::from_raw(request.pid);
        let path = if flags.empty_path() {
            process.read_path(path_ptr)?
        } else {
            process.read_nonempty_path(path_ptr)?
        };
        Ok(Some(Self {
            mode: AccessMode::try_from(args[path_arg + 1])?,
            dirfd: if syscall.takes_dirfd() {
                args[0].to_i32()
            } else {
                libc::AT_FDCWD
            },
            path,
            flags,
            syscall,
            process,
        }))
    }

    fn resolve(&self) -> SysResult<Option<AccessTarget>> {
        if self.flags.empty_path() && self.path.as_os_str().is_empty() {
            let filesystem = self.process.filesystem()?;
            let target = self.process.duplicate_fd(self.dirfd)?;
            let Some(label) = fd_label_under_root(&filesystem.root_label, target.as_fd())? else {
                return Ok(None);
            };
            let lexical = label.clean_lexically();
            return Ok(Some(AccessTarget {
                requested_path: label.clone(),
                label,
                lexical,
            }));
        }
        let target = self.process.filesystem()?.resolve(
            self.dirfd,
            &self.path,
            self.flags.follows(),
            MissingTarget::Disallow,
            0,
        )?;
        Ok(Some(AccessTarget {
            label: target.label,
            lexical: target.lexical,
            requested_path: self.path.clone(),
        }))
    }
}

struct AccessTarget {
    label: PathBuf,
    lexical: PathBuf,
    requested_path: PathBuf,
}

struct AccessDenial {
    operation: TrapOperation,
    path: PathBuf,
    requested_path: PathBuf,
    syscall: &'static str,
    reason: DenialReason,
    process: ProcessContext,
}

impl AccessDenial {
    fn deny(self, denials: &mut Denials<'_>, allow_query: bool) -> SysResult<NotificationResult> {
        denials.deny(
            Denial::Filesystem(FilesystemDenial {
                operation: self.operation,
                path: self.path,
                requested_path: self.requested_path,
                syscall: self.syscall,
                flags: Vec::new(),
                reason: self.reason,
                process: self.process,
            }),
            allow_query,
            None,
        )
    }
}

pub(super) fn handle_access(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let Some(access) = AccessRequest::from_notification(request)? else {
        return Ok(NotificationResult::Continue);
    };
    if !access.mode.is_supported() || (!access.mode.reads() && !access.mode.writes()) {
        return Ok(NotificationResult::Continue);
    }
    let Some(target) = access.resolve()? else {
        return Ok(NotificationResult::Continue);
    };
    let writes = access.mode.writes();
    let reads = access.mode.reads();
    let hard_write_denied = writes && policy.is_write_denied_always(&target.label, &target.lexical);
    let hard_read_denied = reads
        && (policy.is_read_denied_always(&target.label)
            || policy.is_read_denied_always(&target.lexical));
    let allow_query = !hard_write_denied && !hard_read_denied;
    let denial = |operation, reason| AccessDenial {
        operation,
        path: target.label.clone(),
        requested_path: target.requested_path.clone(),
        syscall: access.syscall.name(),
        reason,
        process: access.process.context(),
    };

    if writes && let Some(reason) = policy.write_reason(&target.label, true) {
        return denial(TrapOperation::Write, reason).deny(denials, allow_query);
    }
    if reads
        && let Some(reason) = policy
            .read_reason(&target.label)
            .or_else(|| {
                policy
                    .is_read_denied(&target.lexical)
                    .then_some(DenialReason::DenyMatch)
            })
            .or_else(|| hard_read_denied.then_some(DenialReason::DenyMatch))
    {
        return denial(TrapOperation::Read, reason).deny(denials, allow_query);
    }

    Ok(NotificationResult::Continue)
}

pub(super) fn handle_openat(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let open_request = OpenRequest::try_from(request)?;
    let target = open_request.resolve()?;
    let OpenRequest {
        path,
        open: Open {
            flags,
            mode,
            resolve,
        },
        syscall,
        ..
    } = open_request;
    let lexical = target.lexical.clone();
    let resolved = target.label.clone();
    let anonymous = target.anonymous;
    let open_grant = OpenGrant::new(target, flags, mode, resolve);
    let wants_write = flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) != 0;
    let reports_write = flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) != 0;
    let wants_read = flags & libc::O_WRONLY == 0;
    let hard_read_denied = wants_read
        && (policy.is_read_denied_always(&resolved) || policy.is_read_denied_always(&lexical));
    let hard_write_denied = wants_write && policy.is_write_denied_always(&resolved, &lexical);
    let allow_query = !hard_read_denied && !hard_write_denied;
    // Hard policy denials still apply to future descendants with missing parents.
    if !hard_read_denied
        && !hard_write_denied
        && let Err(err) = &open_grant
    {
        return Err(*err);
    }
    let open_grant = open_grant.ok();

    if wants_write
        && !hard_read_denied
        && let Some(reason) = policy.write_reason(&resolved, !anonymous)
    {
        return OpenDenial {
            operation: TrapOperation::Write,
            path: resolved,
            requested_path: path,
            syscall,
            flags,
            grant: open_grant,
            reason,
            pid: request.pid,
            report: reports_write,
        }
        .deny(denials, allow_query);
    }
    if wants_read
        && let Some(reason) = policy
            .read_reason(&resolved)
            .or_else(|| {
                policy
                    .is_read_denied(&lexical)
                    .then_some(DenialReason::DenyMatch)
            })
            .or_else(|| hard_read_denied.then_some(DenialReason::DenyMatch))
    {
        return OpenDenial {
            operation: TrapOperation::Read,
            path: resolved,
            requested_path: path,
            syscall,
            flags,
            grant: open_grant,
            reason,
            pid: request.pid,
            report: true,
        }
        .deny(denials, allow_query);
    }

    if flags & libc::O_PATH != 0 {
        return Ok(NotificationResult::Continue);
    }
    Ok(NotificationResult::grant(open_grant.ok_or(
        BrokerError::SystemCall {
            errno: libc::ENOENT,
        },
    )?))
}

/// A policy denial anchored at one of a mutation's resolved paths.
#[derive(Clone, Copy)]
struct DenialAt {
    index: usize,
    reason: DenialReason,
    operation: TrapOperation,
}

impl DenialAt {
    fn read(index: usize, reason: DenialReason) -> Self {
        Self {
            index,
            reason,
            operation: TrapOperation::Read,
        }
    }

    fn write(index: usize, reason: DenialReason) -> Self {
        Self {
            index,
            reason,
            operation: TrapOperation::Write,
        }
    }
}

/// Denials that outlive a name change. Seatbelt subtracts every denied read
/// root from writes with `file-write-unlink`, so removing a denied path or
/// giving it another name cannot escape the read policy here either. A protected
/// link cannot be removed or renamed for the same reason: it leads to the
/// denied subtree and re-pointing it would invalidate the deny roots.
fn name_change_denial(
    policy: &AccessPolicy,
    spec: &Syscall,
    paths: &[(ResolvedPath, PathBuf)],
) -> Option<DenialAt> {
    if spec.kind.is_removal() || spec.kind.is_reparent() {
        let (source, _) = paths.first()?;
        if policy.is_denied_link(&source.lexical) {
            return Some(DenialAt::write(0, DenialReason::DenyMatch));
        }
    }
    if spec.kind.is_removal() {
        let (source, _) = paths.first()?;
        let denied = policy.is_read_denied(&source.label) || policy.is_read_denied(&source.lexical);
        return denied.then(|| DenialAt::read(0, DenialReason::DenyMatch));
    }
    if !spec.kind.is_reparent() {
        return None;
    }
    let read_denial = |target: &ResolvedPath| {
        policy.read_reason(&target.label).or_else(|| {
            policy
                .has_read_denied_under(&target.label)
                .then_some(DenialReason::DenyMatch)
        })
    };
    let (source, _) = paths.first()?;
    if let Some(reason) = read_denial(source) {
        let dest_readable = paths
            .get(1)
            .is_none_or(|(dest, _)| policy.read_reason(&dest.label).is_none());
        if dest_readable {
            return Some(DenialAt::read(0, reason));
        }
    }
    if let Some((dest, _)) = paths.get(1)
        && let Some(reason) = read_denial(dest)
        && policy.read_reason(&source.label).is_none()
    {
        return Some(DenialAt::read(1, reason));
    }
    None
}

#[allow(
    clippy::too_many_lines,
    reason = "mutation path checks and grant construction share one policy decision"
)]
pub(super) fn handle_mutation(
    policy: &AccessPolicy,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let syscall = i64::from(request.data.nr);
    let Some(spec) = MUTATION_SYSCALLS.iter().find(|s| s.nr == Some(syscall)) else {
        return Ok(NotificationResult::Continue);
    };
    spec.kind.validate_flags(&request.data.args)?;
    if spec.paths.is_empty()
        || (spec.kind == MutationSyscall::Utimensat && request.data.args[1] == 0)
    {
        return handle_fd_mutation(policy, spec, request, denials);
    }

    let process = TargetProcess::from_raw(request.pid);
    let filesystem = process.filesystem()?;
    let mut paths: Vec<(ResolvedPath, PathBuf)> = Vec::with_capacity(spec.paths.len());
    let no_follow = spec.kind.no_follow(&request.data.args);
    for (index, (dirfd_arg, path_arg)) in spec.paths.iter().enumerate() {
        let dirfd = match dirfd_arg {
            Some(arg) => request.data.args[*arg].to_i32(),
            None => libc::AT_FDCWD,
        };
        let path_ptr =
            usize::try_from(request.data.args[*path_arg]).map_err(|_| BrokerError::BadAddress)?;
        let path = process.read_path(path_ptr)?;
        if spec.kind.empty_path_uses_fd(&request.data.args, &path)? {
            return handle_fd_mutation(policy, spec, request, denials);
        }
        let follow = !no_follow
            && match spec.kind {
                MutationSyscall::Rename
                | MutationSyscall::Renameat
                | MutationSyscall::Renameat2
                | MutationSyscall::Symlink
                | MutationSyscall::Symlinkat
                | MutationSyscall::Mkdir
                | MutationSyscall::Mkdirat
                | MutationSyscall::Mknod
                | MutationSyscall::Mknodat => false,
                MutationSyscall::Link | MutationSyscall::Linkat => index == 0,
                _ => true,
            };
        let missing = if spec.kind.is_mkdir()
            || (index == 1
                && matches!(
                    spec.kind,
                    MutationSyscall::Rename
                        | MutationSyscall::Renameat
                        | MutationSyscall::Renameat2
                )
                && paths.first().is_some_and(|(from, _)| from.is_directory()))
        {
            MissingTarget::Directory
        } else {
            MissingTarget::File
        };
        let target = filesystem.resolve(dirfd, &path, follow, missing, 0)?;
        if spec.kind.is_mkdir()
            && target
                .anchor
                .as_ref()
                .is_some_and(|anchor| anchor.target.is_some())
        {
            return Err(BrokerError::SystemCall {
                errno: libc::EEXIST,
            });
        }
        paths.push((target, path));
    }

    // A removal of a missing target can only fail with ENOENT, which is
    // also what the kernel would answer. Denying it with the write policy
    // instead would make `rm -f` fail on nonexistent denyWrite paths.
    if spec.kind.is_removal()
        && paths.iter().all(|(target, _)| {
            target
                .anchor
                .as_ref()
                .is_none_or(|anchor| anchor.target.is_none())
        })
    {
        return Err(BrokerError::SystemCall {
            errno: libc::ENOENT,
        });
    }

    let mut denial: Option<DenialAt> = None;
    for (index, (target, _)) in paths.iter().enumerate() {
        // The broker executes every granted mutation outside Landlock, so
        // allowWrite misses must be enforced here.
        if let Some(reason) = policy.write_reason(&target.label, true) {
            denial = Some(DenialAt::write(index, reason));
            break;
        }
        if spec.kind.is_reparent() && policy.has_write_denied_under(&target.label) {
            denial = Some(DenialAt::write(index, DenialReason::DenyMatch));
            break;
        }
    }
    let hard_read_denial = (spec.kind.is_reparent() || spec.kind.is_removal())
        .then(|| {
            paths.iter().position(|(target, _)| {
                policy.is_read_denied_always(&target.label)
                    || policy.is_read_denied_always(&target.lexical)
                    || policy.has_read_denied_always_under(&target.label)
            })
        })
        .flatten();
    let hard_write_denial = paths.iter().position(|(target, _)| {
        policy.is_write_denied_always(&target.label, &target.lexical)
            || (spec.kind.is_reparent() && policy.has_write_denied_always_under(&target.label))
    });
    let hard_link_denial = (spec.kind.is_removal() || spec.kind.is_reparent())
        .then(|| {
            paths
                .first()
                .filter(|(source, _)| policy.is_denied_link_always(&source.lexical))
        })
        .flatten();
    let allow_query =
        hard_read_denial.is_none() && hard_write_denial.is_none() && hard_link_denial.is_none();
    denial = hard_read_denial
        .map(|index| DenialAt::read(index, DenialReason::DenyMatch))
        .or_else(|| hard_write_denial.map(|index| DenialAt::write(index, DenialReason::DenyMatch)))
        .or_else(|| hard_link_denial.map(|_| DenialAt::write(0, DenialReason::DenyMatch)))
        .or(denial)
        .or_else(|| name_change_denial(policy, spec, &paths));

    let denial = denial.map(|denial| {
        let (target, path) = &paths[denial.index];
        Denial::Filesystem(FilesystemDenial {
            operation: denial.operation,
            path: target.label.clone(),
            requested_path: path.clone(),
            syscall: spec.kind.into(),
            flags: Vec::new(),
            reason: denial.reason,
            process: process.context(),
        })
    });
    let grant = spec.kind.grant(request, &process, paths);
    let Some(denial) = denial else {
        return Ok(NotificationResult::grant(grant?));
    };
    let grant = denials
        .can_query(allow_query)
        .then_some(grant)
        .transpose()?;
    denials.deny(denial, allow_query, grant)
}

fn mutation_target_fd(
    process: &TargetProcess,
    child_fd: RawFd,
    kind: MutationSyscall,
) -> SysResult<OwnedFd> {
    let at_cwd = child_fd == libc::AT_FDCWD
        && matches!(kind, MutationSyscall::Fchmodat2 | MutationSyscall::Fchownat);
    if child_fd < 0 && !at_cwd {
        return Err(BrokerError::BadFileDescriptor);
    }
    if !at_cwd {
        return process.duplicate_fd(child_fd);
    }

    open_path(&process.proc_path("cwd"), libc::O_PATH | libc::O_CLOEXEC)
}

fn handle_fd_mutation(
    policy: &AccessPolicy,
    spec: &Syscall,
    request: &libc::seccomp_notif,
    denials: &mut Denials<'_>,
) -> SysResult<NotificationResult> {
    let args = &request.data.args;
    let process = TargetProcess::from_raw(request.pid);
    if spec.kind == MutationSyscall::Utimensat && args[3].to_i32() != 0 {
        return Err(BrokerError::SystemCall {
            errno: libc::EINVAL,
        });
    }

    let target = mutation_target_fd(&process, args[0].to_i32(), spec.kind)?;
    let filesystem = process.filesystem()?;
    let mutation = spec.kind.fd_mutation(&process, args)?;
    let Some(requested_path) = fd_label_under_root(&filesystem.root_label, target.as_fd())? else {
        return Ok(NotificationResult::grant(MutationGrant::Fd {
            target,
            mutation,
        }));
    };
    let resolved = requested_path.clone();
    let lexical = requested_path.clean_lexically();
    let hard_write_denied = policy.is_write_denied_always(&resolved, &lexical);
    let reason = policy.write_reason(&resolved, true);
    let operation = MutationGrant::Fd { target, mutation };

    let Some(reason) = reason else {
        return Ok(NotificationResult::grant(operation));
    };

    let denial = FilesystemDenial {
        operation: TrapOperation::Write,
        path: resolved,
        requested_path,
        syscall: spec.kind.into(),
        flags: Vec::new(),
        reason,
        process: process.context(),
    };
    denials.deny(
        Denial::Filesystem(denial),
        !hard_write_denied,
        Some(Grant::from(operation)),
    )
}

impl MutationSyscall {
    fn grant(
        self,
        request: &libc::seccomp_notif,
        process: &TargetProcess,
        paths: Vec<(ResolvedPath, PathBuf)>,
    ) -> SysResult<Grant> {
        let mut paths = paths.into_iter();
        let (mut resolved, _) = paths.next().ok_or(BrokerError::InvalidAddress)?;
        let args = &request.data.args;
        if self == Self::Creat {
            return OpenGrant::new(
                resolved,
                libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
                args[1].to_u32(),
                0,
            )
            .map(Grant::Open);
        }
        let at = resolved
            .anchor
            .take()
            .ok_or_else(|| BrokerError::syscall(libc::ENOENT))?;
        let to = paths.next().and_then(|(target, _)| target.anchor);
        let no_follow = self.no_follow(args);
        let operation = match self {
            MutationSyscall::Mkdirat => Ok(MutationGrant::Mkdir {
                at,
                mode: args[2].to_u32(),
            }),
            MutationSyscall::Mkdir => Ok(MutationGrant::Mkdir {
                at,
                mode: args[1].to_u32(),
            }),
            MutationSyscall::Mknodat => Ok(MutationGrant::Mknod {
                at,
                mode: args[2].to_u32(),
                dev: args[3],
            }),
            MutationSyscall::Mknod => Ok(MutationGrant::Mknod {
                at,
                mode: args[1].to_u32(),
                dev: args[2],
            }),
            MutationSyscall::Unlinkat => Ok(MutationGrant::Unlink {
                at,
                flags: args[2].to_i32(),
            }),
            MutationSyscall::Unlink => Ok(MutationGrant::Unlink { at, flags: 0 }),
            MutationSyscall::Rmdir => Ok(MutationGrant::Unlink {
                at,
                flags: libc::AT_REMOVEDIR,
            }),
            MutationSyscall::Renameat2 => Ok(MutationGrant::Rename {
                from: at,
                to: to.ok_or_else(|| BrokerError::syscall(libc::ENOENT))?,
                flags: args[4].to_u32(),
            }),
            MutationSyscall::Renameat | MutationSyscall::Rename => Ok(MutationGrant::Rename {
                from: at,
                to: to.ok_or_else(|| BrokerError::syscall(libc::ENOENT))?,
                flags: 0,
            }),
            MutationSyscall::Linkat | MutationSyscall::Link => {
                let to = to.ok_or_else(|| BrokerError::syscall(libc::ENOENT))?;
                let flags = if self == Self::Linkat {
                    args[4].to_i32()
                } else {
                    0
                };
                MutationTarget::new(at, no_follow).map(|from| MutationGrant::Link {
                    from,
                    to,
                    flags,
                })
            }
            MutationSyscall::Symlinkat | MutationSyscall::Symlink => {
                let target = process.read_target(args[0])?;
                Ok(MutationGrant::Symlink { at, target })
            }
            MutationSyscall::Truncate => at.into_target().map(|target| MutationGrant::Truncate {
                target,
                length: args[1].cast_signed(),
            }),
            MutationSyscall::Fchmodat => at.into_target().map(|target| MutationGrant::Chmod {
                target,
                mode: args[2].to_u32(),
            }),
            MutationSyscall::Chmod => at.into_target().map(|target| MutationGrant::Chmod {
                target,
                mode: args[1].to_u32(),
            }),
            _ => {
                let mutation = self.path_mutation(process, args)?;
                MutationTarget::new(at, no_follow)
                    .map(|target| MutationGrant::Metadata { target, mutation })
            }
        };

        Ok(Grant::Mutation(operation))
    }

    fn path_mutation(self, process: &TargetProcess, args: &[u64; 6]) -> SysResult<PathMutation> {
        Ok(match self {
            Self::Fchmodat2 => PathMutation::ChmodAt {
                mode: args[2].to_u32(),
            },
            Self::Fchownat => PathMutation::ChownAt {
                uid: args[2].to_u32(),
                gid: args[3].to_u32(),
            },
            Self::Chown | Self::Lchown => PathMutation::Chown {
                uid: args[1].to_u32(),
                gid: args[2].to_u32(),
            },
            Self::Utimensat => PathMutation::Utimes {
                times: process.read_times(args[2])?,
            },
            Self::Setxattr | Self::Lsetxattr => PathMutation::SetXattr {
                name: process.read_xattr_name(args[1])?,
                value: process.read_bytes(args[2], args[3])?,
                flags: args[4].to_i32(),
            },
            Self::Removexattr | Self::Lremovexattr => PathMutation::RemoveXattr {
                name: process.read_xattr_name(args[1])?,
            },
            _ => return Err(BrokerError::syscall(libc::EINVAL)),
        })
    }

    fn fd_mutation(self, process: &TargetProcess, args: &[u64; 6]) -> SysResult<FdMutation> {
        Ok(match self {
            Self::Fchmod => FdMutation::Chmod {
                mode: args[1].to_u32(),
            },
            Self::Fchmodat2 => FdMutation::ChmodAt {
                mode: args[2].to_u32(),
                flags: args[3].to_i32(),
            },
            Self::Fchown => FdMutation::Chown {
                uid: args[1].to_u32(),
                gid: args[2].to_u32(),
            },
            Self::Fchownat => FdMutation::ChownAt {
                uid: args[2].to_u32(),
                gid: args[3].to_u32(),
                flags: args[4].to_i32(),
            },
            Self::Utimensat => FdMutation::Utimes {
                times: process.read_times(args[2])?,
            },
            Self::Fsetxattr => FdMutation::SetXattr {
                name: process.read_xattr_name(args[1])?,
                value: process.read_bytes(args[2], args[3])?,
                flags: args[4].to_i32(),
            },
            Self::Fremovexattr => FdMutation::RemoveXattr {
                name: process.read_xattr_name(args[1])?,
            },
            _ => return Err(BrokerError::syscall(libc::EINVAL)),
        })
    }

    fn validate_flags(self, args: &[u64; 6]) -> SysResult<()> {
        let flags = match self {
            Self::Fchmodat2 | Self::Utimensat => args[3].to_i32(),
            Self::Fchownat => args[4].to_i32(),
            _ => return Ok(()),
        };
        if flags & !(libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW) != 0 {
            return Err(BrokerError::syscall(libc::EINVAL));
        }
        Ok(())
    }

    fn empty_path_uses_fd(self, args: &[u64; 6], path: &Path) -> SysResult<bool> {
        if !path.as_os_str().is_empty() {
            return Ok(false);
        }
        let flags = match self {
            Self::Fchmodat2 => args[3].to_i32(),
            Self::Fchownat => args[4].to_i32(),
            _ => 0,
        };
        if flags & libc::AT_EMPTY_PATH != 0 {
            Ok(true)
        } else {
            Err(BrokerError::syscall(libc::ENOENT))
        }
    }
}
