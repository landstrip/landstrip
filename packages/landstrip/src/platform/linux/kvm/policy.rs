// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Filesystem policy mediation for the syscall broker.
//!
//! Every path the payload names is resolved to the lexical and canonical forms
//! the policy rules are written against, and refused with `EACCES` when the
//! policy does not grant the access. A path the broker cannot resolve is left
//! to the kernel, which answers with the error the payload would have seen
//! without a broker.

use crate::paths::PathExt;
use crate::policy::exec_state::Rules;
use crate::policy::{AccessPolicy, DenialReason};
use crate::trap::ProcessContext;
use anyhow::Result;
use bitflags::bitflags;
use linux_raw_sys::general::{
    RESOLVE_BENEATH, RESOLVE_CACHED, RESOLVE_IN_ROOT, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS,
    RESOLVE_NO_XDEV, open_how,
};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, readlinkat};
use nix::sys::stat::{fstat, fstatat};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Error the guest sees when the policy refuses an access.
pub(crate) const DENIED: syscalls::Errno = syscalls::Errno::EACCES;

/// Kind of access a syscall asks for.
#[derive(Clone, Copy)]
pub(crate) enum Access {
    Read,
    Write,
}

impl Access {
    pub(crate) const fn from_open_flags(flags: i32) -> Self {
        const WRITES: i32 = libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND;
        if flags & libc::O_ACCMODE == libc::O_RDONLY && flags & WRITES == 0 {
            Self::Read
        } else {
            Self::Write
        }
    }
}

/// Whether a syscall reaches the rules when the entry it names is missing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Missing {
    /// The kernel answers `ENOENT`, and nothing is reported: the payload
    /// learns nothing the filesystem does not already tell it.
    Kernel,
    /// The syscall creates or removes the entry, so the rules classify it
    /// whether or not it exists.
    Rules,
}

/// What a mutation does, in the terms the rules distinguish.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mutation {
    /// Creates a directory, which an existing name answers with `EEXIST`.
    Mkdir,
    /// Removes a name, which a missing one answers with `ENOENT`.
    Removal,
    /// Moves or links one name to another.
    Reparent,
    /// Rewrites the metadata of the name.
    Metadata,
}

/// A guest path resolved to the forms the rules are written against.
pub(crate) struct Resolved {
    /// The canonical path the rules match, with the entry itself as spelled
    /// when the syscall does not follow it.
    pub(crate) label: PathBuf,
    /// The path as the payload spelled it, cleaned lexically.
    pub(crate) lexical: PathBuf,
    /// Whether the entry the path names exists.
    pub(crate) present: bool,
}

pub(crate) enum Resolution {
    Kernel,
    Unclassified,
    Unresolvable(PathBuf),
    Resolved(Resolved),
}

bitflags! {
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct ResolveFlags: u64 {
        const NO_XDEV = RESOLVE_NO_XDEV as u64;
        const NO_MAGICLINKS = RESOLVE_NO_MAGICLINKS as u64;
        const NO_SYMLINKS = RESOLVE_NO_SYMLINKS as u64;
        const BENEATH = RESOLVE_BENEATH as u64;
        const IN_ROOT = RESOLVE_IN_ROOT as u64;
        const CACHED = RESOLVE_CACHED as u64;
    }
}

impl ResolveFlags {
    pub(crate) const fn has_no_symlinks(self) -> bool {
        self.contains(Self::NO_SYMLINKS)
    }

    const fn is_beneath(self) -> bool {
        self.contains(Self::BENEATH)
    }

    const fn is_scoped(self) -> bool {
        self.intersects(Self::BENEATH.union(Self::IN_ROOT))
    }

    const fn is_valid(self) -> bool {
        Self::from_bits(self.bits()).is_some() && !self.contains(Self::BENEATH.union(Self::IN_ROOT))
    }

    fn append_scoped(self, root_base: &Path, base: &Path, parts: &[&[u8]]) -> Option<PathBuf> {
        let mut stack: Vec<PathBuf> = Vec::new();
        if let Ok(rel) = base.strip_prefix(root_base) {
            for comp in rel.components() {
                stack.push(PathBuf::from(comp.as_os_str()));
            }
        }
        for &part in parts {
            match part {
                b"" | b"." => {}
                b".." => {
                    if stack.pop().is_none() && self.is_beneath() {
                        return None;
                    }
                }
                other => stack.push(PathBuf::from(OsStr::from_bytes(other))),
            }
        }
        let mut out = root_base.to_path_buf();
        for item in stack {
            out.push(item);
        }
        Some(out.clean_lexically())
    }

    fn lexical_path(self, root_base: &Path, path: &Path) -> Option<PathBuf> {
        if self.is_scoped() {
            let parts: Vec<&[u8]> = path
                .as_os_str()
                .as_bytes()
                .split(|&byte| byte == b'/')
                .collect();
            return self.append_scoped(root_base, root_base, &parts);
        }
        let joined = if path.is_absolute() {
            path.to_path_buf()
        } else {
            root_base.join(path)
        };
        Some(joined.clean_lexically())
    }
}

struct ProbeOpen;

impl ProbeOpen {
    fn open(
        dirfd: RawFd,
        path: &Path,
        follow: bool,
        directory: bool,
        resolve: ResolveFlags,
    ) -> Result<super::fds::BrokerFd, i32> {
        let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
        let mut open_flags = libc::O_PATH | libc::O_CLOEXEC;
        if !follow {
            open_flags |= libc::O_NOFOLLOW;
        }
        if directory {
            open_flags |= libc::O_DIRECTORY;
        }
        let how = open_how {
            flags: u64::from(open_flags.cast_unsigned()),
            mode: 0,
            resolve: (resolve - ResolveFlags::CACHED).bits(),
        };
        let _fd_lock = super::fds::GuestFd::read_fd_table();
        let rc = unsafe {
            syscalls::syscall!(
                syscalls::Sysno::openat2,
                dirfd.cast_unsigned() as usize,
                cpath.as_ptr().expose_provenance(),
                (&raw const how).expose_provenance(),
                std::mem::size_of::<open_how>()
            )
        }
        .map_err(syscalls::Errno::into_raw)?;
        let raw = RawFd::try_from(rc).map_err(|_| libc::EMFILE)?;
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        super::fds::GuestFd::relocate_above(owned)
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EMFILE))
    }

    fn label_from_fd(fd: BorrowedFd<'_>, fallback: &Path) -> Result<PathBuf, PathBuf> {
        match FdLabel::resolve(fd) {
            Ok(FdLabel::Linked(label) | FdLabel::Unlinked(label)) => Ok(label),
            Ok(FdLabel::Relinked { path, dev, ino }) => {
                FdLabel::surviving_link(&path, dev, ino).ok_or(path)
            }
            Ok(FdLabel::Anonymous) => Ok(fallback.to_path_buf()),
            Err(()) => Err(fallback.to_path_buf()),
        }
    }

    fn creation_target(
        dirfd: RawFd,
        path: &Path,
        resolve: ResolveFlags,
    ) -> Result<Cow<'_, Path>, i32> {
        const MAX_SYMLINKS: usize = 40;
        let mut target = Cow::Borrowed(path);
        for _ in 0..=MAX_SYMLINKS {
            let fd = match Self::open(dirfd, &target, false, false, resolve) {
                Ok(fd) => fd,
                Err(libc::ENOENT | libc::ENOTDIR) => return Ok(target),
                Err(errno) => return Err(errno),
            };
            let link = match readlinkat(&fd, "") {
                Ok(link) => PathBuf::from(link),
                Err(Errno::EINVAL) => return Ok(target),
                Err(errno) => return Err(errno as i32),
            };
            if link.is_absolute() {
                if resolve.is_beneath() {
                    return Err(libc::EXDEV);
                }
                target = Cow::Owned(link);
            } else {
                let raw = target.as_os_str().as_bytes();
                let prefix = raw.iter().rposition(|&byte| byte == b'/');
                let parent = prefix.map_or(b"".as_slice(), |index| &raw[..=index]);
                target = Cow::Owned(Path::new(OsStr::from_bytes(parent)).join(link));
            }
        }
        Err(libc::ELOOP)
    }

    fn resolve_missing(
        dirfd: RawFd,
        root_base: &Path,
        path: &Path,
        resolve: ResolveFlags,
        lexical: PathBuf,
    ) -> Resolution {
        let mut current = path.as_os_str().as_bytes();
        while current.len() > 1 && current.ends_with(b"/") {
            current = &current[..current.len() - 1];
        }
        let mut tail: Vec<&[u8]> = Vec::new();
        loop {
            if let Some(slash) = current.iter().rposition(|&byte| byte == b'/') {
                let name = &current[slash + 1..];
                if !name.is_empty() {
                    tail.push(name);
                }
                current = if slash == 0 { b"/" } else { &current[..slash] };
            } else {
                if !current.is_empty() {
                    tail.push(current);
                }
                current = b".";
            }
            let probe_path = Path::new(OsStr::from_bytes(current));
            match Self::open(dirfd, probe_path, true, true, resolve) {
                Ok(opened) => {
                    let dir_label = match Self::label_from_fd(opened.as_fd(), root_base) {
                        Ok(label) => label,
                        Err(unres) => return Resolution::Unresolvable(unres),
                    };
                    tail.reverse();
                    let label = if resolve.is_scoped() {
                        let Some(scoped) = resolve.append_scoped(root_base, &dir_label, &tail)
                        else {
                            return Resolution::Kernel;
                        };
                        scoped
                    } else {
                        let mut out = dir_label;
                        for part in tail {
                            out.push(OsStr::from_bytes(part));
                        }
                        out.clean_lexically()
                    };
                    return Resolution::Resolved(Resolved {
                        label,
                        lexical,
                        present: false,
                    });
                }
                Err(errno)
                    if (errno == libc::ENOENT || errno == libc::EACCES)
                        && current != b"."
                        && current != b"/" => {}
                Err(errno) if errno == libc::ENOENT || errno == libc::EACCES => {
                    tail.reverse();
                    let anchor = if current == b"/" && !resolve.is_scoped() {
                        Path::new("/")
                    } else {
                        root_base
                    };
                    let label = if resolve.is_scoped() {
                        let Some(scoped) = resolve.append_scoped(root_base, anchor, &tail) else {
                            return Resolution::Kernel;
                        };
                        scoped
                    } else {
                        let mut out = anchor.to_path_buf();
                        for part in tail {
                            out.push(OsStr::from_bytes(part));
                        }
                        out.clean_lexically()
                    };
                    return Resolution::Resolved(Resolved {
                        label,
                        lexical,
                        present: false,
                    });
                }
                Err(_) => return Resolution::Kernel,
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum DirBase<'a> {
    Cwd,
    Guest(i64),
    Pinned(BorrowedFd<'a>),
    Invalid,
}

impl DirBase<'_> {
    pub(crate) fn from_opt(dirfd: Option<i64>) -> Self {
        match dirfd {
            None => Self::Cwd,
            Some(fd) if fd == i64::from(libc::AT_FDCWD) => Self::Cwd,
            Some(fd) => Self::Guest(fd),
        }
    }
}

pub(crate) struct Policy {
    rules: AccessPolicy,
    cwd: PathBuf,
    cwd_lock: RwLock<()>,
    exe: RwLock<PathBuf>,
    abstract_sockets: RwLock<HashSet<Vec<u8>>>,
}

#[derive(Deserialize, Serialize)]
pub(super) struct ExecPolicy {
    rules: Rules,
    cwd: OsString,
    exe: OsString,
    abstract_sockets: HashSet<Vec<u8>>,
}

impl ExecPolicy {
    pub(super) fn restore(self) -> Result<Policy> {
        Ok(Policy {
            rules: self.rules.restore()?,
            cwd: self.cwd.into(),
            cwd_lock: RwLock::new(()),
            exe: RwLock::new(self.exe.into()),
            abstract_sockets: RwLock::new(self.abstract_sockets),
        })
    }
}

/// A refused access, described the way a trap record reports it.
pub(crate) struct Denial {
    pub(crate) access: Access,
    pub(crate) path: PathBuf,
    pub(crate) requested_path: PathBuf,
    pub(crate) reason: DenialReason,
    /// Whether the refusal rests on a rule the payload cannot argue with. A
    /// denial that is not is offered to a responder before it stands.
    pub(crate) queryable: bool,
}

impl Denial {
    pub(crate) fn unresolvable(access: Access, path: PathBuf) -> Self {
        Self {
            access,
            path: path.clone(),
            requested_path: path,
            reason: DenialReason::AllowMiss,
            queryable: true,
        }
    }
}

impl Policy {
    pub(crate) fn new(policy: &AccessPolicy, cwd: &Path, exe: &Path) -> Self {
        Self {
            rules: policy.clone(),
            cwd: cwd.to_path_buf(),
            cwd_lock: RwLock::new(()),
            exe: RwLock::new(exe.to_path_buf()),
            abstract_sockets: RwLock::new(HashSet::new()),
        }
    }

    pub(crate) fn snapshot(&self) -> Self {
        Self {
            rules: self.rules.clone(),
            cwd: self.cwd.clone(),
            cwd_lock: RwLock::new(()),
            exe: RwLock::new(self.exe()),
            abstract_sockets: RwLock::new(
                self.abstract_sockets
                    .read()
                    .map_or_else(|poisoned| poisoned.into_inner().clone(), |set| set.clone()),
            ),
        }
    }
    pub(crate) fn read_cwd(&self) -> RwLockReadGuard<'_, ()> {
        self.cwd_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn write_cwd(&self) -> RwLockWriteGuard<'_, ()> {
        self.cwd_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn exec_state(&self) -> ExecPolicy {
        ExecPolicy {
            rules: Rules::save(&self.rules),
            cwd: self.cwd.as_os_str().to_owned(),
            exe: self.exe().into_os_string(),
            abstract_sockets: self
                .abstract_sockets
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        }
    }

    pub(crate) fn denial_at(
        &self,
        dir: DirBase<'_>,
        path: &Path,
        access: Access,
        follow: bool,
        missing: Missing,
    ) -> Option<Denial> {
        let resolved = match self.resolve_at(dir, path, follow, ResolveFlags::empty()) {
            Resolution::Kernel | Resolution::Unclassified => return None,
            Resolution::Unresolvable(unres) => return Some(Denial::unresolvable(access, unres)),
            Resolution::Resolved(resolved) => resolved,
        };
        if Self::is_forbidden_proc_or_internal(&resolved.label)
            || Self::is_forbidden_proc_or_internal(&resolved.lexical)
        {
            return Some(Denial {
                access,
                path: resolved.label,
                requested_path: resolved.lexical,
                reason: DenialReason::DenyMatch,
                queryable: false,
            });
        }
        if missing == Missing::Kernel && !resolved.present {
            return None;
        }
        let reason = self.reason(access, &resolved)?;
        let queryable = !self.hard(access, &resolved);
        Some(Denial {
            access,
            path: resolved.label,
            requested_path: resolved.lexical,
            reason,
            queryable,
        })
    }

    pub(crate) fn open_denials_at(
        &self,
        dir: DirBase<'_>,
        path: &Path,
        flags: i32,
        follow: bool,
        resolve: ResolveFlags,
        missing: Missing,
    ) -> Vec<Denial> {
        const WRITES: i32 = libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC;
        let access = Access::from_open_flags(flags);
        let creating = follow && flags & libc::O_CREAT != 0;
        let resolution = if creating && !resolve.is_empty() {
            self.resolve_scoped_at(dir, path, follow, resolve, true)
        } else {
            match self.resolve_at(dir, path, follow, resolve) {
                Resolution::Resolved(resolved) if creating && !resolved.present => {
                    self.resolve_scoped_at(dir, path, follow, resolve, true)
                }
                resolution => resolution,
            }
        };
        let resolved = match resolution {
            Resolution::Kernel | Resolution::Unclassified => return Vec::new(),
            Resolution::Unresolvable(unres) => {
                let mut denial = Denial::unresolvable(access, unres);
                denial.queryable = !creating && !Self::is_broker_proc_self_fd(&denial.path);
                return vec![denial];
            }
            Resolution::Resolved(resolved) => resolved,
        };
        if Self::is_forbidden_proc_or_internal(&resolved.label)
            || Self::is_forbidden_proc_or_internal(&resolved.lexical)
        {
            return vec![Denial {
                access,
                path: resolved.label,
                requested_path: resolved.lexical,
                reason: DenialReason::DenyMatch,
                queryable: false,
            }];
        }
        if missing == Missing::Kernel && !resolved.present {
            return Vec::new();
        }
        let rules = &self.rules;
        let wants_write = flags & WRITES != 0;
        let wants_read = flags & libc::O_WRONLY == 0;
        let hard_read = wants_read
            && rules
                .read_denials
                .is_denied_always(&resolved.label, &resolved.lexical);
        let hard_write = wants_write
            && rules
                .write_denials
                .is_denied_always(&resolved.label, &resolved.lexical);
        let queryable = !hard_read && !hard_write;
        let mut denials = Vec::new();
        if wants_read
            && (!hard_write || hard_read)
            && let Some(reason) = rules.read_access_reason(&resolved.label, &resolved.lexical)
        {
            denials.push(Denial {
                access: Access::Read,
                path: resolved.label.clone(),
                requested_path: resolved.lexical.clone(),
                reason,
                queryable,
            });
            if !queryable {
                return denials;
            }
        }
        if wants_write && let Some(reason) = rules.write_reason(&resolved.label, true) {
            denials.push(Denial {
                access: Access::Write,
                path: resolved.label,
                requested_path: resolved.lexical,
                reason,
                queryable,
            });
        }
        denials
    }

    fn hard(&self, access: Access, resolved: &Resolved) -> bool {
        match access {
            Access::Read => self
                .rules
                .read_denials
                .is_denied_always(&resolved.label, &resolved.lexical),
            Access::Write => self
                .rules
                .write_denials
                .is_denied_always(&resolved.label, &resolved.lexical),
        }
    }

    pub(crate) fn resolved(&self, dirfd: i64, path: &Path, follow: bool) -> Option<Resolved> {
        match self.resolve_at(DirBase::Guest(dirfd), path, follow, ResolveFlags::empty()) {
            Resolution::Resolved(resolved) => Some(resolved),
            Resolution::Kernel | Resolution::Unclassified | Resolution::Unresolvable(_) => None,
        }
    }

    pub(crate) fn resolve_at(
        &self,
        dir: DirBase<'_>,
        path: &Path,
        follow: bool,
        resolve: ResolveFlags,
    ) -> Resolution {
        if !resolve.is_empty() {
            return self.resolve_scoped_at(dir, path, follow, resolve, false);
        }
        let base = if path.is_absolute() {
            None
        } else {
            match dir {
                DirBase::Cwd => Some(self.cwd()),
                DirBase::Guest(fd) if fd == i64::from(libc::AT_FDCWD) => Some(self.cwd()),
                DirBase::Guest(fd) => match DescriptorTarget::resolve(fd) {
                    DescriptorTarget::Path(base) => Some(base),
                    DescriptorTarget::Unresolvable(unres) => {
                        return Resolution::Unresolvable(unres);
                    }
                    DescriptorTarget::Unclassified => return Resolution::Unclassified,
                    DescriptorTarget::Invalid => return Resolution::Kernel,
                },
                DirBase::Pinned(fd) => match DescriptorTarget::resolve_borrowed(fd) {
                    DescriptorTarget::Path(base) => Some(base),
                    DescriptorTarget::Unresolvable(unres) => {
                        return Resolution::Unresolvable(unres);
                    }
                    DescriptorTarget::Unclassified => return Resolution::Unclassified,
                    DescriptorTarget::Invalid => return Resolution::Kernel,
                },
                DirBase::Invalid => return Resolution::Kernel,
            }
        };
        let joined = match base {
            Some(base) => base.join(path),
            None => path.to_path_buf(),
        };
        let lexical = joined.clean_lexically();
        if Self::is_broker_proc_self_fd(&lexical) {
            return Resolution::Unresolvable(lexical);
        }
        let proc_dir = if path.is_absolute() {
            DirBase::Cwd
        } else {
            dir
        };
        if follow && self.is_proc_self_exe_at(proc_dir, path.as_os_str().as_bytes(), true) {
            return Resolution::Resolved(Resolved {
                label: self.exe(),
                lexical,
                present: true,
            });
        }
        if follow {
            if let Some(resolution) = Self::resolve_proc_self_fd(&lexical, true) {
                return resolution;
            }
            let canonical = fs::canonicalize(&lexical);
            if canonical.is_err()
                && let Some(resolution) = Self::resolve_proc_self_fd(&lexical, false)
            {
                return resolution;
            }
            let label = canonical.unwrap_or_else(|_| lexical.canonicalize_existing_prefix());
            let present = Resolved::exists_at(dir, path, true);
            return Resolution::Resolved(Resolved {
                label,
                lexical,
                present,
            });
        }
        let label = Resolved::without_follow(&lexical);
        let present = Resolved::exists_at(dir, path, false);
        Resolution::Resolved(Resolved {
            label,
            lexical,
            present,
        })
    }

    fn resolve_scoped_at(
        &self,
        dir: DirBase<'_>,
        path: &Path,
        follow: bool,
        resolve: ResolveFlags,
        creating: bool,
    ) -> Resolution {
        if !resolve.is_valid() || (resolve.is_beneath() && path.is_absolute()) {
            return Resolution::Kernel;
        }
        let (raw_dirfd, root_base) = if !resolve.is_scoped() && path.is_absolute() {
            (libc::AT_FDCWD, PathBuf::from("/"))
        } else {
            match dir {
                DirBase::Cwd => (libc::AT_FDCWD, self.cwd()),
                DirBase::Guest(fd) if fd == i64::from(libc::AT_FDCWD) => {
                    (libc::AT_FDCWD, self.cwd())
                }
                DirBase::Guest(fd) => match DescriptorTarget::resolve(fd) {
                    DescriptorTarget::Path(base) => {
                        let Ok(raw) = RawFd::try_from(fd) else {
                            return Resolution::Kernel;
                        };
                        (raw, base)
                    }
                    DescriptorTarget::Unresolvable(unres) => {
                        return Resolution::Unresolvable(unres);
                    }
                    DescriptorTarget::Unclassified => return Resolution::Unclassified,
                    DescriptorTarget::Invalid => return Resolution::Kernel,
                },
                DirBase::Pinned(fd) => match DescriptorTarget::resolve_borrowed(fd) {
                    DescriptorTarget::Path(base) => (fd.as_raw_fd(), base),
                    DescriptorTarget::Unresolvable(unres) => {
                        return Resolution::Unresolvable(unres);
                    }
                    DescriptorTarget::Unclassified => return Resolution::Unclassified,
                    DescriptorTarget::Invalid => return Resolution::Kernel,
                },
                DirBase::Invalid => return Resolution::Kernel,
            }
        };
        let Some(lexical) = resolve.lexical_path(&root_base, path) else {
            return Resolution::Kernel;
        };
        if Self::is_broker_proc_self_fd(&lexical) {
            return Resolution::Unresolvable(lexical);
        }
        match ProbeOpen::open(raw_dirfd, path, follow, false, resolve) {
            Ok(fd) => {
                if follow && matches!(FdLabel::resolve(fd.as_fd()), Ok(FdLabel::Anonymous)) {
                    return Resolution::Kernel;
                }
                match ProbeOpen::label_from_fd(fd.as_fd(), &lexical) {
                    Ok(label) => Resolution::Resolved(Resolved {
                        label,
                        lexical,
                        present: true,
                    }),
                    Err(unres) => Resolution::Unresolvable(unres),
                }
            }
            Err(libc::ENOENT) if creating => {
                let Ok(target) = ProbeOpen::creation_target(raw_dirfd, path, resolve) else {
                    return Resolution::Unresolvable(lexical);
                };
                ProbeOpen::resolve_missing(raw_dirfd, &root_base, &target, resolve, lexical)
            }
            Err(errno) if errno == libc::ENOENT || errno == libc::EACCES => {
                ProbeOpen::resolve_missing(raw_dirfd, &root_base, path, resolve, lexical)
            }
            Err(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOSYS) => {
                Resolution::Unresolvable(lexical)
            }
            Err(_) => Resolution::Kernel,
        }
    }

    pub(crate) fn rules(&self) -> &AccessPolicy {
        &self.rules
    }

    pub(crate) fn resolve_descriptor_at(&self, dir: DirBase<'_>) -> Resolution {
        let target = match dir {
            DirBase::Cwd => {
                return self.resolve_at(DirBase::Cwd, Path::new("."), true, ResolveFlags::empty());
            }
            DirBase::Guest(fd) if fd == i64::from(libc::AT_FDCWD) => {
                return self.resolve_at(DirBase::Cwd, Path::new("."), true, ResolveFlags::empty());
            }
            DirBase::Guest(fd) => DescriptorTarget::resolve(fd),
            DirBase::Pinned(fd) => DescriptorTarget::resolve_borrowed(fd),
            DirBase::Invalid => return Resolution::Kernel,
        };
        match target {
            DescriptorTarget::Path(label) if label.is_absolute() => {
                Resolution::Resolved(Resolved {
                    lexical: label.clone(),
                    label,
                    present: true,
                })
            }
            DescriptorTarget::Unresolvable(unres) => Resolution::Unresolvable(unres),
            DescriptorTarget::Unclassified => Resolution::Unclassified,
            DescriptorTarget::Invalid | DescriptorTarget::Path(_) => Resolution::Kernel,
        }
    }

    pub(crate) fn descriptor_denial_at(&self, dir: DirBase<'_>, access: Access) -> Option<Denial> {
        let target = match dir {
            DirBase::Cwd => {
                return self.denial_at(DirBase::Cwd, Path::new("."), access, true, Missing::Rules);
            }
            DirBase::Guest(fd) if fd == i64::from(libc::AT_FDCWD) => {
                return self.denial_at(DirBase::Cwd, Path::new("."), access, true, Missing::Rules);
            }
            DirBase::Guest(fd) => DescriptorTarget::resolve(fd),
            DirBase::Pinned(fd) => DescriptorTarget::resolve_borrowed(fd),
            DirBase::Invalid => return None,
        };
        match target {
            DescriptorTarget::Path(path) if path.is_absolute() => {
                self.denial_at(DirBase::Cwd, &path, access, true, Missing::Rules)
            }
            DescriptorTarget::Invalid
            | DescriptorTarget::Unclassified
            | DescriptorTarget::Path(_) => None,
            DescriptorTarget::Unresolvable(path) => Some(Denial {
                access,
                path: path.clone(),
                requested_path: path,
                reason: DenialReason::AllowMiss,
                queryable: true,
            }),
        }
    }

    pub(crate) fn borrowed_descriptor_denial(
        &self,
        fd: BorrowedFd<'_>,
        access: Access,
    ) -> Option<Denial> {
        self.descriptor_denial_at(DirBase::Pinned(fd), access)
    }

    pub(crate) fn descriptor_open_denials(&self, fd: i64, flags: i32) -> Vec<Denial> {
        self.descriptor_open_denials_at(DirBase::Guest(fd), flags)
    }

    pub(crate) fn descriptor_open_denials_at(&self, dir: DirBase<'_>, flags: i32) -> Vec<Denial> {
        let access = Access::from_open_flags(flags);
        let target = match dir {
            DirBase::Cwd => {
                return self.open_denials_at(
                    DirBase::Cwd,
                    Path::new("."),
                    flags,
                    true,
                    ResolveFlags::empty(),
                    Missing::Rules,
                );
            }
            DirBase::Guest(fd) if fd == i64::from(libc::AT_FDCWD) => {
                return self.open_denials_at(
                    DirBase::Cwd,
                    Path::new("."),
                    flags,
                    true,
                    ResolveFlags::empty(),
                    Missing::Rules,
                );
            }
            DirBase::Guest(fd) => DescriptorTarget::resolve(fd),
            DirBase::Pinned(fd) => DescriptorTarget::resolve_borrowed(fd),
            DirBase::Invalid => return Vec::new(),
        };
        match target {
            DescriptorTarget::Path(path) if path.is_absolute() => self.open_denials_at(
                DirBase::Cwd,
                &path,
                flags,
                true,
                ResolveFlags::empty(),
                Missing::Rules,
            ),
            DescriptorTarget::Invalid
            | DescriptorTarget::Unclassified
            | DescriptorTarget::Path(_) => Vec::new(),
            DescriptorTarget::Unresolvable(path) => vec![Denial {
                access,
                path: path.clone(),
                requested_path: path,
                reason: DenialReason::AllowMiss,
                queryable: true,
            }],
        }
    }

    /// Names the program an `execve` replaced the payload with.
    pub(crate) fn set_exe(&self, exe: &Path) {
        if let Ok(mut current) = self.exe.write() {
            *current = exe.to_path_buf();
        }
    }

    /// The program the guest runs, as traps report it.
    pub(crate) fn exe(&self) -> PathBuf {
        self.exe
            .read()
            .map_or_else(|poisoned| poisoned.into_inner().clone(), |exe| exe.clone())
    }

    pub(crate) fn record_abstract_socket(&self, name: &[u8]) {
        if let Ok(mut set) = self.abstract_sockets.write() {
            set.insert(name.to_vec());
        }
    }

    pub(crate) fn owns_abstract_socket(&self, name: &[u8]) -> bool {
        self.abstract_sockets.read().map_or_else(
            |poisoned| poisoned.into_inner().contains(name),
            |set| set.contains(name),
        )
    }

    /// The working directory guest paths are resolved against.
    ///
    /// The broker forwards the payload's `chdir` to the host kernel, so both
    /// resolve relative paths against the same directory.
    pub(crate) fn cwd(&self) -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| self.cwd.clone())
    }

    fn join_base(&self, dir: DirBase<'_>, candidate: &Path) -> Option<PathBuf> {
        if candidate.is_absolute() {
            return Some(candidate.clean_lexically());
        }
        match dir {
            DirBase::Cwd => Some(self.cwd().join(candidate).clean_lexically()),
            DirBase::Guest(fd) if fd == i64::from(libc::AT_FDCWD) => {
                Some(self.cwd().join(candidate).clean_lexically())
            }
            DirBase::Guest(fd) => match DescriptorTarget::resolve(fd) {
                DescriptorTarget::Path(base) => Some(base.join(candidate).clean_lexically()),
                _ => None,
            },
            DirBase::Pinned(fd) => match DescriptorTarget::resolve_borrowed(fd) {
                DescriptorTarget::Path(base) => Some(base.join(candidate).clean_lexically()),
                _ => None,
            },
            DirBase::Invalid => None,
        }
    }

    pub(crate) fn is_proc_self_exe_at(
        &self,
        dir: DirBase<'_>,
        raw_path: &[u8],
        follow: bool,
    ) -> bool {
        const MAX_SYMLINKS: usize = 40;
        let candidate = Path::new(OsStr::from_bytes(raw_path));
        let Some(mut current) = self.join_base(dir, candidate) else {
            return false;
        };
        let self_root = PathBuf::from(format!("/proc/{}", std::process::id()));
        let limit = if follow { MAX_SYMLINKS } else { 0 };
        for _ in 0..=limit {
            let Some(parent) = current.parent() else {
                return false;
            };
            let Some(name) = current.file_name() else {
                return false;
            };
            if name == OsStr::new("exe")
                && let Ok(canon_parent) = fs::canonicalize(parent)
                && (canon_parent == self_root
                    || canon_parent
                        .strip_prefix(&self_root)
                        .ok()
                        .is_some_and(|rel| {
                            rel.starts_with("task") && rel.components().count() == 2
                        }))
            {
                return true;
            }
            if !follow {
                return false;
            }
            let Ok(target) = fs::read_link(&current) else {
                return false;
            };
            current = if target.is_absolute() {
                target.clean_lexically()
            } else {
                parent.join(target).clean_lexically()
            };
        }
        false
    }
    pub(crate) fn has_forbidden_proc_target_at(
        &self,
        dir: DirBase<'_>,
        path: &Path,
        follow: bool,
    ) -> bool {
        match self.resolve_at(dir, path, follow, ResolveFlags::empty()) {
            Resolution::Resolved(resolved) => {
                Self::is_forbidden_proc_or_internal(&resolved.label)
                    || Self::is_forbidden_proc_or_internal(&resolved.lexical)
            }
            Resolution::Unresolvable(unres) => Self::is_forbidden_proc_or_internal(&unres),
            Resolution::Kernel | Resolution::Unclassified => false,
        }
    }

    pub(crate) fn is_forbidden_proc_or_internal(path: &Path) -> bool {
        if let Ok(rel) = path.strip_prefix("/tmp")
            && let Some(first) = rel.components().next()
            && first.as_os_str().as_bytes().starts_with(b"landstrip-dbus-")
        {
            return true;
        }
        let Ok(rel) = path.strip_prefix("/proc") else {
            return false;
        };
        let mut comps = rel.components().map(|c| c.as_os_str().to_str());
        let Some(Some(first)) = comps.next() else {
            return false;
        };
        if matches!(first, "kcore" | "kmem" | "keys" | "key-users") {
            return true;
        }
        let is_self = match first {
            "self" | "thread-self" => true,
            _ => match first.parse::<u32>() {
                Ok(pid) => pid == std::process::id(),
                Err(_) => return false,
            },
        };
        let Some(Some(second)) = comps.next() else {
            return false;
        };
        let entry = if second == "task" {
            let Some(Some(_tid)) = comps.next() else {
                return false;
            };
            let Some(Some(task_entry)) = comps.next() else {
                return false;
            };
            task_entry
        } else {
            second
        };
        if matches!(
            entry,
            "mem"
                | "pagemap"
                | "clear_refs"
                | "map_files"
                | "smaps"
                | "smaps_rollup"
                | "numa_maps"
                | "syscall"
                | "stack"
                | "personality"
        ) {
            return true;
        }
        !is_self
            && matches!(
                entry,
                "maps" | "fd" | "fdinfo" | "exe" | "cwd" | "root" | "environ" | "auxv"
            )
    }

    pub(crate) fn is_proc_self_fd_dir(fd: RawFd) -> bool {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
            return false;
        }
        let stat = unsafe { stat.assume_init() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return false;
        }
        let Ok(target) = fs::read_link(format!("/proc/self/fd/{fd}")) else {
            return false;
        };
        let self_root = PathBuf::from(format!("/proc/{}", std::process::id()));
        let Ok(rel) = target.strip_prefix(&self_root) else {
            return false;
        };
        rel == Path::new("fd")
            || rel == Path::new("fdinfo")
            || (rel.starts_with("task")
                && matches!(
                    rel.file_name().and_then(OsStr::to_str),
                    Some("fd" | "fdinfo")
                )
                && rel.components().count() == 3)
    }

    pub(crate) fn is_broker_proc_fd(&self, dirfd: Option<i64>, raw_path: &[u8]) -> bool {
        self.is_broker_proc_fd_at(DirBase::from_opt(dirfd), raw_path)
    }

    pub(crate) fn is_broker_proc_fd_at(&self, dir: DirBase<'_>, raw_path: &[u8]) -> bool {
        let candidate = Path::new(OsStr::from_bytes(raw_path));
        let Some(full) = self.join_base(dir, candidate) else {
            return false;
        };
        Self::is_broker_proc_self_fd(&full)
    }

    fn is_broker_proc_self_fd(lexical: &Path) -> bool {
        Self::proc_self_fd_target(lexical, true)
            .and_then(|(fd, _)| RawFd::try_from(fd).ok())
            .is_some_and(|raw| super::fds::GuestFd::from_raw(raw).is_broker())
    }

    fn resolve_proc_self_fd(lexical: &Path, fast_only: bool) -> Option<Resolution> {
        if fast_only && !lexical.starts_with("/proc") && !lexical.starts_with("/dev") {
            return None;
        }
        let (fd, remainder) = Self::proc_self_fd_target(lexical, false)?;
        if RawFd::try_from(fd)
            .ok()
            .is_some_and(|raw| super::fds::GuestFd::from_raw(raw).is_broker())
        {
            return Some(Resolution::Unresolvable(lexical.to_path_buf()));
        }
        Some(match DescriptorTarget::resolve(fd) {
            DescriptorTarget::Path(label) => {
                let target = if remainder.as_os_str().is_empty() {
                    label
                } else {
                    let joined = label.join(&remainder);
                    fs::canonicalize(&joined)
                        .unwrap_or_else(|_| joined.canonicalize_existing_prefix())
                };
                let present = if remainder.as_os_str().is_empty() {
                    true
                } else {
                    Resolved::exists_at(DirBase::Cwd, &target, true)
                };
                Resolution::Resolved(Resolved {
                    label: target,
                    lexical: lexical.to_path_buf(),
                    present,
                })
            }
            DescriptorTarget::Unresolvable(unres) => Resolution::Unresolvable(unres),
            DescriptorTarget::Unclassified | DescriptorTarget::Invalid => Resolution::Kernel,
        })
    }

    fn proc_self_fd_target(path: &Path, include_fdinfo: bool) -> Option<(i64, PathBuf)> {
        const MAX_SYMLINKS: usize = 40;
        let self_root = PathBuf::from(format!("/proc/{}", std::process::id()));
        let mut current = path.clean_lexically();
        for _ in 0..=MAX_SYMLINKS {
            if let Some(hit) = Self::match_proc_self_fd(&current, &self_root, include_fdinfo) {
                return Some(hit);
            }
            if let Ok(rel) = current.strip_prefix("/dev/fd")
                && let Some(first) = rel.components().next()
                && let Ok(fd) = first.as_os_str().to_str()?.parse::<i64>()
            {
                let mut rest = PathBuf::new();
                for comp in rel.components().skip(1) {
                    rest.push(comp.as_os_str());
                }
                return Some((fd, rest));
            }
            let parent = current.parent()?;
            let Ok(target) = fs::read_link(&current) else {
                return None;
            };
            current = if target.is_absolute() {
                target.clean_lexically()
            } else {
                parent.join(target).clean_lexically()
            };
        }
        None
    }

    fn match_proc_self_fd(
        path: &Path,
        self_root: &Path,
        include_fdinfo: bool,
    ) -> Option<(i64, PathBuf)> {
        let mut ancestors: Vec<&OsStr> = Vec::new();
        let mut cursor = path;
        while let (Some(parent), Some(name)) = (cursor.parent(), cursor.file_name()) {
            if let Ok(canon_parent) = fs::canonicalize(parent)
                && let Ok(rel) = canon_parent.strip_prefix(self_root)
            {
                let is_fd = rel == Path::new("fd")
                    || (rel.starts_with("task")
                        && rel.file_name() == Some(OsStr::new("fd"))
                        && rel.components().count() == 3);
                let is_fdinfo = include_fdinfo
                    && ancestors.is_empty()
                    && (rel == Path::new("fdinfo")
                        || (rel.starts_with("task")
                            && rel.file_name() == Some(OsStr::new("fdinfo"))
                            && rel.components().count() == 3));
                if is_fd || is_fdinfo {
                    let fd = name.to_str()?.parse::<i64>().ok()?;
                    let mut remainder = PathBuf::new();
                    for part in ancestors.into_iter().rev() {
                        remainder.push(part);
                    }
                    return Some((fd, remainder));
                }
            }
            ancestors.push(name);
            cursor = parent;
            if cursor.as_os_str().is_empty() || cursor == Path::new("/") {
                break;
            }
        }
        None
    }

    pub(crate) fn process_context(&self) -> ProcessContext {
        ProcessContext {
            pid: std::process::id(),
            exe: Some(self.exe().to_string_lossy().into_owned()),
            cwd: Some(self.cwd().to_string_lossy().into_owned()),
        }
    }

    /// Why the rules refuse `access` to a resolved path, if they do.
    fn reason(&self, access: Access, resolved: &Resolved) -> Option<DenialReason> {
        let rules = &self.rules;
        match access {
            Access::Read => rules.read_access_reason(&resolved.label, &resolved.lexical),
            Access::Write => rules.write_reason(&resolved.label, true),
        }
    }
}

impl Mutation {
    pub(crate) fn denial(self, policy: &Policy, paths: &[Resolved]) -> Option<Denial> {
        let rules = policy.rules();
        let reparent = self == Self::Reparent;
        let removal = self == Self::Removal;
        let name_change = reparent || removal;
        let source = paths.first()?;
        let deny = |index: usize, access: Access, reason: DenialReason, queryable: bool| {
            let target = &paths[index];
            Some(Denial {
                access,
                path: target.label.clone(),
                requested_path: target.lexical.clone(),
                reason,
                queryable,
            })
        };

        if let Some(index) = paths.iter().position(|target| {
            Policy::is_forbidden_proc_or_internal(&target.label)
                || Policy::is_forbidden_proc_or_internal(&target.lexical)
        }) {
            return deny(index, Access::Write, DenialReason::DenyMatch, false);
        }
        if name_change
            && let Some(index) = paths.iter().position(|target| {
                rules
                    .read_denials
                    .is_denied_always(&target.label, &target.lexical)
                    || rules.read_denials.has_denied_always_under(&target.label)
            })
        {
            return deny(index, Access::Read, DenialReason::DenyMatch, false);
        }
        if let Some(index) = paths.iter().position(|target| {
            rules
                .write_denials
                .is_denied_always(&target.label, &target.lexical)
                || (reparent && rules.write_denials.has_denied_always_under(&target.label))
        }) {
            return deny(index, Access::Write, DenialReason::DenyMatch, false);
        }
        if name_change
            && let Some(index) = paths.iter().position(|target| {
                rules.is_denied_link_always(&target.lexical)
                    || (target.label != target.lexical
                        && rules.is_denied_link_always(&target.label))
            })
        {
            return deny(index, Access::Write, DenialReason::DenyMatch, false);
        }
        for (index, target) in paths.iter().enumerate() {
            if let Some(reason) = rules.write_reason(&target.label, true) {
                return deny(index, Access::Write, reason, true);
            }
            if reparent && rules.write_denials.has_denied_under(&target.label) {
                return deny(index, Access::Write, DenialReason::DenyMatch, true);
            }
        }
        if name_change
            && let Some(index) = paths.iter().position(|target| {
                rules.is_denied_link(&target.lexical)
                    || (target.label != target.lexical && rules.is_denied_link(&target.label))
            })
        {
            return deny(index, Access::Write, DenialReason::DenyMatch, true);
        }
        if removal {
            if !rules
                .read_denials
                .is_denied_pair(&source.label, &source.lexical)
            {
                return None;
            }
            return deny(0, Access::Read, DenialReason::DenyMatch, true);
        }
        if !reparent {
            return None;
        }
        let unreadable = |target: &Resolved| {
            rules.read_reason(&target.label).or_else(|| {
                rules
                    .read_denials
                    .has_denied_under(&target.label)
                    .then_some(DenialReason::DenyMatch)
            })
        };
        if let Some(reason) = unreadable(source) {
            return deny(0, Access::Read, reason, true);
        }
        let (index, target) = paths.iter().enumerate().nth(1)?;
        let reason = unreadable(target)?;
        deny(index, Access::Read, reason, true)
    }
}

impl Resolved {
    fn exists_at(dir: DirBase<'_>, path: &Path, follow: bool) -> bool {
        let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
        let dirfd = match dir {
            DirBase::Cwd => libc::AT_FDCWD,
            DirBase::Pinned(fd) => fd.as_raw_fd(),
            DirBase::Guest(fd) => i32::try_from(fd)
                .ok()
                .filter(|&fd| !super::fds::GuestFd::from_raw(fd).is_broker())
                .unwrap_or(-1),
            DirBase::Invalid => -1,
        };
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        unsafe { libc::fstatat(dirfd, path.as_ptr(), stat.as_mut_ptr(), flags) == 0 }
    }

    fn without_follow(path: &Path) -> PathBuf {
        match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => parent.normalize().join(name),
            _ => path.normalize(),
        }
    }
}

enum DescriptorTarget {
    Invalid,
    Unclassified,
    Path(PathBuf),
    Unresolvable(PathBuf),
}

impl DescriptorTarget {
    fn resolve(fd: i64) -> Self {
        let Ok(raw) = RawFd::try_from(fd) else {
            return Self::Invalid;
        };
        if raw < 0
            || super::fds::GuestFd::from_raw(raw).is_broker()
            || unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0
        {
            return Self::Invalid;
        }
        Self::resolve_borrowed(unsafe { BorrowedFd::borrow_raw(raw) })
    }

    fn resolve_borrowed(fd: BorrowedFd<'_>) -> Self {
        let Ok(label) = FdLabel::resolve(fd) else {
            return Self::Invalid;
        };
        match label {
            FdLabel::Anonymous => Self::Unclassified,
            FdLabel::Linked(path) | FdLabel::Unlinked(path) => Self::Path(path),
            FdLabel::Relinked { path, dev, ino } => FdLabel::surviving_link(&path, dev, ino)
                .map_or(Self::Unresolvable(path), Self::Path),
        }
    }
}

enum FdLabel {
    Anonymous,
    Linked(PathBuf),
    Unlinked(PathBuf),
    Relinked {
        path: PathBuf,
        dev: libc::dev_t,
        ino: libc::ino_t,
    },
}

impl FdLabel {
    fn memfd_dev() -> Option<libc::dev_t> {
        static DEV: OnceLock<Option<libc::dev_t>> = OnceLock::new();
        *DEV.get_or_init(|| {
            let raw = unsafe { libc::memfd_create(c"landstrip-dev".as_ptr(), libc::MFD_CLOEXEC) };
            if raw < 0 {
                return None;
            }
            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
            fstat(&owned).ok().map(|stat| stat.st_dev)
        })
    }

    fn resolve(fd: BorrowedFd<'_>) -> Result<Self, ()> {
        let proc_path = Path::new("/proc/self/fd").join(fd.as_raw_fd().to_string());
        let label = fs::read_link(proc_path).map_err(|_| ())?;
        if !label.is_absolute() {
            return Ok(Self::Anonymous);
        }
        let raw_bytes = label.as_os_str().as_bytes();
        let Some(path) = raw_bytes.strip_suffix(b" (deleted)") else {
            return Ok(Self::Linked(label));
        };
        let stat = fstat(fd).map_err(|_| ())?;
        if stat.st_nlink == 0
            && raw_bytes.starts_with(b"/memfd:")
            && Self::memfd_dev() == Some(stat.st_dev)
        {
            return Ok(Self::Anonymous);
        }
        let path = PathBuf::from(OsStr::from_bytes(path));
        Ok(if stat.st_nlink == 0 {
            Self::Unlinked(path)
        } else {
            Self::Relinked {
                path,
                dev: stat.st_dev,
                ino: stat.st_ino,
            }
        })
    }

    fn surviving_link(path: &Path, dev: libc::dev_t, ino: libc::ino_t) -> Option<PathBuf> {
        let cpath = CString::new(path.parent()?.as_os_str().as_bytes()).ok()?;
        let dir = {
            let _fd_lock = super::fds::GuestFd::read_fd_table();
            let raw = unsafe {
                libc::open(
                    cpath.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return None;
            }
            let dir = unsafe { OwnedFd::from_raw_fd(raw) };
            super::fds::GuestFd::relocate_above(dir).ok()?
        };
        let Ok(Self::Linked(dir_path)) = Self::resolve(dir.as_fd()) else {
            return None;
        };
        let proc_dir = Path::new("/proc/self/fd").join(dir.as_raw_fd().to_string());
        fs::read_dir(proc_dir)
            .ok()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .find(|name| {
                fstatat(&dir, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .is_ok_and(|stat| stat.st_dev == dev && stat.st_ino == ino)
            })
            .map(|name| dir_path.join(name))
    }
}
