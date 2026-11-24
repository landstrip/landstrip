// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::ErrnoExt;
use super::super::fds::{BrokerFd, GuestFd};
use super::super::machine::{PAGE_BYTES, Regs};
use super::super::memory::{GuestMemory, HostCString};
use super::super::policy::{
    self, Access, Missing, Mutation, Policy, Resolution, ResolveFlags, Resolved,
};
#[cfg(target_arch = "x86_64")]
use super::TIMEVAL_BYTES;
use super::{Arg, Denials, Empty, GuestReg, Process, Request, SyscallArgs, TIMESPEC_BYTES};
use linux_raw_sys::general::open_how;
use std::ffi::{CString, OsStr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use syscalls::{Errno, Sysno};

#[cfg(target_arch = "x86_64")]
const UTIMBUF_BYTES: u64 = std::mem::size_of::<libc::utimbuf>() as u64;

pub(super) trait SysnoExt: Copy {
    fn is_denied(self) -> bool;
    fn is_restartable(self) -> bool;
    fn mutation(self) -> Option<(Mutation, &'static [PathSpec])>;
}

/// One brokered syscall and the arguments it was called with.
#[derive(Clone, Copy)]
pub(super) struct Call<'a> {
    pub(super) process: &'a Process,
    pub(super) sink: &'a Denials,
    pub(super) policy: &'a Policy,
    pub(super) syscall: Sysno,
    pub(super) registers: &'a Regs,
    pub(super) memory: &'a GuestMemory,
}

impl Call<'_> {
    pub(super) fn open_syscall(self) -> Option<u64> {
        let arguments = SyscallArgs::raw(self.registers);
        let status = match self.syscall {
            #[cfg(target_arch = "x86_64")]
            Sysno::open => self.open(None, 0, GuestReg(arguments[1]).as_i32()),
            #[cfg(target_arch = "x86_64")]
            Sysno::creat => self.open(None, 0, libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC),
            Sysno::openat => self.open(
                Some(GuestFd::from_reg(arguments[0]).policy_dirfd()),
                1,
                GuestReg(arguments[2]).as_i32(),
            ),
            Sysno::openat2 => self.openat2(),
            #[cfg(target_arch = "x86_64")]
            Sysno::access => self.access_syscall(&arguments),
            Sysno::faccessat | Sysno::faccessat2 => self.access_syscall(&arguments),
            #[cfg(target_arch = "x86_64")]
            Sysno::readlink => self.readlink_syscall(None, 0, &arguments),
            Sysno::readlinkat => self.readlink_syscall(
                Some(GuestFd::from_reg(arguments[0]).policy_dirfd()),
                1,
                &arguments,
            ),
            Sysno::inotify_add_watch => self.inotify_add_watch_syscall(&arguments),
            _ => return None,
        };
        Some(status)
    }

    pub(super) fn mutation_syscall(self) -> Option<u64> {
        let syscall = self.syscall;
        let args = SyscallArgs::raw(self.registers);
        let status = match syscall {
            Sysno::ftruncate | Sysno::fchmod | Sysno::fchown | Sysno::fallocate => {
                self.check(Request::write_descriptor(0), &[Arg::fd(0)])
            }
            Sysno::flistxattr => self.check(
                Request::xattr_fd(syscall, 0),
                &[Arg::fd(0), Arg::bytes(1, args[2])],
            ),
            Sysno::fsetxattr | Sysno::fgetxattr => self.check(
                Request::xattr_fd(syscall, 0),
                &[Arg::fd(0), Arg::cstr(1), Arg::bytes(2, args[3])],
            ),
            Sysno::fremovexattr => {
                self.check(Request::xattr_fd(syscall, 0), &[Arg::fd(0), Arg::cstr(1)])
            }
            Sysno::listxattr
            | Sysno::llistxattr
            | Sysno::setxattr
            | Sysno::lsetxattr
            | Sysno::getxattr
            | Sysno::lgetxattr
            | Sysno::removexattr
            | Sysno::lremovexattr => self.xattr_path_syscall(&args),
            _ => {
                let (mutation, paths) = syscall.mutation()?;
                self.mutation_status(mutation, paths)
            }
        };
        Some(status)
    }

    fn xattr_path_syscall(self, args: &[u64; 6]) -> u64 {
        let path = match HostCString::read(self.memory, args[0]) {
            Ok(path) => path,
            Err(errno) => return errno.negated(),
        };
        if let Some(raw) = path.as_bytes()
            && self.policy.is_broker_proc_fd(None, raw)
        {
            return Errno::ENOENT.negated();
        }
        let request = Request::xattr_path(self.syscall, &path);
        match self.syscall {
            Sysno::listxattr | Sysno::llistxattr => self.check(
                request,
                &[Arg::copied_path(0, &path), Arg::bytes(1, args[2])],
            ),
            Sysno::setxattr | Sysno::lsetxattr | Sysno::getxattr | Sysno::lgetxattr => self.check(
                request,
                &[
                    Arg::copied_path(0, &path),
                    Arg::cstr(1),
                    Arg::bytes(2, args[3]),
                ],
            ),
            _ => self.check(request, &[Arg::copied_path(0, &path), Arg::cstr(1)]),
        }
    }

    fn inotify_add_watch_syscall(self, arguments: &[u64; 6]) -> u64 {
        if GuestFd::from_reg(arguments[0]).valid().is_none() {
            return Errno::EBADF.negated();
        }
        let path = match HostCString::read(self.memory, arguments[1]) {
            Ok(path) => path,
            Err(errno) => return errno.negated(),
        };
        if let Some(raw) = path.as_bytes()
            && self.policy.is_broker_proc_fd(None, raw)
        {
            return Errno::ENOENT.negated();
        }
        let mask = GuestReg(arguments[2]).as_u32();
        let trailing_slash = path.as_bytes().is_some_and(|bytes| bytes.ends_with(b"/"));
        let follow = trailing_slash || mask & libc::IN_DONT_FOLLOW == 0;
        let request = Request::read(None, &path, follow);
        self.check(request, &[Arg::fd(0), Arg::copied_path(1, &path)])
    }

    fn check(self, request: Request<'_>, specs: &[Arg<'_>]) -> u64 {
        if let Some(errno) = self
            .sink
            .refuse_target(self.policy, self.registers, request)
        {
            return errno.negated();
        }
        SyscallArgs::forward_translated(self.registers, self.memory, self.syscall, specs)
    }

    fn access_syscall(self, arguments: &[u64; 6]) -> u64 {
        const KNOWN_FLAGS: i32 = libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;
        const KNOWN_MODE: i32 = libc::R_OK | libc::W_OK | libc::X_OK;
        let syscall = self.syscall;
        #[cfg(target_arch = "x86_64")]
        let is_legacy = syscall == Sysno::access;
        #[cfg(target_arch = "aarch64")]
        let is_legacy = false;
        let path_index = usize::from(!is_legacy);
        let dirfd = (!is_legacy).then(|| GuestFd::from_reg(arguments[0]).policy_dirfd());
        let mode = GuestReg(arguments[path_index + 1]).as_i32();
        let path = match HostCString::read(self.memory, arguments[path_index]) {
            Ok(path) => path,
            Err(errno) => return errno.negated(),
        };
        let specs: Vec<Arg<'_>> = if is_legacy {
            vec![Arg::copied_path(0, &path)]
        } else {
            vec![Arg::dirfd(0), Arg::copied_path(1, &path)]
        };
        let flags = if syscall == Sysno::faccessat2 {
            GuestReg(arguments[3]).as_i32()
        } else {
            0
        };
        if let Some(raw) = path.as_bytes()
            && self.policy.is_broker_proc_fd(dirfd, raw)
        {
            return Errno::ENOENT.negated();
        }
        let trailing_slash = path.as_bytes().is_some_and(|bytes| bytes.ends_with(b"/"));
        let follow = trailing_slash || flags & libc::AT_SYMLINK_NOFOLLOW == 0;
        if flags & !KNOWN_FLAGS == 0
            && mode & !KNOWN_MODE == 0
            && !path.as_path().as_os_str().is_empty()
            && self
                .policy
                .has_forbidden_proc_target(dirfd, path.as_path(), follow)
        {
            return Errno::EACCES.negated();
        }
        let reads = mode & libc::R_OK != 0;
        let writes = mode & libc::W_OK != 0;
        if flags & !KNOWN_FLAGS != 0 || mode & !KNOWN_MODE != 0 || (!reads && !writes) {
            return SyscallArgs::forward_translated(self.registers, self.memory, syscall, &specs);
        }
        let open_flags = match (reads, writes) {
            (true, true) => libc::O_RDWR,
            (false, true) => libc::O_WRONLY,
            _ => libc::O_RDONLY,
        };
        let access = if writes { Access::Write } else { Access::Read };
        let mut request = Request::path(dirfd, &path, access, follow)
            .opens(open_flags)
            .missing(Missing::Kernel);
        if syscall == Sysno::faccessat2 {
            request = request.empty(Empty::Flagged { index: 3 });
        }
        self.check(request, &specs)
    }

    fn verify_opened_fd(self, result: u64, flags: i32) -> u64 {
        let guarded = GuestFd::guard_created(result);
        let signed = GuestReg(guarded).as_c_long();
        if signed < 0 {
            return guarded;
        }
        let Ok(raw_fd) = i32::try_from(signed) else {
            return Errno::EMFILE.negated();
        };
        for denial in self
            .policy
            .descriptor_open_denials(i64::from(raw_fd), flags)
        {
            if !denial.queryable || !self.sink.is_cached_allow(denial.access, &denial.path) {
                unsafe { libc::close(raw_fd) };
                return Errno::EACCES.negated();
            }
        }
        guarded
    }

    fn open(self, dirfd: Option<i64>, index: usize, flags: i32) -> u64 {
        let arguments = SyscallArgs::raw(self.registers);
        let path = match HostCString::read(self.memory, arguments[index]) {
            Ok(path) => path,
            Err(errno) => return errno.negated(),
        };
        if let Some(raw) = path.as_bytes()
            && self.policy.is_broker_proc_fd(dirfd, raw)
        {
            return Errno::ENOENT.negated();
        }
        let follow = Request::open_follows(flags, &path, ResolveFlags::empty());
        let mut request =
            Request::path(dirfd, &path, Access::from_open_flags(flags), follow).opens(flags);
        request.flags = Request::open_flag_names(flags);
        if flags & libc::O_CREAT == 0 {
            request = request.missing(Missing::Kernel);
        }
        if let Some(errno) = self
            .sink
            .refuse_target(self.policy, self.registers, request)
        {
            return errno.negated();
        }
        if let Some(fd) = self.open_proc_maps(dirfd, &path, flags, follow) {
            return fd;
        }
        if let Some(fd) = self.open_proc_exe(dirfd, &path, flags, follow, ResolveFlags::empty()) {
            return fd;
        }
        let specs = if dirfd.is_some() {
            vec![Arg::dirfd(0), Arg::copied_path(index, &path)]
        } else {
            vec![Arg::copied_path(index, &path)]
        };
        let raw_res =
            SyscallArgs::forward_translated(self.registers, self.memory, self.syscall, &specs);
        self.verify_opened_fd(raw_res, flags)
    }

    fn openat2(self) -> u64 {
        const HOW_BYTES: usize = std::mem::size_of::<open_how>();
        let arguments = SyscallArgs::raw(self.registers);
        let size = arguments[3];
        if size < HOW_BYTES as u64 {
            return Errno::EINVAL.negated();
        }
        if size > PAGE_BYTES {
            return Errno::E2BIG.negated();
        }
        let Ok(raw_bytes) = self.memory.read(arguments[2], size) else {
            return Errno::EFAULT.negated();
        };
        if raw_bytes[HOW_BYTES..].iter().any(|&byte| byte != 0) {
            return Errno::E2BIG.negated();
        }
        let how = unsafe { std::ptr::read_unaligned(raw_bytes.as_ptr().cast::<open_how>()) };
        let (Ok(flags_u32), Ok(_)) = (u32::try_from(how.flags), u32::try_from(how.mode)) else {
            return Errno::EINVAL.negated();
        };
        let flags = flags_u32.cast_signed();
        let resolve = ResolveFlags::from_bits_retain(how.resolve);
        let path = match HostCString::read(self.memory, arguments[1]) {
            Ok(path) => path,
            Err(errno) => return errno.negated(),
        };
        let dirfd = GuestFd::from_reg(arguments[0]).policy_dirfd();
        if !path.is_null() {
            if let Some(raw) = path.as_bytes()
                && self.policy.is_broker_proc_fd(Some(dirfd), raw)
            {
                return Errno::ENOENT.negated();
            }
            let follow = Request::open_follows(flags, &path, resolve);
            let mut request =
                Request::path(Some(dirfd), &path, Access::from_open_flags(flags), follow)
                    .opens(flags)
                    .resolves(resolve);
            request.flags = Request::open_flag_names(flags);
            if flags & libc::O_CREAT == 0 {
                request = request.missing(Missing::Kernel);
            }
            if let Some(errno) = self
                .sink
                .refuse_target(self.policy, self.registers, request)
            {
                return errno.negated();
            }
            if ResolveFlags::from_bits(how.resolve).is_some()
                && !(resolve.contains(ResolveFlags::BENEATH)
                    && resolve.contains(ResolveFlags::IN_ROOT))
                && !(resolve.contains(ResolveFlags::BENEATH) && path.as_path().is_absolute())
            {
                if let Some(fd) = self.open_proc_maps(Some(dirfd), &path, flags, follow) {
                    return fd;
                }
                if let Some(fd) = self.open_proc_exe(Some(dirfd), &path, flags, follow, resolve) {
                    return fd;
                }
            }
        }
        let raw_res = SyscallArgs::forward_translated(
            self.registers,
            self.memory,
            Sysno::openat2,
            &[
                Arg::dirfd(0),
                Arg::copied_path(1, &path),
                Arg::copied_bytes(2, &raw_bytes),
            ],
        );
        self.verify_opened_fd(raw_res, flags)
    }

    /// Synthesizes `/proc/self/maps` from the guest's virtual address space so
    /// runtimes querying main-thread stack bounds (`pthread_getattr_np`) see
    /// the guest layout rather than the broker's host mappings.
    fn open_proc_maps(
        self,
        dirfd: Option<i64>,
        path: &HostCString,
        flags: i32,
        follow: bool,
    ) -> Option<u64> {
        if flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_PATH) != 0 {
            return None;
        }
        let raw = path.as_bytes()?;
        let candidate = std::path::Path::new(OsStr::from_bytes(raw));
        let full = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            match dirfd {
                None => self.policy.cwd().join(candidate),
                Some(fd) if fd == i64::from(libc::AT_FDCWD) => self.policy.cwd().join(candidate),
                Some(fd)
                    if i32::try_from(fd)
                        .ok()
                        .is_some_and(|raw| GuestFd::from_raw(raw).valid().is_some()) =>
                {
                    std::path::PathBuf::from(format!("/proc/self/fd/{fd}")).join(candidate)
                }
                Some(_) => return None,
            }
        };
        if !follow
            && let Ok(meta) = std::fs::symlink_metadata(&full)
            && meta.file_type().is_symlink()
        {
            return None;
        }
        let canonical = std::fs::canonicalize(full).ok()?;
        let self_root = std::path::PathBuf::from(format!("/proc/{}", std::process::id()));
        let relative = canonical.strip_prefix(&self_root).ok()?;
        let is_self_maps = relative == std::path::Path::new("maps")
            || (relative.starts_with("task")
                && relative.file_name() == Some(OsStr::new("maps"))
                && relative.components().count() == 3);
        if !is_self_maps {
            return None;
        }

        let space = self.process.space_snapshot();
        let exe = self.policy.exe();
        let content = space.format_proc_maps(&exe);
        let mfd_flags = if flags & libc::O_CLOEXEC != 0 {
            libc::MFD_CLOEXEC
        } else {
            0
        };
        // SAFETY: `"maps\0"` is a static NUL-terminated name and `mfd_flags`
        // contains only `MFD_CLOEXEC` or zero.
        let fd = unsafe { libc::memfd_create(c"maps".as_ptr(), mfd_flags) };
        if fd < 0 {
            return Some(Errno::last_os(Errno::EMFILE).negated());
        }
        let guarded = GuestFd::guard_created(u64::from(fd.cast_unsigned()));
        let signed = i64::from_ne_bytes(guarded.to_ne_bytes());
        if signed < 0 {
            return Some(guarded);
        }
        let Ok(fd) = i32::try_from(signed) else {
            return Some(Errno::EMFILE.negated());
        };
        let bytes = content.as_bytes();
        let mut offset = 0usize;
        while offset < bytes.len() {
            // SAFETY: `fd` is a newly created writable memfd and `bytes[offset..]` is valid.
            let written =
                unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
            if written < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                unsafe { libc::close(fd) };
                return Some(Errno::EIO.negated());
            }
            let Ok(step) = usize::try_from(written) else {
                unsafe { libc::close(fd) };
                return Some(Errno::EIO.negated());
            };
            if step == 0 {
                unsafe { libc::close(fd) };
                return Some(Errno::EIO.negated());
            }
            offset += step;
        }
        if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
            unsafe { libc::close(fd) };
            return Some(Errno::EIO.negated());
        }
        Some(u64::try_from(fd).unwrap_or_else(|_| Errno::EMFILE.negated()))
    }

    fn open_proc_exe(
        self,
        dirfd: Option<i64>,
        path: &HostCString,
        flags: i32,
        follow: bool,
        resolve: ResolveFlags,
    ) -> Option<u64> {
        let raw = path.as_bytes()?;
        if !self.policy.is_proc_self_exe(dirfd, raw, follow) {
            return None;
        }
        if !follow {
            if flags & libc::O_PATH == 0 || resolve.contains(ResolveFlags::NO_SYMLINKS) {
                return Some(Errno::ELOOP.negated());
            }
            return None;
        }
        if resolve.intersects(ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS) {
            return Some(Errno::ELOOP.negated());
        }
        if resolve.intersects(ResolveFlags::BENEATH | ResolveFlags::NO_XDEV) {
            return Some(Errno::EXDEV.negated());
        }
        let exe = self.policy.exe();
        let Ok(cexe) = CString::new(exe.as_os_str().as_bytes()) else {
            return Some(Errno::EACCES.negated());
        };
        let rc = unsafe { libc::openat(libc::AT_FDCWD, cexe.as_ptr(), flags, 0_u32) };
        let result = if rc < 0 {
            Errno::last_os(Errno::EIO).negated()
        } else {
            u64::from(rc.cast_unsigned())
        };
        Some(self.verify_opened_fd(result, flags))
    }

    fn readlink_syscall(self, dirfd: Option<i64>, index: usize, arguments: &[u64; 6]) -> u64 {
        let path = match HostCString::read(self.memory, arguments[index]) {
            Ok(path) => path,
            Err(errno) => return errno.negated(),
        };
        let bufsiz = GuestReg(arguments[index + 2]).as_i32();
        if !path.is_null()
            && let Some(raw) = path.as_bytes()
        {
            if self.policy.is_broker_proc_fd(dirfd, raw) {
                return Errno::ENOENT.negated();
            }
            if self.policy.is_proc_self_exe(dirfd, raw, false) {
                if bufsiz <= 0 {
                    return Errno::EINVAL.negated();
                }
                let exe = self.policy.exe();
                let bytes = exe.as_os_str().as_bytes();
                let copy_len = bytes.len().min(usize::try_from(bufsiz).unwrap_or(0));
                if self
                    .memory
                    .write(arguments[index + 1], &bytes[..copy_len])
                    .is_err()
                {
                    return Errno::EFAULT.negated();
                }
                return u64::try_from(copy_len).unwrap_or(0);
            }
            if !raw.is_empty()
                && self
                    .policy
                    .has_forbidden_proc_target(dirfd, path.as_path(), false)
            {
                return Errno::EACCES.negated();
            }
        }
        let len = u64::try_from(bufsiz.max(0)).unwrap_or(0);
        let specs = if dirfd.is_some() {
            vec![
                Arg::dirfd(0),
                Arg::copied_path(index, &path),
                Arg::bytes(index + 1, len),
            ]
        } else {
            vec![Arg::copied_path(index, &path), Arg::bytes(index + 1, len)]
        };
        SyscallArgs::forward_translated(self.registers, self.memory, self.syscall, &specs)
    }
}

/// How a mutation resolves the entry a path argument names.
#[derive(Clone, Copy)]
enum Follow {
    /// The entry itself, never a link it may be.
    Never,
    /// Through a link, as `utimes` and its relatives do.
    Always,
    /// Through a link unless the flags argument at `index` asks otherwise.
    Unless(usize),
    /// Through a link when the flags argument at `index` asks for it.
    Flag(usize),
}

impl Follow {
    fn follows(self, arguments: &[u64; 6]) -> bool {
        let set = |index: usize, flag: i32| GuestReg(arguments[index]).as_i32() & flag != 0;
        match self {
            Self::Never => false,
            Self::Always => true,
            Self::Unless(index) => !set(index, libc::AT_SYMLINK_NOFOLLOW),
            Self::Flag(index) => set(index, libc::AT_SYMLINK_FOLLOW),
        }
    }
}

/// One path argument of a mutation.
pub(super) struct PathSpec {
    /// The argument that holds the directory descriptor the path is relative
    /// to, absent when the syscall takes an absolute or working directory
    /// relative path.
    dirfd: Option<usize>,
    /// The argument that holds the path.
    path: usize,
    follow: Follow,
}

impl PathSpec {
    const fn new(dirfd: Option<usize>, path: usize, follow: Follow) -> Self {
        Self {
            dirfd,
            path,
            follow,
        }
    }

    fn pins(specs: &[Self], arguments: &[u64; 6]) -> bool {
        let follows = specs
            .first()
            .is_some_and(|spec| spec.follow.follows(arguments));
        follows && matches!(specs.len(), 1)
    }
}

impl SysnoExt for Sysno {
    fn is_denied(self) -> bool {
        #[cfg(target_arch = "x86_64")]
        if matches!(self, Self::ioperm | Self::iopl) {
            return true;
        }
        matches!(
            self,
            Self::io_uring_setup
                | Self::io_uring_enter
                | Self::io_uring_register
                | Self::io_setup
                | Self::io_destroy
                | Self::io_submit
                | Self::io_cancel
                | Self::io_getevents
                | Self::io_pgetevents
                | Self::unshare
                | Self::setns
                | Self::mount
                | Self::umount2
                | Self::pivot_root
                | Self::chroot
                | Self::move_mount
                | Self::fsopen
                | Self::fsconfig
                | Self::fsmount
                | Self::fspick
                | Self::open_tree
                | Self::open_tree_attr
                | Self::mount_setattr
                | Self::statmount
                | Self::listmount
                | Self::name_to_handle_at
                | Self::open_by_handle_at
                | Self::fanotify_init
                | Self::fanotify_mark
                | Self::quotactl
                | Self::quotactl_fd
                | Self::acct
                | Self::swapon
                | Self::swapoff
                | Self::sethostname
                | Self::setdomainname
                | Self::syslog
                | Self::init_module
                | Self::finit_module
                | Self::delete_module
                | Self::kexec_load
                | Self::kexec_file_load
                | Self::bpf
                | Self::perf_event_open
                | Self::userfaultfd
                | Self::seccomp
                | Self::landlock_create_ruleset
                | Self::landlock_add_rule
                | Self::landlock_restrict_self
                | Self::pidfd_getfd
                | Self::process_vm_readv
                | Self::process_vm_writev
                | Self::process_madvise
                | Self::process_mrelease
                | Self::add_key
                | Self::request_key
                | Self::keyctl
                | Self::lsm_get_self_attr
                | Self::lsm_set_self_attr
                | Self::lsm_list_modules
        )
    }

    fn is_restartable(self) -> bool {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::pause | Self::poll | Self::select | Self::epoll_wait => false,
            Self::semop | Self::semtimedop | Self::msgsnd | Self::msgrcv => false,
            Self::rt_sigsuspend
            | Self::rt_sigtimedwait
            | Self::ppoll
            | Self::pselect6
            | Self::epoll_pwait
            | Self::epoll_pwait2
            | Self::nanosleep
            | Self::clock_nanosleep => false,
            _ => true,
        }
    }

    fn mutation(self) -> Option<(Mutation, &'static [PathSpec])> {
        #[cfg(target_arch = "x86_64")]
        const ONE: &[PathSpec] = &[PathSpec::new(None, 0, Follow::Never)];
        const ONE_FOLLOW: &[PathSpec] = &[PathSpec::new(None, 0, Follow::Always)];
        #[cfg(target_arch = "x86_64")]
        const TWO_NEVER: &[PathSpec] = &[
            PathSpec::new(None, 0, Follow::Never),
            PathSpec::new(None, 1, Follow::Never),
        ];
        const TWO_AT_NEVER: &[PathSpec] = &[
            PathSpec::new(Some(0), 1, Follow::Never),
            PathSpec::new(Some(2), 3, Follow::Never),
        ];
        #[cfg(target_arch = "x86_64")]
        const SYMLINK_PATH: &[PathSpec] = &[PathSpec::new(None, 1, Follow::Never)];
        #[cfg(target_arch = "x86_64")]
        const FUTIMESAT_PATH: &[PathSpec] = &[PathSpec::new(Some(0), 1, Follow::Always)];
        const UTIMENSAT_PATH: &[PathSpec] = &[PathSpec::new(Some(0), 1, Follow::Unless(3))];
        const FCHMODAT_PATH: &[PathSpec] = &[PathSpec::new(Some(0), 1, Follow::Always)];
        const FCHMODAT2_PATH: &[PathSpec] = &[PathSpec::new(Some(0), 1, Follow::Unless(3))];
        const FCHOWNAT_PATH: &[PathSpec] = &[PathSpec::new(Some(0), 1, Follow::Unless(4))];
        const UNLINKAT_PATH: &[PathSpec] = &[PathSpec::new(Some(0), 1, Follow::Never)];
        const MKDIRAT_PATH: &[PathSpec] = &[PathSpec::new(Some(0), 1, Follow::Never)];
        const MKNODAT_PATH: &[PathSpec] = &[PathSpec::new(Some(0), 1, Follow::Never)];
        const SYMLINKAT_PATH: &[PathSpec] = &[PathSpec::new(Some(1), 2, Follow::Never)];
        const LINKAT_PATHS: &[PathSpec] = &[
            PathSpec::new(Some(0), 1, Follow::Flag(4)),
            PathSpec::new(Some(2), 3, Follow::Never),
        ];
        let pair: (Mutation, &'static [PathSpec]) = match self {
            Sysno::truncate => (Mutation::Metadata, ONE_FOLLOW),
            #[cfg(target_arch = "x86_64")]
            Sysno::chmod | Sysno::chown | Sysno::utime | Sysno::utimes => {
                (Mutation::Metadata, ONE_FOLLOW)
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::lchown | Sysno::mknod => (Mutation::Metadata, ONE),
            #[cfg(target_arch = "x86_64")]
            Sysno::mkdir => (Mutation::Mkdir, ONE),
            #[cfg(target_arch = "x86_64")]
            Sysno::unlink | Sysno::rmdir => (Mutation::Removal, ONE),
            #[cfg(target_arch = "x86_64")]
            Sysno::symlink => (Mutation::Metadata, SYMLINK_PATH),
            #[cfg(target_arch = "x86_64")]
            Sysno::futimesat => (Mutation::Metadata, FUTIMESAT_PATH),
            Sysno::utimensat => (Mutation::Metadata, UTIMENSAT_PATH),
            Sysno::fchmodat => (Mutation::Metadata, FCHMODAT_PATH),
            Sysno::fchmodat2 => (Mutation::Metadata, FCHMODAT2_PATH),
            Sysno::fchownat => (Mutation::Metadata, FCHOWNAT_PATH),
            Sysno::unlinkat => (Mutation::Removal, UNLINKAT_PATH),
            Sysno::mkdirat => (Mutation::Mkdir, MKDIRAT_PATH),
            Sysno::mknodat => (Mutation::Metadata, MKNODAT_PATH),
            Sysno::symlinkat => (Mutation::Metadata, SYMLINKAT_PATH),
            #[cfg(target_arch = "x86_64")]
            Sysno::rename | Sysno::link => (Mutation::Reparent, TWO_NEVER),
            Sysno::renameat | Sysno::renameat2 => (Mutation::Reparent, TWO_AT_NEVER),
            Sysno::linkat => (Mutation::Reparent, LINKAT_PATHS),
            _ => return None,
        };
        Some(pair)
    }
}

impl Call<'_> {
    fn spec_names_descriptor(
        syscall: Sysno,
        spec_index: usize,
        dirfd: Option<i64>,
        path: &HostCString,
        arguments: &[u64; 6],
    ) -> bool {
        if path.is_null() {
            let Some(fd) = dirfd else {
                return false;
            };
            if fd == i64::from(libc::AT_FDCWD) {
                return false;
            }
            #[cfg(target_arch = "x86_64")]
            if syscall == Sysno::futimesat && spec_index == 0 {
                return true;
            }
            return syscall == Sysno::utimensat && spec_index == 0;
        }
        if !path.is_empty_non_null() || spec_index != 0 {
            return false;
        }
        let flag_arg = match syscall {
            Sysno::linkat | Sysno::fchownat => Some(4),
            Sysno::utimensat | Sysno::fchmodat2 => Some(3),
            _ => None,
        };
        flag_arg.is_some_and(|idx| GuestReg(arguments[idx]).as_i32() & libc::AT_EMPTY_PATH != 0)
    }

    fn mutation_status(self, mutation: Mutation, specs: &[PathSpec]) -> u64 {
        let syscall = self.syscall;
        let arguments = SyscallArgs::raw(self.registers);
        let mut copied: Vec<HostCString> = Vec::with_capacity(specs.len());
        for spec in specs {
            match HostCString::read(self.memory, arguments[spec.path]) {
                Ok(path) => copied.push(path),
                Err(errno) => return errno.negated(),
            }
        }
        let ptrs = Self::copied_path_args(specs, &copied, syscall);
        let mut paths: Vec<Resolved> = Vec::with_capacity(specs.len());
        let mut descriptor_target = false;
        for (spec_index, (spec, path)) in specs.iter().zip(&copied).enumerate() {
            let dirfd = spec
                .dirfd
                .map(|index| GuestFd::from_reg(arguments[index]).policy_dirfd());
            let base = dirfd.unwrap_or_else(GuestFd::at_fdcwd);
            let resolution = if path.as_path().as_os_str().is_empty() {
                if !Self::spec_names_descriptor(syscall, spec_index, dirfd, path, &arguments) {
                    return SyscallArgs::forward_translated(
                        self.registers,
                        self.memory,
                        syscall,
                        &ptrs,
                    );
                }
                descriptor_target = true;
                self.policy.resolve_descriptor(base)
            } else {
                self.policy.resolve_path(
                    base,
                    path.as_path(),
                    spec.follow.follows(&arguments),
                    ResolveFlags::empty(),
                )
            };
            let resolved = match resolution {
                Resolution::Kernel => {
                    return SyscallArgs::forward_translated(
                        self.registers,
                        self.memory,
                        syscall,
                        &ptrs,
                    );
                }
                Resolution::Unclassified => continue,
                Resolution::Unresolvable(unres) => {
                    let denial = policy::Denial::unresolvable(Access::Write, unres);
                    if let Some(errno) = self.sink.refuse(self.policy, syscall, denial, Vec::new())
                    {
                        return errno.negated();
                    }
                    continue;
                }
                Resolution::Resolved(resolved) => resolved,
            };
            paths.push(resolved);
        }
        let reached = match mutation {
            Mutation::Mkdir => !paths.iter().any(|path| path.present),
            Mutation::Removal => paths.iter().any(|path| path.present),
            Mutation::Reparent | Mutation::Metadata => true,
        };
        let pinned = (self.sink.can_query() && !descriptor_target).then(|| {
            let path = paths.first()?;
            PathSpec::pins(specs, &arguments).then(|| Pinned::open(&path.label))?
        });
        let pinned = pinned.flatten();
        if let Some(denial) = mutation.denial(self.policy, &paths).filter(|_| reached) {
            match self.sink.refuse(self.policy, syscall, denial, Vec::new()) {
                Some(errno) => return errno.negated(),
                None => {
                    if let Some(pinned) = pinned {
                        let trailing_slash = copied
                            .first()
                            .and_then(HostCString::as_bytes)
                            .is_some_and(|bytes| bytes.ends_with(b"/"));
                        if trailing_slash && !pinned.is_dir() {
                            return Errno::ENOTDIR.negated();
                        }
                        return SyscallArgs::with_translated(
                            self.registers,
                            self.memory,
                            &ptrs,
                            |raw| pinned.mutate(syscall, raw),
                        );
                    }
                }
            }
        }
        SyscallArgs::forward_translated(self.registers, self.memory, syscall, &ptrs)
    }

    fn copied_path_args<'b>(
        specs: &[PathSpec],
        copied: &'b [HostCString],
        syscall: Sysno,
    ) -> Vec<Arg<'b>> {
        let extra = Self::extra_args(syscall);
        let mut args = Vec::with_capacity(specs.len() * 2 + extra.len());
        for (spec, path) in specs.iter().zip(copied) {
            if let Some(dirfd) = spec.dirfd {
                args.push(Arg::dirfd(dirfd));
            }
            args.push(Arg::copied_path(spec.path, path));
        }
        args.extend_from_slice(extra);
        args
    }

    fn extra_args(syscall: Sysno) -> &'static [Arg<'static>] {
        const SYMLINK: &[Arg<'static>] = &[Arg::cstr(0)];
        #[cfg(target_arch = "x86_64")]
        const UTIME: &[Arg<'static>] = &[Arg::bytes(1, UTIMBUF_BYTES)];
        #[cfg(target_arch = "x86_64")]
        const UTIMES: &[Arg<'static>] = &[Arg::bytes(1, 2 * TIMEVAL_BYTES)];
        #[cfg(target_arch = "x86_64")]
        const FUTIMESAT: &[Arg<'static>] = &[Arg::bytes(2, 2 * TIMEVAL_BYTES)];
        const UTIMENSAT: &[Arg<'static>] = &[Arg::bytes(2, 2 * TIMESPEC_BYTES)];
        match syscall {
            #[cfg(target_arch = "x86_64")]
            Sysno::symlink => SYMLINK,
            Sysno::symlinkat => SYMLINK,
            #[cfg(target_arch = "x86_64")]
            Sysno::utime => UTIME,
            #[cfg(target_arch = "x86_64")]
            Sysno::utimes => UTIMES,
            #[cfg(target_arch = "x86_64")]
            Sysno::futimesat => FUTIMESAT,
            Sysno::utimensat => UTIMENSAT,
            _ => &[],
        }
    }
}

/// The entry a metadata change reaches, held open across a responder's answer.
struct Pinned(BrokerFd);

impl Pinned {
    fn open(path: &std::path::Path) -> Option<Self> {
        let path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let _fd_lock = GuestFd::read_fd_table();
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return None;
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        GuestFd::relocate_above(owned).ok().map(Self)
    }

    fn path(&self) -> CString {
        CString::new(format!("/proc/self/fd/{}", self.0.as_raw_fd())).unwrap_or_default()
    }

    fn is_dir(&self) -> bool {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(self.0.as_raw_fd(), &raw mut st) };
        rc == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
    }

    fn mutate(&self, syscall: Sysno, arguments: &[u64; 6]) -> u64 {
        let path = self.path();
        let path = path.as_ptr();
        let result = match syscall {
            Sysno::truncate => unsafe { libc::truncate(path, GuestReg(arguments[1]).as_c_long()) },
            #[cfg(target_arch = "x86_64")]
            Sysno::chmod => unsafe { libc::chmod(path, GuestReg(arguments[1]).as_u32()) },
            Sysno::fchmodat | Sysno::fchmodat2 => unsafe {
                libc::chmod(path, GuestReg(arguments[2]).as_u32())
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::chown => unsafe {
                libc::chown(
                    path,
                    GuestReg(arguments[1]).as_u32(),
                    GuestReg(arguments[2]).as_u32(),
                )
            },
            Sysno::fchownat => unsafe {
                libc::chown(
                    path,
                    GuestReg(arguments[2]).as_u32(),
                    GuestReg(arguments[3]).as_u32(),
                )
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::utime => unsafe { libc::utime(path, arguments[1] as *const libc::utimbuf) },
            #[cfg(target_arch = "x86_64")]
            Sysno::utimes => unsafe { libc::utimes(path, arguments[1] as *const libc::timeval) },
            #[cfg(target_arch = "x86_64")]
            Sysno::futimesat => unsafe { libc::utimes(path, arguments[2] as *const libc::timeval) },
            Sysno::utimensat => unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path,
                    arguments[2] as *const libc::timespec,
                    0,
                )
            },
            _ => return Errno::EINVAL.negated(),
        };
        if result < 0 {
            return Errno::last_os(Errno::EIO).negated();
        }
        0
    }
}
