// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::ErrnoExt;
use super::super::cancel::Client;
use super::super::fds::GuestFd;
use super::super::machine::Regs;
use super::super::memory::{GuestMemory, HostCString};
use super::super::policy::{DirBase, Policy};
use super::super::ptrace::PtraceTable;
use super::{
    ARG_BYTES_LIMIT, GuestReg, ITIMERSPEC_BYTES, Process, SIGINFO_BYTES, TIMESPEC_BYTES,
    TIMEVAL_BYTES, ThreadState, WORD_SIZE,
};
use linux_raw_sys::general::{
    _LINUX_CAPABILITY_VERSION_1, _LINUX_CAPABILITY_VERSION_2, _LINUX_CAPABILITY_VERSION_3,
    F_ADD_SEALS, F_DUPFD, F_DUPFD_CLOEXEC, F_GET_FILE_RW_HINT, F_GET_RW_HINT, F_GET_SEALS, F_GETFD,
    F_GETFL, F_GETLEASE, F_GETLK, F_GETOWN, F_GETOWN_EX, F_GETPIPE_SZ, F_GETSIG, F_NOTIFY,
    F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW, F_SET_FILE_RW_HINT, F_SET_RW_HINT, F_SETFD, F_SETFL,
    F_SETLEASE, F_SETLK, F_SETLKW, F_SETOWN, F_SETOWN_EX, F_SETPIPE_SZ, F_SETSIG, FUTEX_CMD_MASK,
    FUTEX_CMP_REQUEUE, FUTEX_CMP_REQUEUE_PI, FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_REQUEUE,
    FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI, FUTEX_WAITV_MAX, FUTEX_WAKE_OP,
    cachestat, cachestat_range, futex_waitv, termios2,
};
use linux_raw_sys::ioctl::{
    FIOASYNC, FIOCLEX, FIONBIO, FIONCLEX, FIONREAD, TCFLSH, TCGETS, TCGETS2, TCSBRK, TCSBRKP,
    TCSETS, TCSETS2, TCSETSF, TCSETSF2, TCSETSW, TCSETSW2, TCXONC, TIOCCBRK, TIOCEXCL, TIOCGEXCL,
    TIOCGPGRP, TIOCGPKT, TIOCGPTN, TIOCGPTPEER, TIOCGSID, TIOCGWINSZ, TIOCMBIC, TIOCMBIS, TIOCMGET,
    TIOCMSET, TIOCNOTTY, TIOCNXCL, TIOCOUTQ, TIOCPKT, TIOCSBRK, TIOCSCTTY, TIOCSPGRP, TIOCSPTLCK,
    TIOCSWINSZ,
};
use linux_raw_sys::mempolicy::MPOL_F_ADDR;
use linux_raw_sys::prctl::{PR_GET_NAME, PR_SET_NAME};
use std::ffi::CString;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use syscalls::{Errno, Sysno};

const STAT_BYTES: u64 = std::mem::size_of::<libc::stat>() as u64;
const STATFS_BYTES: u64 = std::mem::size_of::<libc::statfs>() as u64;
const STATX_BYTES: u64 = std::mem::size_of::<libc::statx>() as u64;
const RUSAGE_BYTES: u64 = std::mem::size_of::<libc::rusage>() as u64;
const TMS_BYTES: u64 = std::mem::size_of::<libc::tms>() as u64;
const TIMEZONE_BYTES: u64 = std::mem::size_of::<libc::timezone>() as u64;
const UTSNAME_BYTES: u64 = std::mem::size_of::<libc::utsname>() as u64;
const SYSINFO_BYTES: u64 = std::mem::size_of::<libc::sysinfo>() as u64;
const RLIMIT64_BYTES: u64 = std::mem::size_of::<libc::rlimit64>() as u64;
const POLLFD_BYTES: u64 = std::mem::size_of::<libc::pollfd>() as u64;
const EPOLL_EVENT_BYTES: u64 = std::mem::size_of::<libc::epoll_event>() as u64;
const WINSIZE_BYTES: u64 = std::mem::size_of::<libc::winsize>() as u64;
const FLOCK_BYTES: u64 = std::mem::size_of::<libc::flock>() as u64;
const KERNEL_TERMIOS_BYTES: u64 = 36;
const KERNEL_TERMIOS2_BYTES: u64 = std::mem::size_of::<termios2>() as u64;
const MAX_VECTORS: usize = 1024;
const MSGHDR_BYTES: u64 = std::mem::size_of::<KernelMsghdr>() as u64;
const MMSGHDR_BYTES: u64 = std::mem::size_of::<KernelMmsghdr>() as u64;
const CACHESTAT_RANGE_BYTES: u64 = std::mem::size_of::<cachestat_range>() as u64;
const CACHESTAT_BYTES: u64 = std::mem::size_of::<cachestat>() as u64;
const FUTEX_WORD_BYTES: u64 = 4;
const FUTEX_WAITV_BYTES: u64 = std::mem::size_of::<futex_waitv>() as u64;
const TASK_COMM_LEN: u64 = 16;

#[derive(Clone, Copy)]
pub(super) enum Arg<'a> {
    Fd(usize),
    DirFd(usize),
    BorrowedFd(usize, BorrowedFd<'a>),
    InvalidFd(usize),
    CString(usize),
    CopiedPath(usize, &'a HostCString),
    CopiedBytes(usize, &'a [u8]),
    Bytes { ptr: usize, len: u64 },
}

impl<'a> Arg<'a> {
    pub(super) const fn fd(index: usize) -> Self {
        Self::Fd(index)
    }

    pub(super) const fn dirfd(index: usize) -> Self {
        Self::DirFd(index)
    }

    pub(super) const fn borrowed_fd(index: usize, fd: BorrowedFd<'a>) -> Self {
        Self::BorrowedFd(index, fd)
    }

    pub(super) const fn invalid_fd(index: usize) -> Self {
        Self::InvalidFd(index)
    }

    pub(super) const fn cstr(ptr: usize) -> Self {
        Self::CString(ptr)
    }

    pub(super) const fn copied_path(ptr: usize, path: &'a HostCString) -> Self {
        Self::CopiedPath(ptr, path)
    }

    pub(super) const fn copied_bytes(ptr: usize, bytes: &'a [u8]) -> Self {
        Self::CopiedBytes(ptr, bytes)
    }

    pub(super) const fn bytes(ptr: usize, len: u64) -> Self {
        Self::Bytes { ptr, len }
    }
}

struct TranslatedArgs {
    raw: [u64; 6],
    owned: Vec<CString>,
}

impl TranslatedArgs {
    fn forward(self, syscall: Sysno) -> u64 {
        let Self { raw, owned } = self;
        let result = SyscallArgs::invoke(syscall, &raw);
        drop(owned);
        result
    }
}

#[derive(Clone, Copy)]
pub(super) struct SyscallArgs(pub(super) [u64; 6]);

impl SyscallArgs {
    pub(super) const fn raw(registers: &Regs) -> [u64; 6] {
        registers.arguments()
    }

    const fn from_regs(registers: &Regs) -> Self {
        Self(Self::raw(registers))
    }

    pub(super) fn invoke(syscall: Sysno, arguments: &[u64; 6]) -> u64 {
        Client::invoke(syscall, arguments)
    }

    fn translate(
        mut self,
        memory: &GuestMemory,
        specs: &[Arg<'_>],
    ) -> std::result::Result<TranslatedArgs, Errno> {
        let mut done = [false; 6];
        let mut owned = Vec::with_capacity(specs.len());
        for spec in specs {
            let index = match *spec {
                Arg::Fd(idx) | Arg::DirFd(idx) | Arg::BorrowedFd(idx, _) | Arg::InvalidFd(idx) => {
                    idx
                }
                Arg::CString(ptr)
                | Arg::CopiedPath(ptr, _)
                | Arg::CopiedBytes(ptr, _)
                | Arg::Bytes { ptr, .. } => ptr,
            };
            let (Some(slot), Some(seen)) = (self.0.get_mut(index), done.get_mut(index)) else {
                continue;
            };
            if *seen {
                continue;
            }
            *slot = match *spec {
                Arg::Fd(_) => GuestFd::from_reg(*slot).syscall_fd(),
                Arg::DirFd(_) => GuestFd::from_reg(*slot).syscall_dirfd(),
                Arg::BorrowedFd(_, fd) => u64::from(fd.as_raw_fd().cast_unsigned()),
                Arg::InvalidFd(_) => u64::MAX,
                Arg::CString(_) => {
                    let copied = HostCString::read(memory, *slot)?;
                    if let Some(cstr) = copied.into_inner() {
                        owned.push(cstr);
                        owned
                            .last()
                            .map_or(0, |stored| stored.as_ptr().expose_provenance() as u64)
                    } else {
                        0
                    }
                }
                Arg::CopiedPath(_, path) => path.host_ptr(),
                Arg::CopiedBytes(_, bytes) => {
                    if bytes.is_empty() {
                        c"".as_ptr().expose_provenance() as u64
                    } else {
                        bytes.as_ptr().expose_provenance() as u64
                    }
                }
                Arg::Bytes { len, .. } => memory.translated_address(*slot, len),
            };
            *seen = true;
        }
        Ok(TranslatedArgs { raw: self.0, owned })
    }

    fn forward(self, syscall: Sysno) -> u64 {
        Self::invoke(syscall, &self.0)
    }

    pub(super) fn forward_raw(self, syscall: Sysno) -> u64 {
        self.forward(syscall)
    }

    pub(super) fn with_translated(
        registers: &Regs,
        memory: &GuestMemory,
        specs: &[Arg<'_>],
        call: impl FnOnce(&[u64; 6]) -> u64,
    ) -> u64 {
        match Self::from_regs(registers).translate(memory, specs) {
            Ok(translated) => {
                let result = call(&translated.raw);
                drop(translated);
                result
            }
            Err(errno) => errno.negated(),
        }
    }

    pub(super) fn translate_and_forward(
        self,
        memory: &GuestMemory,
        syscall: Sysno,
        specs: &[Arg<'_>],
    ) -> u64 {
        match self.translate(memory, specs) {
            Ok(translated) => translated.forward(syscall),
            Err(errno) => errno.negated(),
        }
    }

    pub(super) fn forward_translated(
        registers: &Regs,
        memory: &GuestMemory,
        syscall: Sysno,
        specs: &[Arg<'_>],
    ) -> u64 {
        Self::from_regs(registers).translate_and_forward(memory, syscall, specs)
    }

    pub(super) fn prctl(registers: &Regs, memory: &GuestMemory) -> u64 {
        match GuestReg(registers.arguments()[0]).as_u32() {
            PR_SET_NAME if registers.arguments()[0] == u64::from(PR_SET_NAME) => {
                let mut args = Self::raw(registers);
                let Ok(comm) = memory.read_comm(args[1]) else {
                    return Errno::EFAULT.negated();
                };
                args[1] = comm.as_ptr().expose_provenance() as u64;
                Self::invoke(Sysno::prctl, &args)
            }
            PR_GET_NAME if registers.arguments()[0] == u64::from(PR_GET_NAME) => {
                Self::forward_translated(
                    registers,
                    memory,
                    Sysno::prctl,
                    &[Arg::bytes(1, TASK_COMM_LEN)],
                )
            }
            _ => Errno::EINVAL.negated(),
        }
    }

    fn sched_affinity(syscall: Sysno, registers: &Regs, memory: &GuestMemory) -> u64 {
        Self::forward_translated(
            registers,
            memory,
            syscall,
            &[Arg::bytes(2, registers.arguments()[1])],
        )
    }

    fn getgroups(self, memory: &GuestMemory) -> u64 {
        // Nonpositive sizes never access the output buffer.
        if GuestReg(self.0[0]).as_i32() <= 0 {
            return self.forward(Sysno::getgroups);
        }
        // Only the calling thread can change its kernel credentials, and no
        // guest code runs between these calls. Translate the actual list, not
        // the caller's capacity, which may exceed the available guest memory.
        let result = Self::invoke(Sysno::getgroups, &[0; 6]);
        let Ok(count) = u32::try_from(result) else {
            return result;
        };
        self.translate_and_forward(
            memory,
            Sysno::getgroups,
            &[Arg::bytes(
                1,
                u64::from(count) * std::mem::size_of::<libc::gid_t>() as u64,
            )],
        )
    }

    /// Host address of a guest futex word. An untranslatable word becomes a
    /// faulting address of the same alignment, so the kernel still reports
    /// misalignment before the fault.
    fn futex_word(memory: &GuestMemory, word: u64) -> u64 {
        memory
            .address(word, FUTEX_WORD_BYTES)
            .unwrap_or(word & (FUTEX_WORD_BYTES - 1))
    }

    fn futex(registers: &Regs, memory: &GuestMemory) -> u64 {
        let mut arguments = Self::raw(registers);
        let command = GuestReg(arguments[1]).as_u32() & FUTEX_CMD_MASK.cast_unsigned();
        arguments[0] = Self::futex_word(memory, arguments[0]);
        if matches!(
            command,
            FUTEX_WAIT | FUTEX_LOCK_PI | FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI | FUTEX_LOCK_PI2
        ) && arguments[3] != 0
        {
            arguments[3] = memory.address(arguments[3], TIMESPEC_BYTES).unwrap_or(1);
        }
        if matches!(
            command,
            FUTEX_REQUEUE
                | FUTEX_CMP_REQUEUE
                | FUTEX_WAKE_OP
                | FUTEX_WAIT_REQUEUE_PI
                | FUTEX_CMP_REQUEUE_PI
        ) {
            arguments[4] = Self::futex_word(memory, arguments[4]);
        }
        Self::invoke(Sysno::futex, &arguments)
    }

    /// `futex_wake`, `futex_wait`, `futex_waitv` and `futex_requeue`.
    fn futex2(registers: &Regs, memory: &GuestMemory, syscall: Sysno) -> u64 {
        let mut arguments = Self::raw(registers);
        let timeout = match syscall {
            Sysno::futex_wait => Some(4),
            Sysno::futex_waitv => Some(3),
            _ => None,
        };
        if let Some(index) = timeout
            && arguments[index] != 0
        {
            arguments[index] = memory
                .address(arguments[index], TIMESPEC_BYTES)
                .unwrap_or(1);
        }
        if matches!(syscall, Sysno::futex_wake | Sysno::futex_wait) {
            arguments[0] = Self::futex_word(memory, arguments[0]);
            return Self::invoke(syscall, &arguments);
        }
        // The kernel reads the `futex_waitv` count as an `unsigned int`.
        let count = if syscall == Sysno::futex_requeue {
            2
        } else {
            arguments[1] & u64::from(u32::MAX)
        };
        Self::futex_vector(memory, arguments[0], count, |vector| {
            arguments[0] = vector;
            Self::invoke(syscall, &arguments)
        })
    }

    /// Calls `call` with a host copy of a guest `futex_waitv` array whose
    /// futex words are translated. The kernel validates each element as it
    /// copies it, so an unreadable element is placed at an inaccessible page:
    /// the kernel then faults there only if the preceding elements are valid.
    fn futex_vector(
        memory: &GuestMemory,
        vector: u64,
        count: u64,
        call: impl FnOnce(u64) -> u64,
    ) -> u64 {
        if vector == 0 || count == 0 || count > u64::from(FUTEX_WAITV_MAX) {
            // The kernel rejects these before reading the array.
            return call(u64::from(vector != 0));
        }
        let mut copied = Vec::new();
        for index in 0..count {
            let Some(mut element) = vector
                .checked_add(index * FUTEX_WAITV_BYTES)
                .and_then(|address| memory.read(address, FUTEX_WAITV_BYTES).ok())
            else {
                return Self::with_faulting_suffix(&copied, call);
            };
            let word = u64::from_le_bytes(element[8..16].try_into().unwrap_or([0; 8]));
            element[8..16].copy_from_slice(&Self::futex_word(memory, word).to_le_bytes());
            copied.extend_from_slice(&element);
        }
        call(copied.as_ptr().expose_provenance() as u64)
    }

    /// Calls `call` with a host copy of `prefix` that ends at an inaccessible page.
    fn with_faulting_suffix(prefix: &[u8], call: impl FnOnce(u64) -> u64) -> u64 {
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
        let length = prefix.len().div_ceil(page) * page;
        let total = length + page;
        // SAFETY: a fresh private anonymous mapping, unmapped below.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Errno::ENOMEM.negated();
        }
        // SAFETY: `length` and `length - prefix.len()` lie inside the mapping.
        let guard = unsafe { mapping.byte_add(length) };
        let result = if unsafe { libc::mprotect(guard, page, libc::PROT_NONE) } == 0 {
            let start = unsafe { guard.byte_sub(prefix.len()) }.cast::<u8>();
            // SAFETY: `start..guard` is writable and does not overlap `prefix`.
            unsafe { std::ptr::copy_nonoverlapping(prefix.as_ptr(), start, prefix.len()) };
            call(start.expose_provenance() as u64)
        } else {
            Errno::ENOMEM.negated()
        };
        // SAFETY: the mapping is no longer referenced.
        unsafe { libc::munmap(mapping, total) };
        result
    }

    fn stat_syscall(
        policy: &Policy,
        syscall: Sysno,
        registers: &Regs,
        memory: &GuestMemory,
    ) -> u64 {
        let args = Self::raw(registers);
        if syscall == Sysno::statx {
            let path = match HostCString::read(memory, args[1]) {
                Ok(path) => path,
                Err(errno) => return errno.negated(),
            };
            let dirfd = GuestFd::from_reg(args[0]).policy_dirfd();
            if let Some(raw) = path.as_bytes()
                && policy.is_broker_proc_fd(Some(dirfd), raw)
            {
                return Errno::ENOENT.negated();
            }
            return Self::forward_translated(
                registers,
                memory,
                Sysno::statx,
                &[
                    Arg::dirfd(0),
                    Arg::copied_path(1, &path),
                    Arg::bytes(4, STATX_BYTES),
                ],
            );
        }
        let path = match HostCString::read(memory, args[0]) {
            Ok(path) => path,
            Err(errno) => return errno.negated(),
        };
        if let Some(raw) = path.as_bytes()
            && policy.is_broker_proc_fd(None, raw)
        {
            return Errno::ENOENT.negated();
        }
        Self::forward_translated(
            registers,
            memory,
            syscall,
            &[Arg::copied_path(0, &path), Arg::bytes(1, STAT_BYTES)],
        )
    }

    fn splice_syscall(syscall: Sysno, registers: &Regs, memory: &GuestMemory) -> u64 {
        match syscall {
            Sysno::sendfile => Self::forward_translated(
                registers,
                memory,
                syscall,
                &[Arg::fd(0), Arg::fd(1), Arg::bytes(2, WORD_SIZE)],
            ),
            Sysno::tee => {
                Self::forward_translated(registers, memory, syscall, &[Arg::fd(0), Arg::fd(1)])
            }
            _ => Self::forward_translated(
                registers,
                memory,
                syscall,
                &[
                    Arg::fd(0),
                    Arg::bytes(1, WORD_SIZE),
                    Arg::fd(2),
                    Arg::bytes(3, WORD_SIZE),
                ],
            ),
        }
    }

    fn memfd_create(registers: &Regs, memory: &GuestMemory) -> u64 {
        let args = Self::raw(registers);
        let name = match HostCString::read(memory, args[0]) {
            Ok(path) if !path.is_null() => path,
            Ok(_) => return Errno::EFAULT.negated(),
            Err(Errno::ENAMETOOLONG) => return Errno::EINVAL.negated(),
            Err(errno) => return errno.negated(),
        };
        GuestFd::guard_created(Self::forward_translated(
            registers,
            memory,
            Sysno::memfd_create,
            &[Arg::copied_path(0, &name)],
        ))
    }

    fn signal_syscall(syscall: Sysno, registers: &Regs) -> u64 {
        let targets_init = GuestReg(registers.arguments()[0]).as_i32() == 1
            || (syscall == Sysno::tgkill && GuestReg(registers.arguments()[1]).as_i32() == 1);
        if targets_init {
            return Errno::EPERM.negated();
        }
        Self::invoke(syscall, &Self::raw(registers))
    }

    pub(super) fn sigqueue_syscall(registers: &Regs, memory: &GuestMemory, syscall: Sysno) -> u64 {
        let mut args = Self::raw(registers);
        let is_tg = syscall == Sysno::rt_tgsigqueueinfo;
        let targets_init =
            GuestReg(args[0]).as_i32() == 1 || (is_tg && GuestReg(args[1]).as_i32() == 1);
        if targets_init {
            return Errno::EPERM.negated();
        }
        let info_idx = if is_tg { 3 } else { 2 };
        let Ok(mut info_buf) = memory.read(args[info_idx], SIGINFO_BYTES) else {
            return Errno::EFAULT.negated();
        };
        args[info_idx] = info_buf.as_mut_ptr().expose_provenance() as u64;
        Self::invoke(syscall, &args)
    }

    pub(super) fn fcntl(registers: &Regs, memory: &GuestMemory) -> u64 {
        let guest_fd = GuestFd::from_reg(registers.arguments()[0]);
        if guest_fd.valid().is_none() {
            return Errno::EBADF.negated();
        }
        match GuestReg(registers.arguments()[1]).as_u32() {
            F_DUPFD | F_DUPFD_CLOEXEC => {
                let min_fd = GuestReg(registers.arguments()[2]).as_i32();
                if min_fd < 0
                    || u64::try_from(min_fd).map_or(true, |val| val >= GuestFd::soft_limit())
                {
                    return if guest_fd.is_open() {
                        Errno::EINVAL.negated()
                    } else {
                        Errno::EBADF.negated()
                    };
                }
                GuestFd::guard_created_from(
                    Self::forward_translated(registers, memory, Sysno::fcntl, &[Arg::fd(0)]),
                    min_fd,
                )
            }
            F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
                Self::forward_translated(
                    registers,
                    memory,
                    Sysno::fcntl,
                    &[Arg::fd(0), Arg::bytes(2, FLOCK_BYTES)],
                )
            }
            F_SETOWN_EX => {
                let Ok(raw) = memory.read(registers.arguments()[2], WORD_SIZE) else {
                    return Errno::EFAULT.negated();
                };
                let owner_pid = i32::from_ne_bytes(raw[4..8].try_into().unwrap_or([0; 4]));
                if owner_pid == 1 || owner_pid == -1 {
                    return Errno::EPERM.negated();
                }
                Self::forward_translated(
                    registers,
                    memory,
                    Sysno::fcntl,
                    &[Arg::fd(0), Arg::bytes(2, WORD_SIZE)],
                )
            }
            F_GETOWN_EX | F_GET_RW_HINT | F_SET_RW_HINT | F_GET_FILE_RW_HINT
            | F_SET_FILE_RW_HINT => Self::forward_translated(
                registers,
                memory,
                Sysno::fcntl,
                &[Arg::fd(0), Arg::bytes(2, WORD_SIZE)],
            ),
            F_SETOWN => {
                let target = GuestReg(registers.arguments()[2]).as_i32();
                if target == 1 || target == -1 {
                    return Errno::EPERM.negated();
                }
                Self::forward_translated(registers, memory, Sysno::fcntl, &[Arg::fd(0)])
            }
            F_GETFD | F_SETFD | F_GETFL | F_SETFL | F_GETOWN | F_SETSIG | F_GETSIG | F_SETLEASE
            | F_GETLEASE | F_NOTIFY | F_SETPIPE_SZ | F_GETPIPE_SZ | F_ADD_SEALS | F_GET_SEALS => {
                Self::forward_translated(registers, memory, Sysno::fcntl, &[Arg::fd(0)])
            }
            _ => {
                if guest_fd.is_open() {
                    Errno::EINVAL.negated()
                } else {
                    Errno::EBADF.negated()
                }
            }
        }
    }

    pub(super) fn plain_syscall(
        process: &Process,
        thread: &mut ThreadState,
        syscall: Sysno,
        registers: &Regs,
        memory: &GuestMemory,
    ) -> Option<u64> {
        let raw = Self::from_regs(registers);
        if let Some(result) = raw
            .fs_or_io_syscall(&process.policy, registers, memory, syscall)
            .or_else(|| raw.time_or_proc_syscall(process, registers, memory, syscall))
            .or_else(|| raw.poll_or_select(thread, registers, memory, syscall))
            .or_else(|| raw.net_syscall(memory, syscall))
            .or_else(|| raw.ipc_syscall(process.mqueue, memory, syscall))
        {
            return Some(result);
        }
        match syscall {
            Sysno::kill | Sysno::tkill | Sysno::tgkill => {
                Some(Self::signal_syscall(syscall, registers))
            }
            Sysno::lseek | Sysno::shutdown => {
                Some(raw.translate_and_forward(memory, syscall, &[Arg::fd(0)]))
            }
            Sysno::fchdir => {
                let _cwd = process.policy.write_cwd();
                Some(raw.translate_and_forward(memory, syscall, &[Arg::fd(0)]))
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::eventfd | Sysno::epoll_create | Sysno::inotify_init => {
                Some(GuestFd::guard_created(raw.forward(syscall)))
            }
            Sysno::socket
            | Sysno::eventfd2
            | Sysno::epoll_create1
            | Sysno::inotify_init1
            | Sysno::timerfd_create
            | Sysno::memfd_secret => Some(GuestFd::guard_created(raw.forward(syscall))),
            Sysno::memfd_create => Some(Self::memfd_create(registers, memory)),
            Sysno::pidfd_open => {
                // The host resolves this PID in the broker's private PID namespace.
                if GuestReg(raw.0[0]).as_i32() == 1 {
                    return Some(Errno::EPERM.negated());
                }
                Some(GuestFd::guard_created(raw.forward(syscall)))
            }
            Sysno::kcmp => Some(raw.kcmp(memory)),
            Sysno::get_mempolicy => Some(raw.get_mempolicy(memory)),
            Sysno::set_mempolicy => Some(raw.set_mempolicy(memory)),
            Sysno::migrate_pages => Some(raw.migrate_pages(memory)),
            Sysno::move_pages => Some(raw.move_pages(memory)),
            #[cfg(target_arch = "x86_64")]
            Sysno::ustat => Some(raw.translate_and_forward(memory, syscall, &[Arg::bytes(1, 32)])),
            #[cfg(target_arch = "x86_64")]
            Sysno::sysfs => Some(raw.sysfs_syscall(memory)),
            #[cfg(target_arch = "x86_64")]
            Sysno::getpgrp | Sysno::pause => Some(raw.forward(syscall)),
            Sysno::getppid
            | Sysno::setpgid
            | Sysno::getpgid
            | Sysno::setsid
            | Sysno::getsid
            | Sysno::setpriority
            | Sysno::getpriority
            | Sysno::ioprio_get
            | Sysno::ioprio_set
            | Sysno::sched_yield
            | Sysno::sched_getscheduler
            | Sysno::sched_get_priority_min
            | Sysno::sched_get_priority_max => Some(raw.forward(syscall)),
            Sysno::futex => Some(Self::futex(registers, memory)),
            Sysno::futex_waitv | Sysno::futex_wake | Sysno::futex_wait | Sysno::futex_requeue => {
                Some(Self::futex2(registers, memory, syscall))
            }
            _ => None,
        }
    }

    fn fs_or_io_syscall(
        self,
        policy: &Policy,
        registers: &Regs,
        memory: &GuestMemory,
        syscall: Sysno,
    ) -> Option<u64> {
        match syscall {
            Sysno::inotify_rm_watch => {
                Some(self.translate_and_forward(memory, syscall, &[Arg::fd(0)]))
            }
            Sysno::read | Sysno::write | Sysno::pread64 | Sysno::pwrite64 => {
                Some(self.translate_and_forward(
                    memory,
                    syscall,
                    &[Arg::fd(0), Arg::bytes(1, self.0[2])],
                ))
            }
            Sysno::readv
            | Sysno::writev
            | Sysno::preadv
            | Sysno::pwritev
            | Sysno::preadv2
            | Sysno::pwritev2
            | Sysno::vmsplice => Some(Self::vectored_io(registers, memory, syscall)),
            Sysno::fstat => Some(self.translate_and_forward(
                memory,
                syscall,
                &[Arg::fd(0), Arg::bytes(1, STAT_BYTES)],
            )),
            #[cfg(target_arch = "x86_64")]
            Sysno::newfstatat => Some(self.fstatat_syscall(policy, memory, syscall)),
            #[cfg(target_arch = "aarch64")]
            Sysno::fstatat => Some(self.fstatat_syscall(policy, memory, syscall)),
            #[cfg(target_arch = "x86_64")]
            Sysno::stat | Sysno::lstat => {
                Some(Self::stat_syscall(policy, syscall, registers, memory))
            }
            Sysno::statx => Some(Self::stat_syscall(policy, syscall, registers, memory)),
            Sysno::fstatfs => Some(self.translate_and_forward(
                memory,
                syscall,
                &[Arg::fd(0), Arg::bytes(1, STATFS_BYTES)],
            )),
            Sysno::statfs => {
                let path = match HostCString::read(memory, self.0[0]) {
                    Ok(path) => path,
                    Err(errno) => return Some(errno.negated()),
                };
                if let Some(raw) = path.as_bytes()
                    && policy.is_broker_proc_fd(None, raw)
                {
                    return Some(Errno::ENOENT.negated());
                }
                Some(self.translate_and_forward(
                    memory,
                    syscall,
                    &[Arg::copied_path(0, &path), Arg::bytes(1, STATFS_BYTES)],
                ))
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::getdents => Some(self.getdents(memory, syscall)),
            Sysno::getdents64 => Some(self.getdents(memory, syscall)),
            Sysno::cachestat => Some(self.translate_and_forward(
                memory,
                syscall,
                &[
                    Arg::fd(0),
                    Arg::bytes(1, CACHESTAT_RANGE_BYTES),
                    Arg::bytes(2, CACHESTAT_BYTES),
                ],
            )),
            Sysno::chdir => {
                let path = match HostCString::read(memory, self.0[0]) {
                    Ok(path) => path,
                    Err(errno) => return Some(errno.negated()),
                };
                let _cwd = policy.write_cwd();
                if let Some(raw) = path.as_bytes() {
                    if policy.is_broker_proc_fd_at(DirBase::Cwd, raw) {
                        return Some(Errno::ENOENT.negated());
                    }
                    if !raw.is_empty()
                        && policy.has_forbidden_proc_target_at(DirBase::Cwd, path.as_path(), true)
                    {
                        return Some(Errno::EACCES.negated());
                    }
                }
                Some(self.translate_and_forward(memory, syscall, &[Arg::copied_path(0, &path)]))
            }
            Sysno::getcwd | Sysno::getrandom => {
                Some(self.translate_and_forward(memory, syscall, &[Arg::bytes(0, self.0[1])]))
            }
            Sysno::sendfile | Sysno::copy_file_range | Sysno::splice | Sysno::tee => {
                Some(Self::splice_syscall(syscall, registers, memory))
            }
            _ => None,
        }
    }

    fn fstatat_syscall(self, policy: &Policy, memory: &GuestMemory, syscall: Sysno) -> u64 {
        let path = match HostCString::read(memory, self.0[1]) {
            Ok(path) => path,
            Err(errno) => return errno.negated(),
        };
        let dirfd = GuestFd::from_reg(self.0[0]).policy_dirfd();
        if let Some(raw) = path.as_bytes()
            && policy.is_broker_proc_fd(Some(dirfd), raw)
        {
            return Errno::ENOENT.negated();
        }
        self.translate_and_forward(
            memory,
            syscall,
            &[
                Arg::dirfd(0),
                Arg::copied_path(1, &path),
                Arg::bytes(2, STAT_BYTES),
            ],
        )
    }

    fn getdents(self, memory: &GuestMemory, syscall: Sysno) -> u64 {
        let len = u64::from(GuestReg(self.0[2]).as_u32());
        let Some(raw_fd) = GuestFd::from_reg(self.0[0]).valid() else {
            return Errno::EBADF.negated();
        };
        if !Policy::is_proc_self_fd_dir(raw_fd) {
            return self.translate_and_forward(memory, syscall, &[Arg::fd(0), Arg::bytes(1, len)]);
        }
        let Ok(cap) = usize::try_from(len) else {
            return Errno::EINVAL.negated();
        };
        if cap == 0 || memory.address(self.0[1], len).is_err() {
            return self.translate_and_forward(memory, syscall, &[Arg::fd(0), Arg::bytes(1, len)]);
        }
        let capped = cap.min(1 << 20);
        let mut host_buf = vec![0u8; capped];
        let mut filtered = Vec::with_capacity(capped);
        let name_off = if syscall == Sysno::getdents64 { 19 } else { 18 };
        loop {
            let rc = Self::invoke(
                syscall,
                &[
                    u64::from(raw_fd.cast_unsigned()),
                    host_buf.as_mut_ptr().expose_provenance() as u64,
                    u64::try_from(capped).unwrap_or(0),
                    0,
                    0,
                    0,
                ],
            );
            let signed = GuestReg(rc).as_c_long();
            if signed <= 0 {
                return rc;
            }
            let Ok(read_bytes) = usize::try_from(signed) else {
                return Errno::EIO.negated();
            };
            filtered.clear();
            let mut offset = 0usize;
            while offset + name_off < read_bytes {
                let reclen = usize::from(u16::from_ne_bytes([
                    host_buf[offset + 16],
                    host_buf[offset + 17],
                ]));
                if reclen < name_off + 2 || offset + reclen > read_bytes {
                    break;
                }
                let name_end = if syscall == Sysno::getdents64 {
                    offset + reclen
                } else {
                    offset + reclen - 1
                };
                let raw_name = &host_buf[offset + name_off..name_end];
                let nul = raw_name
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(raw_name.len());
                let hide = std::str::from_utf8(&raw_name[..nul])
                    .ok()
                    .and_then(|s| s.parse::<RawFd>().ok())
                    .is_some_and(|fd| GuestFd::from_raw(fd).is_broker());
                if !hide {
                    filtered.extend_from_slice(&host_buf[offset..offset + reclen]);
                }
                offset += reclen;
            }
            if !filtered.is_empty() {
                if memory.write(self.0[1], &filtered).is_err() {
                    return Errno::EFAULT.negated();
                }
                return u64::try_from(filtered.len()).unwrap_or(0);
            }
        }
    }

    fn time_or_proc_syscall(
        self,
        process: &Process,
        registers: &Regs,
        memory: &GuestMemory,
        syscall: Sysno,
    ) -> Option<u64> {
        let ptrace = &process.ptrace;
        let specs: &[Arg<'_>] = match syscall {
            Sysno::getrusage => &[Arg::bytes(1, RUSAGE_BYTES)],
            Sysno::times => &[Arg::bytes(0, TMS_BYTES)],
            Sysno::getgroups => return Some(self.getgroups(memory)),
            Sysno::setgroups => return Some(self.setgroups(memory)),
            Sysno::getcpu => &[Arg::bytes(0, 4), Arg::bytes(1, 4)],
            Sysno::sched_rr_get_interval => &[Arg::bytes(1, TIMESPEC_BYTES)],
            Sysno::clock_gettime | Sysno::clock_getres => &[Arg::bytes(1, TIMESPEC_BYTES)],
            Sysno::clock_settime => return Some(self.clock_settime(memory)),
            Sysno::adjtimex | Sysno::clock_adjtime => {
                return Some(self.clock_adjustment(memory, syscall));
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::alarm => return Some(self.forward(syscall)),
            Sysno::getitimer => &[Arg::bytes(1, 2 * TIMEVAL_BYTES)],
            Sysno::setitimer => &[
                Arg::bytes(1, 2 * TIMEVAL_BYTES),
                Arg::bytes(2, 2 * TIMEVAL_BYTES),
            ],
            Sysno::clock_nanosleep => {
                &[Arg::bytes(2, TIMESPEC_BYTES), Arg::bytes(3, TIMESPEC_BYTES)]
            }
            Sysno::nanosleep => &[Arg::bytes(0, TIMESPEC_BYTES), Arg::bytes(1, TIMESPEC_BYTES)],
            Sysno::gettimeofday => &[Arg::bytes(0, TIMEVAL_BYTES), Arg::bytes(1, TIMEZONE_BYTES)],
            Sysno::settimeofday => return Some(self.settimeofday(memory)),
            #[cfg(target_arch = "x86_64")]
            Sysno::time => &[Arg::bytes(0, WORD_SIZE)],
            #[cfg(target_arch = "x86_64")]
            Sysno::pipe => return Some(self.forward_fd_pair(memory, syscall, 0)),
            Sysno::pipe2 => return Some(self.forward_fd_pair(memory, syscall, 0)),
            Sysno::uname => &[Arg::bytes(0, UTSNAME_BYTES)],
            Sysno::sysinfo => &[Arg::bytes(0, SYSINFO_BYTES)],
            Sysno::prlimit64 => return Some(self.prlimit64(process, memory)),
            Sysno::getrlimit => return Some(self.getrlimit(memory)),
            Sysno::setrlimit => return Some(self.setrlimit(memory)),
            Sysno::wait4 => return Some(self.wait4_syscall(ptrace, memory)),
            Sysno::waitid => return Some(self.waitid_syscall(ptrace, memory)),
            Sysno::sched_setparam | Sysno::sched_getparam => &[Arg::bytes(1, 4)],
            Sysno::sched_setscheduler => &[Arg::bytes(2, 4)],
            Sysno::sched_getattr => &[Arg::bytes(1, u64::from(GuestReg(self.0[2]).as_u32()))],
            Sysno::sched_setattr => return Some(self.sched_setattr(memory)),
            Sysno::sched_getaffinity | Sysno::sched_setaffinity => {
                return Some(Self::sched_affinity(syscall, registers, memory));
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::signalfd => return Some(self.signalfd(memory, syscall)),
            Sysno::signalfd4 => return Some(self.signalfd(memory, syscall)),
            Sysno::capget | Sysno::capset => {
                let data_len =
                    memory.read(self.0[0], WORD_SIZE).ok().map_or(
                        0,
                        |hdr| match u32::from_le_bytes(hdr[..4].try_into().unwrap_or([0; 4])) {
                            _LINUX_CAPABILITY_VERSION_1 => 12,
                            _LINUX_CAPABILITY_VERSION_2 | _LINUX_CAPABILITY_VERSION_3 => 24,
                            _ => 0,
                        },
                    );
                return Some(self.translate_and_forward(
                    memory,
                    syscall,
                    &[Arg::bytes(0, WORD_SIZE), Arg::bytes(1, data_len)],
                ));
            }
            _ => return None,
        };
        Some(self.translate_and_forward(memory, syscall, specs))
    }

    fn sched_setattr(mut self, memory: &GuestMemory) -> u64 {
        // The first version of Linux's sched_attr was 48 bytes. A zero size
        // selects that legacy layout. The kernel accepts up to one host page.
        const ATTR_V0_BYTES: u32 = 48;
        let pid = GuestReg(self.0[0]).as_i32();
        let guest = self.0[1];
        if pid < 0 || guest == 0 || GuestReg(self.0[2]).as_u32() != 0 {
            return Errno::EINVAL.negated();
        }
        if pid == 1 {
            return Errno::EPERM.negated();
        }
        let Ok(header) = memory.read(guest, 4) else {
            return Errno::EFAULT.negated();
        };
        let mut size = [0; 4];
        size.copy_from_slice(&header);
        let length = match u32::from_ne_bytes(size) {
            0 => ATTR_V0_BYTES,
            value => value,
        };
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Errno::EIO.negated();
        }
        let mut attr = if length < ATTR_V0_BYTES || i64::from(length) > page_size {
            header
        } else {
            let Ok(mut buffer) = memory.read(guest, u64::from(length)) else {
                return Errno::EFAULT.negated();
            };
            // Pin the length checked above even if the guest changes its copy.
            buffer[..4].copy_from_slice(&size);
            buffer
        };
        self.0[1] = attr.as_mut_ptr().expose_provenance() as u64;
        let result = self.forward(Sysno::sched_setattr);
        if result == Errno::E2BIG.negated() {
            // Linux reports its current structure size on E2BIG, even when
            // the user's size field was read-only.
            let _ = memory.write(guest, &attr[..4]);
        }
        result
    }

    fn clock_adjustment(mut self, memory: &GuestMemory, syscall: Sysno) -> u64 {
        const TIMEX_BYTES: u64 = size_of::<libc::timex>() as u64;
        let index = usize::from(syscall == Sysno::clock_adjtime);
        let guest = self.0[index];
        let Ok(mut timex) = memory.read(guest, TIMEX_BYTES) else {
            return Errno::EFAULT.negated();
        };
        // Use the same private copy for validation and the syscall so another
        // vCPU cannot turn a read into a host clock adjustment after the check.
        let mut mode = [0; 4];
        mode.copy_from_slice(&timex[..4]);
        if !matches!(u32::from_ne_bytes(mode), 0 | libc::ADJ_OFFSET_SS_READ) {
            return Errno::EPERM.negated();
        }
        if index == 1 {
            const CLOCKFD: i32 = 3;
            let clock = GuestReg(self.0[0]).as_i32();
            if clock < 0 && clock & 7 == CLOCKFD {
                // Do not resolve an encoded descriptor in the broker's table.
                return Errno::EOPNOTSUPP.negated();
            }
        }
        self.0[index] = timex.as_mut_ptr().expose_provenance() as u64;
        let result = self.forward(syscall);
        if GuestReg(result).as_c_long() >= 0 && memory.write(guest, &timex).is_err() {
            return Errno::EFAULT.negated();
        }
        result
    }

    fn signalfd(self, memory: &GuestMemory, syscall: Sysno) -> u64 {
        if GuestFd::from_reg(self.0[0]).is_broker() {
            return Errno::EBADF.negated();
        }
        GuestFd::guard_created(self.translate_and_forward(
            memory,
            syscall,
            &[Arg::dirfd(0), Arg::bytes(1, self.0[2])],
        ))
    }

    fn forward_fd_pair(mut self, memory: &GuestMemory, syscall: Sysno, index: usize) -> u64 {
        let guest_ptr = self.0[index];
        if memory.address(guest_ptr, WORD_SIZE).is_err() {
            return Errno::EFAULT.negated();
        }
        let mut fds = [-1i32; 2];
        self.0[index] = (&raw mut fds).expose_provenance() as u64;
        let result = self.forward(syscall);
        if GuestReg(result).as_c_long() < 0 {
            return result;
        }
        match GuestFd::guard_pair(fds) {
            Ok(raw) => {
                if memory.write(guest_ptr, &raw).is_err() {
                    unsafe {
                        libc::close(fds[0]);
                        libc::close(fds[1]);
                    }
                    return Errno::EFAULT.negated();
                }
                result
            }
            Err(errno) => errno.negated(),
        }
    }

    fn getrlimit(self, memory: &GuestMemory) -> u64 {
        let resource = i64::from(GuestReg(self.0[0]).as_u32());
        if resource == i64::from(libc::RLIMIT_NOFILE) {
            return Self::write_fd_limit(memory, self.0[1], GuestFd::limits());
        }
        if resource == i64::from(libc::RLIMIT_AS) {
            return Self::write_fd_limit(memory, self.0[1], GuestFd::as_limits());
        }
        self.translate_and_forward(memory, Sysno::getrlimit, &[Arg::bytes(1, RLIMIT64_BYTES)])
    }

    fn setrlimit(self, memory: &GuestMemory) -> u64 {
        let resource = i64::from(GuestReg(self.0[0]).as_u32());
        let is_nofile = resource == i64::from(libc::RLIMIT_NOFILE);
        let is_as = resource == i64::from(libc::RLIMIT_AS);
        if !is_nofile && !is_as {
            return self.translate_and_forward(
                memory,
                Sysno::setrlimit,
                &[Arg::bytes(1, RLIMIT64_BYTES)],
            );
        }
        let Ok(raw) = memory.read(self.0[1], RLIMIT64_BYTES) else {
            return Errno::EFAULT.negated();
        };
        let cur = u64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8]));
        let max = u64::from_le_bytes(raw[8..].try_into().unwrap_or([0; 8]));
        let outcome = if is_nofile {
            GuestFd::set_limits(cur, max)
        } else {
            GuestFd::set_as_limits(cur, max)
        };
        match outcome {
            Ok(()) => 0,
            Err(errno) => errno.negated(),
        }
    }

    fn write_fd_limit(memory: &GuestMemory, address: u64, (cur, max): (u64, u64)) -> u64 {
        let mut raw = [0u8; 16];
        raw[..8].copy_from_slice(&cur.to_ne_bytes());
        raw[8..].copy_from_slice(&max.to_ne_bytes());
        if memory.write(address, &raw).is_ok() {
            0
        } else {
            Errno::EFAULT.negated()
        }
    }

    fn prlimit64(self, process: &Process, memory: &GuestMemory) -> u64 {
        let pid = GuestReg(self.0[0]).as_i32();
        if pid < 0 {
            return Errno::EINVAL.negated();
        }
        if pid == 1 {
            return Errno::EPERM.negated();
        }
        let self_pid = i32::try_from(std::process::id()).unwrap_or(0);
        let is_self = pid == 0 || pid == self_pid || process.has_worker_tid(pid);
        let resource = i64::from(GuestReg(self.0[1]).as_u32());
        let is_nofile = resource == i64::from(libc::RLIMIT_NOFILE);
        let is_as = resource == i64::from(libc::RLIMIT_AS);
        if is_nofile || is_as {
            return Self::virtual_prlimit(pid, is_self, is_nofile, memory, self.0[2], self.0[3]);
        }
        self.translate_and_forward(
            memory,
            Sysno::prlimit64,
            &[Arg::bytes(2, RLIMIT64_BYTES), Arg::bytes(3, RLIMIT64_BYTES)],
        )
    }

    fn virtual_prlimit(
        pid: i32,
        is_self: bool,
        is_nofile: bool,
        memory: &GuestMemory,
        new_ptr: u64,
        old_ptr: u64,
    ) -> u64 {
        let new_limit = if new_ptr != 0 {
            let Ok(raw) = memory.read(new_ptr, RLIMIT64_BYTES) else {
                return Errno::EFAULT.negated();
            };
            let cur = u64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8]));
            let max = u64::from_le_bytes(raw[8..].try_into().unwrap_or([0; 8]));
            Some((cur, max))
        } else {
            None
        };
        if old_ptr != 0 && memory.address(old_ptr, RLIMIT64_BYTES).is_err() {
            return Errno::EFAULT.negated();
        }
        if !is_self {
            if unsafe { libc::kill(pid, 0) } < 0 {
                return Errno::last_os(Errno::ESRCH).negated();
            }
            if new_limit.is_some() {
                return Errno::EPERM.negated();
            }
        }
        let old = if is_nofile {
            GuestFd::limits()
        } else {
            GuestFd::as_limits()
        };
        if let Some((cur, max)) = new_limit {
            let res = if is_nofile {
                GuestFd::set_limits(cur, max)
            } else {
                GuestFd::set_as_limits(cur, max)
            };
            if let Err(errno) = res {
                return errno.negated();
            }
        }
        if old_ptr == 0 {
            0
        } else {
            Self::write_fd_limit(memory, old_ptr, old)
        }
    }

    fn wait4_target(upid: i32) -> Option<(u32, u32)> {
        if upid == -1 {
            Some((libc::P_ALL, 0))
        } else if upid > 0 {
            Some((libc::P_PID, upid.cast_unsigned()))
        } else if upid == 0 {
            let pgid = unsafe { libc::getpgid(0) };
            (pgid > 0).then_some((libc::P_PGID, pgid.cast_unsigned()))
        } else {
            upid.checked_neg()
                .map(|pgid| (libc::P_PGID, pgid.cast_unsigned()))
        }
    }

    fn peek_traced_stop(
        ptrace: &PtraceTable,
        parent: i32,
        idtype: u32,
        id: u32,
        extra_opts: i32,
    ) -> Option<i32> {
        let mut info = [0_u8; 128];
        let opts = libc::WEXITED | libc::WSTOPPED | libc::WNOWAIT | extra_opts;
        let rc = Self::invoke(
            Sysno::waitid,
            &[
                u64::from(idtype),
                u64::from(id),
                info.as_mut_ptr().expose_provenance() as u64,
                i64::from(opts).cast_unsigned(),
                0,
                0,
            ],
        );
        if rc != 0 {
            return None;
        }
        let si_signo = i32::from_ne_bytes(info[0..4].try_into().unwrap_or([0; 4]));
        let si_code = i32::from_ne_bytes(info[8..12].try_into().unwrap_or([0; 4]));
        let si_pid = i32::from_ne_bytes(info[16..20].try_into().unwrap_or([0; 4]));
        (si_signo == libc::SIGCHLD
            && matches!(si_code, libc::CLD_STOPPED | libc::CLD_TRAPPED)
            && ptrace.is_traced_by(si_pid, parent))
        .then_some(si_pid)
    }

    fn wait4_syscall(mut self, ptrace: &PtraceTable, memory: &GuestMemory) -> u64 {
        const VALID_OPTIONS: i32 = libc::WNOHANG
            | libc::WUNTRACED
            | libc::WCONTINUED
            | libc::__WALL
            | libc::__WCLONE
            | libc::__WNOTHREAD;
        let upid = GuestReg(self.0[0]).as_i32();
        let orig_options = GuestReg(self.0[2]).as_i32();
        let status_ptr = self.0[1];
        if orig_options & !VALID_OPTIONS != 0
            || (status_ptr != 0 && memory.address(status_ptr, 4).is_err())
        {
            return self.translate_and_forward(
                memory,
                Sysno::wait4,
                &[Arg::bytes(1, 4), Arg::bytes(3, RUSAGE_BYTES)],
            );
        }
        let parent = unsafe { libc::getpid() };
        let host_rusage = memory.translated_address(self.0[3], RUSAGE_BYTES);
        let mut effective_pid = self.0[0];
        let mut effective_opts = orig_options;
        if orig_options & libc::WUNTRACED == 0 {
            let can_peek = orig_options & libc::WNOHANG == 0 || ptrace.has_tracees_for(parent);
            if can_peek && let Some((idtype, id)) = Self::wait4_target(upid) {
                let extra = orig_options
                    & (libc::WNOHANG
                        | libc::WCONTINUED
                        | libc::__WALL
                        | libc::__WCLONE
                        | libc::__WNOTHREAD);
                if let Some(traced_pid) = Self::peek_traced_stop(ptrace, parent, idtype, id, extra)
                {
                    effective_pid = i64::from(traced_pid).cast_unsigned();
                    effective_opts = orig_options | libc::WUNTRACED;
                }
            }
        }
        let mut host_status = 0_i32;
        self.0[0] = effective_pid;
        self.0[1] = (&raw mut host_status).expose_provenance() as u64;
        self.0[2] = i64::from(effective_opts).cast_unsigned();
        self.0[3] = host_rusage;
        let rc = self.forward(Sysno::wait4);
        let child = GuestReg(rc).as_i32();
        if child <= 0 {
            return rc;
        }
        if libc::WIFEXITED(host_status) || libc::WIFSIGNALED(host_status) {
            ptrace.forget_tracee(child);
        }
        if status_ptr != 0
            && memory
                .write(status_ptr, &host_status.to_ne_bytes())
                .is_err()
        {
            return Errno::EFAULT.negated();
        }
        rc
    }

    fn waitid_syscall(mut self, ptrace: &PtraceTable, memory: &GuestMemory) -> u64 {
        const VALID_OPTIONS: i32 = libc::WNOHANG
            | libc::WEXITED
            | libc::WSTOPPED
            | libc::WCONTINUED
            | libc::WNOWAIT
            | libc::__WALL
            | libc::__WCLONE
            | libc::__WNOTHREAD;
        let idtype = GuestReg(self.0[0]).as_u32();
        let infop = self.0[2];
        let orig_options = GuestReg(self.0[3]).as_i32();
        let parent = unsafe { libc::getpid() };
        let add_stopped = orig_options & !VALID_OPTIONS == 0
            && orig_options & libc::WEXITED != 0
            && orig_options & libc::WSTOPPED == 0
            && orig_options & libc::WNOWAIT == 0
            && (orig_options & libc::WNOHANG == 0 || ptrace.has_tracees_for(parent));
        if add_stopped && idtype != libc::P_PIDFD {
            let id = GuestReg(self.0[1]).as_u32();
            if Self::peek_traced_stop(ptrace, parent, idtype, id, orig_options).is_some() {
                self.0[3] = i64::from(orig_options | libc::WSTOPPED).cast_unsigned();
            }
        }
        let pointers = [Arg::bytes(2, SIGINFO_BYTES), Arg::bytes(4, RUSAGE_BYTES)];
        let result = if idtype == libc::P_PIDFD {
            self.translate_and_forward(
                memory,
                Sysno::waitid,
                &[Arg::fd(1), pointers[0], pointers[1]],
            )
        } else {
            self.translate_and_forward(memory, Sysno::waitid, &pointers)
        };
        if result != 0 || infop == 0 {
            return result;
        }
        if let Ok(info) = memory.read(infop, 24) {
            let si_code = i32::from_ne_bytes(info[8..12].try_into().unwrap_or([0; 4]));
            let si_pid = i32::from_ne_bytes(info[16..20].try_into().unwrap_or([0; 4]));
            if orig_options & libc::WNOWAIT == 0
                && si_pid > 1
                && matches!(
                    si_code,
                    libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
                )
            {
                ptrace.forget_tracee(si_pid);
            }
        }
        0
    }

    fn setgroups(self, memory: &GuestMemory) -> u64 {
        let size = GuestReg(self.0[0]).as_i32();
        if size <= 0 || size > 65_536 {
            return Self::invoke(Sysno::setgroups, &[self.0[0], 0, 0, 0, 0, 0]);
        }
        self.translate_and_forward(
            memory,
            Sysno::setgroups,
            &[Arg::bytes(
                1,
                u64::try_from(size).unwrap_or(0) * std::mem::size_of::<libc::gid_t>() as u64,
            )],
        )
    }

    fn clock_settime(self, memory: &GuestMemory) -> u64 {
        if memory.read(self.0[1], TIMESPEC_BYTES).is_err() {
            return Errno::EFAULT.negated();
        }
        Errno::EPERM.negated()
    }

    fn settimeofday(self, memory: &GuestMemory) -> u64 {
        if self.0[0] != 0 && memory.read(self.0[0], TIMEVAL_BYTES).is_err() {
            return Errno::EFAULT.negated();
        }
        if self.0[1] != 0 && memory.read(self.0[1], TIMEZONE_BYTES).is_err() {
            return Errno::EFAULT.negated();
        }
        Errno::EPERM.negated()
    }

    fn kcmp(self, memory: &GuestMemory) -> u64 {
        const KCMP_FILE: u32 = 0;
        const KCMP_EPOLL_TFD: u32 = 7;
        let pid1 = GuestReg(self.0[0]).as_i32();
        let pid2 = GuestReg(self.0[1]).as_i32();
        if pid1 == 1 || pid2 == 1 {
            return Errno::EPERM.negated();
        }
        let kind = GuestReg(self.0[2]).as_u32();
        if kind == KCMP_FILE {
            let self_pid = i32::try_from(std::process::id()).unwrap_or(0);
            if (pid1 == self_pid && GuestFd::from_reg(self.0[3]).valid().is_none())
                || (pid2 == self_pid && GuestFd::from_reg(self.0[4]).valid().is_none())
            {
                return Errno::EBADF.negated();
            }
        } else if kind == KCMP_EPOLL_TFD {
            let self_pid = i32::try_from(std::process::id()).unwrap_or(0);
            if pid1 == self_pid && GuestFd::from_reg(self.0[3]).valid().is_none() {
                return Errno::EBADF.negated();
            }
            return self.translate_and_forward(memory, Sysno::kcmp, &[Arg::bytes(4, 12)]);
        }
        self.forward(Sysno::kcmp)
    }

    fn get_mempolicy(mut self, memory: &GuestMemory) -> u64 {
        let probe = Self::invoke(Sysno::get_mempolicy, &[0, 0, 0, 0, u64::MAX, 0]);
        if probe == Errno::ENOSYS.negated() {
            return probe;
        }
        let maxnode = self.0[2];
        if maxnode > 65_536 {
            return Errno::EINVAL.negated();
        }
        let mask_bytes = maxnode.saturating_sub(1).div_ceil(64) * WORD_SIZE;
        if self.0[4] & u64::from(MPOL_F_ADDR) != 0 {
            let Ok(host_addr) = memory.address(self.0[3], 1) else {
                return Errno::EFAULT.negated();
            };
            self.0[3] = host_addr;
        }
        self.translate_and_forward(
            memory,
            Sysno::get_mempolicy,
            &[Arg::bytes(0, 4), Arg::bytes(1, mask_bytes)],
        )
    }

    fn set_mempolicy(self, memory: &GuestMemory) -> u64 {
        let maxnode = self.0[2];
        if maxnode > 65_536 {
            return Self::invoke(Sysno::set_mempolicy, &[self.0[0], 0, maxnode, 0, 0, 0]);
        }
        let mask_bytes = maxnode.saturating_sub(1).div_ceil(64) * WORD_SIZE;
        self.translate_and_forward(memory, Sysno::set_mempolicy, &[Arg::bytes(1, mask_bytes)])
    }

    fn migrate_pages(self, memory: &GuestMemory) -> u64 {
        if GuestReg(self.0[0]).as_i32() == 1 {
            return Errno::EPERM.negated();
        }
        let maxnode = self.0[1];
        if maxnode > 65_536 {
            return Self::invoke(Sysno::migrate_pages, &[self.0[0], maxnode, 0, 0, 0, 0]);
        }
        let mask_bytes = maxnode.saturating_sub(1).div_ceil(64) * WORD_SIZE;
        self.translate_and_forward(
            memory,
            Sysno::migrate_pages,
            &[Arg::bytes(2, mask_bytes), Arg::bytes(3, mask_bytes)],
        )
    }

    fn move_pages(mut self, memory: &GuestMemory) -> u64 {
        let probe = Self::invoke(Sysno::move_pages, &[0, 0, 0, 0, 0, u64::MAX]);
        if probe == Errno::ENOSYS.negated() {
            return probe;
        }
        if GuestReg(self.0[0]).as_i32() == 1 {
            return Errno::EPERM.negated();
        }
        let count = self.0[1];
        if count > 65_536 {
            return Errno::EINVAL.negated();
        }
        if count == 0 || self.0[2] == 0 {
            self.0[2] = 0;
            self.0[3] = 0;
            self.0[4] = 0;
            return self.forward(Sysno::move_pages);
        }
        let Ok(raw_pages) = memory.read(self.0[2], count * WORD_SIZE) else {
            return Errno::EFAULT.negated();
        };
        let mut host_pages = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
        for chunk in raw_pages.chunks_exact(8) {
            let guest_addr = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            host_pages.push(memory.address(guest_addr, 1).unwrap_or(1));
        }
        self.0[2] = host_pages.as_ptr().expose_provenance() as u64;
        let result = self.translate_and_forward(
            memory,
            Sysno::move_pages,
            &[Arg::bytes(3, count * 4), Arg::bytes(4, count * 4)],
        );
        drop(host_pages);
        result
    }

    #[cfg(target_arch = "x86_64")]
    fn sysfs_syscall(self, memory: &GuestMemory) -> u64 {
        match GuestReg(self.0[0]).as_i32() {
            1 => self.translate_and_forward(memory, Sysno::sysfs, &[Arg::cstr(1)]),
            2 => self.translate_and_forward(memory, Sysno::sysfs, &[Arg::bytes(2, 256)]),
            3 => self.forward(Sysno::sysfs),
            _ => Self::invoke(Sysno::sysfs, &[self.0[0], 0, 0, 0, 0, 0]),
        }
    }

    fn poll_or_select(
        self,
        thread: &mut ThreadState,
        registers: &Regs,
        memory: &GuestMemory,
        syscall: Sysno,
    ) -> Option<u64> {
        match syscall {
            #[cfg(target_arch = "x86_64")]
            Sysno::poll => Some(self.poll_fds(thread, memory, syscall)),
            Sysno::ppoll => Some(self.poll_fds(thread, memory, syscall)),
            #[cfg(target_arch = "x86_64")]
            Sysno::select => Some(self.select_fds(thread, memory, syscall)),
            Sysno::pselect6 => Some(self.select_fds(thread, memory, syscall)),
            #[cfg(target_arch = "x86_64")]
            Sysno::epoll_wait => Some(Self::epoll_or_timerfd(thread, syscall, registers, memory)),
            Sysno::epoll_ctl
            | Sysno::epoll_pwait
            | Sysno::epoll_pwait2
            | Sysno::timerfd_settime
            | Sysno::timerfd_gettime => {
                Some(Self::epoll_or_timerfd(thread, syscall, registers, memory))
            }
            _ => None,
        }
    }

    fn poll_fds(mut self, thread: &mut ThreadState, memory: &GuestMemory, syscall: Sysno) -> u64 {
        let nfds = GuestReg(self.0[1]).as_u32();
        if u64::from(nfds) > GuestFd::soft_limit() {
            return Errno::EINVAL.negated();
        }
        let guest_fds = self.0[0];
        let bytes = u64::from(nfds).saturating_mul(POLLFD_BYTES);
        let mut host_buf = if nfds == 0 {
            Vec::new()
        } else {
            let Ok(buf) = memory.read(guest_fds, bytes) else {
                return Errno::EFAULT.negated();
            };
            buf
        };
        let mut invalid = Vec::new();
        for (idx, chunk) in host_buf.chunks_exact_mut(8).enumerate() {
            let fd = i32::from_le_bytes(chunk[..4].try_into().unwrap_or([0; 4]));
            if GuestFd::from_raw(fd).is_broker() {
                chunk[..4].copy_from_slice(&(-1i32).to_le_bytes());
                invalid.push(idx);
            }
        }
        let ss_ptr = self.0[3];
        let ss_len = self.0[4];
        if syscall == Sysno::ppoll {
            if !invalid.is_empty()
                && self.0[2] != 0
                && memory.read(self.0[2], TIMESPEC_BYTES).is_err()
            {
                return Errno::EFAULT.negated();
            }
            self.0[2] = memory.translated_address(self.0[2], TIMESPEC_BYTES);
            self.0[3] = memory.translated_address(ss_ptr, ss_len);
        }
        let mut zero_ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if !invalid.is_empty() {
            if syscall == Sysno::ppoll {
                self.0[2] = (&raw mut zero_ts).expose_provenance() as u64;
            } else {
                self.0[2] = 0;
            }
        }
        self.0[0] = if nfds == 0 {
            0
        } else {
            host_buf.as_mut_ptr().expose_provenance() as u64
        };
        let result = if syscall == Sysno::ppoll {
            thread.run_with_temp_mask(memory, ss_ptr, ss_len, || self.forward(syscall))
        } else {
            self.forward(syscall)
        };
        if GuestReg(result).as_c_long() < 0 || nfds == 0 {
            return result;
        }
        let mut ready = GuestReg(result).as_c_long();
        for idx in invalid {
            host_buf[idx * 8 + 6..idx * 8 + 8].copy_from_slice(&libc::POLLNVAL.to_le_bytes());
            ready += 1;
        }
        for (idx, chunk) in host_buf.chunks_exact(8).enumerate() {
            let offset = guest_fds + u64::try_from(idx * 8 + 6).unwrap_or(0);
            if memory.write(offset, &chunk[6..8]).is_err() {
                return Errno::EFAULT.negated();
            }
        }
        u64::try_from(ready).unwrap_or(0)
    }

    fn select_fds(mut self, thread: &mut ThreadState, memory: &GuestMemory, syscall: Sysno) -> u64 {
        let n = GuestReg(self.0[0]).as_i32();
        if n < 0 {
            return Errno::EINVAL.negated();
        }
        let cap = GuestFd::select_cap();
        let inspect_n = n.min(cap.saturating_add(4096));
        if inspect_n > 0 {
            let clamped_n = n.min(cap);
            let broker_fds = if clamped_n > 0 {
                GuestFd::broker_fds_in(0, u32::try_from(clamped_n - 1).unwrap_or(0))
            } else {
                Vec::new()
            };
            if inspect_n > cap || !broker_fds.is_empty() {
                let inspect_bytes = u64::try_from(inspect_n)
                    .unwrap_or(0)
                    .div_ceil(64)
                    .saturating_mul(WORD_SIZE);
                for idx in 1..=3 {
                    if self.0[idx] == 0 {
                        continue;
                    }
                    let Ok(bytes) = memory.read(self.0[idx], inspect_bytes) else {
                        return Errno::EFAULT.negated();
                    };
                    for &bfd in &broker_fds {
                        let byte_idx = (bfd / 8) as usize;
                        let mask = 1u8 << (bfd % 8);
                        if bytes.get(byte_idx).copied().unwrap_or(0) & mask != 0 {
                            return Errno::EBADF.negated();
                        }
                    }
                    for bit in cap..inspect_n {
                        let byte_idx = usize::try_from(bit / 8).unwrap_or(0);
                        let mask = 1u8 << (bit % 8);
                        if bytes.get(byte_idx).copied().unwrap_or(0) & mask != 0 {
                            return Errno::EBADF.negated();
                        }
                    }
                }
            }
        }
        let clamped = u64::try_from(n.min(cap)).unwrap_or(0);
        self.0[0] = clamped;
        let fd_bytes = clamped.div_ceil(64).saturating_mul(WORD_SIZE);
        let time_bytes = if syscall == Sysno::pselect6 {
            TIMESPEC_BYTES
        } else {
            TIMEVAL_BYTES
        };
        let Ok(mut translated) = self.translate(
            memory,
            &[
                Arg::bytes(1, fd_bytes),
                Arg::bytes(2, fd_bytes),
                Arg::bytes(3, fd_bytes),
                Arg::bytes(4, time_bytes),
            ],
        ) else {
            return Errno::EFAULT.negated();
        };
        let host_pack: [u64; 2];
        let mut temp_ss = (0u64, 0u64);
        if syscall == Sysno::pselect6 && translated.raw[5] != 0 {
            if let Ok(raw) = memory.read(translated.raw[5], 2 * WORD_SIZE) {
                let ss = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
                let ss_len = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
                temp_ss = (ss, ss_len);
                host_pack = [memory.translated_address(ss, ss_len), ss_len];
                translated.raw[5] = (&raw const host_pack).expose_provenance() as u64;
            } else {
                translated.raw[5] = 1;
            }
        }
        if syscall == Sysno::pselect6 {
            thread.run_with_temp_mask(memory, temp_ss.0, temp_ss.1, || translated.forward(syscall))
        } else {
            translated.forward(syscall)
        }
    }

    fn net_syscall(self, memory: &GuestMemory, syscall: Sysno) -> Option<u64> {
        match syscall {
            Sysno::setsockopt => {
                let optlen = u64::try_from(GuestReg(self.0[4]).as_i32().max(0)).unwrap_or(0);
                Some(self.translate_and_forward(
                    memory,
                    syscall,
                    &[Arg::fd(0), Arg::bytes(3, optlen)],
                ))
            }
            Sysno::socketpair => Some(self.forward_fd_pair(memory, syscall, 3)),
            Sysno::accept | Sysno::accept4 => Some(GuestFd::guard_created(self.forward_socklen(
                memory,
                syscall,
                &[Arg::fd(0)],
                1,
                2,
            ))),
            Sysno::getsockname | Sysno::getpeername => {
                Some(self.forward_socklen(memory, syscall, &[Arg::fd(0)], 1, 2))
            }
            Sysno::getsockopt => Some(self.forward_socklen(memory, syscall, &[Arg::fd(0)], 3, 4)),
            Sysno::recvfrom => Some(self.forward_socklen(
                memory,
                syscall,
                &[Arg::fd(0), Arg::bytes(1, self.0[2])],
                4,
                5,
            )),
            Sysno::recvmsg => Some(KernelMsghdr::recv_single(self, memory)),
            Sysno::recvmmsg => Some(KernelMsghdr::recv_multi(self, memory)),
            _ => None,
        }
    }

    fn forward_socklen(
        self,
        memory: &GuestMemory,
        syscall: Sysno,
        specs: &[Arg<'_>],
        buf_idx: usize,
        len_idx: usize,
    ) -> u64 {
        let mut translated = match self.translate(memory, specs) {
            Ok(args) => args,
            Err(errno) => return errno.negated(),
        };
        let guest_buf = translated.raw[buf_idx];
        let guest_len_ptr = translated.raw[len_idx];
        if guest_buf == 0 {
            translated.raw[len_idx] = memory.translated_address(guest_len_ptr, 4);
            return translated.forward(syscall);
        }
        if guest_len_ptr == 0 {
            translated.raw[buf_idx] = 1;
            translated.raw[len_idx] = 0;
            return translated.forward(syscall);
        }
        let Ok(raw_len) = memory.read(guest_len_ptr, 4) else {
            translated.raw[buf_idx] = 1;
            translated.raw[len_idx] = 1;
            return translated.forward(syscall);
        };
        let mut host_len = i32::from_le_bytes(raw_len.try_into().unwrap_or([0; 4]));
        translated.raw[buf_idx] = if let Ok(cap) = u64::try_from(host_len) {
            memory.address(guest_buf, cap).unwrap_or(1)
        } else {
            1
        };
        translated.raw[len_idx] = (&raw mut host_len).expose_provenance() as u64;
        let result = translated.forward(syscall);
        if GuestReg(result).as_c_long() >= 0
            && memory
                .write(guest_len_ptr, &host_len.to_le_bytes())
                .is_err()
        {
            if matches!(syscall, Sysno::accept | Sysno::accept4)
                && let Ok(new_fd) = RawFd::try_from(GuestReg(result).as_c_long())
                && !GuestFd::from_raw(new_fd).is_broker()
            {
                unsafe { libc::close(new_fd) };
            }
            return Errno::EFAULT.negated();
        }
        result
    }

    fn vectored_io(registers: &Regs, memory: &GuestMemory, syscall: Sysno) -> u64 {
        let args = registers.arguments();
        let Some(fd) = GuestFd::from_reg(args[0]).valid() else {
            return Errno::EBADF.negated();
        };
        let count = usize::try_from(args[2]).unwrap_or(usize::MAX);
        let vectors = match KernelMsghdr::decode_iovecs(memory, args[1], count) {
            Ok(vectors) => vectors,
            Err(errno) => return errno.negated(),
        };
        let ptr = if vectors.is_empty() {
            0
        } else {
            vectors.as_ptr().expose_provenance() as u64
        };
        let result = Self::invoke(
            syscall,
            &[
                u64::from(fd.cast_unsigned()),
                ptr,
                u64::try_from(vectors.len()).unwrap_or(0),
                args[3],
                args[4],
                args[5],
            ],
        );
        drop(vectors);
        result
    }

    /// Duplicates a descriptor onto a chosen number, which must fit within
    /// `RLIMIT_NOFILE` and must not be owned by the broker.
    pub(super) fn duplicate(registers: &Regs, memory: &GuestMemory, syscall: Sysno) -> u64 {
        let [old_reg, new_reg, flags_reg, ..] = registers.arguments();
        let old = GuestFd::from_reg(old_reg);
        let new = GuestFd::from_reg(new_reg);
        if new.is_broker() && new.valid().is_none() {
            GuestFd::wait_occupy_idle();
        }
        let _fd_lock = GuestFd::write_fd_table();
        let Some(old_raw) = old.valid() else {
            return Errno::EBADF.negated();
        };
        let Some(new_raw) = new.valid() else {
            return Errno::EBADF.negated();
        };
        if syscall == Sysno::dup3 {
            let flags = GuestReg(flags_reg).as_i32();
            if flags & !libc::O_CLOEXEC != 0 || old_raw == new_raw {
                return if old.is_open() {
                    Errno::EINVAL.negated()
                } else {
                    Errno::EBADF.negated()
                };
            }
        } else if old_raw == new_raw {
            return if old.is_open() {
                u64::from(new_raw.cast_unsigned())
            } else {
                Errno::EBADF.negated()
            };
        }
        if !GuestFd::within_soft_limit(new_raw) {
            return Errno::EBADF.negated();
        }
        let result =
            Self::forward_translated(registers, memory, syscall, &[Arg::fd(0), Arg::fd(1)]);
        if GuestReg(result).as_c_long() >= 0 {
            GuestFd::note_guest_fd(new_raw);
        }
        result
    }

    pub(super) fn close_range(registers: &Regs) -> u64 {
        let first = GuestReg(registers.arguments()[0]).as_u32();
        let last = GuestReg(registers.arguments()[1]).as_u32();
        let flags = GuestReg(registers.arguments()[2]).as_u32();
        let valid_flags = libc::CLOSE_RANGE_UNSHARE | libc::CLOSE_RANGE_CLOEXEC;
        if first > last || flags & !valid_flags != 0 {
            return Errno::EINVAL.negated();
        }
        let _fd_lock = GuestFd::write_fd_table();
        let kernel_flags = flags & !libc::CLOSE_RANGE_UNSHARE;
        let broker_fds = GuestFd::broker_fds_in(first, last);
        let mut cursor = first;
        for broker_fd in broker_fds {
            if cursor < broker_fd {
                let rc = Self::invoke(
                    Sysno::close_range,
                    &[
                        u64::from(cursor),
                        u64::from(broker_fd - 1),
                        u64::from(kernel_flags),
                        0,
                        0,
                        0,
                    ],
                );
                if GuestReg(rc).as_c_long() < 0 {
                    return rc;
                }
            }
            let Some(next) = broker_fd.checked_add(1) else {
                return 0;
            };
            cursor = next;
            if cursor > last {
                return 0;
            }
        }
        Self::invoke(
            Sysno::close_range,
            &[
                u64::from(cursor),
                u64::from(last),
                u64::from(kernel_flags),
                0,
                0,
                0,
            ],
        )
    }

    pub(super) fn ioctl(registers: &Regs, memory: &GuestMemory) -> u64 {
        if !GuestFd::from_reg(registers.arguments()[0]).is_open() {
            return Errno::EBADF.negated();
        }
        let cmd = GuestReg(registers.arguments()[1]).as_u32();
        if cmd == TIOCGPTPEER {
            return GuestFd::guard_created(Self::forward_translated(
                registers,
                memory,
                Sysno::ioctl,
                &[Arg::fd(0)],
            ));
        }
        let len = match cmd {
            FIOCLEX | FIONCLEX | TCSBRK | TCSBRKP | TCXONC | TCFLSH | TIOCEXCL | TIOCNXCL
            | TIOCSCTTY | TIOCNOTTY | TIOCSBRK | TIOCCBRK => {
                return Self::forward_translated(registers, memory, Sysno::ioctl, &[Arg::fd(0)]);
            }
            TCGETS | TCSETS | TCSETSW | TCSETSF => KERNEL_TERMIOS_BYTES,
            TCGETS2 | TCSETS2 | TCSETSW2 | TCSETSF2 => KERNEL_TERMIOS2_BYTES,
            TIOCGWINSZ | TIOCSWINSZ => WINSIZE_BYTES,
            TIOCGPGRP | TIOCSPGRP | TIOCOUTQ | TIOCGSID | FIONREAD | FIONBIO | FIOASYNC
            | TIOCMGET | TIOCMBIS | TIOCMBIC | TIOCMSET | TIOCPKT | TIOCGPTN | TIOCSPTLCK
            | TIOCGPKT | TIOCGEXCL => 4,
            _ => return Errno::ENOTTY.negated(),
        };
        Self::forward_translated(
            registers,
            memory,
            Sysno::ioctl,
            &[Arg::fd(0), Arg::bytes(2, len)],
        )
    }

    fn epoll_or_timerfd(
        thread: &mut ThreadState,
        syscall: Sysno,
        registers: &Regs,
        memory: &GuestMemory,
    ) -> u64 {
        if GuestFd::from_reg(registers.arguments()[0])
            .valid()
            .is_none()
            || (syscall == Sysno::epoll_ctl
                && GuestFd::from_reg(registers.arguments()[2])
                    .valid()
                    .is_none())
        {
            return Errno::EBADF.negated();
        }
        let args = Self::raw(registers);
        let events_bytes = u64::try_from(GuestReg(args[2]).as_i32().max(0))
            .unwrap_or(0)
            .saturating_mul(EPOLL_EVENT_BYTES);
        match syscall {
            Sysno::epoll_ctl => Self::forward_translated(
                registers,
                memory,
                syscall,
                &[Arg::fd(0), Arg::fd(2), Arg::bytes(3, EPOLL_EVENT_BYTES)],
            ),
            #[cfg(target_arch = "x86_64")]
            Sysno::epoll_wait => Self::forward_translated(
                registers,
                memory,
                syscall,
                &[Arg::fd(0), Arg::bytes(1, events_bytes)],
            ),
            Sysno::epoll_pwait => thread.run_with_temp_mask(memory, args[4], args[5], || {
                Self::forward_translated(
                    registers,
                    memory,
                    syscall,
                    &[
                        Arg::fd(0),
                        Arg::bytes(1, events_bytes),
                        Arg::bytes(4, args[5]),
                    ],
                )
            }),
            Sysno::epoll_pwait2 => thread.run_with_temp_mask(memory, args[4], args[5], || {
                Self::forward_translated(
                    registers,
                    memory,
                    syscall,
                    &[
                        Arg::fd(0),
                        Arg::bytes(1, events_bytes),
                        Arg::bytes(3, TIMESPEC_BYTES),
                        Arg::bytes(4, args[5]),
                    ],
                )
            }),
            Sysno::timerfd_gettime => Self::forward_translated(
                registers,
                memory,
                syscall,
                &[Arg::fd(0), Arg::bytes(1, ITIMERSPEC_BYTES)],
            ),
            Sysno::timerfd_settime => Self::forward_translated(
                registers,
                memory,
                syscall,
                &[
                    Arg::fd(0),
                    Arg::bytes(2, ITIMERSPEC_BYTES),
                    Arg::bytes(3, ITIMERSPEC_BYTES),
                ],
            ),
            _ => Errno::ENOSYS.negated(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct KernelMsghdr {
    name: *mut libc::c_void,
    namelen: u32,
    iov: *mut libc::iovec,
    iovlen: usize,
    control: *mut libc::c_void,
    controllen: usize,
    flags: i32,
}

#[repr(C)]
struct KernelMmsghdr {
    hdr: KernelMsghdr,
    len: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct AlignedWord(u64);

struct ControlBuffer {
    words: Vec<AlignedWord>,
    len: usize,
}

impl ControlBuffer {
    const fn empty() -> Self {
        Self {
            words: Vec::new(),
            len: 0,
        }
    }

    fn zeroed(len: usize) -> Self {
        Self {
            words: vec![AlignedWord(0); len.div_ceil(8)],
            len,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = Self::zeroed(bytes.len());
        buf.as_mut_slice().copy_from_slice(bytes);
        buf
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.len == 0 {
            return &mut [];
        }
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast::<u8>(), self.len) }
    }

    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        if self.len == 0 {
            std::ptr::null_mut()
        } else {
            self.words.as_mut_ptr().cast()
        }
    }
}

pub(super) struct DecodedMsg {
    hdr: KernelMsghdr,
    vectors: Vec<libc::iovec>,
    send_name: Option<Vec<u8>>,
    control_buf: ControlBuffer,
    guest_control: u64,
}

impl DecodedMsg {
    pub(super) fn send_name(&self) -> Option<&[u8]> {
        self.send_name.as_deref()
    }

    fn bind_buffers(&mut self) {
        self.hdr.iov = self.vectors.as_mut_ptr();
        if let Some(name) = &mut self.send_name {
            self.hdr.name = if name.is_empty() {
                c"".as_ptr().cast_mut().cast()
            } else {
                name.as_mut_ptr().cast()
            };
        }
        if !self.control_buf.is_empty() {
            self.hdr.control = self.control_buf.as_mut_ptr();
        }
    }

    pub(super) fn send_single(&mut self, fd: RawFd, flags: u64) -> u64 {
        self.bind_buffers();
        SyscallArgs::invoke(
            Sysno::sendmsg,
            &[
                u64::try_from(fd).unwrap_or(u64::MAX),
                (&raw mut self.hdr).expose_provenance() as u64,
                flags,
                0,
                0,
                0,
            ],
        )
    }
}

impl KernelMsghdr {
    fn mmsg_entry(base: u64, index: usize) -> Option<u64> {
        u64::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(MMSGHDR_BYTES))
            .and_then(|bytes| base.checked_add(bytes))
    }

    pub(super) fn decode_batch(
        memory: &GuestMemory,
        base: u64,
        vlen_reg: u64,
        is_send: bool,
    ) -> std::result::Result<Vec<DecodedMsg>, Errno> {
        let count = usize::try_from(GuestReg(vlen_reg).as_u32())
            .unwrap_or(0)
            .min(MAX_VECTORS);
        let mut decoded = Vec::with_capacity(count);
        for index in 0..count {
            let Some(entry) = Self::mmsg_entry(base, index) else {
                if index == 0 {
                    return Err(Errno::EFAULT);
                }
                break;
            };
            if memory.read(entry, MMSGHDR_BYTES).is_err() {
                if index == 0 {
                    return Err(Errno::EFAULT);
                }
                break;
            }
            match Self::decode(memory, entry, is_send) {
                Ok(msg) => decoded.push(msg),
                Err(errno) => {
                    if index == 0 {
                        return Err(errno);
                    }
                    break;
                }
            }
        }
        Ok(decoded)
    }

    fn prepare_mmsg(decoded: &mut [DecodedMsg]) -> Vec<KernelMmsghdr> {
        let mut items = Vec::with_capacity(decoded.len());
        for msg in decoded {
            msg.bind_buffers();
            items.push(KernelMmsghdr {
                hdr: msg.hdr,
                len: 0,
            });
        }
        items
    }

    fn decode_iovecs(
        memory: &GuestMemory,
        address: u64,
        count: usize,
    ) -> std::result::Result<Vec<libc::iovec>, Errno> {
        if count > MAX_VECTORS {
            return Err(Errno::EINVAL);
        }
        let mut vectors = Vec::with_capacity(count);
        for index in 0..count {
            let Some(offset) = u64::try_from(index)
                .ok()
                .and_then(|i| i.checked_mul(2 * WORD_SIZE))
                .and_then(|bytes| address.checked_add(bytes))
            else {
                return Err(Errno::EFAULT);
            };
            let Ok(vector) = memory.read(offset, 2 * WORD_SIZE) else {
                return Err(Errno::EFAULT);
            };
            let base = u64::from_le_bytes(vector[..8].try_into().unwrap_or([0; 8]));
            let length = u64::from_le_bytes(vector[8..].try_into().unwrap_or([0; 8]));
            let Ok(len) = usize::try_from(length) else {
                return Err(Errno::EINVAL);
            };
            let host_base = if len == 0 {
                0_usize
            } else {
                memory
                    .address(base, length)
                    .ok()
                    .and_then(|addr| usize::try_from(addr).ok())
                    .unwrap_or(usize::MAX)
            };
            vectors.push(libc::iovec {
                iov_base: std::ptr::with_exposed_provenance_mut(host_base),
                iov_len: len,
            });
        }
        Ok(vectors)
    }

    const KERNEL_CMSG_HDR_LEN: usize = 16;

    const fn cmsg_align(len: usize) -> Option<usize> {
        let Some(padded) = len.checked_add(7) else {
            return None;
        };
        Some(padded & !7)
    }

    fn validate_control(buf: &mut ControlBuffer) -> std::result::Result<(), Errno> {
        let bytes = buf.as_slice();
        let len = bytes.len();
        let mut offset = 0usize;
        while len.saturating_sub(offset) >= Self::KERNEL_CMSG_HDR_LEN {
            let hdr = &bytes[offset..offset + Self::KERNEL_CMSG_HDR_LEN];
            let Ok(cmsg_len) =
                usize::try_from(u64::from_ne_bytes(hdr[0..8].try_into().unwrap_or([0; 8])))
            else {
                return Err(Errno::EINVAL);
            };
            let cmsg_level = i32::from_ne_bytes(hdr[8..12].try_into().unwrap_or([0; 4]));
            let cmsg_type = i32::from_ne_bytes(hdr[12..16].try_into().unwrap_or([0; 4]));
            if cmsg_len < Self::KERNEL_CMSG_HDR_LEN || cmsg_len > len - offset {
                return Err(Errno::EINVAL);
            }
            if cmsg_level == libc::SOL_SOCKET && cmsg_type == libc::SCM_RIGHTS {
                let data_len = cmsg_len - Self::KERNEL_CMSG_HDR_LEN;
                if !data_len.is_multiple_of(std::mem::size_of::<RawFd>()) {
                    return Err(Errno::EINVAL);
                }
                let data = &bytes[offset + Self::KERNEL_CMSG_HDR_LEN..offset + cmsg_len];
                for chunk in data.chunks_exact(std::mem::size_of::<RawFd>()) {
                    let fd = RawFd::from_ne_bytes(chunk.try_into().unwrap_or([0; 4]));
                    if GuestFd::from_raw(fd).valid().is_none() {
                        return Err(Errno::EBADF);
                    }
                }
            }
            let Some(step) = Self::cmsg_align(cmsg_len) else {
                return Err(Errno::EINVAL);
            };
            let Some(next) = offset.checked_add(step) else {
                return Err(Errno::EINVAL);
            };
            offset = next;
        }
        Ok(())
    }

    fn sanitize_recv_control(&mut self, buf: &mut ControlBuffer, received: usize) -> usize {
        if received == 0 {
            return 0;
        }
        let capped = received.min(buf.len());
        let bytes = &mut buf.as_mut_slice()[..capped];
        let mut kept_end = capped;
        let mut overflowed = false;
        let mut offset = 0usize;
        while capped.saturating_sub(offset) >= Self::KERNEL_CMSG_HDR_LEN {
            let hdr_slice = &bytes[offset..offset + Self::KERNEL_CMSG_HDR_LEN];
            let Ok(cmsg_len) = usize::try_from(u64::from_ne_bytes(
                hdr_slice[0..8].try_into().unwrap_or([0; 8]),
            )) else {
                if !overflowed {
                    kept_end = offset;
                }
                break;
            };
            let cmsg_level = i32::from_ne_bytes(hdr_slice[8..12].try_into().unwrap_or([0; 4]));
            let cmsg_type = i32::from_ne_bytes(hdr_slice[12..16].try_into().unwrap_or([0; 4]));
            if cmsg_len < Self::KERNEL_CMSG_HDR_LEN || cmsg_len > capped - offset {
                if !overflowed {
                    kept_end = offset;
                }
                break;
            }
            let next_offset = Self::cmsg_align(cmsg_len).and_then(|step| offset.checked_add(step));
            if cmsg_level == libc::SOL_SOCKET && cmsg_type == libc::SCM_RIGHTS {
                let data_start = offset + Self::KERNEL_CMSG_HDR_LEN;
                let data_end = offset + cmsg_len;
                let mut kept_fds = 0usize;
                let mut truncated_here = false;
                for chunk in
                    bytes[data_start..data_end].chunks_exact_mut(std::mem::size_of::<RawFd>())
                {
                    let raw_fd = RawFd::from_ne_bytes(chunk.try_into().unwrap_or([0; 4]));
                    let fd = if overflowed {
                        raw_fd
                    } else {
                        GuestFd::relocate_received(raw_fd)
                    };
                    if !overflowed && GuestFd::within_soft_limit(fd) {
                        chunk.copy_from_slice(&fd.to_ne_bytes());
                        GuestFd::note_guest_fd(fd);
                        kept_fds += 1;
                    } else {
                        if !overflowed {
                            overflowed = true;
                            truncated_here = true;
                            self.flags |= libc::MSG_CTRUNC;
                        }
                        if fd >= 0 && !GuestFd::from_raw(fd).is_broker() {
                            unsafe { libc::close(fd) };
                        }
                        chunk.fill(0);
                    }
                }
                if truncated_here {
                    if kept_fds == 0 {
                        kept_end = offset;
                    } else {
                        let kept_bytes = kept_fds * std::mem::size_of::<RawFd>();
                        let new_len = Self::KERNEL_CMSG_HDR_LEN + kept_bytes;
                        let new_space = Self::cmsg_align(new_len).unwrap_or(new_len);
                        bytes[offset..offset + 8].copy_from_slice(&(new_len as u64).to_ne_bytes());
                        kept_end = (offset + new_space).min(capped);
                    }
                }
            }
            let Some(next) = next_offset else {
                break;
            };
            offset = next;
        }
        kept_end
    }

    fn finish_recv(
        &mut self,
        memory: &GuestMemory,
        entry: u64,
        guest_control: u64,
        control_buf: &mut ControlBuffer,
    ) -> std::result::Result<(), Errno> {
        let received = self.controllen.min(control_buf.len());
        let kept = self.sanitize_recv_control(control_buf, received);
        self.controllen = kept;
        if kept > 0
            && guest_control != 0
            && memory
                .write(guest_control, &control_buf.as_slice()[..kept])
                .is_err()
        {
            return Err(Errno::EFAULT);
        }
        self.write_back(memory, entry)
    }

    pub(super) fn decode(
        memory: &GuestMemory,
        address: u64,
        is_send: bool,
    ) -> std::result::Result<DecodedMsg, Errno> {
        let Ok(raw) = memory.read(address, MSGHDR_BYTES) else {
            return Err(Errno::EFAULT);
        };
        let name = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
        let namelen = u32::from_le_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
        if i32::from_ne_bytes(namelen.to_ne_bytes()) < 0 {
            return Err(Errno::EINVAL);
        }
        let iov = u64::from_le_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
        let iovlen = usize::try_from(u64::from_le_bytes(raw[24..32].try_into().unwrap_or([0; 8])))
            .unwrap_or(usize::MAX);
        let control = u64::from_le_bytes(raw[32..40].try_into().unwrap_or([0; 8]));
        let controllen = u64::from_le_bytes(raw[40..48].try_into().unwrap_or([0; 8]));
        let flags = i32::from_le_bytes(raw[48..52].try_into().unwrap_or([0; 4]));
        let vectors = Self::decode_iovecs(memory, iov, iovlen)?;
        let mut send_name = None;
        let (host_name, host_namelen) = if name == 0 || (is_send && namelen == 0) {
            (std::ptr::null_mut(), 0)
        } else if is_send {
            if usize::try_from(namelen)
                .map_or(true, |n| n > std::mem::size_of::<libc::sockaddr_storage>())
            {
                return Err(Errno::EINVAL);
            }
            send_name = Some(
                memory
                    .read(name, u64::from(namelen))
                    .map_err(|_| Errno::EFAULT)?,
            );
            (std::ptr::null_mut(), namelen)
        } else {
            let Ok(addr) = memory.address(name, u64::from(namelen)) else {
                return Err(Errno::EFAULT);
            };
            (
                std::ptr::with_exposed_provenance_mut(usize::try_from(addr).unwrap_or(1)),
                namelen,
            )
        };
        let mut control_buf = ControlBuffer::empty();
        let host_controllen = if control == 0 || controllen == 0 {
            0
        } else {
            memory
                .address(control, controllen)
                .map_err(|_| Errno::EFAULT)?;
            let Ok(len) = usize::try_from(controllen) else {
                return Err(Errno::EINVAL);
            };
            if is_send {
                if len > ARG_BYTES_LIMIT {
                    return Err(Errno::EINVAL);
                }
                let raw_control = memory
                    .read(control, controllen)
                    .map_err(|_| Errno::EFAULT)?;
                control_buf = ControlBuffer::from_bytes(&raw_control);
                Self::validate_control(&mut control_buf)?;
                len
            } else {
                let capped = len.min(ARG_BYTES_LIMIT);
                control_buf = ControlBuffer::zeroed(capped);
                capped
            }
        };
        Ok(DecodedMsg {
            hdr: Self {
                name: host_name,
                namelen: host_namelen,
                iov: std::ptr::null_mut(),
                iovlen: vectors.len(),
                control: std::ptr::null_mut(),
                controllen: host_controllen,
                flags,
            },
            vectors,
            send_name,
            control_buf,
            guest_control: control,
        })
    }

    fn write_back(&self, memory: &GuestMemory, address: u64) -> std::result::Result<(), Errno> {
        if memory
            .write(address + 8, &self.namelen.to_le_bytes())
            .is_err()
            || memory
                .write_u64(address + 40, u64::try_from(self.controllen).unwrap_or(0))
                .is_err()
            || memory
                .write(address + 48, &self.flags.to_le_bytes())
                .is_err()
        {
            return Err(Errno::EFAULT);
        }
        Ok(())
    }

    fn recv_single(args: SyscallArgs, memory: &GuestMemory) -> u64 {
        let Some(fd) = GuestFd::from_reg(args.0[0]).valid() else {
            return Errno::EBADF.negated();
        };
        let mut msg = match Self::decode(memory, args.0[1], false) {
            Ok(decoded) => decoded,
            Err(errno) => return errno.negated(),
        };
        msg.bind_buffers();
        let result = SyscallArgs::invoke(
            Sysno::recvmsg,
            &[
                u64::try_from(fd).unwrap_or(u64::MAX),
                (&raw mut msg.hdr).expose_provenance() as u64,
                args.0[2],
                0,
                0,
                0,
            ],
        );
        if GuestReg(result).as_c_long() >= 0
            && let Err(errno) =
                msg.hdr
                    .finish_recv(memory, args.0[1], msg.guest_control, &mut msg.control_buf)
        {
            return errno.negated();
        }
        result
    }

    pub(super) fn send_multi(
        fd: RawFd,
        base: u64,
        flags: u64,
        memory: &GuestMemory,
        mut decoded: Vec<DecodedMsg>,
    ) -> u64 {
        let mut items = Self::prepare_mmsg(&mut decoded);
        let host_mmsg = if items.is_empty() {
            memory.translated_address(base, 0)
        } else {
            items.as_mut_ptr().expose_provenance() as u64
        };
        let batch_len = u64::try_from(items.len()).unwrap_or(0);
        let result = SyscallArgs::invoke(
            Sysno::sendmmsg,
            &[
                u64::try_from(fd).unwrap_or(u64::MAX),
                host_mmsg,
                batch_len,
                flags,
                0,
                0,
            ],
        );
        if GuestReg(result).as_c_long() < 0 {
            return result;
        }
        let processed = usize::try_from(result).unwrap_or(0).min(items.len());
        let mut written = 0usize;
        for (index, item) in items.iter().enumerate().take(processed) {
            if let Some(entry) = Self::mmsg_entry(base, index) {
                if memory
                    .write(entry + MSGHDR_BYTES, &item.len.to_le_bytes())
                    .is_err()
                {
                    if index == 0 {
                        return Errno::EFAULT.negated();
                    }
                    break;
                }
                written += 1;
            }
        }
        drop(decoded);
        u64::try_from(written).unwrap_or(0)
    }

    fn recv_multi(args: SyscallArgs, memory: &GuestMemory) -> u64 {
        let Some(fd) = GuestFd::from_reg(args.0[0]).valid() else {
            return Errno::EBADF.negated();
        };
        let mut decoded = match Self::decode_batch(memory, args.0[1], args.0[2], false) {
            Ok(batch) => batch,
            Err(errno) => return errno.negated(),
        };
        let timeout = memory.translated_address(args.0[4], TIMESPEC_BYTES);
        let mut items = Self::prepare_mmsg(&mut decoded);
        let host_mmsg = if items.is_empty() {
            memory.translated_address(args.0[1], 0)
        } else {
            items.as_mut_ptr().expose_provenance() as u64
        };
        let batch_len = u64::try_from(items.len()).unwrap_or(0);
        let result = SyscallArgs::invoke(
            Sysno::recvmmsg,
            &[
                u64::try_from(fd).unwrap_or(u64::MAX),
                host_mmsg,
                batch_len,
                args.0[3],
                timeout,
                0,
            ],
        );
        if GuestReg(result).as_c_long() < 0 {
            return result;
        }
        let processed = usize::try_from(result).unwrap_or(0).min(items.len());
        let mut written = 0usize;
        for (index, (item, msg)) in items
            .iter_mut()
            .zip(decoded.iter_mut())
            .enumerate()
            .take(processed)
        {
            if let Some(entry) = Self::mmsg_entry(args.0[1], index) {
                let hdr_ok = memory
                    .write(entry + MSGHDR_BYTES, &item.len.to_le_bytes())
                    .is_ok();
                let recv_ok = item
                    .hdr
                    .finish_recv(memory, entry, msg.guest_control, &mut msg.control_buf)
                    .is_ok();
                if !hdr_ok || !recv_ok {
                    if index == 0 {
                        return Errno::EFAULT.negated();
                    }
                    break;
                }
                written += 1;
            }
        }
        u64::try_from(written).unwrap_or(0)
    }
}
