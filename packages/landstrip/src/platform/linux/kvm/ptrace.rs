// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Intra-sandbox `ptrace` state shared across forked guest processes.
//!
//! Because guest tasks run inside KVM vCPUs rather than native user contexts,
//! attaching host `ptrace` directly to another broker process would expose the
//! broker's own registers and collide with cancellation watches. Instead, a
//! shared table tracks parent-child trace relationships within the sandbox so
//! `PTRACE_TRACEME`, stop notifications in `wait4`/`waitid`, and continuation
//! requests work as on the host.

use super::ErrnoExt;
use super::fds::{BrokerFd, GuestFd};
use super::handoff::Inherited;
use anyhow::{Context, Result, bail};
use nix::sys::memfd::{MFdFlags, memfd_create};
use std::io;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use syscalls::Errno;

const SLOTS: usize = 512;
const TABLE_BYTES: usize = SLOTS * std::mem::size_of::<AtomicU64>();
const TABLE_LEN: libc::off_t = 4096;

const PTRACE_TRACEME: u64 = 0;
const PTRACE_CONT: u64 = 7;
const PTRACE_KILL: u64 = 8;
const PTRACE_SINGLESTEP: u64 = 9;
const PTRACE_DETACH: u64 = 17;
const PTRACE_SYSCALL: u64 = 24;

pub(super) struct PtraceTable {
    fd: BrokerFd,
    slots: *const [AtomicU64; SLOTS],
}

unsafe impl Send for PtraceTable {}
unsafe impl Sync for PtraceTable {}

impl PtraceTable {
    pub(super) fn new() -> Result<Self> {
        let _fd_lock = GuestFd::read_fd_table();
        let owned = memfd_create("landstrip-ptrace", MFdFlags::MFD_CLOEXEC)
            .context("create ptrace state memfd")?;
        if unsafe { libc::ftruncate(owned.as_raw_fd(), TABLE_LEN) } < 0 {
            return Err(io::Error::last_os_error()).context("size ptrace state memfd");
        }
        let fd = GuestFd::relocate_above(owned).context("relocate ptrace state memfd")?;
        Self::from_fd(fd)
    }

    pub(super) fn from_handoff(raw: RawFd, floor: RawFd) -> Result<Self> {
        Inherited::adopt(raw, floor).and_then(Self::from_fd)
    }

    pub(super) fn keep(&self, inherit: &mut Inherited) -> Result<RawFd> {
        inherit.keep(self.fd.as_fd())
    }

    fn from_fd(fd: BrokerFd) -> Result<Self> {
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                TABLE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            bail!("map ptrace state table: {}", io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            slots: mapped.cast::<[AtomicU64; SLOTS]>(),
        })
    }

    fn slots(&self) -> &[AtomicU64; SLOTS] {
        unsafe { &*self.slots }
    }

    const fn pack(parent: i32, child: i32) -> u64 {
        ((parent.cast_unsigned() as u64) << 32) | (child.cast_unsigned() as u64)
    }

    #[allow(clippy::cast_possible_truncation)]
    const fn unpack(entry: u64) -> (i32, i32) {
        let parent = ((entry >> 32) as u32).cast_signed();
        let child = (entry as u32).cast_signed();
        (parent, child)
    }

    fn process_alive(pid: i32) -> bool {
        if pid <= 0 {
            return false;
        }
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    pub(super) fn is_traced_by(&self, child: i32, parent: i32) -> bool {
        if child <= 1 || parent <= 1 {
            return false;
        }
        let target = Self::pack(parent, child);
        self.slots()
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == target)
    }

    pub(super) fn has_tracees_for(&self, parent: i32) -> bool {
        if parent <= 1 {
            return false;
        }
        self.slots().iter().any(|slot| {
            let entry = slot.load(Ordering::Acquire);
            entry != 0 && Self::unpack(entry).0 == parent
        })
    }

    pub(super) fn forget_tracee(&self, child: i32) {
        if child <= 1 {
            return;
        }
        for slot in self.slots() {
            let entry = slot.load(Ordering::Acquire);
            if entry != 0 && Self::unpack(entry).1 == child {
                let _ = slot.compare_exchange(entry, 0, Ordering::AcqRel, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn syscall(&self, request: u64, pid: i32, data: u64) -> u64 {
        let table = self.slots();
        if request == PTRACE_TRACEME {
            let child = unsafe { libc::getpid() };
            let parent = unsafe { libc::getppid() };
            if parent <= 1 || child <= 1 {
                return Errno::EPERM.negated();
            }
            for slot in table {
                let entry = slot.load(Ordering::Acquire);
                if entry == 0 {
                    continue;
                }
                let (_, existing) = Self::unpack(entry);
                if !Self::process_alive(existing) {
                    let _ = slot.compare_exchange(entry, 0, Ordering::AcqRel, Ordering::Relaxed);
                } else if existing == child {
                    return Errno::EPERM.negated();
                }
            }
            let packed = Self::pack(parent, child);
            for slot in table {
                if slot
                    .compare_exchange(0, packed, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    return 0;
                }
            }
            return Errno::ENOMEM.negated();
        }

        let parent = unsafe { libc::getpid() };
        if pid <= 1 || !self.is_traced_by(pid, parent) {
            return Errno::ESRCH.negated();
        }
        if !Self::process_alive(pid) {
            self.forget_tracee(pid);
            return Errno::ESRCH.negated();
        }
        match request {
            PTRACE_CONT | PTRACE_SINGLESTEP | PTRACE_SYSCALL | PTRACE_DETACH => {
                let Ok(sig) = i32::try_from(data) else {
                    return Errno::EIO.negated();
                };
                if !(0..=64).contains(&sig) {
                    return Errno::EIO.negated();
                }
                if request == PTRACE_DETACH {
                    self.forget_tracee(pid);
                }
                if sig == libc::SIGSTOP {
                    if unsafe { libc::kill(pid, libc::SIGSTOP) } < 0 {
                        return Errno::last_os(Errno::ESRCH).negated();
                    }
                } else {
                    if unsafe { libc::kill(pid, libc::SIGCONT) } < 0 {
                        return Errno::last_os(Errno::ESRCH).negated();
                    }
                    if sig != 0 && unsafe { libc::kill(pid, sig) } < 0 {
                        return Errno::last_os(Errno::ESRCH).negated();
                    }
                }
                0
            }
            PTRACE_KILL => {
                if unsafe { libc::kill(pid, libc::SIGKILL) } < 0 {
                    return Errno::last_os(Errno::ESRCH).negated();
                }
                0
            }
            _ => Errno::EIO.negated(),
        }
    }
}

impl Drop for PtraceTable {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.slots.cast_mut().cast(), TABLE_BYTES);
        }
    }
}
