// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Robust futex lists of guest threads.
//!
//! The kernel cannot walk a guest list itself, so the broker releases the
//! locks of an exiting or exec'ing guest thread exactly as the kernel's
//! `exit_robust_list` does. Each broker thread also registers a native head
//! with an empty list that records the guest head, so that `get_robust_list`
//! on another process gets kernel permission checks and the guest value.
//!
//! A fatal signal kills the broker before it can walk the list. The outer
//! supervisor therefore traces the exit of each thread with a guest list and,
//! while the dying thread is stopped, mirrors the guest list into the native
//! one: guest node `g` becomes `mirror + g`, and the native futex offset
//! translates mirror nodes to the host addresses of the guest futex words.
//! The kernel then releases the locks with its own atomic exit handling.

use super::ErrnoExt;
use super::machine::RESERVED_END;
use super::memory::GuestMemory;
use anyhow::{Context, Result};
use std::cell::UnsafeCell;
use std::collections::BTreeSet;
use syscalls::{Errno, Sysno};

/// The size of `struct robust_list_head`, the only length the kernel accepts.
pub(crate) const HEAD_BYTES: u64 = 24;
/// The kernel's `ROBUST_LIST_LIMIT`, which stops circular lists.
const LIST_LIMIT: usize = 2048;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
/// Distinguishes a broker head from one registered by the broker's libc.
const TAG_KEY: u64 = 0x6c61_6e64_7374_7270;

/// A native `struct robust_list_head` followed by broker data.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct NativeHead {
    next: u64,
    offset: u64,
    pending: u64,
    guest: u64,
    tag: u64,
    /// The host addresses of the list mirror and guest memory, and the end
    /// of the guest memory covered by the mirror.
    mirror: u64,
    base: u64,
    end: u64,
}

thread_local! {
    static NATIVE: UnsafeCell<NativeHead> = const {
        UnsafeCell::new(NativeHead {
            next: 0,
            offset: 0,
            pending: 0,
            guest: 0,
            tag: 0,
            mirror: 0,
            base: 0,
            end: 0,
        })
    };
}

#[derive(Clone, Copy)]
pub(crate) struct RobustMirror {
    address: u64,
    end: u64,
}

impl RobustMirror {
    pub(crate) fn reserve(memory: &GuestMemory) -> Result<Self> {
        let end = memory.size();
        let length = usize::try_from(end + 8).context("robust list mirror size")?;
        // SAFETY: a fresh private anonymous mapping that is never unmapped.
        let mirror = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if mirror == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context("reserve robust list mirror");
        }
        Ok(Self {
            address: mirror.expose_provenance() as u64,
            end,
        })
    }

    pub(crate) fn register(self, memory: &GuestMemory, guest: u64) {
        NATIVE.with(|native| {
            let head = native.get();
            let address = head.expose_provenance() as u64;
            // SAFETY: only this thread writes its head, and the supervisor only
            // while this thread is stopped at exit.
            unsafe {
                head.write(NativeHead {
                    next: address,
                    offset: 0,
                    pending: 0,
                    guest,
                    tag: address ^ TAG_KEY,
                    mirror: self.address,
                    base: memory.base(),
                    end: self.end,
                });
                // A fork child starts unregistered, so register on every call.
                let _ = syscalls::syscall!(
                    Sysno::set_robust_list,
                    head.expose_provenance(),
                    usize::try_from(HEAD_BYTES).unwrap_or(24)
                );
            }
        });
    }

    pub(super) fn clear_thread_local() {
        NATIVE.with(|native| {
            // SAFETY: the forked child is single-threaded here and owns its TLS slot.
            unsafe {
                native.get().write(NativeHead::default());
            }
        });
    }

    pub(super) fn prepare_exec(memory: &GuestMemory) -> Result<()> {
        NATIVE.with(|native| {
            let head = native.get();
            let address = head.expose_provenance() as u64;
            // SAFETY: the current thread owns this head. The supervisor only writes
            // it at a ptrace exit stop, when this thread cannot run.
            let snapshot = unsafe { head.read() };
            if snapshot.base != memory.base() {
                return Ok(());
            }
            let read = |host: u64| {
                memory
                    .read_array::<8>(host.checked_sub(snapshot.base)?)
                    .ok()
                    .map(u64::from_ne_bytes)
            };
            for (target, value) in snapshot.exit_writes(address, read) {
                let target =
                    usize::try_from(target).context("invalid native robust list address")?;
                // SAFETY: exit_writes returns ranges in this thread's head or the
                // reserved, writable mirror. Guest list entries can be unaligned.
                unsafe {
                    std::ptr::with_exposed_provenance_mut::<u64>(target).write_unaligned(value);
                }
            }
            Ok(())
        })
    }

    pub(crate) fn query(tid: i32) -> Result<u64, Errno> {
        let mut head = 0u64;
        let mut length = 0usize;
        // SAFETY: both outputs are valid local variables.
        unsafe {
            syscalls::syscall!(
                Sysno::get_robust_list,
                tid.cast_unsigned() as usize,
                (&raw mut head).expose_provenance(),
                (&raw mut length).expose_provenance()
            )
        }?;
        if head == 0 {
            return Ok(0);
        }
        let mut fields = [0u64; 2];
        let local = libc::iovec {
            iov_base: fields.as_mut_ptr().cast(),
            iov_len: size_of_val(&fields),
        };
        let remote = libc::iovec {
            iov_base: std::ptr::without_provenance_mut(
                usize::try_from(head + HEAD_BYTES).unwrap_or(0),
            ),
            iov_len: size_of_val(&fields),
        };
        // SAFETY: the kernel validates the remote range and writes only `fields`.
        let copied =
            unsafe { libc::process_vm_readv(tid, &raw const local, 1, &raw const remote, 1, 0) };
        if copied < 0 {
            // An exited thread has no head; a forbidden one must not be guessed.
            let errno = Errno::last_os(Errno::EIO);
            return if errno == Errno::EPERM {
                Err(errno)
            } else {
                Ok(0)
            };
        }
        let registered = usize::try_from(copied).ok() == Some(size_of_val(&fields))
            && fields[1] == head ^ TAG_KEY;
        Ok(if registered { fields[0] } else { 0 })
    }
}

/// The guest list as the kernel would walk it, up to where it would stop.
struct Walk {
    /// Each entry and the link value naming it, with its PI bit.
    chain: Vec<(u64, u64)>,
    /// Whether the walk ends normally, so the kernel handles `pending`.
    complete: bool,
}

impl NativeHead {
    fn inside(&self, address: u64, length: u64) -> bool {
        address >= RESERVED_END
            && address
                .checked_add(length)
                .is_some_and(|end| end <= self.end)
    }

    /// Walks the guest list from `link` and cuts it before an entry that
    /// cannot be mirrored: a node outside guest memory or overlapping another
    /// one, or a futex word outside guest memory, where the kernel would fault.
    /// A cycle ends the list, as the kernel's later rounds release nothing.
    fn walk(
        &self,
        mut link: u64,
        offset: u64,
        pending: u64,
        fetch: impl Fn(u64) -> Option<u64>,
    ) -> Walk {
        let mut chain = Vec::new();
        let mut nodes = BTreeSet::new();
        let mut complete = true;
        for _ in 0..LIST_LIMIT {
            let entry = link & !1;
            if entry == self.guest {
                break;
            }
            if nodes.contains(&entry) {
                break;
            }
            let overlaps = nodes
                .range(entry.saturating_sub(7)..entry.saturating_add(8))
                .next()
                .is_some();
            let word_inside = entry == pending || self.inside(entry.wrapping_add(offset), 4);
            if overlaps || !self.inside(entry, 8) || !word_inside {
                complete = overlaps;
                break;
            }
            nodes.insert(entry);
            chain.push((entry, link));
            let Some(next) = fetch(entry) else {
                // The kernel releases this entry, then stops at the fault.
                complete = false;
                break;
            };
            link = next;
        }
        Walk { chain, complete }
    }

    /// The writes into a dying thread that make the kernel release its guest
    /// list as it would release a native one; `native` is the head address
    /// and `read` reads a host word of the thread. Every mirrored node and
    /// futex word lies in guest memory. The kernel skips the pending entry in
    /// the list, so it is left out unless the kernel handles it afterwards.
    pub(crate) fn exit_writes(
        &self,
        native: u64,
        read: impl Fn(u64) -> Option<u64>,
    ) -> Vec<(u64, u64)> {
        let fetch = |address: u64| {
            self.inside(address, 8)
                .then(|| read(self.base + address))
                .flatten()
        };
        let guest = self.guest;
        if self.tag != native ^ TAG_KEY || self.mirror == 0 || guest == 0 {
            return Vec::new();
        }
        let (Some(first), Some(offset), Some(pending)) = (
            fetch(guest),
            fetch(guest.wrapping_add(8)),
            fetch(guest.wrapping_add(16)),
        ) else {
            return Vec::new();
        };
        // A link keeps its PI bit; the walk names no entry at the guest head.
        let mirrored = |link: u64| self.mirror.wrapping_add(link & !1) | (link & 1);
        let pending_entry = pending & !1;
        let walk = self.walk(first, offset, pending_entry, fetch);
        let handles_pending = walk.complete
            && pending_entry != 0
            && self.inside(pending_entry.wrapping_add(offset), 4);
        let mut writes = Vec::new();
        let mut node = native;
        for &(entry, link) in &walk.chain {
            if entry != pending_entry || handles_pending {
                writes.push((node, mirrored(link)));
                node = self.mirror + entry;
            }
        }
        writes.push((node, native));
        writes.push((
            native + 8,
            self.base.wrapping_add(offset).wrapping_sub(self.mirror),
        ));
        let pending = if handles_pending {
            mirrored(pending)
        } else {
            0
        };
        writes.push((native + 16, pending));
        writes
    }
}

impl RobustMirror {
    pub(crate) fn release(memory: &GuestMemory, head: u64, tid: u64) {
        let Ok(tid) = u32::try_from(tid) else {
            return;
        };
        let entry_at = |address: u64| {
            let entry = memory.read_u64(address).ok()?;
            Some((entry & !1, entry & 1 != 0))
        };
        if head == 0 {
            return;
        }
        let Some((mut entry, mut pi)) = entry_at(head) else {
            return;
        };
        let Ok(offset) = memory.read_u64(head.wrapping_add(8)) else {
            return;
        };
        let Some((pending, pending_pi)) = entry_at(head.wrapping_add(16)) else {
            return;
        };
        let mut limit = LIST_LIMIT;
        while entry != head {
            // Fetch the next entry before releasing this one.
            let next = entry_at(entry);
            if entry != pending
                && !Self::owner_died(memory, entry.wrapping_add(offset), tid, pi, false)
            {
                return;
            }
            let Some(next) = next else {
                return;
            };
            (entry, pi) = next;
            limit -= 1;
            if limit == 0 {
                break;
            }
        }
        if pending != 0 {
            Self::owner_died(memory, pending.wrapping_add(offset), tid, pending_pi, true);
        }
    }

    fn owner_died(memory: &GuestMemory, word: u64, tid: u32, pi: bool, pending: bool) -> bool {
        if !word.is_multiple_of(4) {
            return false;
        }
        loop {
            let Some(value) = memory
                .read(word, 4)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
            else {
                return false;
            };
            let owner = value & FUTEX_TID_MASK;
            if pending && !pi && owner == 0 {
                // The owner died unlocking, before waking a waiter.
                Self::wake(memory, word, 1);
                return true;
            }
            if owner != tid {
                return true;
            }
            let Ok(exchange) = memory.compare_exchange_u32(
                word,
                value,
                (value & FUTEX_WAITERS) | FUTEX_OWNER_DIED,
            ) else {
                return false;
            };
            if exchange.found != value {
                continue;
            }
            // PI waiters are woken when the kernel releases the PI state. A
            // non-atomic exchange may have dropped a concurrently set
            // `FUTEX_WAITERS`, so it wakes every waiter to make them retry.
            if !pi && !exchange.atomic {
                Self::wake(memory, word, i32::MAX);
            } else if !pi && value & FUTEX_WAITERS != 0 {
                Self::wake(memory, word, 1);
            }
            return true;
        }
    }

    fn wake(memory: &GuestMemory, word: u64, count: i32) {
        if let Ok(host) = memory.address(word, 4)
            && let Ok(addr) = usize::try_from(host)
        {
            // SAFETY: a wake only hashes the address and never dereferences it.
            unsafe {
                let _ = syscalls::syscall!(
                    Sysno::futex,
                    addr,
                    libc::FUTEX_WAKE.cast_unsigned() as usize,
                    count.cast_unsigned() as usize,
                    0_usize,
                    0_usize,
                    0_usize
                );
            }
        }
    }
}
