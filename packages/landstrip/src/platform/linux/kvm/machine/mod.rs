// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Guest layout and vCPU bootstrap.
//!
//! The payload runs unprivileged without a guest kernel. The privileged level
//! consists of a stub that the system call instruction enters, which exits to
//! the VMM. Page tables and the stub are written into guest physical memory by
//! the VMM before the vCPU starts, and the guest physical address of every
//! payload byte equals its virtual address.
//!
//! Each architecture provides the same [`Machine`], [`VcpuState`], and
//! [`Regs`] interface, so the syscall broker never names a guest register.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub(super) use aarch64::{Machine, Regs, VcpuState};
#[cfg(target_arch = "x86_64")]
pub(super) use x86_64::{Machine, Regs, VcpuState};

use super::fds::BrokerHandle;
use anyhow::{Context, Result, bail};
use kvm_ioctls::{Kvm, VcpuFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Mapped guest virtual address space (64 GiB, leaving a 4 KiB mapped page
/// above `STACK_TOP` so wide SIMD or stack-top reads never cross unmapped end).
pub(crate) const ADDRESS_SPACE_SIZE: usize = 64 << 30;
pub(crate) const ADDRESS_SPACE_BYTES: u64 = ADDRESS_SPACE_SIZE as u64;
const PT_ARENA_BYTES: u64 = 128 << 20;
pub(crate) const USER_ADDRESS_BYTES: u64 = ADDRESS_SPACE_BYTES - PT_ARENA_BYTES;
const PT_ARENA_BASE: u64 = USER_ADDRESS_BYTES;
pub(crate) const STACK_TOP: u64 = USER_ADDRESS_BYTES - PAGE_BYTES;
const MAPPING_RESERVE: u64 = 0x0100_0000;
pub(crate) const MAPPING_CEILING: u64 = STACK_TOP - MAPPING_RESERVE;

/// Guest page size, which the payload sees as `AT_PAGESZ`.
const PAGE_LEN: usize = 4096;
pub(crate) const PAGE_BYTES: u64 = PAGE_LEN as u64;
const HUGE_PAGE_SIZE: u64 = 2 << 20;
const GIB_BYTES: u64 = 1 << 30;
const TABLE_ENTRIES: u64 = PAGE_BYTES / 8;

/// End of the supervisor-only first huge page, which the payload must not map.
pub(crate) const RESERVED_END: u64 = HUGE_PAGE_SIZE;
const KVM_API_VERSION: i32 = 12;
pub(super) const SEGV_MAPERR: i32 = 1;
pub(super) const SEGV_ACCERR: i32 = 2;
const FPE_FLTINV: i32 = 7;

#[derive(Clone, Copy)]
pub(super) struct GuestFault {
    pub(super) signal: i32,
    pub(super) code: i32,
    pub(super) address: u64,
    pub(super) is_page_fault: bool,
}

/// Why the vCPU returned to the VMM.
pub(super) enum ExitReason {
    /// The payload issued a system call, which the guest registers describe.
    Syscall,
    /// A host signal interrupted the vCPU.
    Interrupted,
    Fault(GuestFault),
}

/// vCPUs of exited guest threads, kept so later threads reuse their kernel
/// slots instead of exhausting the per-VM vCPU limit.
struct VcpuPool {
    next_id: AtomicU64,
    tlb_epoch: AtomicU64,
    idle: Mutex<Vec<BrokerHandle<VcpuFd>>>,
}

impl VcpuPool {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            tlb_epoch: AtomicU64::new(0),
            idle: Mutex::new(Vec::new()),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn bump_tlb(&self) {
        self.tlb_epoch.fetch_add(1, Ordering::Release);
    }

    fn tlb_epoch(&self) -> u64 {
        self.tlb_epoch.load(Ordering::Acquire)
    }
}

impl Machine {
    pub(super) fn is_available() -> bool {
        Self::open_kvm().is_ok()
    }
    pub(super) fn probe() -> Result<()> {
        Self::open_kvm()?
            .create_vm()
            .context("create a KVM virtual machine")?;
        Ok(())
    }

    fn open_kvm() -> Result<Kvm> {
        let kvm = Kvm::new().context("open /dev/kvm")?;
        let version = kvm.get_api_version();
        if version != KVM_API_VERSION {
            bail!("unsupported KVM API version {version}");
        }
        Ok(kvm)
    }

    /// Returns a recycled vCPU when an earlier guest thread has already exited.
    pub(super) fn pop_idle_vcpu(&self) -> Option<BrokerHandle<VcpuFd>> {
        self.pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
    }

    /// Returns an exited thread's vCPU to the pool so later threads reuse its
    /// kernel slot.
    pub(super) fn recycle_vcpu(&self, vcpu: BrokerHandle<VcpuFd>) {
        self.pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(vcpu);
    }

    /// Closes broker VM and pooled vCPU descriptors inherited from a
    /// multithreaded parent when its `Arc<Process>` cannot be dropped safely.
    pub(super) fn release_forked_fds(&self) {
        self.vm.close_for_forked_parent();
        if let Ok(idle) = self.pool.idle.try_lock() {
            for vcpu in idle.iter() {
                vcpu.close_for_forked_parent();
            }
        }
    }
}
