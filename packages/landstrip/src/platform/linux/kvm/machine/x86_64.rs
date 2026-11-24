// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! x86-64 guest layout and vCPU lifecycle.
//!
//! The payload runs in ring 3. Ring 0 consists of a single stub that the
//! `syscall` instruction enters, which writes to an I/O port to exit to the
//! VMM and then returns with `sysretq`. Page tables, GDT, TSS, IDT, and the
//! stub are written into guest physical memory by the VMM before the vCPU
//! starts.

use super::super::memory::GuestMemory;
use super::{
    ExitReason, FPE_FLTINV, GIB_BYTES, GuestFault, HUGE_PAGE_SIZE, PAGE_BYTES, PAGE_LEN,
    PT_ARENA_BASE, PT_ARENA_BYTES, RESERVED_END, SEGV_ACCERR, SEGV_MAPERR, TABLE_ENTRIES,
    USER_ADDRESS_BYTES, VcpuPool,
};
use anyhow::{Context, Result, bail};
use kvm_bindings::{
    CpuId, KVM_MAX_CPUID_ENTRIES, Msrs, kvm_fpu, kvm_msr_entry, kvm_regs, kvm_segment, kvm_sregs,
    kvm_userspace_memory_region, kvm_xcrs, kvm_xsave,
};
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};
use std::mem::offset_of;

const PML4: u64 = 0x1000;
const PDP: u64 = 0x2000;
const GDT: u64 = 0x3000;
const STUB: u64 = 0x4000;
const HANDLERS: u64 = 0x5000;
const IDT: u64 = 0x6000;
const PT: u64 = 0x7000;
const PD_BASE: u64 = 0x8000;
const TSS_POOL: u64 = 0x4_8000;
const TSS_SLOTS: u64 = 1024;
const TSS_SLOT_BYTES: u64 = 256;

const PAGE_PRESENT: u64 = 1 << 0;
const PAGE_WRITE: u64 = 1 << 1;
const PAGE_USER: u64 = 1 << 2;
const PAGE_HUGE: u64 = 1 << 7;
const PAGE_NX: u64 = 1 << 63;
const ADDR_MASK_4K: u64 = 0x000f_ffff_ffff_f000;

const GDT_LIMIT: u16 = 0x37;
const IDT_LIMIT: u16 = 0x1ff;
const TSS_LIMIT: u16 = 0x67;
const TSS_ACCESS: u8 = 0x89;
const EXCEPTION_VECTORS: u64 = 32;
const HANDLER_SIZE: u64 = 16;

const SEGMENT_TYPE_CODE: u8 = 0xb;
const SEGMENT_TYPE_DATA: u8 = 0x3;
const SEGMENT_TYPE_BUSY_TSS: u8 = 0xb;
const SEGMENT_TYPE_INTERRUPT_GATE: u8 = 0x8e;
const SEGMENT_TYPE_USER_TRAP_GATE: u8 = 0xee;

const USER_CS: u16 = 0x23;
const USER_DS: u16 = 0x1b;
const KERNEL_CS: u16 = 0x08;
const KERNEL_DS: u16 = 0x10;
const TSS_SELECTOR: u16 = 0x28;

const CR0_LONG_MODE: u64 = 0x8005_0033;
const CR4_PAE: u64 = 0x20;
const CR4_OSFXSR: u64 = 0x200;
const CR4_OSXMMEXCPT: u64 = 0x400;
const CR4_FSGSBASE: u64 = 0x1_0000;
const CR4_OSXSAVE: u64 = 0x4_0000;
const XCR0_FP_SSE: u64 = 0x3;
const XCR0_AVX: u64 = 0x4;
const EFER_SCE_LME_LMA: u64 = 0x501;
const EFER_NXE: u64 = 0x800;
const RFLAGS_RESERVED: u64 = 0x2;
const RFLAGS_DIRECTION: u64 = 0x400;
const RFLAGS_USER_MASK: u64 = 0x0005_0dd5;
const RFLAGS_SYSCALL_CLEAR: u64 = 0x0004_7700;

const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_FMASK: u32 = 0xc000_0084;

const STAR_KERNEL_CS: u64 = (KERNEL_CS as u64) << 32;
const STAR_USER_BASE: u64 = (KERNEL_DS as u64) << 48;

const TRAP_PORT: u16 = 0x80;
const FAULT_PORT: u16 = 0x81;

/// `sysretq`, which returns to the address saved by `syscall`.
const SYSRET: [u8; 3] = [0x48, 0x0f, 0x07];
/// Bytes of the `out` and `sysretq` instructions the stub consists of.
const STUB_LEN: u64 = 5;
/// Length of the `syscall` instruction, which a restarted call re-executes.
const SYSCALL_LEN: u64 = 2;
/// Bytes below the stack pointer that leaf functions may use without moving it.
const RED_ZONE_BYTES: u64 = 128;
/// Vectors that push an error code, shifting the saved instruction pointer.
const ERROR_CODE_VECTORS: [u64; 10] = [8, 10, 11, 12, 13, 14, 17, 21, 29, 30];

/// Architectural state of a vCPU besides its general-purpose registers.
pub(crate) struct VcpuState {
    sregs: kvm_sregs,
    fpu: kvm_fpu,
    xsave: Option<Box<kvm_xsave>>,
}

/// General-purpose registers of a vCPU.
///
/// While the vCPU is in the ring-0 stub, `rcx` and `r11` hold the payload's
/// instruction pointer and flags, which `sysretq` restores.
#[derive(Clone, Copy)]
pub(crate) struct Regs {
    raw: kvm_regs,
    in_kernel_stub: bool,
}

impl Regs {
    /// Registers that enter a freshly loaded program at `entry` on `stack`.
    pub(crate) fn start(entry: u64, stack: u64) -> Self {
        Self {
            raw: kvm_regs {
                rip: entry,
                rsp: stack,
                rflags: RFLAGS_RESERVED,
                ..kvm_regs::default()
            },
            in_kernel_stub: false,
        }
    }

    /// System call number.
    pub(crate) const fn number(&self) -> u64 {
        self.raw.rax
    }

    pub(crate) fn syscall(&self) -> Option<syscalls::Sysno> {
        usize::try_from(self.number())
            .ok()
            .and_then(syscalls::Sysno::new)
    }

    /// System call arguments in ABI order.
    pub(crate) const fn arguments(&self) -> [u64; 6] {
        [
            self.raw.rdi,
            self.raw.rsi,
            self.raw.rdx,
            self.raw.r10,
            self.raw.r8,
            self.raw.r9,
        ]
    }

    /// Value the system call returns to the payload.
    pub(crate) const fn result(&self) -> u64 {
        self.raw.rax
    }

    pub(crate) const fn set_result(&mut self, value: u64) {
        self.raw.rax = value;
    }

    pub(crate) const fn stack_pointer(&self) -> u64 {
        self.raw.rsp
    }

    pub(crate) const fn leave_kernel_stub(&mut self) {
        if self.in_kernel_stub {
            self.raw.rip = self.raw.rcx;
            self.raw.rflags = self.raw.r11;
            self.in_kernel_stub = false;
        }
    }

    pub(crate) const fn normalize_interrupted(&mut self) {
        if self.in_kernel_stub {
            self.raw.rip = if self.raw.rip == STUB {
                self.raw.rcx.wrapping_sub(SYSCALL_LEN)
            } else {
                self.raw.rcx
            };
            self.raw.rflags = self.raw.r11;
            self.in_kernel_stub = false;
        }
    }

    pub(crate) const fn is_canonical_addr(addr: u64) -> bool {
        let shift = (addr.cast_signed()) >> 47;
        shift == 0 || shift == -1
    }

    pub(crate) const fn has_valid_return_ip(&self) -> bool {
        Self::is_canonical_addr(self.raw.rip) && Self::is_canonical_addr(self.raw.rsp)
    }

    /// Registers of a `clone` or `fork` child, which returns zero from the
    /// system call on `stack`, or on the parent's stack when it is zero.
    pub(crate) const fn child(&self, stack: u64) -> Self {
        let mut regs = self.raw;
        regs.rip = regs.rcx;
        regs.rflags = regs.r11;
        regs.rax = 0;
        if stack != 0 {
            regs.rsp = stack;
        }
        Self {
            raw: regs,
            in_kernel_stub: false,
        }
    }

    /// Rewinds a system call trapped in the stub so that it is issued again
    /// with the number `origin` trapped with.
    pub(crate) const fn rewind_syscall(&mut self, origin: &Self) {
        self.raw.rax = origin.raw.rax;
        if self.in_kernel_stub {
            self.raw.rcx = self.raw.rcx.wrapping_sub(SYSCALL_LEN);
        } else {
            self.raw.rip = self.raw.rip.wrapping_sub(SYSCALL_LEN);
        }
    }

    pub(crate) const fn signal_frame_at(sp: u64, on_altstack: bool, size: u64) -> u64 {
        let red = if on_altstack { 0 } else { RED_ZONE_BYTES };
        sp.saturating_sub(red + size) & !0xf
    }

    pub(crate) fn write_ucontext(
        &self,
        raw: &mut [u8],
        stack: (u64, i32, u64),
        mask: u64,
        fault_addr: u64,
        ucontext_addr: u64,
    ) {
        let stack_off = offset_of!(libc::ucontext_t, uc_stack);
        let mc_off = offset_of!(libc::ucontext_t, uc_mcontext);
        let mask_off = offset_of!(libc::ucontext_t, uc_sigmask);
        let fp_off = mask_off + std::mem::size_of::<libc::sigset_t>();
        if raw.len() < fp_off + 32 {
            return;
        }
        raw[stack_off..stack_off + 8].copy_from_slice(&stack.0.to_le_bytes());
        raw[stack_off + 8..stack_off + 12].copy_from_slice(&stack.1.to_le_bytes());
        raw[stack_off + 16..stack_off + 24].copy_from_slice(&stack.2.to_le_bytes());
        raw[mask_off..mask_off + 8].copy_from_slice(&mask.to_le_bytes());
        let rip = if self.in_kernel_stub {
            self.raw.rcx
        } else {
            self.raw.rip
        };
        let rflags = if self.in_kernel_stub {
            self.raw.r11
        } else {
            self.raw.rflags
        };
        let csgsfs = u64::from(USER_CS) | (u64::from(USER_DS) << 48);
        let gregs = [
            self.raw.r8,
            self.raw.r9,
            self.raw.r10,
            self.raw.r11,
            self.raw.r12,
            self.raw.r13,
            self.raw.r14,
            self.raw.r15,
            self.raw.rdi,
            self.raw.rsi,
            self.raw.rbp,
            self.raw.rbx,
            self.raw.rdx,
            self.raw.rax,
            self.raw.rcx,
            self.raw.rsp,
            rip,
            rflags,
            csgsfs,
            0,
            0,
            mask,
            fault_addr,
            ucontext_addr.saturating_add(u64::try_from(fp_off).unwrap_or(0)),
        ];
        for (idx, word) in gregs.iter().enumerate() {
            let at = mc_off + idx * 8;
            raw[at..at + 8].copy_from_slice(&word.to_le_bytes());
        }
        raw[fp_off..fp_off + 2].copy_from_slice(&0x037f_u16.to_le_bytes());
        raw[fp_off + 24..fp_off + 28].copy_from_slice(&0x1f80_u32.to_le_bytes());
    }

    pub(crate) fn read_ucontext_meta(raw: &[u8]) -> Option<(u64, (u64, i32, u64))> {
        let stack_off = offset_of!(libc::ucontext_t, uc_stack);
        let mask_off = offset_of!(libc::ucontext_t, uc_sigmask);
        if raw.len() < mask_off + 8 || raw.len() < stack_off + 24 {
            return None;
        }
        let mask = u64::from_le_bytes(raw[mask_off..mask_off + 8].try_into().ok()?);
        let sp = u64::from_le_bytes(raw[stack_off..stack_off + 8].try_into().ok()?);
        let flags = i32::from_le_bytes(raw[stack_off + 8..stack_off + 12].try_into().ok()?);
        let size = u64::from_le_bytes(raw[stack_off + 16..stack_off + 24].try_into().ok()?);
        Some((mask, (sp, flags, size)))
    }

    pub(crate) fn apply_ucontext(&mut self, raw: &[u8]) {
        let mc_off = offset_of!(libc::ucontext_t, uc_mcontext);
        if raw.len() < mc_off + 18 * 8 {
            return;
        }
        let word = |idx: usize| -> u64 {
            let at = mc_off + idx * 8;
            u64::from_le_bytes(raw[at..at + 8].try_into().unwrap_or([0; 8]))
        };
        self.raw.r8 = word(0);
        self.raw.r9 = word(1);
        self.raw.r10 = word(2);
        self.raw.r11 = word(3);
        self.raw.r12 = word(4);
        self.raw.r13 = word(5);
        self.raw.r14 = word(6);
        self.raw.r15 = word(7);
        self.raw.rdi = word(8);
        self.raw.rsi = word(9);
        self.raw.rbp = word(10);
        self.raw.rbx = word(11);
        self.raw.rdx = word(12);
        self.raw.rax = word(13);
        self.raw.rcx = word(14);
        self.raw.rsp = word(15);
        self.raw.rip = word(16);
        let efl = word(17);
        self.raw.rflags =
            (self.raw.rflags & !RFLAGS_USER_MASK) | (efl & RFLAGS_USER_MASK) | RFLAGS_RESERVED;
        self.in_kernel_stub = false;
    }

    /// Enters the signal handler at `handler` with `arguments`, below the
    /// signal frame at `frame`, returning to `restorer`.
    pub(crate) fn enter_handler(
        &mut self,
        memory: &GuestMemory,
        handler: u64,
        restorer: Option<u64>,
        frame: u64,
        arguments: [u64; 3],
    ) -> Result<()> {
        let stack = frame.saturating_sub(8);
        memory.write_u64(stack, restorer.unwrap_or(0))?;
        let flags = if self.in_kernel_stub {
            self.raw.r11
        } else {
            self.raw.rflags
        };
        let [signal, info, context] = arguments;
        self.raw.rip = handler;
        self.raw.rsp = stack;
        self.raw.rdi = signal;
        self.raw.rsi = info;
        self.raw.rdx = context;
        self.raw.rax = 0;
        self.raw.rflags = (flags & !RFLAGS_DIRECTION) | RFLAGS_RESERVED;
        self.in_kernel_stub = false;
        Ok(())
    }
}

pub(crate) struct Machine {
    pub(crate) memory: GuestMemory,
    pub(super) vm: super::BrokerHandle<VmFd>,
    cpuid: CpuId,
    xcr0: Option<u64>,
    nxe: bool,
    fsgsbase: bool,
    pub(super) pool: VcpuPool,
}

impl Machine {
    pub(crate) fn create(memory: GuestMemory) -> Result<(Self, super::BrokerHandle<VcpuFd>)> {
        let (machine, vcpu) = Self::attach(memory)?;
        machine.install_layout()?;
        Ok((machine, vcpu))
    }

    /// Creates a guest for a forked child over the guest memory it
    /// inherited, continuing in the state the parent trapped in, with the
    /// thread pointer replaced by `tls` when present.
    pub(crate) fn inherit(
        trapped: &VcpuState,
        memory: GuestMemory,
        tls: Option<u64>,
    ) -> Result<(Self, super::BrokerHandle<VcpuFd>)> {
        let _range = super::super::fds::Range::occupy_unused()?;
        let (machine, vcpu) = Self::attach(memory)?;
        let mut sregs = vcpu.get().get_sregs().context("read vCPU state")?;
        sregs.fs = trapped.sregs.fs;
        sregs.gs = trapped.sregs.gs;
        sregs.cr2 = trapped.sregs.cr2;
        if let Some(base) = tls {
            sregs.fs.base = base;
        }
        vcpu.get()
            .set_sregs(&sregs)
            .context("set vCPU state of the forked child")?;
        Self::restore_fpu(vcpu.get(), trapped)?;
        Ok((machine, vcpu))
    }

    /// Reads the architectural state of `vcpu` for a child thread or process,
    /// or for a signal handler to return to.
    pub(crate) fn state(&self, vcpu: &VcpuFd) -> Result<VcpuState> {
        let xsave = if self.xcr0.is_some() {
            Some(Box::new(vcpu.get_xsave().context("read vCPU XSAVE state")?))
        } else {
            None
        };
        Ok(VcpuState {
            sregs: vcpu.get_sregs().context("read vCPU state")?,
            fpu: vcpu.get_fpu().context("read vCPU FPU state")?,
            xsave,
        })
    }

    /// Restores floating-point state when a signal handler returns, keeping
    /// the guest's current TLS segment bases intact.
    pub(crate) fn restore_signal(vcpu: &VcpuFd, state: &VcpuState) -> Result<()> {
        Self::restore_fpu(vcpu, state)
    }

    pub(crate) fn reset_fpu(&self, vcpu: &VcpuFd) -> Result<()> {
        let fpu = kvm_fpu {
            fcw: 0x037f,
            mxcsr: 0x1f80,
            ..kvm_fpu::default()
        };
        if self.xcr0.is_some() {
            let xsave = Box::new(kvm_xsave::default());
            // SAFETY: zeroed `kvm_xsave` (`XSTATE_BV == 0`) places all enabled
            // XSAVE components in their architectural INIT state.
            unsafe { vcpu.set_xsave(&xsave) }.context("reset vCPU XSAVE state")?;
        }
        vcpu.set_fpu(&fpu).context("reset vCPU FPU state")
    }

    fn restore_fpu(vcpu: &VcpuFd, state: &VcpuState) -> Result<()> {
        if let Some(xsave) = &state.xsave {
            // SAFETY: `xsave` was returned by `KVM_GET_XSAVE` on a vCPU with
            // the same `XCR0` configuration.
            unsafe { vcpu.set_xsave(xsave) }.context("set vCPU XSAVE state")
        } else {
            vcpu.set_fpu(&state.fpu).context("set vCPU FPU state")
        }
    }

    fn attach(memory: GuestMemory) -> Result<(Self, super::BrokerHandle<VcpuFd>)> {
        let kvm = Self::open_kvm()?;
        let vm =
            super::BrokerHandle::register(kvm.create_vm().context("create a KVM virtual machine")?);
        let region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: memory.allocation_size(),
            userspace_addr: memory.base(),
            flags: 0,
        };
        unsafe { vm.get().set_user_memory_region(region) }.context("register guest memory")?;

        let vcpu = super::BrokerHandle::register(vm.get().create_vcpu(0).context("create a vCPU")?);
        let mut cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .context("read supported CPUID")?;
        let (xcr0, nxe, fsgsbase) = Self::sanitize_cpuid(&mut cpuid);
        vcpu.get().set_cpuid2(&cpuid).context("set vCPU CPUID")?;
        vcpu.get()
            .set_sregs(&Self::long_mode_sregs(xcr0.is_some(), nxe, fsgsbase, 0))
            .context("set vCPU state")?;
        if let Some(mask) = xcr0 {
            Self::set_xcr0(vcpu.get(), mask)?;
        }
        vcpu.get()
            .set_msrs(&Self::msrs()?)
            .context("set vCPU MSRs")?;

        Ok((
            Self {
                memory,
                vm,
                cpuid,
                xcr0,
                nxe,
                fsgsbase,
                pool: VcpuPool::new(),
            },
            vcpu,
        ))
    }

    /// Allocates a fresh vCPU above the payload descriptor ceiling.
    pub(crate) fn allocate_vcpu(&self) -> Result<super::BrokerHandle<VcpuFd>> {
        let id = self.pool.next_id();
        let vcpu = {
            let _range = super::super::fds::Range::occupy_unused()?;
            super::BrokerHandle::register(
                self.vm
                    .get()
                    .create_vcpu(id)
                    .context("create thread vCPU")?,
            )
        };
        vcpu.get()
            .set_cpuid2(&self.cpuid)
            .context("set thread vCPU CPUID")?;
        vcpu.get()
            .set_sregs(&Self::long_mode_sregs(
                self.xcr0.is_some(),
                self.nxe,
                self.fsgsbase,
                id,
            ))
            .context("set initial thread vCPU state")?;
        Ok(vcpu)
    }

    /// Initializes `vcpu` for a spawned guest thread that continues in
    /// `state` with `registers`, and with the thread pointer replaced by `tls`
    /// when present.
    pub(crate) fn configure_vcpu(
        &self,
        vcpu: &VcpuFd,
        state: &VcpuState,
        tls: Option<u64>,
        registers: &Regs,
    ) -> Result<()> {
        let prev_tr = vcpu.get_sregs().map_or(TSS_POOL, |s| s.tr.base);
        let slot = if prev_tr >= TSS_POOL {
            (prev_tr - TSS_POOL) / TSS_SLOT_BYTES
        } else {
            0
        };
        let mut sregs = Self::long_mode_sregs(self.xcr0.is_some(), self.nxe, self.fsgsbase, slot);
        sregs.fs.base = tls.unwrap_or(state.sregs.fs.base);
        sregs.gs.base = state.sregs.gs.base;
        vcpu.set_sregs(&sregs).context("set thread vCPU segments")?;
        if let Some(mask) = self.xcr0 {
            Self::set_xcr0(vcpu, mask)?;
        }
        vcpu.set_msrs(&Self::msrs()?)
            .context("set thread vCPU MSRs")?;
        Self::restore_fpu(vcpu, state)?;
        Self::set_regs(vcpu, registers)
    }

    /// Reads the general-purpose registers of `vcpu`.
    pub(crate) fn regs(&self, vcpu: &VcpuFd) -> Result<Regs> {
        let mut raw = vcpu.get_regs().context("read vCPU registers")?;
        let sregs = vcpu.get_sregs().context("read vCPU segments")?;
        if sregs.cs.selector == KERNEL_CS
            && (HANDLERS..HANDLERS + EXCEPTION_VECTORS * HANDLER_SIZE).contains(&raw.rip)
        {
            self.unwind_interrupted_handler(&mut raw)?;
            return Ok(Regs {
                raw,
                in_kernel_stub: false,
            });
        }
        let in_kernel_stub = sregs.cs.selector == KERNEL_CS && Self::in_stub(raw.rip);
        Ok(Regs {
            raw,
            in_kernel_stub,
        })
    }

    fn unwind_interrupted_handler(&self, raw: &mut kvm_regs) -> Result<()> {
        let rel = raw.rip - HANDLERS;
        let vector = rel / HANDLER_SIZE;
        let offset_in_stub = rel % HANDLER_SIZE;
        let pushed_rax = offset_in_stub >= 1;
        let has_err = ERROR_CODE_VECTORS.contains(&vector);
        let words_needed = 4 + u64::from(pushed_rax) + u64::from(has_err);
        let frame = self
            .memory
            .read_supervisor(raw.rsp, words_needed * 8)
            .context("read interrupted exception frame")?;
        let word = |idx: usize| -> u64 {
            let at = idx * 8;
            u64::from_le_bytes(frame[at..at + 8].try_into().unwrap_or([0; 8]))
        };
        let mut idx = 0usize;
        if pushed_rax {
            raw.rax = word(idx);
            idx += 1;
        }
        if has_err {
            idx += 1;
        }
        raw.rip = word(idx);
        raw.rflags = word(idx + 2);
        raw.rsp = word(idx + 3);
        Ok(())
    }

    /// Writes the general-purpose registers of `vcpu`, leaving ring 0 when
    /// they no longer point into the stub.
    pub(crate) fn set_regs(vcpu: &VcpuFd, registers: &Regs) -> Result<()> {
        if !registers.in_kernel_stub {
            let mut sregs = vcpu.get_sregs().context("read vCPU segments")?;
            if sregs.cs.selector != USER_CS {
                sregs.cs = Self::segment(USER_CS, SEGMENT_TYPE_CODE, 3, true);
                sregs.ss = Self::segment(USER_DS, SEGMENT_TYPE_DATA, 3, false);
                vcpu.set_sregs(&sregs).context("enter user mode")?;
            }
        }
        vcpu.set_regs(&registers.raw)
            .context("write vCPU registers")
    }

    /// Reads the guest's FS or GS base without touching the host thread state.
    pub(crate) fn segment_base(vcpu: &VcpuFd, gs: bool) -> Result<u64> {
        let sregs = vcpu.get_sregs().context("read vCPU segments")?;
        Ok(if gs { sregs.gs.base } else { sregs.fs.base })
    }

    pub(crate) fn set_segment_base(vcpu: &VcpuFd, gs: bool, base: u64) -> Result<()> {
        let mut sregs = vcpu.get_sregs().context("read vCPU segments")?;
        let segment = if gs { &mut sregs.gs } else { &mut sregs.fs };
        segment.selector = 0;
        segment.base = base;
        vcpu.set_sregs(&sregs).context("write vCPU segments")
    }

    pub(crate) fn hwcaps() -> (u64, u64) {
        let primary = unsafe { libc::getauxval(libc::AT_HWCAP) };
        (primary, 0)
    }

    pub(crate) fn tlb_epoch(&self) -> u64 {
        self.pool.tlb_epoch()
    }

    pub(crate) fn sync_tlb(&self, vcpu: &VcpuFd, local_epoch: &mut u64) -> Result<()> {
        let current = self.pool.tlb_epoch();
        if *local_epoch != current {
            let sregs = vcpu.get_sregs().context("read vCPU segments for TLB")?;
            vcpu.set_sregs(&sregs).context("flush vCPU TLB")?;
            *local_epoch = current;
        }
        Ok(())
    }

    pub(crate) fn reset_page_tables(&self) -> Result<()> {
        self.install_page_tables()?;
        self.memory
            .discard_supervisor(PT_ARENA_BASE, PT_ARENA_BYTES);
        self.pool.bump_tlb();
        Ok(())
    }

    pub(crate) fn protect_pages(&self, start: u64, length: u64, prot: u32) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        let end = start
            .checked_add(length)
            .context("page protection range overflow")?
            .min(USER_ADDRESS_BYTES);
        let leaf_flags = self.protection_flags(prot);
        let mut cursor = start.max(RESERVED_END) & !(PAGE_BYTES - 1);
        while cursor < end {
            let block_base = cursor & !(HUGE_PAGE_SIZE - 1);
            let block_end = (block_base + HUGE_PAGE_SIZE).min(USER_ADDRESS_BYTES);
            let seg_end = end.min(block_end);
            let gib = block_base / GIB_BYTES;
            let pd_idx = (block_base % GIB_BYTES) / HUGE_PAGE_SIZE;
            let pd_entry_addr = PD_BASE + gib * PAGE_BYTES + pd_idx * 8;
            if cursor == block_base && seg_end == block_base + HUGE_PAGE_SIZE {
                let block_entry = if leaf_flags == 0 {
                    0
                } else {
                    block_base | leaf_flags | PAGE_HUGE
                };
                self.memory
                    .write_supervisor_u64(pd_entry_addr, block_entry)?;
            } else {
                let block_id = block_base / HUGE_PAGE_SIZE;
                let pt_gpa = PT_ARENA_BASE + block_id * PAGE_BYTES;
                let pd_entry = self.memory.read_supervisor_u64(pd_entry_addr)?;
                let is_split = pd_entry & PAGE_PRESENT != 0
                    && pd_entry & PAGE_HUGE == 0
                    && (pd_entry & ADDR_MASK_4K) == pt_gpa;
                let mut pt_bytes = if is_split {
                    self.memory.read_supervisor(pt_gpa, PAGE_BYTES)?
                } else {
                    let base_flags = if pd_entry & PAGE_PRESENT == 0 {
                        0
                    } else {
                        pd_entry & (PAGE_PRESENT | PAGE_WRITE | PAGE_USER | PAGE_NX)
                    };
                    let mut table = vec![0u8; PAGE_LEN];
                    if base_flags != 0 {
                        for (idx, slot) in (0..TABLE_ENTRIES).zip(table.chunks_exact_mut(8)) {
                            let pte = (block_base + idx * PAGE_BYTES) | base_flags;
                            slot.copy_from_slice(&pte.to_le_bytes());
                        }
                    }
                    table
                };
                let first_page = usize::try_from((cursor - block_base) / PAGE_BYTES)?;
                let last_page = usize::try_from((seg_end - block_base) / PAGE_BYTES)?;
                for page_idx in first_page..last_page {
                    let page_phys = block_base + u64::try_from(page_idx)? * PAGE_BYTES;
                    let pte = if leaf_flags == 0 {
                        0
                    } else {
                        page_phys | leaf_flags
                    };
                    let off = page_idx * 8;
                    pt_bytes[off..off + 8].copy_from_slice(&pte.to_le_bytes());
                }
                self.memory.write_supervisor(pt_gpa, &pt_bytes)?;
                if !is_split {
                    self.memory.write_supervisor_u64(
                        pd_entry_addr,
                        pt_gpa | PAGE_PRESENT | PAGE_WRITE | PAGE_USER,
                    )?;
                }
            }
            cursor = seg_end;
        }
        self.pool.bump_tlb();
        Ok(())
    }

    fn protection_flags(&self, prot: u32) -> u64 {
        let rwx = u32::try_from(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC).unwrap_or(7);
        if prot & rwx == 0 {
            return 0;
        }
        let mut flags = PAGE_PRESENT | PAGE_USER;
        if prot & u32::try_from(libc::PROT_WRITE).unwrap_or(2) != 0 {
            flags |= PAGE_WRITE;
        }
        if self.nxe && prot & u32::try_from(libc::PROT_EXEC).unwrap_or(4) == 0 {
            flags |= PAGE_NX;
        }
        flags
    }

    /// Runs `vcpu` until the payload needs the VMM.
    pub(crate) fn run(&self, vcpu: &mut VcpuFd) -> Result<ExitReason> {
        match vcpu.run() {
            Ok(VcpuExit::IoOut(TRAP_PORT, _)) => Ok(ExitReason::Syscall),
            Ok(VcpuExit::IoOut(FAULT_PORT, _)) => self.fault(vcpu).map(ExitReason::Fault),
            Ok(VcpuExit::IoOut(port, _)) => bail!("guest wrote to unexpected port {port:#x}"),
            Ok(VcpuExit::FailEntry(..) | VcpuExit::InternalError | VcpuExit::Shutdown) => {
                if let Ok(regs) = self.regs(vcpu)
                    && !regs.in_kernel_stub
                    && !regs.has_valid_return_ip()
                {
                    return Ok(ExitReason::Fault(GuestFault {
                        signal: libc::SIGSEGV,
                        code: libc::SI_KERNEL,
                        address: 0,
                        is_page_fault: false,
                    }));
                }
                bail!("unsupported guest exit")
            }
            Ok(_) => bail!("unsupported guest exit"),
            Err(error) if error.errno() == libc::EINTR => Ok(ExitReason::Interrupted),
            Err(error) if error.errno() == libc::EFAULT => Ok(ExitReason::Fault(GuestFault {
                signal: libc::SIGBUS,
                code: libc::BUS_ADRERR,
                address: 0,
                is_page_fault: false,
            })),
            Err(error) => bail!("run the vCPU: {error}"),
        }
    }

    fn fault(&self, vcpu: &VcpuFd) -> Result<GuestFault> {
        let mut registers = vcpu.get_regs().context("read vCPU registers")?;
        let sregs = vcpu.get_sregs().context("read vCPU segments")?;
        let vector = registers.rax;
        let has_err = ERROR_CODE_VECTORS.contains(&vector);
        let word_count = 6 + u64::from(has_err);
        let frame = self
            .memory
            .read_supervisor(registers.rsp, word_count * 8)
            .context("read guest exception frame")?;
        let words: Vec<u64> = frame
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])))
            .collect();
        let saved_rax = words.first().copied().unwrap_or(0);
        let (error_code, base) = if has_err {
            (words.get(1).copied().unwrap_or(0), 2)
        } else {
            (0, 1)
        };
        let rip = words.get(base).copied().unwrap_or(0);
        let cs = words.get(base + 1).copied().unwrap_or(0);
        let rflags = words.get(base + 2).copied().unwrap_or(RFLAGS_RESERVED);
        let user_rsp = words.get(base + 3).copied().unwrap_or(0);
        if cs.trailing_zeros() >= 2 {
            bail!(
                "supervisor fault {vector} at rip {rip:#x} (cr2 {:#x})",
                sregs.cr2
            );
        }
        registers.rax = saved_rax;
        registers.rip = rip;
        registers.rflags = rflags;
        registers.rsp = user_rsp;
        Self::set_regs(
            vcpu,
            &Regs {
                raw: registers,
                in_kernel_stub: false,
            },
        )?;
        Ok(Self::classify_fault(vector, error_code, rip, sregs.cr2))
    }

    const fn classify_fault(vector: u64, error_code: u64, rip: u64, cr2: u64) -> GuestFault {
        const FPE_INTDIV: i32 = 1;
        const ILL_ILLOPN: i32 = 2;
        match vector {
            0 => GuestFault {
                signal: libc::SIGFPE,
                code: FPE_INTDIV,
                address: rip,
                is_page_fault: false,
            },
            1 => GuestFault {
                signal: libc::SIGTRAP,
                code: 1,
                address: rip,
                is_page_fault: false,
            },
            3 => GuestFault {
                signal: libc::SIGTRAP,
                code: 1,
                address: rip.saturating_sub(1),
                is_page_fault: false,
            },
            6 => GuestFault {
                signal: libc::SIGILL,
                code: ILL_ILLOPN,
                address: rip,
                is_page_fault: false,
            },
            7 | 16 | 19 => GuestFault {
                signal: libc::SIGFPE,
                code: FPE_FLTINV,
                address: rip,
                is_page_fault: false,
            },
            14 => GuestFault {
                signal: libc::SIGSEGV,
                code: if error_code & 1 != 0 {
                    SEGV_ACCERR
                } else {
                    SEGV_MAPERR
                },
                address: cr2,
                is_page_fault: true,
            },
            17 => GuestFault {
                signal: libc::SIGBUS,
                code: libc::BUS_ADRALN,
                address: cr2,
                is_page_fault: false,
            },
            _ => GuestFault {
                signal: libc::SIGSEGV,
                code: libc::SI_KERNEL,
                address: 0,
                is_page_fault: false,
            },
        }
    }

    /// Reports whether `rip` is inside the ring-0 stub.
    const fn in_stub(rip: u64) -> bool {
        rip >= STUB && rip < STUB + STUB_LEN
    }

    fn install_layout(&self) -> Result<()> {
        self.install_page_tables()?;
        self.memory.write_supervisor_u64(GDT, 0)?;
        self.memory
            .write_supervisor_u64(GDT + 0x08, 0x00af_9b00_0000_ffff)?;
        self.memory
            .write_supervisor_u64(GDT + 0x10, 0x00cf_9300_0000_ffff)?;
        self.memory
            .write_supervisor_u64(GDT + 0x18, 0x00cf_f300_0000_ffff)?;
        self.memory
            .write_supervisor_u64(GDT + 0x20, 0x00af_fb00_0000_ffff)?;
        let descriptor = (TSS_POOL & 0xffff)
            | ((TSS_POOL & 0xff_0000) << 16)
            | (u64::from(TSS_ACCESS) << 40)
            | (u64::from(TSS_LIMIT) << 48);
        self.memory.write_supervisor_u64(GDT + 0x28, descriptor)?;
        self.memory.write_supervisor_u64(GDT + 0x30, 0)?;
        self.install_handlers()?;
        self.install_idt()?;
        self.install_tss()?;
        let mut stub = Self::out_instruction(TRAP_PORT).to_vec();
        stub.extend_from_slice(&SYSRET);
        self.memory.write_supervisor(STUB, &stub)
    }

    fn install_page_tables(&self) -> Result<()> {
        // The first huge page uses 4 KiB entries without `PAGE_USER` on its
        // directory entry so ring-0 structures and page zero cannot be touched
        // by user mode, while ring 0 still addresses `0..RESERVED_END`.
        let mut pt = [0u8; PAGE_LEN];
        for page in 0..TABLE_ENTRIES {
            let address = page * PAGE_BYTES;
            let entry = address | PAGE_PRESENT | PAGE_WRITE;
            let slot = usize::try_from(page * 8)?;
            pt[slot..slot + 8].copy_from_slice(&entry.to_le_bytes());
        }
        self.memory.write_supervisor(PT, &pt)?;

        let size = self.memory.size();
        let gib_count = size.div_ceil(GIB_BYTES);
        Self::ensure_layout_fits(gib_count)?;
        let mut pdp = [0u8; PAGE_LEN];
        for gib in 0..gib_count {
            let pd_address = PD_BASE + gib * PAGE_BYTES;
            let pdp_entry = pd_address | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
            let pdp_slot = usize::try_from(gib * 8)?;
            pdp[pdp_slot..pdp_slot + 8].copy_from_slice(&pdp_entry.to_le_bytes());

            let mut pd = [0u8; PAGE_LEN];
            if gib == 0 {
                let entry = PT | PAGE_PRESENT | PAGE_WRITE;
                pd[..8].copy_from_slice(&entry.to_le_bytes());
            }
            self.memory.write_supervisor(pd_address, &pd)?;
        }
        self.memory.write_supervisor(PDP, &pdp)?;
        self.memory
            .write_supervisor_u64(PML4, PDP | PAGE_PRESENT | PAGE_WRITE | PAGE_USER)
    }

    fn install_handlers(&self) -> Result<()> {
        for vector in 0..EXCEPTION_VECTORS {
            let mut stub = vec![0x50, 0xb8];
            stub.extend_from_slice(&u32::try_from(vector)?.to_le_bytes());
            stub.extend_from_slice(&Self::out_instruction(FAULT_PORT));
            stub.push(0xf4);
            stub.resize(usize::try_from(HANDLER_SIZE)?, 0x90);
            self.memory
                .write_supervisor(HANDLERS + vector * HANDLER_SIZE, &stub)?;
        }
        Ok(())
    }

    fn install_idt(&self) -> Result<()> {
        for vector in 0..EXCEPTION_VECTORS {
            let offset = HANDLERS + vector * HANDLER_SIZE;
            let gate = if vector == 3 {
                SEGMENT_TYPE_USER_TRAP_GATE
            } else {
                SEGMENT_TYPE_INTERRUPT_GATE
            };
            let low = (offset & 0xffff)
                | (u64::from(KERNEL_CS) << 16)
                | (u64::from(gate) << 40)
                | ((offset >> 16) << 48);
            let at = IDT + vector * HANDLER_SIZE;
            self.memory.write_supervisor_u64(at, low)?;
            self.memory.write_supervisor_u64(at + 8, offset >> 32)?;
        }
        Ok(())
    }

    fn install_tss(&self) -> Result<()> {
        for slot in 0..TSS_SLOTS {
            let base = TSS_POOL + slot * TSS_SLOT_BYTES;
            let rsp0 = base + TSS_SLOT_BYTES;
            let mut tss = [0u8; 0x68];
            for offset in [4, 12, 20] {
                tss[offset..offset + 8].copy_from_slice(&rsp0.to_le_bytes());
            }
            tss[0x64..0x66].copy_from_slice(&TSS_LIMIT.to_le_bytes());
            self.memory.write_supervisor(base, &tss)?;
        }
        Ok(())
    }

    fn out_instruction(port: u16) -> [u8; 2] {
        let [low, _] = port.to_le_bytes();
        [0xe7, low]
    }

    fn sanitize_cpuid(cpuid: &mut CpuId) -> (Option<u64>, bool, bool) {
        let mut xcr0 = None;
        let mut nxe = false;
        let mut fsgsbase = false;
        for entry in cpuid.as_mut_slice() {
            if entry.function == 0x8000_0001 && entry.edx & (1 << 20) != 0 {
                nxe = true;
            }
            if entry.function == 0x1 && entry.ecx & (1 << 26) != 0 {
                let mut mask = XCR0_FP_SSE;
                if entry.ecx & (1 << 28) != 0 {
                    mask |= XCR0_AVX;
                }
                xcr0 = Some(mask);
                entry.ecx |= 1 << 27;
            }
            if entry.function == 0x7 && entry.index == 0 && entry.ebx & 1 != 0 {
                fsgsbase = true;
            }
        }
        for entry in cpuid.as_mut_slice() {
            match entry.function {
                0x1 if xcr0.is_none() => {
                    entry.ecx &=
                        !((1 << 12) | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29) | (1 << 30));
                }
                0x7 if entry.index == 0 => {
                    entry.eax = 0;
                    let avx2_clear = if xcr0.is_some_and(|mask| mask & XCR0_AVX != 0) {
                        0
                    } else {
                        1 << 5
                    };
                    entry.ebx &= !(avx2_clear
                        | (1 << 4)
                        | (1 << 7)
                        | (1 << 11)
                        | (1 << 14)
                        | (1 << 16)
                        | (1 << 17)
                        | (1 << 20)
                        | (1 << 21)
                        | (1 << 26)
                        | (1 << 27)
                        | (1 << 28)
                        | (1 << 30)
                        | (1 << 31));
                    entry.ecx = 0;
                    entry.edx &= !((1 << 8) | (1 << 20) | (1 << 22) | (1 << 24) | (1 << 25));
                }
                0x7 | 0x1d | 0x1e => {
                    entry.eax = 0;
                    entry.ebx = 0;
                    entry.ecx = 0;
                    entry.edx = 0;
                }
                0xd => match (xcr0, entry.index) {
                    (Some(mask), 0) => {
                        entry.eax &= u32::try_from(mask).unwrap_or(0);
                        entry.edx = 0;
                        let max_bytes = if mask & XCR0_AVX != 0 { 832 } else { 576 };
                        entry.ebx = entry.ebx.min(max_bytes);
                        entry.ecx = entry.ecx.min(max_bytes);
                    }
                    (Some(_), 1) => {
                        entry.ecx = 0;
                        entry.edx = 0;
                    }
                    (Some(mask), 2) if mask & XCR0_AVX != 0 => {}
                    _ => {
                        entry.eax = 0;
                        entry.ebx = 0;
                        entry.ecx = 0;
                        entry.edx = 0;
                    }
                },
                _ => {}
            }
        }
        (xcr0, nxe, fsgsbase)
    }

    fn set_xcr0(vcpu: &VcpuFd, mask: u64) -> Result<()> {
        let mut xcrs = kvm_xcrs {
            nr_xcrs: 1,
            ..kvm_xcrs::default()
        };
        xcrs.xcrs[0].xcr = 0;
        xcrs.xcrs[0].value = mask;
        vcpu.set_xcrs(&xcrs).context("set vCPU XCR0")
    }

    fn long_mode_sregs(xsave: bool, nxe: bool, fsgsbase: bool, vcpu_id: u64) -> kvm_sregs {
        let mut sregs = kvm_sregs::default();
        sregs.cs = Self::segment(USER_CS, SEGMENT_TYPE_CODE, 3, true);
        sregs.ds = Self::segment(USER_DS, SEGMENT_TYPE_DATA, 3, false);
        sregs.es = sregs.ds;
        sregs.fs = sregs.ds;
        sregs.fs.selector = 0;
        sregs.gs = sregs.ds;
        sregs.gs.selector = 0;
        sregs.ss = sregs.ds;
        sregs.tr = Self::segment(TSS_SELECTOR, SEGMENT_TYPE_BUSY_TSS, 0, false);
        sregs.tr.base = TSS_POOL + (vcpu_id % TSS_SLOTS) * TSS_SLOT_BYTES;
        sregs.tr.limit = u32::from(TSS_LIMIT);
        sregs.tr.g = 0;
        sregs.ldt.unusable = 1;
        sregs.gdt.base = GDT;
        sregs.gdt.limit = GDT_LIMIT;
        sregs.idt.base = IDT;
        sregs.idt.limit = IDT_LIMIT;
        sregs.cr0 = CR0_LONG_MODE;
        sregs.cr3 = PML4;
        sregs.cr4 = CR4_PAE
            | CR4_OSFXSR
            | CR4_OSXMMEXCPT
            | if fsgsbase { CR4_FSGSBASE } else { 0 }
            | if xsave { CR4_OSXSAVE } else { 0 };
        sregs.efer = EFER_SCE_LME_LMA | if nxe { EFER_NXE } else { 0 };
        sregs
    }

    fn segment(selector: u16, type_: u8, dpl: u8, long: bool) -> kvm_segment {
        kvm_segment {
            base: 0,
            limit: 0xfffff,
            selector,
            type_,
            present: 1,
            dpl,
            db: u8::from(!long),
            s: 1,
            l: u8::from(long),
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        }
    }

    fn msrs() -> Result<Msrs> {
        Msrs::from_entries(&[
            kvm_msr_entry {
                index: MSR_STAR,
                data: STAR_USER_BASE | STAR_KERNEL_CS,
                ..kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: MSR_LSTAR,
                data: STUB,
                ..kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: MSR_FMASK,
                data: RFLAGS_SYSCALL_CLEAR,
                ..kvm_msr_entry::default()
            },
        ])
        .context("build MSR list")
    }

    fn ensure_layout_fits(gib_count: u64) -> Result<()> {
        if gib_count > TABLE_ENTRIES
            || PD_BASE + gib_count * PAGE_BYTES > TSS_POOL
            || TSS_POOL + TSS_SLOTS * TSS_SLOT_BYTES > RESERVED_END
        {
            bail!("guest memory exceeds page-table layout capacity");
        }
        Ok(())
    }
}
