// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! AArch64 guest layout and vCPU lifecycle.
//!
//! The payload runs at EL0. EL1 consists of an exception vector table whose
//! every entry stores to an IPA outside the KVM memory slot, which exits to
//! the VMM as an MMIO write, and then returns to EL0 with `eret`. The entries
//! address the store through `SP_EL1`, so no general-purpose register is
//! clobbered, and the VMM reads and writes the payload state through
//! `KVM_GET_ONE_REG` and `KVM_SET_ONE_REG`.
//!
//! The VMM always resumes a vCPU at an `eret` with the payload state in
//! `ELR_EL1` and `SPSR_EL1`, so writing the payload's program counter never
//! races the program counter advance that completes an MMIO exit.

use super::super::memory::GuestMemory;
use super::{
    ADDRESS_SPACE_BYTES, ExitReason, FPE_FLTINV, GIB_BYTES, GuestFault, HUGE_PAGE_SIZE, PAGE_BYTES,
    PAGE_LEN, PT_ARENA_BASE, PT_ARENA_BYTES, RESERVED_END, SEGV_ACCERR, SEGV_MAPERR, TABLE_ENTRIES,
    USER_ADDRESS_BYTES, VcpuPool,
};
use anyhow::{Context, Result, bail};
use kvm_bindings::{
    KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG, KVM_REG_ARM64_SYSREG_CRM_SHIFT,
    KVM_REG_ARM64_SYSREG_CRN_SHIFT, KVM_REG_ARM64_SYSREG_OP0_SHIFT, KVM_REG_ARM64_SYSREG_OP1_SHIFT,
    KVM_REG_ARM64_SYSREG_OP2_SHIFT, KVM_REG_SIZE_U32, KVM_REG_SIZE_U64, KVM_REG_SIZE_U128,
    KVM_SPSR_EL1, PSR_MODE_EL0t, PSR_MODE_EL1h, PSR_MODE_MASK, PSR_MODE32_BIT, kvm_regs,
    kvm_userspace_memory_region, kvm_vcpu_init, user_fpsimd_state, user_pt_regs,
};
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};
use std::mem::offset_of;

/// IPA range left outside the KVM memory slot. EL1 stores into it exit to the
/// VMM, and it spans 64 KiB so the memory slot stays aligned to 4 KiB, 16 KiB,
/// and 64 KiB host pages alike.
const TRAP_END: u64 = 0x1_0000;
/// `SP_EL1`, the base of the MMIO words the exception vectors store to.
const TRAP_BASE: u64 = 0x1000;
/// EL1-only address that a signal handler installed without `SA_RESTORER`
/// returns to, whose instruction abort performs `rt_sigreturn`.
const SIGNAL_RETURN: u64 = 0x2000;
/// `VBAR_EL1`, aligned to 2 KiB.
const VECTORS: u64 = TRAP_END;
const VECTOR_COUNT: u64 = 16;
const VECTOR_BYTES: u64 = 0x80;
/// Vector taken by synchronous exceptions from EL0 in AArch64 state.
const LOWER_SYNC: u64 = 8;
/// A lone `eret`, which every vCPU resumes at.
const LAUNCH: u64 = VECTORS + VECTOR_COUNT * VECTOR_BYTES;
const LAUNCH_FLUSH: u64 = LAUNCH + INSTRUCTION_BYTES;
const L0_TABLE: u64 = 0x1_1000;
const L1_TABLE: u64 = 0x1_2000;
const L3_TABLE: u64 = 0x1_3000;
const L2_BASE: u64 = 0x1_4000;
const _: () = assert!(L2_BASE + (ADDRESS_SPACE_BYTES / GIB_BYTES) * PAGE_BYTES <= RESERVED_END);

/// `str xzr, [sp]`, whose 12-bit immediate holds the offset in words.
const STORE_ZERO: u32 = 0xf900_03ff;
const STORE_OFFSET_SHIFT: u32 = 10;
const DSB_ISH: u32 = 0xd503_3b9f;
const TLBI_VMALLE1IS: u32 = 0xd508_831f;
const ISB: u32 = 0xd503_3fdf;
const ERET: u32 = 0xd69f_03e0;
const INSTRUCTION_BYTES: u64 = 4;

const DESCRIPTOR_VALID: u64 = 1 << 0;
/// Marks a table descriptor at levels 0 to 2 and a page descriptor at level 3.
const DESCRIPTOR_TABLE: u64 = 1 << 1;
const ATTRIBUTE_NORMAL: u64 = 0 << 2;
const ATTRIBUTE_DEVICE: u64 = 1 << 2;
const ACCESS_EL0: u64 = 1 << 6;
const ACCESS_READ_ONLY: u64 = 1 << 7;
const SHARE_INNER: u64 = 3 << 8;
const ACCESS_FLAG: u64 = 1 << 10;
const PRIVILEGED_NEVER_EXECUTE: u64 = 1 << 53;
const UNPRIVILEGED_NEVER_EXECUTE: u64 = 1 << 54;
const ADDR_MASK_4K: u64 = 0x0000_ffff_ffff_f000;
const USER_PSTATE_MASK: u64 = 0xf000_0c00;
const TRAP_PAGE: u64 = DESCRIPTOR_VALID
    | DESCRIPTOR_TABLE
    | ATTRIBUTE_DEVICE
    | ACCESS_FLAG
    | PRIVILEGED_NEVER_EXECUTE
    | UNPRIVILEGED_NEVER_EXECUTE;
const SUPERVISOR_PAGE: u64 = DESCRIPTOR_VALID
    | DESCRIPTOR_TABLE
    | ATTRIBUTE_NORMAL
    | SHARE_INNER
    | ACCESS_FLAG
    | UNPRIVILEGED_NEVER_EXECUTE;
const USER_BLOCK: u64 = DESCRIPTOR_VALID
    | ATTRIBUTE_NORMAL
    | ACCESS_EL0
    | SHARE_INNER
    | ACCESS_FLAG
    | PRIVILEGED_NEVER_EXECUTE;

/// Normal write-back memory at index 0 and device-nGnRnE memory at index 1.
const MAIR: u64 = 0xff;
/// 48-bit EL0 addresses through `TTBR0_EL1` with 4 KiB granules, inner
/// shareable write-back walks, a 36-bit output size, and the top byte ignored,
/// while `TTBR1_EL1` walks are disabled.
const TCR: u64 =
    16 | (1 << 8) | (1 << 10) | (3 << 12) | (16 << 16) | (1 << 23) | (1 << 32) | (1 << 37);
/// MMU and caches on, EL0 stack alignment checks, and EL0 access to `DC ZVA`,
/// `CTR_EL0`, cache maintenance, `WFI`, and `WFE`, with `RES1` bits set.
const SCTLR: u64 = (1 << 0)
    | (1 << 2)
    | (1 << 4)
    | (1 << 11)
    | (1 << 12)
    | (1 << 14)
    | (1 << 15)
    | (1 << 16)
    | (1 << 18)
    | (1 << 20)
    | (1 << 22)
    | (1 << 23)
    | (1 << 26)
    | (1 << 28)
    | (1 << 29);
/// No trapping of FP and Advanced SIMD instructions.
const CPACR: u64 = 3 << 20;
/// EL0 access to the virtual counter.
const CNTKCTL: u64 = 1 << 1;
/// EL1 on `SP_EL1` with debug, `SError`, IRQ, and FIQ masked.
const PSTATE_EL1H: u64 = PSR_MODE_EL1h as u64 | (0xf << 6);

const EXCEPTION_CLASS_SHIFT: u64 = 26;
const EXCEPTION_CLASS_MASK: u64 = 0x3f;
const EXCEPTION_SVC64: u64 = 0x15;
const EXCEPTION_INSTRUCTION_ABORT_LOWER: u64 = 0x20;

/// `KVM_GET_ONE_REG` and `KVM_SET_ONE_REG` identifiers and accessors.
struct Register;

impl Register {
    const PT_REGS: usize = offset_of!(kvm_regs, regs);
    const FP_REGS: usize = offset_of!(kvm_regs, fp_regs);
    const SP_EL0: u64 = Self::core(Self::PT_REGS + offset_of!(user_pt_regs, sp));
    const PC: u64 = Self::core(Self::PT_REGS + offset_of!(user_pt_regs, pc));
    const PSTATE: u64 = Self::core(Self::PT_REGS + offset_of!(user_pt_regs, pstate));
    const SP_EL1: u64 = Self::core(offset_of!(kvm_regs, sp_el1));
    const ELR_EL1: u64 = Self::core(offset_of!(kvm_regs, elr_el1));
    const SPSR_EL1: u64 =
        Self::core(offset_of!(kvm_regs, spsr) + KVM_SPSR_EL1 as usize * size_of::<u64>());
    const FPSR: u64 = Self::sized(
        Self::FP_REGS + offset_of!(user_fpsimd_state, fpsr),
        KVM_REG_SIZE_U32,
    );
    const FPCR: u64 = Self::sized(
        Self::FP_REGS + offset_of!(user_fpsimd_state, fpcr),
        KVM_REG_SIZE_U32,
    );
    const SCTLR_EL1: u64 = Self::system(3, 0, 1, 0, 0);
    const CPACR_EL1: u64 = Self::system(3, 0, 1, 0, 2);
    const TTBR0_EL1: u64 = Self::system(3, 0, 2, 0, 0);
    const TCR_EL1: u64 = Self::system(3, 0, 2, 0, 2);
    const ESR_EL1: u64 = Self::system(3, 0, 5, 2, 0);
    const FAR_EL1: u64 = Self::system(3, 0, 6, 0, 0);
    const MAIR_EL1: u64 = Self::system(3, 0, 10, 2, 0);
    const VBAR_EL1: u64 = Self::system(3, 0, 12, 0, 0);
    const TPIDR_EL0: u64 = Self::system(3, 3, 13, 0, 2);
    const CNTKCTL_EL1: u64 = Self::system(3, 0, 14, 1, 0);

    /// General-purpose register `x<index>`.
    const fn x(index: usize) -> u64 {
        Self::core(Self::PT_REGS + offset_of!(user_pt_regs, regs) + index * size_of::<u64>())
    }

    /// FP and Advanced SIMD register `v<index>`.
    const fn v(index: usize) -> u64 {
        Self::sized(
            Self::FP_REGS + offset_of!(user_fpsimd_state, vregs) + index * size_of::<u128>(),
            KVM_REG_SIZE_U128,
        )
    }

    const fn core(offset: usize) -> u64 {
        Self::sized(offset, KVM_REG_SIZE_U64)
    }

    /// Core register at byte `offset` into `kvm_regs`, which KVM numbers in
    /// 32-bit words.
    #[allow(clippy::cast_possible_truncation, reason = "kvm_regs is under 1 KiB")]
    const fn sized(offset: usize, size: u64) -> u64 {
        KVM_REG_ARM64 | size | KVM_REG_ARM_CORE as u64 | (offset / size_of::<u32>()) as u64
    }

    const fn system(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
        KVM_REG_ARM64
            | KVM_REG_SIZE_U64
            | KVM_REG_ARM64_SYSREG as u64
            | (op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
            | (op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
            | (crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
            | (crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
            | (op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
    }

    fn read(vcpu: &VcpuFd, id: u64) -> Result<u64> {
        let mut value = [0u8; 8];
        vcpu.get_one_reg(id, &mut value)
            .with_context(|| format!("read vCPU register {id:#x}"))?;
        Ok(u64::from_ne_bytes(value))
    }

    fn write(vcpu: &mut VcpuFd, id: u64, value: u64) -> Result<()> {
        vcpu.set_one_reg(id, &value.to_ne_bytes())
            .with_context(|| format!("write vCPU register {id:#x}"))?;
        Ok(())
    }

    fn read_word(vcpu: &VcpuFd, id: u64) -> Result<u32> {
        let mut value = [0u8; 4];
        vcpu.get_one_reg(id, &mut value)
            .with_context(|| format!("read vCPU register {id:#x}"))?;
        Ok(u32::from_ne_bytes(value))
    }

    fn write_word(vcpu: &mut VcpuFd, id: u64, value: u32) -> Result<()> {
        vcpu.set_one_reg(id, &value.to_ne_bytes())
            .with_context(|| format!("write vCPU register {id:#x}"))?;
        Ok(())
    }

    fn read_vector(vcpu: &VcpuFd, id: u64) -> Result<u128> {
        let mut value = [0u8; 16];
        vcpu.get_one_reg(id, &mut value)
            .with_context(|| format!("read vCPU register {id:#x}"))?;
        Ok(u128::from_ne_bytes(value))
    }

    fn write_vector(vcpu: &mut VcpuFd, id: u64, value: u128) -> Result<()> {
        vcpu.set_one_reg(id, &value.to_ne_bytes())
            .with_context(|| format!("write vCPU register {id:#x}"))?;
        Ok(())
    }
}

/// Architectural state of a vCPU besides its general-purpose registers.
pub(crate) struct VcpuState {
    vectors: [u128; 32],
    fpsr: u32,
    fpcr: u32,
    tls: u64,
}

/// General-purpose registers of the payload, with `pc` and `pstate` being
/// where `eret` resumes it.
#[derive(Clone, Copy, Default)]
pub(crate) struct Regs {
    x: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

impl Regs {
    /// Registers that enter a freshly loaded program at `entry` on `stack`.
    pub(crate) fn start(entry: u64, stack: u64) -> Self {
        Self {
            sp: stack,
            pc: entry,
            pstate: u64::from(PSR_MODE_EL0t),
            ..Self::default()
        }
    }

    /// System call number.
    pub(crate) const fn number(&self) -> u64 {
        self.x[8]
    }

    pub(crate) fn syscall(&self) -> Option<syscalls::Sysno> {
        usize::try_from(self.number())
            .ok()
            .and_then(syscalls::Sysno::new)
    }

    /// System call arguments in ABI order.
    pub(crate) const fn arguments(&self) -> [u64; 6] {
        [
            self.x[0], self.x[1], self.x[2], self.x[3], self.x[4], self.x[5],
        ]
    }

    /// Value the system call returns to the payload.
    pub(crate) const fn result(&self) -> u64 {
        self.x[0]
    }

    pub(crate) const fn set_result(&mut self, value: u64) {
        self.x[0] = value;
    }

    pub(crate) const fn stack_pointer(&self) -> u64 {
        self.sp
    }

    #[allow(clippy::unused_self)]
    pub(crate) const fn leave_kernel_stub(&mut self) {}

    #[allow(clippy::unused_self)]
    pub(crate) const fn normalize_interrupted(&mut self) {}

    #[allow(clippy::unused_self)]
    pub(crate) const fn has_valid_return_ip(&self) -> bool {
        true
    }

    /// Registers of a `clone` or `fork` child, which returns zero from the
    /// system call on `stack`, or on the parent's stack when it is zero.
    pub(crate) const fn child(&self, stack: u64) -> Self {
        let mut regs = *self;
        regs.x[0] = 0;
        if stack != 0 {
            regs.sp = stack;
        }
        regs
    }

    /// Rewinds a system call so that it is issued again with the first
    /// argument `origin` trapped with, which the result overwrote.
    pub(crate) const fn rewind_syscall(&mut self, origin: &Self) {
        self.x[0] = origin.x[0];
        self.pc = self.pc.wrapping_sub(INSTRUCTION_BYTES);
    }

    /// Lowest address of a signal frame of `size` bytes below the payload
    /// stack, which the procedure call standard keeps 16-byte aligned and
    /// without a red zone.
    pub(crate) const fn signal_frame_at(sp: u64, _on_altstack: bool, size: u64) -> u64 {
        sp.saturating_sub(size) & !0xf
    }

    pub(crate) fn write_ucontext(
        &self,
        raw: &mut [u8],
        stack: (u64, i32, u64),
        mask: u64,
        fault_addr: u64,
        _ucontext_addr: u64,
    ) {
        let stack_off = offset_of!(libc::ucontext_t, uc_stack);
        let mask_off = offset_of!(libc::ucontext_t, uc_sigmask);
        let mc_off = offset_of!(libc::ucontext_t, uc_mcontext);
        if raw.len() < mc_off + 296 {
            return;
        }
        raw[stack_off..stack_off + 8].copy_from_slice(&stack.0.to_le_bytes());
        raw[stack_off + 8..stack_off + 12].copy_from_slice(&stack.1.to_le_bytes());
        raw[stack_off + 16..stack_off + 24].copy_from_slice(&stack.2.to_le_bytes());
        raw[mask_off..mask_off + 8].copy_from_slice(&mask.to_le_bytes());
        raw[mc_off..mc_off + 8].copy_from_slice(&fault_addr.to_le_bytes());
        for (idx, reg) in self.x.iter().enumerate() {
            let at = mc_off + 8 + idx * 8;
            raw[at..at + 8].copy_from_slice(&reg.to_le_bytes());
        }
        raw[mc_off + 256..mc_off + 264].copy_from_slice(&self.sp.to_le_bytes());
        raw[mc_off + 264..mc_off + 272].copy_from_slice(&self.pc.to_le_bytes());
        raw[mc_off + 272..mc_off + 280].copy_from_slice(&self.pstate.to_le_bytes());
        raw[mc_off + 288..mc_off + 296].fill(0);
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
        if raw.len() < mc_off + 280 {
            return;
        }
        let word = |off: usize| -> u64 {
            u64::from_le_bytes(raw[off..off + 8].try_into().unwrap_or([0; 8]))
        };
        for (idx, reg) in self.x.iter_mut().enumerate() {
            *reg = word(mc_off + 8 + idx * 8);
        }
        self.sp = word(mc_off + 256);
        self.pc = word(mc_off + 264);
        let pstate = word(mc_off + 272);
        self.pstate = (self.pstate & !USER_PSTATE_MASK)
            | (pstate & USER_PSTATE_MASK)
            | u64::from(PSR_MODE_EL0t);
    }

    /// Enters the signal handler at `handler` with `arguments` on the signal
    /// frame at `frame`, returning to `restorer` through the link register.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "uniform with x86-64, which pushes the return address"
    )]
    pub(crate) fn enter_handler(
        &mut self,
        _memory: &GuestMemory,
        handler: u64,
        restorer: Option<u64>,
        frame: u64,
        arguments: [u64; 3],
    ) -> Result<()> {
        let [signal, info, context] = arguments;
        self.x[0] = signal;
        self.x[1] = info;
        self.x[2] = context;
        self.x[30] = restorer.unwrap_or(SIGNAL_RETURN);
        self.sp = frame;
        self.pc = handler;
        self.pstate = u64::from(PSR_MODE_EL0t);
        Ok(())
    }
}

pub(crate) struct Machine {
    pub(crate) memory: GuestMemory,
    pub(super) vm: super::BrokerHandle<VmFd>,
    target: kvm_vcpu_init,
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
        let (machine, mut vcpu) = Self::attach(memory)?;
        machine.restore(vcpu.get_mut(), trapped)?;
        if let Some(pointer) = tls {
            Register::write(vcpu.get_mut(), Register::TPIDR_EL0, pointer)?;
        }
        Ok((machine, vcpu))
    }

    /// Reads the architectural state of `vcpu` for a child thread or process,
    /// or for a signal handler to return to.
    #[allow(
        clippy::unused_self,
        reason = "uniform with x86-64, which reads the XSAVE state it enabled"
    )]
    pub(crate) fn state(&self, vcpu: &VcpuFd) -> Result<VcpuState> {
        let mut vectors = [0u128; 32];
        for (index, value) in vectors.iter_mut().enumerate() {
            *value = Register::read_vector(vcpu, Register::v(index))?;
        }
        Ok(VcpuState {
            vectors,
            fpsr: Register::read_word(vcpu, Register::FPSR)?,
            fpcr: Register::read_word(vcpu, Register::FPCR)?,
            tls: Register::read(vcpu, Register::TPIDR_EL0)?,
        })
    }

    /// Restores full state (including TLS) for a spawned/forked child.
    pub(crate) fn restore(&self, vcpu: &mut VcpuFd, state: &VcpuState) -> Result<()> {
        self.restore_signal(vcpu, state)?;
        Register::write(vcpu, Register::TPIDR_EL0, state.tls)
    }

    /// Restores floating-point state when a signal handler returns, keeping
    /// the guest's current `TPIDR_EL0` intact.
    #[allow(clippy::unused_self)]
    pub(crate) fn restore_signal(&self, vcpu: &mut VcpuFd, state: &VcpuState) -> Result<()> {
        for (index, value) in state.vectors.iter().enumerate() {
            Register::write_vector(vcpu, Register::v(index), *value)?;
        }
        Register::write_word(vcpu, Register::FPSR, state.fpsr)?;
        Register::write_word(vcpu, Register::FPCR, state.fpcr)
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn reset_fpu(&self, vcpu: &mut VcpuFd) -> Result<()> {
        for index in 0..32 {
            Register::write_vector(vcpu, Register::v(index), 0)?;
        }
        Register::write_word(vcpu, Register::FPSR, 0)?;
        Register::write_word(vcpu, Register::FPCR, 0)
    }

    fn attach(memory: GuestMemory) -> Result<(Self, super::BrokerHandle<VcpuFd>)> {
        let kvm = Self::open_kvm()?;
        let vm =
            super::BrokerHandle::register(kvm.create_vm().context("create a KVM virtual machine")?);
        let region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: TRAP_END,
            memory_size: memory.allocation_size() - TRAP_END,
            userspace_addr: memory.base() + TRAP_END,
            flags: 0,
        };
        unsafe { vm.get().set_user_memory_region(region) }.context("register guest memory")?;
        let mut target = kvm_vcpu_init::default();
        vm.get()
            .get_preferred_target(&mut target)
            .context("read the preferred vCPU target")?;
        let mut vcpu =
            super::BrokerHandle::register(vm.get().create_vcpu(0).context("create a vCPU")?);
        let machine = Self {
            memory,
            vm,
            target,
            pool: VcpuPool::new(),
        };
        machine.reset_vcpu(vcpu.get_mut())?;
        Ok((machine, vcpu))
    }

    /// Resets `vcpu` and points its EL1 at the layout.
    fn reset_vcpu(&self, vcpu: &mut VcpuFd) -> Result<()> {
        vcpu.vcpu_init(&self.target)
            .context("initialize the vCPU")?;
        for (id, value) in [
            (Register::MAIR_EL1, MAIR),
            (Register::TCR_EL1, TCR),
            (Register::TTBR0_EL1, L0_TABLE),
            (Register::CPACR_EL1, CPACR),
            (Register::VBAR_EL1, VECTORS),
            (Register::CNTKCTL_EL1, CNTKCTL),
            (Register::SP_EL1, TRAP_BASE),
            (Register::SCTLR_EL1, SCTLR),
        ] {
            Register::write(vcpu, id, value)?;
        }
        Ok(())
    }

    /// Allocates a fresh vCPU above the payload descriptor ceiling.
    pub(crate) fn allocate_vcpu(&self) -> Result<super::BrokerHandle<VcpuFd>> {
        let id = self.pool.next_id();
        let _range = super::super::fds::Range::occupy_unused()?;
        self.vm
            .get()
            .create_vcpu(id)
            .map(super::BrokerHandle::register)
            .context("create thread vCPU")
    }

    /// Initializes `vcpu` for a spawned guest thread that continues in
    /// `state` with `registers`, and with the thread pointer replaced by `tls`
    /// when present.
    pub(crate) fn configure_vcpu(
        &self,
        vcpu: &mut VcpuFd,
        state: &VcpuState,
        tls: Option<u64>,
        registers: &Regs,
    ) -> Result<()> {
        self.reset_vcpu(vcpu)?;
        self.restore(vcpu, state)?;
        if let Some(pointer) = tls {
            Register::write(vcpu, Register::TPIDR_EL0, pointer)?;
        }
        self.set_regs(vcpu, registers)
    }

    /// Reads the payload registers of `vcpu`.
    ///
    /// A vCPU that a host signal interrupted between taking an exception and
    /// storing to the trap window reports the state the exception was taken
    /// from, rewound to re-issue a system call, so that writing it back
    /// replays the exception instead of losing it.
    #[allow(
        clippy::unused_self,
        reason = "uniform with x86-64, which unwinds interrupted ring-0 handler frames"
    )]
    pub(crate) fn regs(&self, vcpu: &VcpuFd) -> Result<Regs> {
        let mut regs = Regs::default();
        for (index, value) in regs.x.iter_mut().enumerate() {
            *value = Register::read(vcpu, Register::x(index))?;
        }
        regs.sp = Register::read(vcpu, Register::SP_EL0)?;
        let pstate = Register::read(vcpu, Register::PSTATE)?;
        if pstate & u64::from(PSR_MODE_MASK) == u64::from(PSR_MODE_EL0t) {
            regs.pc = Register::read(vcpu, Register::PC)?;
            regs.pstate = pstate;
            return Ok(regs);
        }
        regs.pc = Register::read(vcpu, Register::ELR_EL1)?;
        regs.pstate = Register::read(vcpu, Register::SPSR_EL1)?;
        let pc = Register::read(vcpu, Register::PC)?;
        let entering =
            (VECTORS..LAUNCH).contains(&pc) && (pc - VECTORS).is_multiple_of(VECTOR_BYTES);
        if entering && Self::exception_class(vcpu)? == EXCEPTION_SVC64 {
            regs.pc = regs.pc.wrapping_sub(INSTRUCTION_BYTES);
        }
        Ok(regs)
    }

    /// Writes the payload registers of `vcpu`, which resumes them with `eret`.
    #[allow(clippy::unused_self)]
    pub(crate) fn set_regs(&self, vcpu: &mut VcpuFd, registers: &Regs) -> Result<()> {
        for (index, value) in registers.x.iter().enumerate() {
            Register::write(vcpu, Register::x(index), *value)?;
        }
        let mode = u64::from(PSR_MODE_MASK | PSR_MODE32_BIT);
        for (id, value) in [
            (Register::SP_EL0, registers.sp),
            (Register::ELR_EL1, registers.pc),
            (Register::SPSR_EL1, registers.pstate & !mode),
            (Register::PC, LAUNCH),
            (Register::PSTATE, PSTATE_EL1H),
        ] {
            Register::write(vcpu, id, value)?;
        }
        Ok(())
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn update_regs(
        &self,
        vcpu: &mut VcpuFd,
        origin: &Regs,
        registers: &Regs,
    ) -> Result<()> {
        for (index, (&old, &new)) in origin.x.iter().zip(&registers.x).enumerate() {
            if old != new {
                Register::write(vcpu, Register::x(index), new)?;
            }
        }
        if origin.sp != registers.sp {
            Register::write(vcpu, Register::SP_EL0, registers.sp)?;
        }
        if origin.pc != registers.pc {
            Register::write(vcpu, Register::ELR_EL1, registers.pc)?;
        }
        let mode = u64::from(PSR_MODE_MASK | PSR_MODE32_BIT);
        if (origin.pstate & !mode) != (registers.pstate & !mode) {
            Register::write(vcpu, Register::SPSR_EL1, registers.pstate & !mode)?;
        }
        Ok(())
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn set_tls(&self, vcpu: &mut VcpuFd, pointer: u64) -> Result<()> {
        Register::write(vcpu, Register::TPIDR_EL0, pointer)
    }

    pub(crate) fn hwcaps() -> (u64, u64) {
        const HWCAP_SAFE: u64 = (1 << 0)
            | (1 << 1)
            | (1 << 3)
            | (1 << 4)
            | (1 << 5)
            | (1 << 6)
            | (1 << 7)
            | (1 << 8)
            | (1 << 9)
            | (1 << 10)
            | (1 << 12)
            | (1 << 13)
            | (1 << 14)
            | (1 << 15)
            | (1 << 16)
            | (1 << 17)
            | (1 << 18)
            | (1 << 19)
            | (1 << 20)
            | (1 << 21)
            | (1 << 23)
            | (1 << 24)
            | (1 << 25)
            | (1 << 26)
            | (1 << 27)
            | (1 << 29);
        const HWCAP2_SAFE: u64 = (1 << 0) | (1 << 7) | (1 << 8) | (1 << 13) | (1 << 14) | (1 << 29);
        let primary = unsafe { libc::getauxval(libc::AT_HWCAP) } & HWCAP_SAFE;
        let extended = unsafe { libc::getauxval(libc::AT_HWCAP2) } & HWCAP2_SAFE;
        (primary, extended)
    }

    pub(crate) fn tlb_epoch(&self) -> u64 {
        self.pool.tlb_epoch()
    }

    pub(crate) fn sync_tlb(&self, vcpu: &mut VcpuFd, local_epoch: &mut u64) -> Result<()> {
        let current = self.pool.tlb_epoch();
        if *local_epoch != current {
            let pstate = Register::read(vcpu, Register::PSTATE)?;
            let pc = Register::read(vcpu, Register::PC)?;
            let at_eret = pstate == PSTATE_EL1H
                && (pc == LAUNCH
                    || ((VECTORS..LAUNCH).contains(&pc)
                        && (pc - VECTORS) % VECTOR_BYTES == INSTRUCTION_BYTES));
            if !at_eret {
                let regs = self.regs(vcpu)?;
                self.set_regs(vcpu, &regs)?;
            }
            Register::write(vcpu, Register::PC, LAUNCH_FLUSH)?;
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
        let leaf_flags = Self::protection_flags(prot);
        let mut cursor = start.max(RESERVED_END) & !(PAGE_BYTES - 1);
        while cursor < end {
            let block_base = cursor & !(HUGE_PAGE_SIZE - 1);
            let block_end = (block_base + HUGE_PAGE_SIZE).min(USER_ADDRESS_BYTES);
            let seg_end = end.min(block_end);
            let gib = block_base / GIB_BYTES;
            let l2_idx = (block_base % GIB_BYTES) / HUGE_PAGE_SIZE;
            let l2_entry_addr = L2_BASE + gib * PAGE_BYTES + l2_idx * 8;
            let l2_entry = self.memory.read_supervisor_u64(l2_entry_addr)?;
            let pt_gpa = PT_ARENA_BASE + (block_base / HUGE_PAGE_SIZE) * PAGE_BYTES;
            let is_split = (l2_entry & (DESCRIPTOR_VALID | DESCRIPTOR_TABLE))
                == (DESCRIPTOR_VALID | DESCRIPTOR_TABLE)
                && (l2_entry & ADDR_MASK_4K) == pt_gpa;
            if !is_split && cursor == block_base && seg_end == block_base + HUGE_PAGE_SIZE {
                let block_entry = if leaf_flags == 0 {
                    0
                } else {
                    block_base | leaf_flags
                };
                self.memory
                    .write_supervisor_u64_atomic(l2_entry_addr, block_entry)?;
            } else {
                self.update_split_l2(
                    block_base,
                    cursor,
                    seg_end,
                    l2_entry_addr,
                    l2_entry,
                    pt_gpa,
                    is_split,
                    leaf_flags,
                )?;
            }
            cursor = seg_end;
        }
        self.pool.bump_tlb();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn update_split_l2(
        &self,
        block_base: u64,
        cursor: u64,
        seg_end: u64,
        l2_entry_addr: u64,
        l2_entry: u64,
        pt_gpa: u64,
        is_split: bool,
        leaf_flags: u64,
    ) -> Result<()> {
        let first_page = (cursor - block_base) / PAGE_BYTES;
        let last_page = (seg_end - block_base) / PAGE_BYTES;
        let leaf = if leaf_flags == 0 {
            0
        } else {
            leaf_flags | DESCRIPTOR_TABLE
        };
        if is_split {
            for page_idx in first_page..last_page {
                let pte = if leaf == 0 {
                    0
                } else {
                    (block_base + page_idx * PAGE_BYTES) | leaf
                };
                self.memory
                    .write_supervisor_u64_atomic(pt_gpa + page_idx * 8, pte)?;
            }
            return Ok(());
        }
        let base_flags = if l2_entry & DESCRIPTOR_VALID == 0 {
            0
        } else {
            (l2_entry & !ADDR_MASK_4K) | DESCRIPTOR_TABLE
        };
        for page_idx in 0..TABLE_ENTRIES {
            let flags = if (first_page..last_page).contains(&page_idx) {
                leaf
            } else {
                base_flags
            };
            let pte = if flags == 0 {
                0
            } else {
                (block_base + page_idx * PAGE_BYTES) | flags
            };
            self.memory
                .write_supervisor_u64_atomic(pt_gpa + page_idx * 8, pte)?;
        }
        self.memory.write_supervisor_u64_atomic(
            l2_entry_addr,
            pt_gpa | DESCRIPTOR_VALID | DESCRIPTOR_TABLE,
        )
    }

    const fn protection_flags(prot: u32) -> u64 {
        let rwx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC).cast_unsigned();
        if prot & rwx == 0 {
            return 0;
        }
        let mut flags = USER_BLOCK;
        if prot & libc::PROT_WRITE.cast_unsigned() == 0 {
            flags |= ACCESS_READ_ONLY;
        }
        if prot & libc::PROT_EXEC.cast_unsigned() == 0 {
            flags |= UNPRIVILEGED_NEVER_EXECUTE;
        }
        flags
    }

    /// Runs `vcpu` until the payload needs the VMM.
    #[allow(
        clippy::unused_self,
        reason = "uniform with x86-64, which reads the fault frame from memory"
    )]
    pub(crate) fn run(&self, vcpu: &mut VcpuFd) -> Result<ExitReason> {
        let address = match vcpu.run() {
            Ok(VcpuExit::MmioWrite(address, _)) => address,
            Ok(_) => bail!("unsupported guest exit"),
            Err(error) if error.errno() == libc::EINTR => {
                if let Ok(pc) = Register::read(vcpu, Register::PC)
                    && (LAUNCH_FLUSH..LAUNCH_FLUSH + 4 * INSTRUCTION_BYTES).contains(&pc)
                {
                    self.pool.bump_tlb();
                }
                return Ok(ExitReason::Interrupted);
            }
            Err(error) if error.errno() == libc::EFAULT => {
                return Ok(ExitReason::Fault(GuestFault {
                    signal: libc::SIGBUS,
                    code: libc::BUS_ADRERR,
                    address: 0,
                    is_page_fault: false,
                }));
            }
            Err(error) => bail!("run the vCPU: {error}"),
        };
        Self::complete(vcpu)?;
        let vector = address.wrapping_sub(TRAP_BASE) / 8;
        if vector != LOWER_SYNC {
            return Self::fault(vcpu, vector).map(ExitReason::Fault);
        }
        match Self::exception_class(vcpu)? {
            EXCEPTION_SVC64 => Ok(ExitReason::Syscall),
            EXCEPTION_INSTRUCTION_ABORT_LOWER
                if Register::read(vcpu, Register::ELR_EL1)? == SIGNAL_RETURN =>
            {
                // The restored signal frame replaces every register.
                Register::write(vcpu, Register::x(8), syscalls::Sysno::rt_sigreturn as u64)?;
                Ok(ExitReason::Syscall)
            }
            _ => Self::fault(vcpu, vector).map(ExitReason::Fault),
        }
    }

    /// Completes an MMIO exit without re-entering the guest, which moves the
    /// program counter past the trapping store before registers are touched.
    fn complete(vcpu: &mut VcpuFd) -> Result<()> {
        vcpu.set_kvm_immediate_exit(1);
        let completed = vcpu.run().map(|_| ());
        vcpu.set_kvm_immediate_exit(0);
        match completed {
            Err(error) if error.errno() == libc::EINTR => Ok(()),
            Err(error) => bail!("complete the vCPU exit: {error}"),
            Ok(()) => bail!("vCPU entered the guest despite an immediate exit"),
        }
    }

    fn exception_class(vcpu: &VcpuFd) -> Result<u64> {
        let syndrome = Register::read(vcpu, Register::ESR_EL1)?;
        Ok((syndrome >> EXCEPTION_CLASS_SHIFT) & EXCEPTION_CLASS_MASK)
    }

    fn fault(vcpu: &VcpuFd, vector: u64) -> Result<GuestFault> {
        let syndrome = Register::read(vcpu, Register::ESR_EL1)?;
        let address = Register::read(vcpu, Register::FAR_EL1)?;
        let pc = Register::read(vcpu, Register::ELR_EL1)?;
        let ec = (syndrome >> EXCEPTION_CLASS_SHIFT) & EXCEPTION_CLASS_MASK;
        if vector < LOWER_SYNC {
            bail!(
                "supervisor exception {ec:#x} on vector {vector} at pc {pc:#x} (far {address:#x})"
            );
        }
        let sp = Register::read(vcpu, Register::SP_EL0)?;
        Ok(Self::classify_fault(ec, syndrome & 0x3f, pc, address, sp))
    }

    const fn classify_fault(ec: u64, fsc: u64, pc: u64, far: u64, sp: u64) -> GuestFault {
        const ILL_ILLOPC: i32 = 1;
        match ec {
            0x00 | 0x07 | 0x0e => GuestFault {
                signal: libc::SIGILL,
                code: ILL_ILLOPC,
                address: pc,
                is_page_fault: false,
            },
            0x20 => {
                if (fsc & 0x3c) <= 0x04 {
                    GuestFault {
                        signal: libc::SIGSEGV,
                        code: SEGV_MAPERR,
                        address: far,
                        is_page_fault: true,
                    }
                } else if (fsc & 0x3c) <= 0x0c {
                    GuestFault {
                        signal: libc::SIGSEGV,
                        code: SEGV_ACCERR,
                        address: far,
                        is_page_fault: true,
                    }
                } else {
                    GuestFault {
                        signal: libc::SIGBUS,
                        code: libc::BUS_OBJERR,
                        address: far,
                        is_page_fault: false,
                    }
                }
            }
            0x22 => GuestFault {
                signal: libc::SIGBUS,
                code: libc::BUS_ADRALN,
                address: far,
                is_page_fault: false,
            },
            0x24 => {
                if fsc == 0x21 {
                    GuestFault {
                        signal: libc::SIGBUS,
                        code: libc::BUS_ADRALN,
                        address: far,
                        is_page_fault: false,
                    }
                } else if (fsc & 0x3c) <= 0x04 {
                    GuestFault {
                        signal: libc::SIGSEGV,
                        code: SEGV_MAPERR,
                        address: far,
                        is_page_fault: true,
                    }
                } else if (fsc & 0x3c) <= 0x0c {
                    GuestFault {
                        signal: libc::SIGSEGV,
                        code: SEGV_ACCERR,
                        address: far,
                        is_page_fault: true,
                    }
                } else {
                    GuestFault {
                        signal: libc::SIGBUS,
                        code: libc::BUS_ADRERR,
                        address: far,
                        is_page_fault: false,
                    }
                }
            }
            0x26 => GuestFault {
                signal: libc::SIGBUS,
                code: libc::BUS_ADRALN,
                address: sp,
                is_page_fault: false,
            },
            0x28 | 0x2c => GuestFault {
                signal: libc::SIGFPE,
                code: FPE_FLTINV,
                address: pc,
                is_page_fault: false,
            },
            0x30 | 0x32 | 0x34 | 0x3c => GuestFault {
                signal: libc::SIGTRAP,
                code: 1,
                address: pc,
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

    fn install_layout(&self) -> Result<()> {
        self.install_page_tables()?;
        for vector in 0..VECTOR_COUNT {
            let store = STORE_ZERO | (u32::try_from(vector)? << STORE_OFFSET_SHIFT);
            let entry = VECTORS + vector * VECTOR_BYTES;
            self.memory.write_supervisor(entry, &store.to_le_bytes())?;
            self.memory
                .write_supervisor(entry + INSTRUCTION_BYTES, &ERET.to_le_bytes())?;
        }
        self.memory.write_supervisor(LAUNCH, &ERET.to_le_bytes())?;
        for (idx, insn) in [DSB_ISH, TLBI_VMALLE1IS, DSB_ISH, ISB, ERET]
            .into_iter()
            .enumerate()
        {
            let at = LAUNCH_FLUSH + u64::try_from(idx)? * INSTRUCTION_BYTES;
            self.memory.write_supervisor(at, &insn.to_le_bytes())?;
        }
        Ok(())
    }

    /// Maps `0..RESERVED_END` with EL1-only 4 KiB pages, of which the trap
    /// window is device memory, and the rest of guest memory with EL0 blocks
    /// that EL1 cannot execute.
    fn install_page_tables(&self) -> Result<()> {
        let size = self.memory.size();
        let gib_count = size.div_ceil(GIB_BYTES);
        if gib_count > TABLE_ENTRIES || L2_BASE + gib_count * PAGE_BYTES > RESERVED_END {
            bail!("guest memory exceeds page-table layout capacity");
        }
        self.write_table(L3_TABLE, |index| {
            let address = index * PAGE_BYTES;
            let attributes = if address < TRAP_END {
                TRAP_PAGE
            } else {
                SUPERVISOR_PAGE
            };
            Some(address | attributes)
        })?;
        for gib in 0..gib_count {
            let l2_address = L2_BASE + gib * PAGE_BYTES;
            self.write_table(l2_address, |index| {
                (gib == 0 && index == 0).then_some(L3_TABLE | DESCRIPTOR_VALID | DESCRIPTOR_TABLE)
            })?;
        }
        self.write_table(L1_TABLE, |index| {
            (index < gib_count)
                .then_some((L2_BASE + index * PAGE_BYTES) | DESCRIPTOR_VALID | DESCRIPTOR_TABLE)
        })?;
        self.write_table(L0_TABLE, |index| {
            (index == 0).then_some(L1_TABLE | DESCRIPTOR_VALID | DESCRIPTOR_TABLE)
        })
    }

    fn write_table(&self, address: u64, entry: impl Fn(u64) -> Option<u64>) -> Result<()> {
        let mut table = [0u8; PAGE_LEN];
        for (index, slot) in (0..TABLE_ENTRIES).zip(table.chunks_exact_mut(8)) {
            if let Some(descriptor) = entry(index) {
                slot.copy_from_slice(&descriptor.to_le_bytes());
            }
        }
        self.memory.write_supervisor(address, &table)
    }
}
