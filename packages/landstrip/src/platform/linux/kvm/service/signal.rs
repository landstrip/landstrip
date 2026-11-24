// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::ErrnoExt;
use super::super::machine::{
    GuestFault, Machine, RESERVED_END, Regs, SEGV_ACCERR, SEGV_MAPERR, VcpuState,
};
use super::super::memory::GuestMemory;
use super::{
    Arg, ExitKind, GuestReg, Process, SIGINFO_BYTES, SyscallArgs, SysnoExt, TIMESPEC_BYTES,
    ThreadState, WORD_SIZE,
};
use anyhow::{Context, Result};
use kvm_ioctls::VcpuFd;
use linux_raw_sys::general::{
    SA_NODEFER, SA_ONSTACK, SA_RESETHAND, SA_RESTART, SA_RESTORER, SS_AUTODISARM,
};
use std::cell::UnsafeCell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use syscalls::{Errno, Sysno};

const STACK_T_BYTES: u64 = std::mem::size_of::<libc::stack_t>() as u64;
#[cfg(target_arch = "x86_64")]
const GUEST_MINSIGSTKSZ: u64 = 2048;
#[cfg(target_arch = "aarch64")]
const GUEST_MINSIGSTKSZ: u64 = 5120;
const SIGNAL_SLOTS: usize = 64;
const SLOT_FREE: u8 = 0;
const SLOT_WRITING: u8 = 1;
const SLOT_READY: u8 = 2;
const SLOT_CLAIMING: u8 = 3;
const SIGACTION_BYTES: u64 = 32;
const UCONTEXT_BYTES: u64 = std::mem::size_of::<libc::ucontext_t>() as u64;

pub(super) struct PendingSignal {
    pub(super) number: i32,
    pub(super) info: [u8; 128],
}

/// Signals caught on the host on behalf of guest handlers in this process.
pub(super) static SIGNAL_QUEUE: SignalQueue = SignalQueue::new();

struct SignalSlot {
    state: AtomicU8,
    signo: AtomicU32,
    thread_only: AtomicBool,
    owner_tid: AtomicU64,
    seq: AtomicU64,
    info: UnsafeCell<[u8; 128]>,
}

impl SignalSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(SLOT_FREE),
            signo: AtomicU32::new(0),
            thread_only: AtomicBool::new(false),
            owner_tid: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            info: UnsafeCell::new([0u8; 128]),
        }
    }
}

pub(super) struct SignalQueue {
    next_seq: AtomicU64,
    ready_count: AtomicUsize,
    slots: [SignalSlot; SIGNAL_SLOTS],
}

unsafe impl Sync for SignalQueue {}

impl SignalQueue {
    pub(super) fn transfer_owner(&self, from: u64, to: u64) {
        for slot in &self.slots {
            if slot.state.load(Ordering::Acquire) == SLOT_READY {
                let _ =
                    slot.owner_tid
                        .compare_exchange(from, to, Ordering::AcqRel, Ordering::Relaxed);
            }
        }
    }
    const fn new() -> Self {
        Self {
            next_seq: AtomicU64::new(1),
            ready_count: AtomicUsize::new(0),
            slots: [const { SignalSlot::new() }; SIGNAL_SLOTS],
        }
    }

    pub(super) fn has_any(&self) -> bool {
        self.ready_count.load(Ordering::Acquire) != 0
    }

    pub(super) fn push(&self, signo: u32, tid: u64, thread_only: bool, raw_info: &[u8; 128]) {
        if signo < 32 {
            for slot in &self.slots {
                if slot.state.load(Ordering::Acquire) == SLOT_READY
                    && slot.signo.load(Ordering::Relaxed) == signo
                    && slot.owner_tid.load(Ordering::Relaxed) == tid
                {
                    return;
                }
            }
        }
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let start = usize::try_from(seq % u64::try_from(SIGNAL_SLOTS).unwrap_or(256)).unwrap_or(0);
        for step in 0..SIGNAL_SLOTS {
            let slot = &self.slots[(start + step) % SIGNAL_SLOTS];
            if slot
                .state
                .compare_exchange(
                    SLOT_FREE,
                    SLOT_WRITING,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                slot.signo.store(signo, Ordering::Relaxed);
                slot.thread_only.store(thread_only, Ordering::Relaxed);
                slot.owner_tid.store(tid, Ordering::Relaxed);
                slot.seq.store(seq, Ordering::Relaxed);
                unsafe {
                    *slot.info.get() = *raw_info;
                }
                self.ready_count.fetch_add(1, Ordering::Relaxed);
                slot.state.store(SLOT_READY, Ordering::Release);
                return;
            }
        }
    }

    fn pop_deliverable(&self, tid: u64, allowed_mask: u64) -> Option<(u32, [u8; 128])> {
        loop {
            if !self.has_any() {
                return None;
            }
            let mut best: Option<(usize, u32, u64)> = None;
            for (idx, slot) in self.slots.iter().enumerate() {
                if slot.state.load(Ordering::Acquire) != SLOT_READY {
                    continue;
                }
                let owner = slot.owner_tid.load(Ordering::Acquire);
                if owner != tid && owner != 0 {
                    continue;
                }
                let signo = slot.signo.load(Ordering::Relaxed);
                if !(1..=64).contains(&signo) {
                    continue;
                }
                if allowed_mask & (1u64 << (signo - 1)) == 0 {
                    continue;
                }
                let seq = slot.seq.load(Ordering::Relaxed);
                if best.is_none_or(|(_, b_sig, b_seq)| (signo, seq) < (b_sig, b_seq)) {
                    best = Some((idx, signo, seq));
                }
            }
            let (idx, _, expected_seq) = best?;
            let slot = &self.slots[idx];
            if slot
                .state
                .compare_exchange(
                    SLOT_READY,
                    SLOT_CLAIMING,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                continue;
            }
            if slot.seq.load(Ordering::Relaxed) != expected_seq {
                slot.state.store(SLOT_READY, Ordering::Release);
                continue;
            }
            let signo = slot.signo.load(Ordering::Relaxed);
            let info = unsafe { *slot.info.get() };
            self.ready_count.fetch_sub(1, Ordering::Release);
            slot.state.store(SLOT_FREE, Ordering::Release);
            return Some((signo, info));
        }
    }

    pub(super) fn pending_mask(&self, tid: u64) -> u64 {
        if !self.has_any() {
            return 0;
        }
        let mut mask = 0u64;
        for slot in &self.slots {
            if slot.state.load(Ordering::Acquire) != SLOT_READY {
                continue;
            }
            let owner = slot.owner_tid.load(Ordering::Acquire);
            if owner == tid || owner == 0 {
                let signo = slot.signo.load(Ordering::Relaxed);
                if (1..=64).contains(&signo) {
                    mask |= 1u64 << (signo - 1);
                }
            }
        }
        mask
    }

    pub(super) fn release_orphans(&self, dead_tid: u64) {
        if !self.has_any() {
            return;
        }
        for slot in &self.slots {
            if slot.state.load(Ordering::Acquire) != SLOT_READY
                || slot.owner_tid.load(Ordering::Acquire) != dead_tid
            {
                continue;
            }
            if slot.thread_only.load(Ordering::Relaxed) {
                if slot
                    .state
                    .compare_exchange(
                        SLOT_READY,
                        SLOT_CLAIMING,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    self.ready_count.fetch_sub(1, Ordering::Release);
                    slot.state.store(SLOT_FREE, Ordering::Release);
                }
            } else {
                let _ = slot.owner_tid.compare_exchange(
                    dead_tid,
                    0,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
            }
        }
    }

    pub(super) fn snapshot_for_exec(&self, tid: u64) -> Vec<(u32, Vec<u8>)> {
        let mut signals = Vec::new();
        for slot in &self.slots {
            if slot.state.load(Ordering::Acquire) != SLOT_READY {
                continue;
            }
            let owner = slot.owner_tid.load(Ordering::Relaxed);
            if owner == 0 || owner == tid || !slot.thread_only.load(Ordering::Relaxed) {
                let info = unsafe { &*slot.info.get() };
                signals.push((
                    slot.seq.load(Ordering::Relaxed),
                    slot.signo.load(Ordering::Relaxed),
                    info.to_vec(),
                ));
            }
        }
        signals.sort_by_key(|&(seq, ..)| seq);
        signals
            .into_iter()
            .map(|(_, sig, info)| (sig, info))
            .collect()
    }

    pub(super) fn clear_all(&self) {
        self.ready_count.store(0, Ordering::Release);
        for slot in &self.slots {
            slot.state.store(SLOT_FREE, Ordering::Release);
        }
    }
}

#[derive(Clone, Copy, Default)]
struct GuestSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

pub(super) struct GuestSignals(Mutex<Box<[GuestSigAction; 64]>>);

impl Clone for GuestSignals {
    fn clone(&self) -> Self {
        let actions = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Self(Mutex::new(actions))
    }
}

#[derive(Clone, Copy)]
pub(super) struct AltStack {
    sp: u64,
    flags: i32,
    size: u64,
}

impl Default for AltStack {
    fn default() -> Self {
        Self::disabled()
    }
}

impl AltStack {
    pub(super) const fn disabled() -> Self {
        Self {
            sp: 0,
            flags: libc::SS_DISABLE,
            size: 0,
        }
    }

    pub(super) const fn contains(self, sp: u64) -> bool {
        self.flags & libc::SS_DISABLE == 0
            && sp >= self.sp
            && sp < self.sp.saturating_add(self.size)
    }

    pub(super) fn parse(sp: u64, flags: i32, size: u64) -> std::result::Result<Self, Errno> {
        let autodisarm = SS_AUTODISARM.cast_signed();
        let mode = flags & !autodisarm;
        if mode == libc::SS_DISABLE {
            if flags & autodisarm != 0 {
                return Err(Errno::EINVAL);
            }
            return Ok(Self::disabled());
        }
        if mode != 0 && mode != libc::SS_ONSTACK {
            return Err(Errno::EINVAL);
        }
        if size < GUEST_MINSIGSTKSZ {
            return Err(Errno::ENOMEM);
        }
        Ok(Self {
            sp,
            flags: flags & autodisarm,
            size,
        })
    }
}

pub(super) struct SavedFrame {
    regs: Regs,
    state: VcpuState,
    ucontext_addr: u64,
    old_mask: u64,
    old_altstack: AltStack,
}

impl Process {
    pub(super) fn deliver_fault(
        &self,
        vcpu: &VcpuFd,
        thread: &mut ThreadState,
        fault: GuestFault,
    ) -> Result<Option<ExitKind>> {
        let code = if fault.is_page_fault {
            let mapped = fault.address >= RESERVED_END
                && self
                    .space
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .overlaps(fault.address, fault.address.saturating_add(1));
            if mapped { SEGV_ACCERR } else { SEGV_MAPERR }
        } else {
            fault.code
        };
        let sig = fault.signal;
        if !(1..=64).contains(&sig) {
            return Ok(Some(ExitKind::Signaled(libc::SIGSEGV)));
        }
        let bit_index = u32::try_from(sig - 1).unwrap_or(0);
        let blocked = GuestSignals::thread_mask();
        if blocked & (1u64 << bit_index) != 0 {
            return Ok(Some(ExitKind::Signaled(sig)));
        }
        let action = {
            let mut actions = self
                .signals
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let current = actions[bit_index as usize];
            if current.flags & u64::from(SA_RESETHAND) != 0 && current.handler > 1 {
                actions[bit_index as usize] = GuestSigAction::default();
            }
            current
        };
        if action.handler <= 1 {
            return Ok(Some(ExitKind::Signaled(sig)));
        }
        let mut info = [0u8; 128];
        info[0..4].copy_from_slice(&sig.to_le_bytes());
        info[8..12].copy_from_slice(&code.to_le_bytes());
        info[16..24].copy_from_slice(&fault.address.to_le_bytes());
        GuestSignals::deliver_frame(
            &self.machine,
            vcpu,
            thread,
            blocked,
            blocked,
            bit_index,
            action,
            &info,
            fault.address,
            None,
        )
    }

    pub(super) fn sigaltstack(
        thread: &mut ThreadState,
        registers: &Regs,
        memory: &GuestMemory,
    ) -> u64 {
        let [new_ss_addr, old_ss_addr, ..] = registers.arguments();
        let on_stack = thread.altstack.contains(registers.stack_pointer());
        let mut old_raw = [0u8; 24];
        if thread.altstack.flags & libc::SS_DISABLE != 0 {
            old_raw[8..12].copy_from_slice(&libc::SS_DISABLE.to_le_bytes());
        } else {
            let flags = (thread.altstack.flags & SS_AUTODISARM.cast_signed())
                | if on_stack { libc::SS_ONSTACK } else { 0 };
            old_raw[0..8].copy_from_slice(&thread.altstack.sp.to_le_bytes());
            old_raw[8..12].copy_from_slice(&flags.to_le_bytes());
            old_raw[16..24].copy_from_slice(&thread.altstack.size.to_le_bytes());
        }
        if new_ss_addr != 0 {
            let Ok(raw) = memory.read(new_ss_addr, STACK_T_BYTES) else {
                return Errno::EFAULT.negated();
            };
            let new_sp = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
            let new_flags = i32::from_le_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
            let new_size = u64::from_le_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
            if on_stack {
                return Errno::EPERM.negated();
            }
            let parsed = match AltStack::parse(new_sp, new_flags, new_size) {
                Ok(stack) => stack,
                Err(errno) => return errno.negated(),
            };
            if old_ss_addr != 0 && memory.write(old_ss_addr, &old_raw).is_err() {
                return Errno::EFAULT.negated();
            }
            thread.altstack = parsed;
        } else if old_ss_addr != 0 && memory.write(old_ss_addr, &old_raw).is_err() {
            return Errno::EFAULT.negated();
        }
        0
    }
}

impl GuestSignals {
    pub(super) fn new() -> Self {
        Self(Mutex::new(Box::new([GuestSigAction::default(); 64])))
    }

    pub(super) fn ignored_mask(&self) -> u64 {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .enumerate()
            .filter(|(_, action)| action.handler == 1)
            .fold(0, |mask, (index, _)| mask | (1_u64 << index))
    }

    pub(super) fn restore_ignored(&self, ignored: u64) {
        let mut actions = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (index, action) in actions.iter_mut().enumerate() {
            if ignored & (1_u64 << index) != 0 {
                action.handler = 1;
            }
        }
    }

    pub(super) fn reset_on_exec(&self) {
        let mut actions = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (index, entry) in actions.iter_mut().enumerate() {
            if entry.handler > 1 {
                *entry = GuestSigAction::default();
                let sig = i32::try_from(index + 1).unwrap_or(0);
                Self::install_host_disposition(sig, 0);
            }
        }
    }

    extern "C" fn catch_siginfo(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        _ucontext: *mut libc::c_void,
    ) {
        if !(1..=64).contains(&signal) {
            return;
        }
        let Ok(signo) = u32::try_from(signal) else {
            return;
        };
        let mut raw = [0u8; 128];
        let mut thread_only = false;
        if info.is_null() {
            raw[0..4].copy_from_slice(&signal.to_ne_bytes());
        } else {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    info.cast::<u8>(),
                    raw.as_mut_ptr(),
                    std::mem::size_of::<libc::siginfo_t>().min(128),
                );
            }
            let si_code = i32::from_ne_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
            thread_only = si_code == -6;
        }
        let tid = unsafe { syscalls::syscall!(Sysno::gettid) }.map_or(1, |raw| raw as u64);
        SIGNAL_QUEUE.push(signo, tid, thread_only, &raw);
    }

    fn install_host_disposition(sig: i32, guest_handler: u64) {
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&raw mut act.sa_mask);
            match guest_handler {
                0 => {
                    act.sa_flags = 0;
                    act.sa_sigaction = libc::SIG_DFL;
                }
                1 => {
                    act.sa_flags = 0;
                    act.sa_sigaction = libc::SIG_IGN;
                }
                _ => {
                    act.sa_flags = libc::SA_SIGINFO;
                    act.sa_sigaction = Self::catch_siginfo as *const () as libc::sighandler_t;
                }
            }
            let _ = libc::sigaction(sig, &raw const act, std::ptr::null_mut());
        }
    }

    pub(super) fn rt_sigaction(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let sig = GuestReg(registers.arguments()[0]).as_i32();
        if !(1..=64).contains(&sig)
            || sig == libc::SIGKILL
            || sig == libc::SIGSTOP
            || registers.arguments()[3] != WORD_SIZE
        {
            return Errno::EINVAL.negated();
        }
        let index = usize::try_from(sig - 1).unwrap_or(0);
        let new_action = if registers.arguments()[1] != 0 {
            let Ok(raw) = memory.read(registers.arguments()[1], SIGACTION_BYTES) else {
                return Errno::EFAULT.negated();
            };
            Some(GuestSigAction {
                handler: u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8])),
                flags: u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8])),
                restorer: u64::from_le_bytes(raw[16..24].try_into().unwrap_or([0; 8])),
                mask: u64::from_le_bytes(raw[24..32].try_into().unwrap_or([0; 8])),
            })
        } else {
            None
        };

        let mut actions = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = actions[index];
        if registers.arguments()[2] != 0 {
            let mut raw = [0u8; 32];
            raw[0..8].copy_from_slice(&previous.handler.to_le_bytes());
            raw[8..16].copy_from_slice(&previous.flags.to_le_bytes());
            raw[16..24].copy_from_slice(&previous.restorer.to_le_bytes());
            raw[24..32].copy_from_slice(&previous.mask.to_le_bytes());
            if memory.write(registers.arguments()[2], &raw).is_err() {
                return Errno::EFAULT.negated();
            }
        }
        if let Some(action) = new_action {
            actions[index] = action;
            if !matches!(
                sig,
                libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE | libc::SIGTRAP
            ) {
                Self::install_host_disposition(sig, action.handler);
            }
        }
        0
    }

    pub(super) fn rt_sigprocmask(registers: &Regs, memory: &GuestMemory) -> u64 {
        if registers.arguments()[3] != WORD_SIZE {
            return Errno::EINVAL.negated();
        }
        SyscallArgs::forward_translated(
            registers,
            memory,
            Sysno::rt_sigprocmask,
            &[Arg::bytes(1, WORD_SIZE), Arg::bytes(2, WORD_SIZE)],
        )
    }

    pub(super) fn rt_sigsuspend(
        thread: &mut ThreadState,
        registers: &Regs,
        memory: &GuestMemory,
    ) -> u64 {
        let args = registers.arguments();
        if args[1] != WORD_SIZE {
            return Errno::EINVAL.negated();
        }
        let Ok(raw) = memory.read(args[0], WORD_SIZE) else {
            return Errno::EFAULT.negated();
        };
        let host_mask = u64::from_le_bytes(raw.try_into().unwrap_or([0; 8]));
        thread.run_with_temp_mask(memory, args[0], args[1], || {
            SyscallArgs::invoke(
                Sysno::rt_sigsuspend,
                &[
                    (&raw const host_mask).expose_provenance() as u64,
                    WORD_SIZE,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        })
    }

    pub(super) fn rt_sigpending(registers: &Regs, memory: &GuestMemory) -> u64 {
        let args = registers.arguments();
        if args[1] != WORD_SIZE {
            return Errno::EINVAL.negated();
        }
        let mut host_pending = 0u64;
        let rc = SyscallArgs::invoke(
            Sysno::rt_sigpending,
            &[
                (&raw mut host_pending).expose_provenance() as u64,
                WORD_SIZE,
                0,
                0,
                0,
                0,
            ],
        );
        if GuestReg(rc).as_c_long() < 0 {
            return rc;
        }
        let queued = SIGNAL_QUEUE.pending_mask(ThreadState::current_tid()) & Self::thread_mask();
        let combined = host_pending | queued;
        if memory.write(args[0], &combined.to_le_bytes()).is_err() {
            return Errno::EFAULT.negated();
        }
        0
    }

    pub(super) fn rt_sigtimedwait(registers: &Regs, memory: &GuestMemory) -> u64 {
        let [uthese, uinfo, uts, sigsetsize, ..] = registers.arguments();
        if sigsetsize != WORD_SIZE {
            return Errno::EINVAL.negated();
        }
        let Ok(raw_mask) = memory.read(uthese, WORD_SIZE) else {
            return Errno::EFAULT.negated();
        };
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let ts_ptr = if uts != 0 {
            let Ok(raw_ts) = memory.read(uts, TIMESPEC_BYTES) else {
                return Errno::EFAULT.negated();
            };
            ts.tv_sec = i64::from_le_bytes(raw_ts[0..8].try_into().unwrap_or([0; 8]));
            ts.tv_nsec = i64::from_le_bytes(raw_ts[8..16].try_into().unwrap_or([0; 8]));
            if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
                return Errno::EINVAL.negated();
            }
            (&raw const ts).expose_provenance() as u64
        } else {
            0
        };
        if uinfo != 0 && memory.address(uinfo, SIGINFO_BYTES).is_err() {
            return Errno::EFAULT.negated();
        }
        let uncatchable = (1u64 << (libc::SIGKILL - 1)) | (1u64 << (libc::SIGSTOP - 1));
        let these_mask = u64::from_le_bytes(raw_mask.try_into().unwrap_or([0; 8])) & !uncatchable;
        if let Some((signo, info)) =
            SIGNAL_QUEUE.pop_deliverable(ThreadState::current_tid(), these_mask)
        {
            if uinfo != 0 && memory.write(uinfo, &info).is_err() {
                return Errno::EFAULT.negated();
            }
            return u64::from(signo);
        }
        let mut out_info = [0u8; 128];
        let info_ptr = if uinfo != 0 {
            out_info.as_mut_ptr().expose_provenance() as u64
        } else {
            0
        };
        let rc = SyscallArgs::invoke(
            Sysno::rt_sigtimedwait,
            &[
                (&raw const these_mask).expose_provenance() as u64,
                info_ptr,
                ts_ptr,
                WORD_SIZE,
                0,
                0,
            ],
        );
        if GuestReg(rc).as_c_long() >= 0 && uinfo != 0 && memory.write(uinfo, &out_info).is_err() {
            return Errno::EFAULT.negated();
        }
        rc
    }

    pub(super) fn rt_sigreturn(
        memory: &GuestMemory,
        vcpu: &VcpuFd,
        thread: &mut ThreadState,
        registers: &mut Regs,
    ) -> Result<Option<GuestFault>> {
        let sigsegv = GuestFault {
            signal: libc::SIGSEGV,
            code: libc::SI_KERNEL,
            address: 0,
            is_page_fault: false,
        };
        let Some(mut saved) = thread.signal_frames.pop() else {
            return Ok(Some(sigsegv));
        };
        let Ok(uc_raw) = memory.read(saved.ucontext_addr, UCONTEXT_BYTES) else {
            return Ok(Some(sigsegv));
        };
        saved.regs.apply_ucontext(&uc_raw);
        if !saved.regs.has_valid_return_ip() {
            return Ok(Some(sigsegv));
        }
        let mut mask = saved.old_mask;
        let mut alt = (
            saved.old_altstack.sp,
            saved.old_altstack.flags,
            saved.old_altstack.size,
        );
        if let Some((uc_mask, uc_alt)) = Regs::read_ucontext_meta(&uc_raw) {
            mask = uc_mask;
            alt = uc_alt;
        }
        Self::set_thread_mask(mask);
        thread.restore_altstack(saved.regs.stack_pointer(), alt.0, alt.1, alt.2);
        Machine::restore_signal(vcpu, &saved.state).context("restore vCPU state on sigreturn")?;
        *registers = saved.regs;
        Ok(None)
    }

    pub(super) fn thread_mask() -> u64 {
        let mut mask = 0u64;
        let _ = unsafe {
            syscalls::syscall!(
                Sysno::rt_sigprocmask,
                libc::SIG_SETMASK.cast_unsigned() as usize,
                0_usize,
                (&raw mut mask).expose_provenance(),
                usize::try_from(WORD_SIZE).unwrap_or(8)
            )
        };
        mask
    }

    pub(super) fn set_thread_mask(mask: u64) {
        let mut blocked = mask;
        let uncatchable = (1u64 << (libc::SIGKILL - 1)) | (1u64 << (libc::SIGSTOP - 1));
        blocked &= !uncatchable;
        let _ = unsafe {
            syscalls::syscall!(
                Sysno::rt_sigprocmask,
                libc::SIG_SETMASK.cast_unsigned() as usize,
                (&raw const blocked).expose_provenance(),
                0_usize,
                usize::try_from(WORD_SIZE).unwrap_or(8)
            )
        };
    }

    /// Delivers the first deliverable pending signal, where `origin` holds
    /// the registers of the system call that just returned, if any.
    pub(super) fn deliver_pending(
        &self,
        machine: &Machine,
        vcpu: &VcpuFd,
        thread: &mut ThreadState,
        origin: Option<&Regs>,
    ) -> Result<Option<ExitKind>> {
        let (active_mask, saved_mask) = if let Some((temp, orig)) = thread.temp_signal_mask.take() {
            (temp, orig)
        } else {
            let current = Self::thread_mask();
            (current, current)
        };
        let tid = ThreadState::current_tid();
        while let Some((signo, info)) = SIGNAL_QUEUE.pop_deliverable(tid, !active_mask) {
            let bit_index = signo - 1;
            let sig = i32::try_from(signo).unwrap_or(0);
            let action = {
                let mut actions = self
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let current = actions[bit_index as usize];
                if current.flags & u64::from(SA_RESETHAND) != 0 && current.handler > 1 {
                    actions[bit_index as usize] = GuestSigAction::default();
                    Self::install_host_disposition(sig, 0);
                }
                current
            };
            if action.handler == 1 {
                continue;
            }
            if action.handler == 0 {
                if matches!(
                    sig,
                    libc::SIGCHLD | libc::SIGURG | libc::SIGWINCH | libc::SIGCONT
                ) {
                    continue;
                }
                return Ok(Some(ExitKind::Signaled(sig)));
            }
            return Self::deliver_frame(
                machine,
                vcpu,
                thread,
                active_mask,
                saved_mask,
                bit_index,
                action,
                &info,
                0,
                origin,
            );
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn deliver_frame(
        machine: &Machine,
        vcpu: &VcpuFd,
        thread: &mut ThreadState,
        active_mask: u64,
        saved_mask: u64,
        bit_index: u32,
        action: GuestSigAction,
        siginfo: &[u8; 128],
        fault_addr: u64,
        origin: Option<&Regs>,
    ) -> Result<Option<ExitKind>> {
        let memory = &machine.memory;
        let mut prior_regs = machine.regs(vcpu)?;
        let prior_state = machine.state(vcpu)?;
        if let Some(origin) = origin {
            if prior_regs.result() == Errno::EINTR.negated()
                && action.flags & u64::from(SA_RESTART) != 0
                && origin
                    .syscall()
                    .is_some_and(|sys| sys.is_restartable(origin))
            {
                prior_regs.rewind_syscall(origin);
            }
            prior_regs.leave_kernel_stub();
        } else {
            prior_regs.normalize_interrupted();
        }

        let current_sp = prior_regs.stack_pointer();
        let was_on_altstack = thread.altstack.contains(current_sp);
        let old_altstack = thread.altstack;
        let autodisarm = SS_AUTODISARM.cast_signed();
        let uc_stack = if old_altstack.flags & libc::SS_DISABLE != 0 {
            (0, libc::SS_DISABLE, 0)
        } else {
            let on_flag = if was_on_altstack { libc::SS_ONSTACK } else { 0 };
            (
                old_altstack.sp,
                (old_altstack.flags & autodisarm) | on_flag,
                old_altstack.size,
            )
        };

        let use_altstack = action.flags & u64::from(SA_ONSTACK) != 0
            && (old_altstack.flags & libc::SS_DISABLE == 0)
            && !was_on_altstack;
        let base_sp = if use_altstack {
            if old_altstack.flags & autodisarm != 0 {
                thread.altstack = AltStack::disabled();
            }
            old_altstack.sp.saturating_add(old_altstack.size)
        } else {
            current_sp
        };

        let frame = Regs::signal_frame_at(base_sp, use_altstack, SIGINFO_BYTES + UCONTEXT_BYTES);
        let siginfo_addr = frame;
        let ucontext_addr = frame + SIGINFO_BYTES;
        let sig_no = bit_index + 1;

        let mut uc_raw = vec![0u8; usize::try_from(UCONTEXT_BYTES).unwrap_or(0)];
        prior_regs.write_ucontext(&mut uc_raw, uc_stack, saved_mask, fault_addr, ucontext_addr);

        let mut next_regs = prior_regs;
        if memory.write(siginfo_addr, siginfo).is_err()
            || memory.write(ucontext_addr, &uc_raw).is_err()
            || next_regs
                .enter_handler(
                    memory,
                    action.handler,
                    (action.flags & u64::from(SA_RESTORER) != 0).then_some(action.restorer),
                    frame,
                    [u64::from(sig_no), siginfo_addr, ucontext_addr],
                )
                .is_err()
        {
            return Ok(Some(ExitKind::Signaled(libc::SIGSEGV)));
        }

        if thread.signal_frames.len() >= 64 {
            thread.signal_frames.remove(0);
        }
        thread.signal_frames.push(SavedFrame {
            regs: prior_regs,
            state: prior_state,
            ucontext_addr,
            old_mask: saved_mask,
            old_altstack,
        });

        let defer_self = if action.flags & u64::from(SA_NODEFER) == 0 {
            1u64 << bit_index
        } else {
            0
        };
        Self::set_thread_mask(active_mask | action.mask | defer_self);
        Machine::set_regs(vcpu, &next_regs).context("set handler registers for signal")?;
        Ok(None)
    }
}
