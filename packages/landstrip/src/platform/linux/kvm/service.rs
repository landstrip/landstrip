// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Syscall broker.
//!
//! The guest ABI is the host ABI, so each trap is forwarded to the host kernel
//! with guest addresses translated to host addresses in the guest memory
//! mapping. Nothing is emulated: the host kernel keeps the real semantics.

mod args;
mod fs;
mod ipc;
mod mm;
mod restart;
mod signal;
mod trap;

pub(super) use ipc::MqueueNamespace;
pub(super) use restart::State as RestartState;
pub(crate) use trap::Channel;

use self::args::{Arg, KernelMsghdr, SyscallArgs};
use self::fs::{Call, SysnoExt};
use self::mm::{AddressSpace, MAPPING_CEILING};
use self::signal::{AltStack, GuestSignals, PendingSignal, SIGNAL_QUEUE, SavedFrame};
use self::trap::{Denials, Empty, PendingDenials, QueryOutcome, QueryState, Request, Target};
use super::ErrnoExt;
use super::cancel::{Client, Request as CancelRequest};
use super::dbus::DbusProxies;
use super::fds::{BrokerHandle, GuestFd};
use super::handoff::RestartImage;
use super::machine::{ExitReason, Machine, PAGE_BYTES, RESERVED_END, Regs, VcpuState};
use super::memory::{GuestMemory, HostCString};
use super::network;
use super::payload;
use super::policy::{Access, Missing, Policy};
use super::ptrace::PtraceTable;
use super::robust::{HEAD_BYTES as ROBUST_HEAD_BYTES, RobustMirror};
use crate::trap::NetworkOperation;
use crate::trap_fd::TrapFd;
use anyhow::{Context, Result, bail};
use kvm_ioctls::VcpuFd;
use linux_raw_sys::general::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_FILES, CLONE_FS, CLONE_NEWCGROUP, CLONE_NEWIPC,
    CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS,
    CLONE_PARENT_SETTID, CLONE_SETTLS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VFORK, CLONE_VM,
    file_clone_range, membarrier_cmd, membarrier_cmd_flag,
};
use linux_raw_sys::ioctl::{FICLONE, FICLONERANGE};
use std::collections::{BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use syscalls::{Errno, Sysno};

const TIMEVAL_BYTES: u64 = std::mem::size_of::<libc::timeval>() as u64;
const ITIMERSPEC_BYTES: u64 = std::mem::size_of::<libc::itimerspec>() as u64;
const FILE_CLONE_RANGE_BYTES: u64 = std::mem::size_of::<file_clone_range>() as u64;
const WORD_SIZE: u64 = 8;
const AT_EMPTY_PATH: u64 = libc::AT_EMPTY_PATH as u64;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u64 = 0x4000_0000;
const TIMESPEC_BYTES: u64 = std::mem::size_of::<libc::timespec>() as u64;
const ARG_LIMIT: usize = 32_768;
const ARG_STRING_LIMIT: usize = 131_072;
const ARG_BYTES_LIMIT: usize = 8 << 20;
#[cfg(target_arch = "x86_64")]
const CLONE_CHILD_TID_ARGUMENT: usize = 3;
#[cfg(target_arch = "x86_64")]
const CLONE_TLS_ARGUMENT: usize = 4;
#[cfg(target_arch = "aarch64")]
const CLONE_TLS_ARGUMENT: usize = 3;
#[cfg(target_arch = "aarch64")]
const CLONE_CHILD_TID_ARGUMENT: usize = 4;
const SIGINFO_BYTES: u64 = std::mem::size_of::<libc::siginfo_t>() as u64;

#[derive(Clone, Copy)]
struct GuestReg(u64);

impl GuestReg {
    fn as_i32(self) -> i32 {
        let low = u32::try_from(self.0 & 0xffff_ffff).unwrap_or_default();
        i32::from_ne_bytes(low.to_ne_bytes())
    }

    #[allow(clippy::cast_possible_truncation)]
    const fn as_u32(self) -> u32 {
        self.0 as u32
    }

    const fn as_c_long(self) -> libc::c_long {
        libc::c_long::from_ne_bytes(self.0.to_ne_bytes())
    }
}

#[derive(Default)]
struct ThreadState {
    clear_child_tid: u64,
    /// The guest robust list head, released when the thread exits or execs.
    robust_list: u64,
    /// Whether the supervisor watches the exit of this native thread.
    robust_watched: bool,
    tlb_epoch: u64,
    pub(super) altstack: AltStack,
    pub(super) temp_signal_mask: Option<(u64, u64)>,
    pub(super) signal_frames: Vec<SavedFrame>,
}

impl ThreadState {
    fn drain_private_signals() -> Result<Vec<PendingSignal>> {
        let mut signals = Vec::new();
        loop {
            let status = std::fs::read_to_string("/proc/thread-self/status")?;
            let mask = status
                .lines()
                .find_map(|line| line.strip_prefix("SigPnd:"))
                .context("missing thread pending signals")?;
            let mask = u64::from_str_radix(mask.trim(), 16)?;
            if mask == 0 {
                return Ok(signals);
            }
            let mut info = [0u8; 128];
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let signal = unsafe {
                syscalls::syscall!(
                    Sysno::rt_sigtimedwait,
                    (&raw const mask).expose_provenance(),
                    info.as_mut_ptr().expose_provenance(),
                    (&raw const timeout).expose_provenance(),
                    usize::try_from(WORD_SIZE).unwrap_or(8)
                )
            }
            .map_err(|errno| io::Error::from_raw_os_error(errno.into_raw()))?;
            signals.push(PendingSignal {
                number: i32::try_from(signal)?,
                info,
            });
        }
    }
    pub(super) fn current_tid() -> u64 {
        u64::try_from(unsafe { libc::gettid() }).unwrap_or(1)
    }

    pub(super) fn restore_altstack(&mut self, current_sp: u64, sp: u64, flags: i32, size: u64) {
        if self.altstack.contains(current_sp) {
            return;
        }
        if let Ok(parsed) = AltStack::parse(sp, flags, size) {
            self.altstack = parsed;
        }
    }

    pub(super) fn run_with_temp_mask(
        &mut self,
        memory: &GuestMemory,
        ss_ptr: u64,
        ss_len: u64,
        call: impl FnOnce() -> u64,
    ) -> u64 {
        if ss_ptr == 0 || ss_len != WORD_SIZE {
            return call();
        }
        let Ok(raw) = memory.read(ss_ptr, WORD_SIZE) else {
            return call();
        };
        let uncatchable = (1u64 << (libc::SIGKILL - 1)) | (1u64 << (libc::SIGSTOP - 1));
        let temp_mask = u64::from_le_bytes(raw.try_into().unwrap_or([0; 8])) & !uncatchable;
        let orig_mask = GuestSignals::thread_mask();
        if SIGNAL_QUEUE.pending_mask(Self::current_tid()) & !temp_mask != 0 {
            self.temp_signal_mask = Some((temp_mask, orig_mask));
            return Errno::EINTR.negated();
        }
        let result = call();
        if result == Errno::EINTR.negated() {
            self.temp_signal_mask = Some((temp_mask, orig_mask));
        }
        result
    }

    /// Releases robust locks owned by `owner`: the thread, or the leader
    /// whose TID an exec caller takes, then forgets the list.
    fn release_robust_list(&mut self, robust: RobustMirror, memory: &GuestMemory, owner: u64) {
        RobustMirror::release(memory, std::mem::take(&mut self.robust_list), owner);
        robust.register(memory, 0);
    }

    fn release_child_tid(&mut self, memory: &GuestMemory) {
        let tid_addr = std::mem::take(&mut self.clear_child_tid);
        if tid_addr == 0 {
            return;
        }
        let Ok(host_address) = memory.write_u32_atomic(tid_addr, 0) else {
            return;
        };
        let Ok(addr) = usize::try_from(host_address) else {
            return;
        };
        unsafe {
            let _ = syscalls::syscall!(
                Sysno::futex,
                addr,
                (libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG).cast_unsigned() as usize,
                1_usize,
                0_usize,
                0_usize,
                0_usize
            );
            let _ = syscalls::syscall!(
                Sysno::futex,
                addr,
                libc::FUTEX_WAKE.cast_unsigned() as usize,
                1_usize,
                0_usize,
                0_usize,
                0_usize
            );
        }
    }
}

pub(crate) struct Broker {
    process: Arc<Process>,
    vcpu: BrokerHandle<VcpuFd>,
}

struct Process {
    machine: Machine,
    denials: Denials,
    policy: Policy,
    dbus_proxies: DbusProxies,
    signals: GuestSignals,
    /// Raw kernel timer IDs, shared by guest threads but not inherited by fork.
    timers: Mutex<HashSet<i32>>,
    space: Mutex<AddressSpace>,
    threads: (Mutex<Threads>, Condvar),
    error_pipe: Option<Mutex<BrokerHandle<UnixStream>>>,
    cancellation: Arc<Client>,
    lifecycle: Arc<Mutex<()>>,
    mqueue: MqueueNamespace,
    ptrace: Arc<PtraceTable>,
    robust: RobustMirror,
    restart_image: Option<Arc<RestartImage>>,
    vfork_sync: Mutex<Option<VforkSync>>,
    /// `membarrier` registration commands of the guest image. The kernel
    /// keeps the broker registered across a guest exec, which clears these.
    membarrier: AtomicU32,
}

struct VforkSync {
    tx: BrokerHandle<UnixStream>,
    shares_vm: bool,
}

impl VforkSync {
    fn pair(shares_vm: bool) -> Result<(BrokerHandle<UnixStream>, Self)> {
        let _fd_lock = GuestFd::read_fd_table();
        let (rx, tx) = UnixStream::pair().context("create vfork synchronization channel")?;
        let rx = GuestFd::relocate_above(OwnedFd::from(rx))?.map_same_fd(UnixStream::from);
        let tx = GuestFd::relocate_above(OwnedFd::from(tx))?.map_same_fd(UnixStream::from);
        Ok((rx, Self { tx, shares_vm }))
    }

    fn wait_in_parent(mut rx: BrokerHandle<UnixStream>, memory: &GuestMemory) {
        let stream = rx.get_mut();
        let mut header = [0_u8; 8];
        let mut page = vec![0_u8; usize::try_from(PAGE_BYTES).unwrap_or(4096)];
        while Self::read_frame_part(stream, &mut header) {
            if !Self::read_frame_part(stream, &mut page) {
                break;
            }
            let guest_addr = u64::from_le_bytes(header);
            let _ = memory.write(guest_addr, &page);
        }
    }

    fn read_frame_part(stream: &mut UnixStream, mut buf: &mut [u8]) -> bool {
        while !buf.is_empty() {
            match stream.read(buf) {
                Ok(0) => return false,
                Ok(n) => buf = &mut buf[n..],
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
        true
    }

    fn send_all(fd: RawFd, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            let rc =
                unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL) };
            if rc > 0 {
                let Ok(step) = usize::try_from(rc) else {
                    return false;
                };
                bytes = &bytes[step..];
            } else if rc < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            } else {
                return false;
            }
        }
        true
    }

    fn finish_in_child(self, process: &Process) {
        if !self.shares_vm {
            return;
        }
        let pagemap = {
            let _fd_lock = GuestFd::read_fd_table();
            let raw = unsafe {
                libc::open(
                    c"/proc/self/pagemap".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return;
            }
            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
            let Ok(relocated) = GuestFd::relocate_above(owned) else {
                return;
            };
            relocated.map_same_fd(std::fs::File::from)
        };
        let host_base = process.machine.memory.base();
        let ranges = process.space_snapshot().writable_private_ranges();
        let mut entries = vec![0_u8; 4096 * 8];
        for (start, end) in ranges {
            let mut cursor = start & !(PAGE_BYTES - 1);
            while cursor < end {
                let pages = usize::try_from(((end - cursor) / PAGE_BYTES).min(4096)).unwrap_or(0);
                if pages == 0 {
                    break;
                }
                let host_vfn = (host_base + cursor) / PAGE_BYTES;
                let slice = &mut entries[..pages * 8];
                if pagemap.get().read_exact_at(slice, host_vfn * 8).is_err() {
                    break;
                }
                for (idx, raw_entry) in slice.chunks_exact(8).enumerate() {
                    let word = u64::from_ne_bytes(raw_entry.try_into().unwrap_or([0; 8]));
                    let present_or_swapped = word & ((1_u64 << 63) | (1_u64 << 62)) != 0;
                    let anon_exclusive = word & (1_u64 << 56) != 0;
                    if present_or_swapped && anon_exclusive {
                        let guest_page = cursor + (idx as u64) * PAGE_BYTES;
                        if let Ok(bytes) = process.machine.memory.read(guest_page, PAGE_BYTES) {
                            let hdr = guest_page.to_le_bytes();
                            if !Self::send_all(self.tx.as_raw_fd(), &hdr)
                                || !Self::send_all(self.tx.as_raw_fd(), &bytes)
                            {
                                return;
                            }
                        }
                    }
                }
                cursor += (pages as u64) * PAGE_BYTES;
            }
        }
    }
}

struct Threads {
    live: usize,
    last_status: i32,
    workers: BTreeSet<u64>,
    leader: u64,
    leader_active: bool,
    leader_parked: bool,
    handles: Vec<std::thread::JoinHandle<Vec<PendingSignal>>>,
    pending: Option<PreparedExec>,
}

impl Threads {
    fn new() -> Self {
        let leader = ThreadState::current_tid();
        Self {
            live: 1,
            last_status: 0,
            workers: BTreeSet::from([leader]),
            leader,
            leader_active: true,
            leader_parked: false,
            handles: Vec::new(),
            pending: None,
        }
    }
}

struct PreparedExec {
    invoked: OsString,
    loaded: payload::LoadedProgram,
    environment: Vec<OsString>,
    signal_mask: u64,
    caller: u64,
}

impl PreparedExec {
    fn new(
        invoked: OsString,
        loaded: payload::LoadedProgram,
        environment: Vec<OsString>,
    ) -> std::result::Result<Self, Errno> {
        let staging = GuestMemory::new(super::RAM_SIZE).map_err(|_| Errno::ENOMEM)?;
        let launch = loaded.payload.load(&staging).map_err(|_| Errno::ENOEXEC)?;
        launch
            .initial_stack(&staging, &invoked, &loaded.arguments, &environment)
            .map_err(|_| Errno::E2BIG)?;
        if launch.end >= MAPPING_CEILING {
            return Err(Errno::ENOMEM);
        }
        Ok(Self {
            invoked,
            loaded,
            environment,
            signal_mask: GuestSignals::thread_mask(),
            caller: ThreadState::current_tid(),
        })
    }
}

enum ExitKind {
    Thread(i32),
    Group(i32),
    Signaled(i32),
    Retired,
}

pub(super) struct BrokerFiles {
    pub(super) trap: Option<TrapFd>,
    pub(super) channel: Channel,
    pub(super) error_pipe: Option<BrokerHandle<UnixStream>>,
    pub(super) cancellation: Client,
    pub(super) mqueue: MqueueNamespace,
    pub(super) ptrace: PtraceTable,
    pub(super) restart_image: Option<RestartImage>,
}

impl Broker {
    pub(super) fn new(
        machine: (Machine, BrokerHandle<VcpuFd>),
        launch: &payload::Launch,
        policy: Policy,
        files: BrokerFiles,
    ) -> Result<Self> {
        let (machine, vcpu) = machine;
        let BrokerFiles {
            trap,
            channel,
            error_pipe,
            cancellation,
            mqueue,
            ptrace,
            restart_image,
        } = files;
        let space = AddressSpace::new(launch.end, &launch.segments);
        if space.break_point() >= MAPPING_CEILING {
            bail!("payload does not fit into the guest address space");
        }
        space.sync_page_tables(&machine)?;
        let robust = RobustMirror::reserve(&machine.memory)?;
        let process = Arc::new(Process {
            machine,
            denials: Denials::new(trap, channel),
            policy,
            dbus_proxies: DbusProxies::new(),
            signals: GuestSignals::new(),
            timers: Mutex::new(HashSet::new()),
            space: Mutex::new(space),
            threads: (Mutex::new(Threads::new()), Condvar::new()),
            cancellation: Arc::new(cancellation),
            lifecycle: Arc::new(Mutex::new(())),
            error_pipe: error_pipe.map(Mutex::new),
            mqueue,
            ptrace: Arc::new(ptrace),
            robust,
            restart_image: restart_image.map(Arc::new),
            vfork_sync: Mutex::new(None),
            membarrier: AtomicU32::new(0),
        });
        Ok(Self { process, vcpu })
    }

    pub(crate) fn run(self) -> Result<i32> {
        let Self {
            mut process,
            mut vcpu,
        } = self;
        let mut thread = ThreadState {
            tlb_epoch: process.machine.tlb_epoch(),
            ..ThreadState::default()
        };
        loop {
            match Self::run_vcpu_loop(&mut process, &mut vcpu, &mut thread) {
                Ok(ExitKind::Thread(status)) => {
                    SIGNAL_QUEUE.release_orphans(ThreadState::current_tid());
                    thread.release_robust_list(
                        process.robust,
                        &process.machine.memory,
                        ThreadState::current_tid(),
                    );
                    thread.release_child_tid(&process.machine.memory);
                    let (lock, condvar) = &process.threads;
                    let mut guard = lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.live -= 1;
                    guard.leader_active = false;
                    guard.workers.remove(&ThreadState::current_tid());
                    guard.last_status = status;
                    while guard.live > 0 && !process.denials.is_cancelled() {
                        guard = condvar
                            .wait(guard)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                    if process.denials.is_cancelled() {
                        drop(guard);
                        continue;
                    }
                    let final_status = guard.last_status;
                    drop(guard);
                    process.complete_vfork();
                    process.denials.flush(final_status != 0);
                    return Ok(final_status);
                }
                Ok(ExitKind::Group(status)) => {
                    process.complete_vfork();
                    process.denials.flush(status != 0);
                    let live = process
                        .threads
                        .0
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .live;
                    if live == 1 {
                        return Ok(status);
                    }
                    unsafe { libc::_exit(status) }
                }
                Ok(ExitKind::Signaled(sig)) => {
                    process.complete_vfork();
                    process.denials.flush(true);
                    Process::terminate_with_signal(sig)
                }
                Ok(ExitKind::Retired) => bail!("process leader retired during exec"),
                Err(error) => {
                    process.complete_vfork();
                    let live = process
                        .threads
                        .0
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .live;
                    if live == 1 && !process.denials.is_cancelled() {
                        return Err(error);
                    }
                    process.terminate_with_error(&error)
                }
            }
        }
    }

    fn run_worker(
        mut process: Arc<Process>,
        mut vcpu: BrokerHandle<VcpuFd>,
        clear_child_tid: u64,
    ) -> Vec<PendingSignal> {
        let mut thread = ThreadState {
            clear_child_tid,
            ..ThreadState::default()
        };
        match Self::run_vcpu_loop(&mut process, &mut vcpu, &mut thread) {
            Ok(exit @ (ExitKind::Thread(_) | ExitKind::Retired)) => {
                let retired = matches!(exit, ExitKind::Retired);
                let status = match exit {
                    ExitKind::Thread(status) => status,
                    _ => 0,
                };
                let tid = ThreadState::current_tid();
                let (caller, leader) = {
                    let threads = process
                        .threads
                        .0
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let caller = threads
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.caller == tid);
                    (caller, threads.leader)
                };
                if retired && process.restart_image.is_some() {
                    // The supervisor mirrors this worker's robust list at its native exit.
                } else {
                    // In the in-place path the exec caller releases as the leader.
                    thread.release_robust_list(
                        process.robust,
                        &process.machine.memory,
                        if caller { leader } else { tid },
                    );
                }
                let private_signals = if caller {
                    GuestSignals::set_thread_mask(u64::MAX);
                    let signals = ThreadState::drain_private_signals()
                        .unwrap_or_else(|error| process.terminate_with_error(&error));
                    SIGNAL_QUEUE.transfer_owner(tid, u64::MAX);
                    signals
                } else {
                    SIGNAL_QUEUE.release_orphans(tid);
                    thread.release_child_tid(&process.machine.memory);
                    Vec::new()
                };
                process.machine.recycle_vcpu(vcpu);
                if process.denials.is_cancelled()
                    && let Err(error) = process.cancellation.request(CancelRequest::Retire(tid))
                {
                    process.terminate_with_error(&error);
                }
                let (lock, condvar) = &process.threads;
                let mut guard = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.live -= 1;
                guard.workers.remove(&tid);
                if !retired {
                    guard.last_status = status;
                }
                let last_alive = guard.live == 0 && !process.denials.is_cancelled();
                condvar.notify_all();
                drop(guard);
                if last_alive {
                    process.complete_vfork();
                }
                private_signals
            }
            Ok(ExitKind::Group(status)) => {
                process.complete_vfork();
                process.denials.flush(status != 0);
                unsafe { libc::_exit(status) }
            }
            Ok(ExitKind::Signaled(sig)) => {
                process.complete_vfork();
                process.denials.flush(true);
                Process::terminate_with_signal(sig)
            }
            Err(error) => process.terminate_with_error(&error),
        }
    }

    fn run_vcpu_loop(
        process: &mut Arc<Process>,
        vcpu: &mut BrokerHandle<VcpuFd>,
        thread: &mut ThreadState,
    ) -> Result<ExitKind> {
        loop {
            if process.denials.is_cancelled() {
                if let Some(image) = &process.restart_image {
                    if let Some(prepared) = process.finish_native_exec(thread)? {
                        match process.restart(prepared, image)? {}
                    }
                    return Ok(ExitKind::Retired);
                }
                let leader = process
                    .threads
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .leader;
                if ThreadState::current_tid() != leader {
                    return Ok(ExitKind::Retired);
                }
                process.finish_exec(vcpu.get(), thread)?;
                continue;
            }
            if SIGNAL_QUEUE.has_any()
                && let Some(exit) =
                    process
                        .signals
                        .deliver_pending(&process.machine, vcpu.get(), thread, None)?
            {
                return Ok(exit);
            }
            process
                .machine
                .sync_tlb(vcpu.get(), &mut thread.tlb_epoch)?;
            match process.machine.run(vcpu.get_mut())? {
                ExitReason::Syscall => {
                    let mut registers = Machine::regs(vcpu.get())?;
                    let origin = registers;
                    if let Some(exit) = Self::handle(process, vcpu, thread, &mut registers)? {
                        return Ok(exit);
                    }
                    if process.denials.is_cancelled() {
                        continue;
                    }
                    Machine::set_regs(vcpu.get(), &registers)?;
                    if (SIGNAL_QUEUE.has_any() || thread.temp_signal_mask.is_some())
                        && let Some(exit) = process.signals.deliver_pending(
                            &process.machine,
                            vcpu.get(),
                            thread,
                            Some(&origin),
                        )?
                    {
                        return Ok(exit);
                    }
                    thread.temp_signal_mask = None;
                }
                ExitReason::Interrupted => {
                    if let Some(exit) = process.signals.deliver_pending(
                        &process.machine,
                        vcpu.get(),
                        thread,
                        None,
                    )? {
                        return Ok(exit);
                    }
                }
                ExitReason::Fault(fault) => {
                    if let Some(exit) = process.deliver_fault(vcpu.get(), thread, fault)? {
                        return Ok(exit);
                    }
                }
            }
        }
    }

    fn handle(
        process: &mut Arc<Process>,
        vcpu: &mut BrokerHandle<VcpuFd>,
        thread: &mut ThreadState,
        registers: &mut Regs,
    ) -> Result<Option<ExitKind>> {
        let lifecycle = Arc::clone(&process.lifecycle);
        let syscall = registers.syscall();
        let changes_lifecycle = matches!(
            syscall,
            Some(Sysno::execve | Sysno::execveat | Sysno::clone)
        );
        #[cfg(target_arch = "x86_64")]
        let changes_lifecycle =
            changes_lifecycle || matches!(syscall, Some(Sysno::fork | Sysno::vfork));
        let _lifecycle = changes_lifecycle.then(|| {
            lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        });
        if process.denials.is_cancelled() {
            return Ok(None);
        }
        #[cfg(target_arch = "x86_64")]
        if (X32_SYSCALL_BIT..0x8000_0000).contains(&registers.number()) {
            bail!("payload issued the x32 system call {}", registers.number());
        }
        let Some(syscall) = syscall else {
            log::debug!("kvm: unhandled syscall {}", registers.number());
            registers.set_result(Errno::ENOSYS.negated());
            return Ok(None);
        };
        match syscall {
            Sysno::exit => {
                let status = i32::try_from(registers.arguments()[0] & 0xff).unwrap_or(1);
                return Ok(Some(ExitKind::Thread(status)));
            }
            Sysno::exit_group => {
                let status = i32::try_from(registers.arguments()[0] & 0xff).unwrap_or(1);
                return Ok(Some(ExitKind::Group(status)));
            }
            Sysno::rt_sigreturn => {
                GuestSignals::rt_sigreturn(&process.machine.memory, vcpu.get(), thread, registers)?;
            }
            Sysno::execve | Sysno::execveat => {
                process.exec(vcpu.get(), syscall, registers, thread)?;
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::fork | Sysno::vfork => {
                Self::fork_process(process, vcpu, thread, registers, syscall)?;
            }
            Sysno::clone => match Self::validate_clone_flags(registers.arguments()[0]) {
                Err(errno) => registers.set_result(errno.negated()),
                Ok(true) => {
                    registers.set_result(Self::spawn_thread(process, vcpu.get(), registers)?);
                }
                Ok(false) => {
                    Self::fork_process(process, vcpu, thread, registers, Sysno::clone)?;
                }
            },
            #[cfg(target_arch = "x86_64")]
            Sysno::arch_prctl => registers.set_result(Process::arch_prctl(
                vcpu.get(),
                registers,
                &process.machine.memory,
            )?),
            _ => registers.set_result(process.serve(thread, syscall, registers)),
        }
        Ok(None)
    }

    fn validate_clone_flags(flags: u64) -> std::result::Result<bool, Errno> {
        let ns_flags = u64::from(
            CLONE_NEWNS
                | CLONE_NEWUTS
                | CLONE_NEWIPC
                | CLONE_NEWUSER
                | CLONE_NEWPID
                | CLONE_NEWNET
                | CLONE_NEWCGROUP
                | CLONE_NEWTIME,
        );
        if flags & ns_flags != 0 {
            return Err(Errno::EPERM);
        }
        let is_thread = flags & u64::from(CLONE_THREAD) != 0;
        let has_sighand = flags & u64::from(CLONE_SIGHAND) != 0;
        let has_vm = flags & u64::from(CLONE_VM) != 0;
        let is_vfork = flags & u64::from(CLONE_VFORK) != 0;
        if (is_thread && !has_sighand) || (has_sighand && !has_vm) {
            return Err(Errno::EINVAL);
        }
        if is_thread {
            if is_vfork {
                return Err(Errno::EINVAL);
            }
            return Ok(true);
        }
        if has_sighand || flags & u64::from(CLONE_FILES | CLONE_FS) != 0 || (has_vm && !is_vfork) {
            return Err(Errno::EINVAL);
        }
        Ok(false)
    }

    fn spawn_thread(process: &Arc<Process>, vcpu: &VcpuFd, registers: &Regs) -> Result<u64> {
        let flags = registers.arguments()[0];
        let parent_tidptr = registers.arguments()[2];
        let child_tidptr = registers.arguments()[CLONE_CHILD_TID_ARGUMENT];
        if flags & u64::from(CLONE_PARENT_SETTID) != 0
            && process.machine.memory.address(parent_tidptr, 4).is_err()
        {
            return Ok(Errno::EFAULT.negated());
        }
        if flags & u64::from(CLONE_CHILD_SETTID) != 0
            && process.machine.memory.address(child_tidptr, 4).is_err()
        {
            return Ok(Errno::EFAULT.negated());
        }
        let tls = match Self::clone_tls(registers) {
            Ok(tls) => tls,
            Err(errno) => return Ok(errno.negated()),
        };
        let state = process.machine.state(vcpu)?;
        let child_regs = registers.child(registers.arguments()[1]);
        let child_vcpu = match process.machine.pop_idle_vcpu() {
            Some(recycled) => recycled,
            None => process.machine.allocate_vcpu()?,
        };
        process
            .machine
            .configure_vcpu(child_vcpu.get(), &state, tls, &child_regs)?;

        let mut threads = process
            .threads
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        threads.live += 1;

        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<u64>(1);
        let worker_process = Arc::clone(process);
        let spawned = std::thread::Builder::new().spawn(move || {
            let tid = unsafe { libc::gettid() };
            let tid_word = tid.cast_unsigned();
            if flags & u64::from(CLONE_PARENT_SETTID) != 0 {
                let _ = worker_process
                    .machine
                    .memory
                    .write_u32_atomic(parent_tidptr, tid_word);
            }
            if flags & u64::from(CLONE_CHILD_SETTID) != 0 {
                let _ = worker_process
                    .machine
                    .memory
                    .write_u32_atomic(child_tidptr, tid_word);
            }
            let clear_child_tid = if flags & u64::from(CLONE_CHILD_CLEARTID) != 0 {
                child_tidptr
            } else {
                0
            };
            let _ = ready_tx.send(u64::try_from(tid).unwrap_or(1));
            Self::run_worker(worker_process, child_vcpu, clear_child_tid)
        });

        if let Ok(handle) = spawned {
            let tid = ready_rx.recv().context("guest worker did not start")?;
            threads.workers.insert(tid);
            threads.handles.retain(|handle| !handle.is_finished());
            threads.handles.push(handle);
            Ok(tid)
        } else {
            threads.live -= 1;
            Ok(Errno::EAGAIN.negated())
        }
    }

    fn fork_process(
        process: &mut Arc<Process>,
        vcpu: &mut BrokerHandle<VcpuFd>,
        thread: &mut ThreadState,
        registers: &mut Regs,
        syscall: Sysno,
    ) -> Result<()> {
        let flags = registers.arguments()[0];
        if syscall == Sysno::clone {
            if let Err(errno) = Self::clone_tls(registers) {
                registers.set_result(errno.negated());
                return Ok(());
            }
            if flags & u64::from(CLONE_PARENT_SETTID) != 0
                && process
                    .machine
                    .memory
                    .address(registers.arguments()[2], 4)
                    .is_err()
            {
                registers.set_result(Errno::EFAULT.negated());
                return Ok(());
            }
        }
        let is_vfork = {
            #[cfg(target_arch = "x86_64")]
            let legacy_vfork = syscall == Sysno::vfork;
            #[cfg(not(target_arch = "x86_64"))]
            let legacy_vfork = false;
            legacy_vfork || (syscall == Sysno::clone && flags & u64::from(CLONE_VFORK) != 0)
        };
        let shares_vm = {
            #[cfg(target_arch = "x86_64")]
            let legacy_vfork = syscall == Sysno::vfork;
            #[cfg(not(target_arch = "x86_64"))]
            let legacy_vfork = false;
            legacy_vfork || (syscall == Sysno::clone && flags & u64::from(CLONE_VM) != 0)
        };
        let mut vfork_pair = if is_vfork {
            Some(VforkSync::pair(shares_vm)?)
        } else {
            None
        };
        let snapshot = process.fork_snapshot(vcpu.get())?;
        let child = unsafe { libc::fork() };
        if child < 0 {
            registers.set_result(Errno::last_os(Errno::EPERM).negated());
            drop(vfork_pair);
            drop(snapshot);
            return Ok(());
        }
        if child > 0 {
            drop(snapshot);
            if syscall == Sysno::clone && flags & u64::from(CLONE_PARENT_SETTID) != 0 {
                let _ = process
                    .machine
                    .memory
                    .write_u32_atomic(registers.arguments()[2], child.cast_unsigned());
            }
            if let Some((parent_rx, child_tx)) = vfork_pair.take() {
                drop(child_tx);
                VforkSync::wait_in_parent(parent_rx, &process.machine.memory);
            }
            registers.set_result(u64::try_from(child)?);
            return Ok(());
        }
        let child_vfork = vfork_pair.take().map(|(parent_rx, child_tx)| {
            drop(parent_rx);
            child_tx
        });
        snapshot.into_child(process, vcpu, thread, registers, syscall, child_vfork)
    }

    /// Thread pointer a `clone` with `CLONE_SETTLS` installs in the child.
    #[cfg_attr(
        target_arch = "aarch64",
        allow(
            clippy::unnecessary_wraps,
            reason = "uniform with x86-64, which validates canonical TLS addresses"
        )
    )]
    fn clone_tls(registers: &Regs) -> std::result::Result<Option<u64>, Errno> {
        let arguments = registers.arguments();
        if arguments[0] & u64::from(CLONE_SETTLS) == 0 {
            return Ok(None);
        }
        let tls = arguments[CLONE_TLS_ARGUMENT];
        #[cfg(target_arch = "x86_64")]
        {
            const TASK_SIZE_MAX: u64 = (1 << 47) - PAGE_BYTES;
            if tls >= TASK_SIZE_MAX {
                return Err(Errno::EPERM);
            }
        }
        Ok(Some(tls))
    }
}

impl Process {
    fn complete_vfork(&self) {
        if let Some(sync) = self
            .vfork_sync
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            sync.finish_in_child(self);
        }
    }

    fn release_forked_fds(&self) {
        self.machine.release_forked_fds();
        self.denials.release_forked_fds();
        self.dbus_proxies.release_forked_fds();
        self.cancellation.release_forked_fds();
        if let Some(pipe) = &self.error_pipe
            && let Ok(stream) = pipe.try_lock()
        {
            stream.close_for_forked_parent();
        }
        if let Ok(vfork) = self.vfork_sync.try_lock()
            && let Some(sync) = vfork.as_ref()
        {
            sync.tx.close_for_forked_parent();
        }
    }

    fn finish_native_exec(&self, thread: &mut ThreadState) -> Result<Option<PreparedExec>> {
        let tid = ThreadState::current_tid();
        let (lock, condvar) = &self.threads;
        let guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let caller = guard
            .pending
            .as_ref()
            .context("missing prepared native exec")?
            .caller;
        let leader = guard.leader;
        drop(guard);
        if caller != tid && leader != tid {
            return Ok(None);
        }
        GuestSignals::set_thread_mask(u64::MAX);
        self.cancellation.request(CancelRequest::Retire(tid))?;
        let mut guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if caller != tid {
            SIGNAL_QUEUE.release_orphans(tid);
            thread.release_child_tid(&self.machine.memory);
            guard.leader_parked = true;
            condvar.notify_all();
            // The kernel terminates the original leader and performs robust
            // cleanup before it transfers the process identity to the caller.
            loop {
                guard = condvar
                    .wait(guard)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
        while guard.live > 1 + usize::from(leader != tid && guard.leader_active)
            || (leader != tid && !guard.leader_parked)
        {
            guard = condvar
                .wait(guard)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        Ok(Some(
            guard
                .pending
                .take()
                .context("missing native exec capsule")?,
        ))
    }
    fn finish_exec(&self, vcpu: &VcpuFd, thread: &mut ThreadState) -> Result<()> {
        let tid = ThreadState::current_tid();
        let caller = self
            .threads
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .as_ref()
            .context("missing prepared exec")?
            .caller;
        GuestSignals::set_thread_mask(u64::MAX);
        if caller != tid {
            ThreadState::drain_private_signals()?;
            SIGNAL_QUEUE.release_orphans(tid);
            thread.release_robust_list(self.robust, &self.machine.memory, tid);
            thread.release_child_tid(&self.machine.memory);
        }
        self.cancellation.request(CancelRequest::Retire(tid))?;
        let (lock, condvar) = &self.threads;
        let mut guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while guard.live > usize::from(guard.leader_active) {
            guard = condvar
                .wait(guard)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let pending = guard.pending.take().context("missing prepared exec")?;
        let handles = std::mem::take(&mut guard.handles);
        guard.live = 1;
        guard.leader_active = true;
        guard.workers.insert(tid);
        drop(guard);
        let mut private_signals = Vec::new();
        for handle in handles {
            private_signals.extend(
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("guest worker panicked during exec"))?,
            );
        }
        SIGNAL_QUEUE.transfer_owner(u64::MAX, tid);
        let mut registers = Machine::regs(vcpu)?;
        self.commit_exec(
            vcpu,
            &mut registers,
            thread,
            &pending.invoked,
            &pending.loaded,
            &pending.environment,
        )?;
        Machine::set_regs(vcpu, &registers)?;
        for signal in private_signals {
            unsafe {
                syscalls::syscall!(
                    Sysno::rt_tgsigqueueinfo,
                    libc::getpid().cast_unsigned() as usize,
                    libc::gettid().cast_unsigned() as usize,
                    signal.number.cast_unsigned() as usize,
                    signal.info.as_ptr().expose_provenance()
                )
            }
            .map_err(|errno| io::Error::from_raw_os_error(errno.into_raw()))?;
        }
        self.denials.set_cancelled(false);
        GuestSignals::set_thread_mask(pending.signal_mask);
        Ok(())
    }
    pub(super) fn space_snapshot(&self) -> AddressSpace {
        self.space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn fork_snapshot(&self, vcpu: &VcpuFd) -> Result<ForkSnapshot> {
        let state = self.machine.state(vcpu)?;
        let error_pipe = self.error_pipe.as_ref().and_then(|pipe| {
            pipe.lock()
                .ok()
                .and_then(|stream| Self::clone_stream_above(stream.get()).ok())
        });
        Ok(ForkSnapshot {
            state,
            space: self.space_snapshot(),
            signals: self.signals.clone(),
            policy: self.policy.snapshot(),
            dbus_proxies: self.dbus_proxies.fresh(),
            query_state: self.denials.query_snapshot(),
            error_pipe,
        })
    }

    fn clone_stream_above(stream: &UnixStream) -> io::Result<BrokerHandle<UnixStream>> {
        GuestFd::duplicate_above(stream.as_raw_fd()).map(|fd| fd.map_same_fd(UnixStream::from))
    }

    fn terminate_with_error(&self, error: &anyhow::Error) -> ! {
        self.complete_vfork();
        if let Some(pipe) = &self.error_pipe
            && let Ok(stream) = pipe.lock()
        {
            let formatted = format!("{error:#}");
            unsafe {
                let _ = libc::send(
                    stream.as_raw_fd(),
                    formatted.as_ptr().cast(),
                    formatted.len(),
                    libc::MSG_NOSIGNAL,
                );
            }
        }
        unsafe { libc::_exit(127) }
    }

    fn terminate_with_signal(sig: i32) -> ! {
        unsafe {
            let zero_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let _ = libc::setrlimit(libc::RLIMIT_CORE, &raw const zero_core);
            let mut act: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&raw mut act.sa_mask);
            act.sa_sigaction = libc::SIG_DFL;
            let _ = libc::sigaction(sig, &raw const act, std::ptr::null_mut());
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, sig);
            let _ = libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut());
            let _ = libc::kill(libc::getpid(), sig);
            libc::_exit(128 + sig)
        }
    }

    fn serve(&self, thread: &mut ThreadState, syscall: Sysno, registers: &Regs) -> u64 {
        let memory = &self.machine.memory;
        if syscall.is_denied() {
            return Errno::EPERM.negated();
        }
        self.socket_syscall(syscall, registers, memory)
            .or_else(|| self.path_syscall(syscall, registers, memory))
            .or_else(|| self.state_syscall(thread, memory, syscall, registers))
            .or_else(|| self.timer_syscall(syscall, registers, memory))
            .or_else(|| SyscallArgs::plain_syscall(self, thread, syscall, registers, memory))
            .unwrap_or_else(|| {
                log::debug!("kvm: unhandled syscall {}", syscall.name());
                Errno::ENOSYS.negated()
            })
    }

    fn timer_syscall(&self, syscall: Sysno, registers: &Regs, memory: &GuestMemory) -> Option<u64> {
        let specs: &[Arg<'_>] = match syscall {
            Sysno::timer_create => return Some(self.create_timer(registers, memory)),
            Sysno::timer_gettime => &[Arg::bytes(1, ITIMERSPEC_BYTES)],
            Sysno::timer_settime => &[
                Arg::bytes(2, ITIMERSPEC_BYTES),
                Arg::bytes(3, ITIMERSPEC_BYTES),
            ],
            Sysno::timer_getoverrun | Sysno::timer_delete => &[],
            _ => return None,
        };
        let id = GuestReg(registers.arguments()[0]).as_i32();
        let mut timers = self
            .timers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !timers.contains(&id) {
            return Some(Errno::EINVAL.negated());
        }
        let result = SyscallArgs::forward_translated(registers, memory, syscall, specs);
        if syscall == Sysno::timer_delete && result == 0 {
            timers.remove(&id);
        }
        Some(result)
    }

    fn create_timer(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let mut args = registers.arguments();
        let output = args[2];
        if memory.address(output, 4).is_err() {
            return Errno::EFAULT.negated();
        }
        // sigev_value is opaque guest data, not a pointer the kernel dereferences.
        // SIGEV_THREAD_ID uses the same thread IDs on the guest and the host.
        let event = if args[1] == 0 {
            None
        } else {
            let Ok(bytes) = memory.read(args[1], std::mem::size_of::<libc::sigevent>() as u64)
            else {
                return Errno::EFAULT.negated();
            };
            Some(bytes)
        };
        let mut id = 0_i32;
        args[1] = event
            .as_ref()
            .map_or(0, |bytes| bytes.as_ptr().expose_provenance() as u64);
        args[2] = (&raw mut id).expose_provenance() as u64;
        let mut timers = self
            .timers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = SyscallArgs::invoke(Sysno::timer_create, &args);
        if result != 0 {
            return result;
        }
        // The raw syscall ABI exposes kernel IDs, not libc's timer_t pointers.
        // Keeping those IDs also preserves si_timerid and the default sigval.
        timers.insert(id);
        if memory.write(output, &id.to_ne_bytes()).is_err() {
            let removed = SyscallArgs::invoke(
                Sysno::timer_delete,
                &[id.cast_unsigned().into(), 0, 0, 0, 0, 0],
            );
            if removed == 0 {
                timers.remove(&id);
            }
            return Errno::EFAULT.negated();
        }
        0
    }

    fn delete_timers_on_exec(&self) -> Result<()> {
        let mut timers = self
            .timers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(&id) = timers.iter().next() {
            // SAFETY: id names a timer created by this process; no pointers are passed.
            unsafe { syscalls::syscall!(Sysno::timer_delete, id.cast_unsigned() as usize) }
                .map_err(|errno| io::Error::from_raw_os_error(errno.into_raw()))
                .context("delete POSIX timer on exec")?;
            timers.remove(&id);
        }
        Ok(())
    }

    fn exec(
        &self,
        vcpu: &VcpuFd,
        syscall: Sysno,
        registers: &mut Regs,
        thread: &mut ThreadState,
    ) -> Result<()> {
        match self.replace(vcpu, syscall, registers, thread)? {
            Replacement::Done => {}
            Replacement::Failed(errno) => registers.set_result(errno.negated()),
        }
        Ok(())
    }

    fn replace(
        &self,
        vcpu: &VcpuFd,
        syscall: Sysno,
        registers: &mut Regs,
        thread: &mut ThreadState,
    ) -> Result<Replacement> {
        let prepared = match self.prepare_exec_replacement(syscall, registers) {
            Ok(prepared) => prepared,
            Err(errno) => return Ok(Replacement::Failed(errno)),
        };
        self.complete_vfork();
        let mut threads = self
            .threads
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if threads.live == 1 && threads.leader == ThreadState::current_tid() {
            drop(threads);
            if let Some(image) = &self.restart_image {
                GuestSignals::set_thread_mask(u64::MAX);
                match self.restart(prepared, image)? {}
            }
            return self.commit_exec(
                vcpu,
                registers,
                thread,
                &prepared.invoked,
                &prepared.loaded,
                &prepared.environment,
            );
        }
        let tids = threads.workers.iter().copied().collect::<Vec<_>>();
        if let Err(error) = self.cancellation.request(CancelRequest::Attach(&tids)) {
            return Ok(Replacement::Failed(
                error
                    .downcast_ref::<io::Error>()
                    .map_or(Errno::EPERM, |error| Errno::from_io(error, Errno::EPERM)),
            ));
        }
        threads.pending = Some(prepared);
        self.denials.set_cancelled(true);
        self.threads.1.notify_all();
        drop(threads);
        self.cancellation.request(CancelRequest::Interrupt)?;
        Ok(Replacement::Done)
    }

    fn prepare_exec_replacement(
        &self,
        syscall: Sysno,
        registers: &Regs,
    ) -> std::result::Result<PreparedExec, Errno> {
        let memory = &self.machine.memory;
        let arguments = SyscallArgs::raw(registers);
        let is_at = syscall == Sysno::execveat;
        let index = usize::from(is_at);
        let dirfd = is_at.then(|| GuestFd::from_reg(arguments[0]).policy_dirfd());
        let flags = if is_at {
            let raw_flags = GuestReg(arguments[4]).as_i32();
            if raw_flags & !(libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW) != 0 {
                return Err(Errno::EINVAL);
            }
            raw_flags
        } else {
            0
        };
        let copied_path = HostCString::read(memory, arguments[index])?;
        if copied_path.is_null() {
            return Err(Errno::EFAULT);
        }
        let empty_fd = flags & libc::AT_EMPTY_PATH != 0 && copied_path.is_empty_non_null();
        let trailing_slash = copied_path
            .as_bytes()
            .is_some_and(|bytes| bytes.ends_with(b"/"));
        let follow = trailing_slash || flags & libc::AT_SYMLINK_NOFOLLOW == 0;
        let mut request = Request::read(dirfd, &copied_path, follow);
        if is_at {
            request = request.empty(Empty::Flagged { index: 4 });
        }
        if let Some(errno) = self.denials.refuse_target(&self.policy, registers, request) {
            return Err(errno);
        }
        let path = copied_path.as_path();
        if !empty_fd && path.as_os_str().is_empty() {
            return Err(Errno::ENOENT);
        }
        let argv = memory.read_cstring_vec(
            arguments[index + 1],
            ARG_LIMIT,
            ARG_STRING_LIMIT,
            ARG_BYTES_LIMIT,
        )?;
        let environment = memory.read_cstring_vec(
            arguments[index + 2],
            ARG_LIMIT,
            ARG_STRING_LIMIT,
            ARG_BYTES_LIMIT,
        )?;
        let (invoked, loaded) = self.load_exec_image(
            syscall,
            dirfd.unwrap_or_else(GuestFd::at_fdcwd),
            empty_fd,
            follow,
            path,
            &argv,
        )?;
        PreparedExec::new(invoked, loaded, environment)
    }

    fn load_exec_image(
        &self,
        syscall: Sysno,
        base: i64,
        empty_fd: bool,
        follow: bool,
        path: &Path,
        argv: &[OsString],
    ) -> std::result::Result<(OsString, payload::LoadedProgram), Errno> {
        let authorize = |target: &Path| {
            self.policy
                .denial(
                    GuestFd::at_fdcwd(),
                    target,
                    Access::Read,
                    true,
                    Missing::Kernel,
                )
                .and_then(|denial| {
                    self.denials
                        .refuse(&self.policy, syscall, denial, Vec::new())
                })
        };
        let (invoked, loaded_result) = if empty_fd {
            if base == GuestFd::at_fdcwd() {
                let invoked = OsString::from(".");
                let res = payload::LoadRequest::guest_path(
                    libc::AT_FDCWD,
                    Path::new("."),
                    &invoked,
                    argv,
                )
                .load(authorize);
                (invoked, res)
            } else {
                let guest_fd = GuestFd::from_reg(base.cast_unsigned());
                let raw = guest_fd.valid().ok_or(Errno::EBADF)?;
                let dup = GuestFd::duplicate_above(raw).map_err(|_| Errno::EBADF)?;
                let invoked = OsString::from(format!("/dev/fd/{raw}"));
                let res = payload::LoadRequest::guest_fd(dup.as_fd(), &invoked, argv)
                    .mark_inaccessible(guest_fd.has_cloexec())
                    .load(authorize);
                (invoked, res)
            }
        } else {
            let (raw_dirfd, invoked, inaccessible) =
                if path.is_absolute() || base == GuestFd::at_fdcwd() {
                    (libc::AT_FDCWD, path.as_os_str().to_os_string(), false)
                } else {
                    let guest_fd = GuestFd::from_reg(base.cast_unsigned());
                    let raw = guest_fd.valid().ok_or(Errno::EBADF)?;
                    if !guest_fd.is_open() {
                        return Err(Errno::EBADF);
                    }
                    let mut prefix = OsString::from(format!("/dev/fd/{raw}/"));
                    prefix.push(path.as_os_str());
                    (raw, prefix, guest_fd.has_cloexec())
                };
            let current_exe = (follow
                && self
                    .policy
                    .is_proc_self_exe(Some(base), path.as_os_str().as_bytes()))
            .then(|| self.policy.exe());
            let (open_dirfd, open_target) = match &current_exe {
                Some(exe) => (libc::AT_FDCWD, exe.as_path()),
                None => (raw_dirfd, path),
            };
            let res = payload::LoadRequest::guest_path(open_dirfd, open_target, &invoked, argv)
                .follow_symlinks(follow)
                .mark_inaccessible(inaccessible)
                .load(authorize);
            (invoked, res)
        };
        match loaded_result {
            Ok(loaded) => Ok((invoked, loaded)),
            Err(payload::LoadError::Denied(errno)) => Err(errno),
            Err(payload::LoadError::Io(error)) => Err(Errno::from_io(&error, Errno::ENOEXEC)),
            Err(payload::LoadError::InvalidElf(_)) => Err(Errno::ENOEXEC),
        }
    }

    fn commit_exec(
        &self,
        vcpu: &VcpuFd,
        registers: &mut Regs,
        thread: &mut ThreadState,
        invoked: &OsStr,
        loaded: &payload::LoadedProgram,
        environment: &[OsString],
    ) -> Result<Replacement> {
        let memory = &self.machine.memory;
        thread.release_robust_list(self.robust, memory, ThreadState::current_tid());
        memory.reset(RESERVED_END)?;
        let launch = loaded.payload.load(memory)?;
        let stack = launch.initial_stack(memory, invoked, &loaded.arguments, environment)?;
        self.delete_timers_on_exec()?;
        GuestFd::close_cloexec();
        #[cfg(target_arch = "x86_64")]
        {
            Machine::set_segment_base(vcpu, false, 0)?;
            Machine::set_segment_base(vcpu, true, 0)?;
        }
        #[cfg(target_arch = "aarch64")]
        Machine::set_tls(vcpu, 0)?;
        if !loaded.executable.as_os_str().is_empty() {
            self.policy.set_exe(&loaded.executable);
        }
        self.signals.reset_on_exec();
        self.membarrier.store(0, Ordering::Release);
        self.machine.reset_page_tables()?;
        let new_space = AddressSpace::new(launch.end, &launch.segments);
        new_space.sync_page_tables(&self.machine)?;
        *self
            .space
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = new_space;
        thread.clear_child_tid = 0;
        thread.tlb_epoch = 0;
        thread.altstack = AltStack::disabled();
        thread.temp_signal_mask = None;
        thread.signal_frames.clear();
        *registers = Regs::start(launch.start, stack);
        nix::sys::prctl::set_name(&loaded.comm).context("set payload exec name")?;
        Ok(Replacement::Done)
    }

    /// Execution commands need a registration by the guest image; the rest
    /// are forwarded, so the kernel validates them and performs every barrier.
    fn membarrier(&self, registers: &Regs) -> u64 {
        const QUERY: u32 = membarrier_cmd::MEMBARRIER_CMD_QUERY as u32;
        const REGISTER_GLOBAL_EXPEDITED: u32 =
            membarrier_cmd::MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED as u32;
        const PRIVATE_EXPEDITED: u32 = membarrier_cmd::MEMBARRIER_CMD_PRIVATE_EXPEDITED as u32;
        const REGISTER_PRIVATE_EXPEDITED: u32 =
            membarrier_cmd::MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED as u32;
        const PRIVATE_EXPEDITED_SYNC_CORE: u32 =
            membarrier_cmd::MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE as u32;
        const REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u32 =
            membarrier_cmd::MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE as u32;
        const PRIVATE_EXPEDITED_RSEQ: u32 =
            membarrier_cmd::MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ as u32;
        const REGISTER_PRIVATE_EXPEDITED_RSEQ: u32 =
            membarrier_cmd::MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ as u32;
        const GET_REGISTRATIONS: u32 = membarrier_cmd::MEMBARRIER_CMD_GET_REGISTRATIONS as u32;
        const FLAG_CPU: u32 = membarrier_cmd_flag::MEMBARRIER_CMD_FLAG_CPU as u32;
        let arguments = SyscallArgs::raw(registers);
        let command = GuestReg(arguments[0]).as_u32();
        let flags = GuestReg(arguments[1]).as_u32();
        let forward = || SyscallArgs::invoke(Sysno::membarrier, &arguments);
        let valid_flags = flags == 0 || (command == PRIVATE_EXPEDITED_RSEQ && flags == FLAG_CPU);
        // Each private execution command is paired with the registration
        // command one bit above it.
        let required = match command {
            PRIVATE_EXPEDITED | PRIVATE_EXPEDITED_SYNC_CORE | PRIVATE_EXPEDITED_RSEQ => {
                command << 1
            }
            _ => 0,
        };
        let registration = matches!(
            command,
            REGISTER_GLOBAL_EXPEDITED
                | REGISTER_PRIVATE_EXPEDITED
                | REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
                | REGISTER_PRIVATE_EXPEDITED_RSEQ
        );
        if !valid_flags || (required == 0 && !registration && command != GET_REGISTRATIONS) {
            return forward();
        }
        let query = [u64::from(QUERY), 0, 0, 0, 0, 0];
        let supported = SyscallArgs::invoke(Sysno::membarrier, &query);
        if GuestReg(supported).as_c_long() < 0 || supported & u64::from(command) == 0 {
            return forward();
        }
        let registered = self.membarrier.load(Ordering::Acquire);
        if command == GET_REGISTRATIONS {
            return u64::from(registered);
        }
        if registered & required != required {
            return Errno::EPERM.negated();
        }
        let result = forward();
        if registration && result == 0 {
            self.membarrier.fetch_or(command, Ordering::AcqRel);
        }
        result
    }

    fn ioctl_syscall(&self, registers: &Regs, memory: &GuestMemory) -> u64 {
        let cmd = GuestReg(registers.arguments()[1]).as_u32();
        if cmd == FICLONE || cmd == FICLONERANGE {
            return self.ficlone_ioctl(registers, memory, cmd);
        }
        SyscallArgs::ioctl(registers, memory)
    }

    fn ficlone_ioctl(&self, registers: &Regs, memory: &GuestMemory, cmd: u32) -> u64 {
        let args = SyscallArgs::raw(registers);
        let dest = GuestFd::from_reg(args[0]);
        let Some(dest_raw) = dest.valid().filter(|_| dest.is_open()) else {
            return Errno::EBADF.negated();
        };
        if cmd == FICLONE {
            let src = GuestFd::from_reg(args[2]);
            let Some(src_raw) = src.valid().filter(|_| src.is_open()) else {
                return Errno::EBADF.negated();
            };
            if let Some(errno) =
                self.denials
                    .refuse_target(&self.policy, registers, Request::write_descriptor(0))
            {
                return errno.negated();
            }
            return SyscallArgs::invoke(
                Sysno::ioctl,
                &[
                    u64::from(dest_raw.cast_unsigned()),
                    u64::from(cmd),
                    u64::from(src_raw.cast_unsigned()),
                    0,
                    0,
                    0,
                ],
            );
        }
        let Ok(mut range_buf) = memory.read(args[2], FILE_CLONE_RANGE_BYTES) else {
            return Errno::EFAULT.negated();
        };
        let src_fd = i64::from_le_bytes(range_buf[..8].try_into().unwrap_or([0; 8]));
        let Ok(src_raw) = RawFd::try_from(src_fd) else {
            return Errno::EBADF.negated();
        };
        if !GuestFd::from_raw(src_raw).is_open() {
            return Errno::EBADF.negated();
        }
        if let Some(errno) =
            self.denials
                .refuse_target(&self.policy, registers, Request::write_descriptor(0))
        {
            return errno.negated();
        }
        SyscallArgs::invoke(
            Sysno::ioctl,
            &[
                u64::from(dest_raw.cast_unsigned()),
                u64::from(cmd),
                range_buf.as_mut_ptr().expose_provenance() as u64,
                0,
                0,
                0,
            ],
        )
    }

    fn socket_syscall(
        &self,
        syscall: Sysno,
        registers: &Regs,
        memory: &GuestMemory,
    ) -> Option<u64> {
        let operation = match syscall {
            Sysno::bind => NetworkOperation::Bind,
            Sysno::connect => NetworkOperation::Connect,
            Sysno::sendto | Sysno::sendmsg | Sysno::sendmmsg => {
                return Some(self.datagram_syscall(registers, memory, syscall));
            }
            Sysno::socket => {
                let [domain, ty, proto, ..] =
                    SyscallArgs::raw(registers).map(|reg| GuestReg(reg).as_i32());
                return network::Info::new(domain, ty, proto)
                    .admit(&self.policy)
                    .err()
                    .map(|errno| Errno::new(errno).negated());
            }
            _ => return None,
        };
        let arguments = SyscallArgs::raw(registers);
        let Some(descriptor) = GuestFd::from_reg(arguments[0]).valid() else {
            return Some(Errno::EBADF.negated());
        };
        let Ok(length) = usize::try_from(GuestReg(arguments[2]).as_i32()) else {
            return Some(Errno::EINVAL.negated());
        };
        if length > std::mem::size_of::<libc::sockaddr_storage>() {
            return Some(Errno::EINVAL.negated());
        }
        let Ok(address) = memory.read(arguments[1], length as u64) else {
            return Some(Errno::EFAULT.negated());
        };
        match network::Verdict::mediate(&self.policy, descriptor, operation, &address) {
            network::Verdict::Allow => {}
            network::Verdict::SessionBus {
                upstream,
                target,
                allowed,
            } => {
                let eacces = Errno::EACCES.negated();
                if !self.dbus_proxies.is_available() {
                    return Some(eacces);
                }
                if !allowed {
                    if !self.denials.can_query() {
                        return Some(eacces);
                    }
                    match self.denials.query_network(
                        &self.policy,
                        NetworkOperation::Connect,
                        &target,
                    ) {
                        QueryOutcome::Allowed => {}
                        QueryOutcome::Cancelled => return Some(eacces),
                        QueryOutcome::Denied => {
                            self.denials.deny_network(
                                &self.policy,
                                NetworkOperation::Connect,
                                target,
                            );
                            return Some(eacces);
                        }
                    }
                }
                return Some(
                    match self
                        .dbus_proxies
                        .connect(descriptor, std::os::fd::AsFd::as_fd(&upstream))
                    {
                        Ok(()) => 0,
                        Err(errno) => Errno::new(errno).negated(),
                    },
                );
            }
            network::Verdict::Refuse { errno, denial } => {
                if let Some(status) = self.refuse_network(errno, denial) {
                    return Some(status);
                }
            }
        }
        Some(SyscallArgs::forward_translated(
            registers,
            memory,
            syscall,
            &[Arg::fd(0), Arg::copied_bytes(1, &address)],
        ))
    }

    fn datagram_syscall(&self, registers: &Regs, memory: &GuestMemory, syscall: Sysno) -> u64 {
        let arguments = SyscallArgs::raw(registers);
        let Some(descriptor) = GuestFd::from_reg(arguments[0]).valid() else {
            return Errno::EBADF.negated();
        };
        match syscall {
            Sysno::sendto => self.sendto_syscall(registers, memory, descriptor, &arguments),
            Sysno::sendmsg => {
                let mut decoded = match KernelMsghdr::decode(memory, arguments[1], true) {
                    Ok(msg) => msg,
                    Err(errno) => return errno.negated(),
                };
                if let Some(dest) = decoded.send_name().filter(|bytes| !bytes.is_empty())
                    && let Some(status) = self.mediate_datagram_bytes(descriptor, dest)
                {
                    return status;
                }
                decoded.send_single(descriptor, arguments[2])
            }
            Sysno::sendmmsg => {
                let decoded =
                    match KernelMsghdr::decode_batch(memory, arguments[1], arguments[2], true) {
                        Ok(batch) => batch,
                        Err(errno) => return errno.negated(),
                    };
                for msg in &decoded {
                    if let Some(dest) = msg.send_name().filter(|bytes| !bytes.is_empty())
                        && let Some(status) = self.mediate_datagram_bytes(descriptor, dest)
                    {
                        return status;
                    }
                }
                KernelMsghdr::send_multi(descriptor, arguments[1], arguments[3], memory, decoded)
            }
            _ => Errno::ENOSYS.negated(),
        }
    }

    fn sendto_syscall(
        &self,
        registers: &Regs,
        memory: &GuestMemory,
        descriptor: RawFd,
        arguments: &[u64; 6],
    ) -> u64 {
        if arguments[4] == 0 {
            return SyscallArgs::forward_translated(
                registers,
                memory,
                Sysno::sendto,
                &[Arg::fd(0), Arg::bytes(1, arguments[2])],
            );
        }
        let Ok(length) = usize::try_from(GuestReg(arguments[5]).as_i32()) else {
            return Errno::EINVAL.negated();
        };
        if length > std::mem::size_of::<libc::sockaddr_storage>() {
            return Errno::EINVAL.negated();
        }
        let Ok(dest) = memory.read(arguments[4], length as u64) else {
            return Errno::EFAULT.negated();
        };
        if let Some(status) = self.mediate_datagram_bytes(descriptor, &dest) {
            return status;
        }
        SyscallArgs::forward_translated(
            registers,
            memory,
            Sysno::sendto,
            &[
                Arg::fd(0),
                Arg::bytes(1, arguments[2]),
                Arg::copied_bytes(4, &dest),
            ],
        )
    }

    fn mediate_datagram_bytes(&self, descriptor: RawFd, bytes: &[u8]) -> Option<u64> {
        match network::Verdict::mediate_datagram(&self.policy, descriptor, bytes) {
            network::Verdict::Allow => None,
            network::Verdict::SessionBus { .. } => Some(Errno::EACCES.negated()),
            network::Verdict::Refuse { errno, denial } => self.refuse_network(errno, denial),
        }
    }

    fn refuse_network(&self, errno: i32, denial: Option<network::NetworkDenial>) -> Option<u64> {
        if let Some(denial) = denial {
            if denial.queryable {
                match self
                    .denials
                    .query_network(&self.policy, denial.operation, &denial.target)
                {
                    QueryOutcome::Allowed => return None,
                    QueryOutcome::Cancelled => return Some(Errno::new(errno).negated()),
                    QueryOutcome::Denied => {}
                }
            }
            self.denials
                .deny_network(&self.policy, denial.operation, denial.target);
        }
        Some(Errno::new(errno).negated())
    }

    fn path_syscall(&self, syscall: Sysno, registers: &Regs, memory: &GuestMemory) -> Option<u64> {
        let call = Call {
            process: self,
            sink: &self.denials,
            policy: &self.policy,
            syscall,
            registers,
            memory,
        };
        call.open_syscall().or_else(|| call.mutation_syscall())
    }

    fn state_syscall(
        &self,
        thread: &mut ThreadState,
        memory: &GuestMemory,
        syscall: Sysno,
        registers: &Regs,
    ) -> Option<u64> {
        let status = match syscall {
            Sysno::mmap => self.mmap(registers, memory),
            Sysno::mremap => self.mremap(registers, memory),
            Sysno::msync => self.msync(registers, memory),
            Sysno::mincore => self.mincore(registers, memory),
            Sysno::shmat => self.shmat(registers, memory),
            Sysno::shmdt => self.shmdt(registers, memory),
            Sysno::mlock | Sysno::mlock2 | Sysno::munlock => {
                self.mlock_range(registers, memory, syscall)
            }
            Sysno::mlockall => self.mlockall(registers),
            Sysno::munlockall => SyscallArgs::invoke(syscall, &SyscallArgs::raw(registers)),
            Sysno::mbind => self.mbind(registers, memory),
            Sysno::set_mempolicy_home_node => self.set_mempolicy_home_node(registers, memory),
            Sysno::mseal => Self::mseal(registers),
            Sysno::remap_file_pages => Self::remap_file_pages(registers),
            Sysno::map_shadow_stack => Self::map_shadow_stack(registers),
            Sysno::pkey_alloc => Self::pkey_alloc(registers),
            Sysno::pkey_free => Self::pkey_free(),
            Sysno::pkey_mprotect => self.pkey_mprotect(registers, memory),
            Sysno::ptrace => {
                let args = registers.arguments();
                self.ptrace
                    .syscall(args[0], GuestReg(args[1]).as_i32(), args[3])
            }
            Sysno::restart_syscall => Errno::EINTR.negated(),
            Sysno::personality => Self::personality(registers),
            #[cfg(target_arch = "x86_64")]
            Sysno::modify_ldt => Self::modify_ldt(registers, memory),
            Sysno::brk => self.brk(registers.arguments()[0], memory),
            Sysno::prctl => SyscallArgs::prctl(registers, memory),
            Sysno::rt_sigaction => self.signals.rt_sigaction(registers, memory),
            Sysno::rt_sigprocmask => GuestSignals::rt_sigprocmask(registers, memory),
            Sysno::rt_sigsuspend => GuestSignals::rt_sigsuspend(thread, registers, memory),
            Sysno::rt_sigpending => GuestSignals::rt_sigpending(registers, memory),
            Sysno::rt_sigtimedwait => GuestSignals::rt_sigtimedwait(registers, memory),
            Sysno::rt_sigqueueinfo | Sysno::rt_tgsigqueueinfo => {
                SyscallArgs::sigqueue_syscall(registers, memory, syscall)
            }
            Sysno::close => GuestFd::from_reg(registers.arguments()[0]).close(),
            Sysno::close_range => SyscallArgs::close_range(registers),
            Sysno::dup => GuestFd::guard_created(SyscallArgs::forward_translated(
                registers,
                memory,
                Sysno::dup,
                &[Arg::fd(0)],
            )),
            Sysno::fcntl => SyscallArgs::fcntl(registers, memory),
            Sysno::flock
            | Sysno::fadvise64
            | Sysno::fsync
            | Sysno::fdatasync
            | Sysno::syncfs
            | Sysno::sync_file_range
            | Sysno::readahead => {
                SyscallArgs::forward_translated(registers, memory, syscall, &[Arg::fd(0)])
            }
            #[cfg(target_arch = "x86_64")]
            Sysno::dup2 => SyscallArgs::duplicate(registers, memory, syscall),
            Sysno::dup3 => SyscallArgs::duplicate(registers, memory, syscall),
            Sysno::munmap => self.munmap(registers, memory),
            Sysno::mprotect => self.mprotect(registers, memory),
            Sysno::sigaltstack => Self::sigaltstack(thread, registers, memory),
            Sysno::madvise => self.madvise(registers, memory),
            Sysno::set_robust_list => self.set_robust_list(thread, registers, memory),
            Sysno::get_robust_list => Self::get_robust_list(thread, registers, memory),
            Sysno::membarrier => self.membarrier(registers),
            Sysno::set_tid_address => {
                thread.clear_child_tid = registers.arguments()[0];
                ThreadState::current_tid()
            }
            Sysno::getpid => u64::from(std::process::id()),
            Sysno::gettid => ThreadState::current_tid(),
            Sysno::getuid
            | Sysno::geteuid
            | Sysno::getgid
            | Sysno::getegid
            | Sysno::setuid
            | Sysno::setgid
            | Sysno::setreuid
            | Sysno::setregid
            | Sysno::setresuid
            | Sysno::setresgid
            | Sysno::setfsuid
            | Sysno::setfsgid
            | Sysno::umask => SyscallArgs::invoke(syscall, &SyscallArgs::raw(registers)),
            Sysno::getresuid | Sysno::getresgid => {
                let mut arguments = SyscallArgs::raw(registers);
                for slot in &mut arguments[..3] {
                    *slot = memory.translated_address(*slot, 4);
                }
                SyscallArgs::invoke(syscall, &arguments)
            }
            Sysno::ioctl => self.ioctl_syscall(registers, memory),
            Sysno::rseq | Sysno::clone3 => Errno::ENOSYS.negated(),
            _ => return None,
        };
        Some(status)
    }

    fn personality(registers: &Regs) -> u64 {
        let persona = GuestReg(registers.arguments()[0]).as_u32();
        if persona == u32::MAX || persona == 0 {
            SyscallArgs::invoke(Sysno::personality, &[u64::from(u32::MAX), 0, 0, 0, 0, 0])
        } else {
            Errno::EINVAL.negated()
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn modify_ldt(registers: &Regs, memory: &GuestMemory) -> u64 {
        let args = registers.arguments();
        match GuestReg(args[0]).as_i32() {
            0 | 2 => SyscallArgs::forward_translated(
                registers,
                memory,
                Sysno::modify_ldt,
                &[Arg::bytes(1, args[2])],
            ),
            1 | 0x11 => Errno::EPERM.negated(),
            _ => SyscallArgs::invoke(Sysno::modify_ldt, &[args[0], 0, 0, 0, 0, 0]),
        }
    }

    /// The supervisor watches the exit of a thread with a list, so that a
    /// fatal signal also releases the guest locks.
    fn set_robust_list(
        &self,
        thread: &mut ThreadState,
        registers: &Regs,
        memory: &GuestMemory,
    ) -> u64 {
        let [head, length, ..] = registers.arguments();
        if length != ROBUST_HEAD_BYTES {
            return Errno::EINVAL.negated();
        }
        if head != 0 && !thread.robust_watched {
            if let Err(error) = self
                .cancellation
                .request(CancelRequest::WatchRobust(ThreadState::current_tid()))
            {
                self.terminate_with_error(&error.context("watch robust list owner"));
            }
            thread.robust_watched = true;
        }
        thread.robust_list = head;
        self.robust.register(memory, head);
        0
    }

    /// The kernel checks the target before storing the length, then the head.
    fn get_robust_list(thread: &ThreadState, registers: &Regs, memory: &GuestMemory) -> u64 {
        let [pid, head_pointer, length_pointer, ..] = registers.arguments();
        let pid = GuestReg(pid).as_i32();
        let head = if pid == 0 {
            thread.robust_list
        } else {
            match RobustMirror::query(pid) {
                Ok(head) => head,
                Err(errno) => return errno.negated(),
            }
        };
        // The host kernel passes the head through `IS_ERR`, so a head that
        // looks like a negated errno is returned as that error.
        if head > u64::MAX - 4095 {
            return head;
        }
        if memory.write_u64(length_pointer, ROBUST_HEAD_BYTES).is_err()
            || memory.write_u64(head_pointer, head).is_err()
        {
            return Errno::EFAULT.negated();
        }
        0
    }

    #[cfg(target_arch = "x86_64")]
    fn arch_prctl(vcpu: &VcpuFd, registers: &Regs, memory: &GuestMemory) -> Result<u64> {
        const ARCH_SET_GS: u32 = 0x1001;
        const ARCH_SET_FS: u32 = 0x1002;
        const ARCH_GET_FS: u32 = 0x1003;
        const ARCH_GET_GS: u32 = 0x1004;
        // The guest always uses four-level paging. Linux excludes the top user page.
        const TASK_SIZE_MAX: u64 = (1 << 47) - PAGE_BYTES;
        let [code, address, ..] = registers.arguments();
        let code = GuestReg(code).as_u32();
        match code {
            ARCH_SET_FS | ARCH_SET_GS => {
                if address >= TASK_SIZE_MAX {
                    return Ok(Errno::EPERM.negated());
                }
                Machine::set_segment_base(vcpu, code == ARCH_SET_GS, address)?;
                Ok(0)
            }
            ARCH_GET_FS | ARCH_GET_GS => {
                let base = Machine::segment_base(vcpu, code == ARCH_GET_GS)?;
                Ok(if memory.write_u64(address, base).is_ok() {
                    0
                } else {
                    Errno::EFAULT.negated()
                })
            }
            _ => Ok(Errno::EINVAL.negated()),
        }
    }
}

struct ForkSnapshot {
    state: VcpuState,
    space: AddressSpace,
    signals: GuestSignals,
    policy: Policy,
    dbus_proxies: DbusProxies,
    query_state: QueryState,
    error_pipe: Option<BrokerHandle<UnixStream>>,
}

impl ForkSnapshot {
    fn into_child(
        mut self,
        process: &mut Arc<Process>,
        vcpu: &mut BrokerHandle<VcpuFd>,
        thread: &mut ThreadState,
        registers: &mut Regs,
        syscall: Sysno,
        vfork_sync: Option<VforkSync>,
    ) -> Result<()> {
        let flags = registers.arguments()[0];
        SIGNAL_QUEUE.clear_all();
        RobustMirror::clear_thread_local();
        let shared_memory = process.machine.memory.shared();
        let omitted = self.space.dont_fork_ranges();
        for &(start, end) in &omitted {
            // DONTFORK removed these host VMAs. Restore inaccessible backing
            // reservations before attaching KVM; do not inherit guest mappings.
            shared_memory.restore_anonymous(start, end - start)?;
            self.space.remove_range(start, end);
        }
        let denials = process.denials.child_clone(self.query_state)?;
        process.machine.memory.disown();

        let tls = if syscall == Sysno::clone {
            Broker::clone_tls(registers).ok().flatten()
        } else {
            None
        };
        let (machine, child_vcpu) = Machine::inherit(&self.state, shared_memory, tls)?;
        for (start, end) in omitted {
            machine.protect_pages(start, end - start, 0)?;
        }

        let child_process = Arc::new(Process {
            machine,
            denials,
            policy: self.policy,
            dbus_proxies: self.dbus_proxies,
            signals: self.signals,
            timers: Mutex::new(HashSet::new()),
            space: Mutex::new(self.space),
            threads: (Mutex::new(Threads::new()), Condvar::new()),
            cancellation: Arc::new(process.cancellation.child_clone()?),
            lifecycle: Arc::new(Mutex::new(())),
            error_pipe: self.error_pipe.map(Mutex::new),
            mqueue: process.mqueue,
            ptrace: Arc::clone(&process.ptrace),
            robust: process.robust,
            restart_image: process.restart_image.clone(),
            vfork_sync: Mutex::new(vfork_sync),
            membarrier: AtomicU32::new(process.membarrier.load(Ordering::Acquire)),
        });

        let old_process = std::mem::replace(process, child_process);
        if Arc::strong_count(&old_process) == 1 {
            drop(old_process);
        } else {
            old_process.release_forked_fds();
            std::mem::forget(old_process);
        }
        *vcpu = child_vcpu;

        let mut stack = 0;
        thread.clear_child_tid = 0;
        // Like the kernel, a fork child starts without a robust list, and
        // its new native thread is not watched.
        thread.robust_list = 0;
        thread.robust_watched = false;
        thread.tlb_epoch = process.machine.tlb_epoch();
        thread.temp_signal_mask = None;
        if syscall == Sysno::clone {
            let arguments = registers.arguments();
            let child_tidptr = arguments[CLONE_CHILD_TID_ARGUMENT];
            stack = arguments[1];
            if flags & u64::from(CLONE_CHILD_SETTID) != 0 {
                let tid = unsafe { libc::gettid() }.cast_unsigned();
                let _ = process.machine.memory.write_u32_atomic(child_tidptr, tid);
            }
            if flags & u64::from(CLONE_CHILD_CLEARTID) != 0 {
                thread.clear_child_tid = child_tidptr;
            }
        }
        *registers = registers.child(stack);
        Ok(())
    }
}

enum Replacement {
    Done,
    Failed(Errno),
}
