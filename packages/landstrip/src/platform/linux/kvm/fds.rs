// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Guest `RLIMIT_NOFILE` accounting and broker descriptor isolation.

use super::ErrnoExt;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use syscalls::Errno;

const DEFAULT_RESERVE_FLOOR: RawFd = 4096;
const HOST_NOFILE_CAP: u64 = 524_288;
const BROKER_HEADROOM: RawFd = 512;
const MARGIN: RawFd = 64;
const LOW_WORDS: usize = 128;
const LOW_LIMIT: RawFd = 8192;
const HIGH_WORDS: usize = 16;
const HIGH_SPAN: RawFd = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(crate) struct SavedFdLimits {
    pub(crate) cur: u64,
    pub(crate) max: u64,
    pub(crate) reserve_floor: RawFd,
    pub(crate) broker_base: RawFd,
    pub(crate) select_cap: RawFd,
}

#[derive(Clone, Copy)]
struct FdConfig {
    reserve_floor: RawFd,
    broker_base: RawFd,
}

static CONFIG: OnceLock<FdConfig> = OnceLock::new();
static GUEST_NOFILE_CUR: AtomicU64 = AtomicU64::new(1024);
static GUEST_NOFILE_MAX: AtomicU64 = AtomicU64::new(1024);
static GUEST_NOFILE_LOCK: Mutex<()> = Mutex::new(());
static SELECT_CAP: AtomicI32 = AtomicI32::new(1024);
static OCCUPY_ACTIVE: AtomicUsize = AtomicUsize::new(0);

struct BrokerBitmap {
    low: [AtomicU64; LOW_WORDS],
    high_base: AtomicI32,
    high: [AtomicU64; HIGH_WORDS],
    overflow_len: AtomicUsize,
    overflow: Mutex<BTreeSet<RawFd>>,
}

impl BrokerBitmap {
    const fn new() -> Self {
        Self {
            low: [const { AtomicU64::new(0) }; LOW_WORDS],
            high_base: AtomicI32::new(DEFAULT_RESERVE_FLOOR),
            high: [const { AtomicU64::new(0) }; HIGH_WORDS],
            overflow_len: AtomicUsize::new(0),
            overflow: Mutex::new(BTreeSet::new()),
        }
    }

    fn set_high_base(&self, base: RawFd) {
        self.high_base.store(base, Ordering::Release);
    }

    fn insert(&self, fd: RawFd) {
        let Ok(fd_usize) = usize::try_from(fd) else {
            return;
        };
        if fd < LOW_LIMIT {
            let word = fd_usize / 64;
            let bit = 1_u64 << (fd_usize % 64);
            self.low[word].fetch_or(bit, Ordering::AcqRel);
            return;
        }
        let high_base = self.high_base.load(Ordering::Acquire);
        if fd >= high_base
            && fd < high_base.saturating_add(HIGH_SPAN)
            && let Ok(offset) = usize::try_from(fd - high_base)
        {
            self.high[offset / 64].fetch_or(1_u64 << (offset % 64), Ordering::AcqRel);
            return;
        }
        let mut guard = self
            .overflow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.insert(fd) {
            self.overflow_len.fetch_add(1, Ordering::Release);
        }
    }

    fn remove(&self, fd: RawFd) {
        let Ok(fd_usize) = usize::try_from(fd) else {
            return;
        };
        if fd < LOW_LIMIT {
            let word = fd_usize / 64;
            let bit = 1_u64 << (fd_usize % 64);
            self.low[word].fetch_and(!bit, Ordering::AcqRel);
            return;
        }
        let high_base = self.high_base.load(Ordering::Acquire);
        if fd >= high_base
            && fd < high_base.saturating_add(HIGH_SPAN)
            && let Ok(offset) = usize::try_from(fd - high_base)
        {
            self.high[offset / 64].fetch_and(!(1_u64 << (offset % 64)), Ordering::AcqRel);
            return;
        }
        let mut guard = self
            .overflow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.remove(&fd) {
            self.overflow_len.fetch_sub(1, Ordering::Release);
        }
    }

    fn contains(&self, fd: RawFd) -> bool {
        let Ok(fd_usize) = usize::try_from(fd) else {
            return false;
        };
        if fd < LOW_LIMIT {
            let word = fd_usize / 64;
            let bit = 1_u64 << (fd_usize % 64);
            return self.low[word].load(Ordering::Acquire) & bit != 0;
        }
        let high_base = self.high_base.load(Ordering::Acquire);
        if fd >= high_base
            && fd < high_base.saturating_add(HIGH_SPAN)
            && let Ok(offset) = usize::try_from(fd - high_base)
        {
            return self.high[offset / 64].load(Ordering::Acquire) & (1_u64 << (offset % 64)) != 0;
        }
        if self.overflow_len.load(Ordering::Acquire) == 0 {
            return false;
        }
        self.overflow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&fd)
    }

    fn in_range(&self, first: u32, last: u32) -> Vec<u32> {
        let mut out = Vec::new();
        for (idx, slot) in self.low.iter().enumerate() {
            let mut bits = slot.load(Ordering::Acquire);
            while bits != 0 {
                let tz = bits.trailing_zeros();
                let fd = u32::try_from(idx * 64).unwrap_or(0) + tz;
                if (first..=last).contains(&fd) {
                    out.push(fd);
                }
                bits &= bits - 1;
            }
        }
        let high_base = u32::try_from(self.high_base.load(Ordering::Acquire).max(0)).unwrap_or(0);
        for (idx, slot) in self.high.iter().enumerate() {
            let mut bits = slot.load(Ordering::Acquire);
            while bits != 0 {
                let tz = bits.trailing_zeros();
                let fd = high_base
                    .saturating_add(u32::try_from(idx * 64).unwrap_or(0))
                    .saturating_add(tz);
                if (first..=last).contains(&fd) {
                    out.push(fd);
                }
                bits &= bits - 1;
            }
        }
        if self.overflow_len.load(Ordering::Acquire) != 0 {
            let guard = self
                .overflow
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for &fd in guard.iter() {
                if let Ok(fd_u32) = u32::try_from(fd)
                    && (first..=last).contains(&fd_u32)
                {
                    out.push(fd_u32);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

static BROKER_FDS: BrokerBitmap = BrokerBitmap::new();

/// RAII wrapper keeping a broker-owned handle registered in `BROKER_FDS`
/// until after its underlying descriptor has been closed.
#[derive(Debug)]
pub(crate) struct BrokerHandle<T: AsRawFd>(ManuallyDrop<T>);

pub(crate) type BrokerFd = BrokerHandle<OwnedFd>;

impl<T: AsRawFd> BrokerHandle<T> {
    pub(crate) fn register(inner: T) -> Self {
        GuestFd::register_broker(inner.as_raw_fd());
        Self(ManuallyDrop::new(inner))
    }

    pub(crate) fn get(&self) -> &T {
        &self.0
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }

    pub(crate) fn map_same_fd<U: AsRawFd>(mut self, map: impl FnOnce(T) -> U) -> BrokerHandle<U> {
        let raw = self.0.as_raw_fd();
        // SAFETY: `self` is forgotten below so `inner` is moved once without
        // clearing `raw` in `BROKER_FDS`.
        let inner = unsafe { ManuallyDrop::take(&mut self.0) };
        std::mem::forget(self);
        let mapped = map(inner);
        debug_assert_eq!(mapped.as_raw_fd(), raw);
        BrokerHandle(ManuallyDrop::new(mapped))
    }
}

impl BrokerFd {
    /// Transfers descriptor ownership to another RAII type (`TrapFd`) that
    /// takes responsibility for unregistering the descriptor after close.
    pub(crate) fn into_unregistered_owned(mut self) -> OwnedFd {
        // SAFETY: `self` is forgotten so `Drop` does not run; the caller keeps
        // the broker registration until closing the returned `OwnedFd`.
        let inner = unsafe { ManuallyDrop::take(&mut self.0) };
        std::mem::forget(self);
        inner
    }
}

impl<T: AsRawFd> Drop for BrokerHandle<T> {
    fn drop(&mut self) {
        let raw = self.0.as_raw_fd();
        // SAFETY: `self.0` is dropped once here so the kernel closes `raw`
        // before `BROKER_FDS` exposes the number to the guest again.
        unsafe { ManuallyDrop::drop(&mut self.0) };
        GuestFd::unregister_broker(raw);
    }
}

impl<T: AsRawFd + AsFd> AsFd for BrokerHandle<T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl<T: AsRawFd> AsRawFd for BrokerHandle<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestFd(RawFd);

impl GuestFd {
    pub(crate) const fn from_raw(raw: RawFd) -> Self {
        Self(raw)
    }

    pub(crate) fn from_reg(raw: u64) -> Self {
        let low = u32::try_from(raw & 0xffff_ffff).unwrap_or_default();
        Self(i32::from_ne_bytes(low.to_ne_bytes()))
    }

    pub(crate) fn at_fdcwd() -> i64 {
        i64::from(libc::AT_FDCWD)
    }

    /// Captures the caller's native `RLIMIT_NOFILE` for the guest and raises
    /// the host soft limit so broker descriptors can sit near the hard limit.
    pub(crate) fn init_limits(inherited: &[RawFd]) -> Result<()> {
        let mut native = libc::rlimit64 {
            rlim_cur: 1024,
            rlim_max: 1024,
        };
        if unsafe { libc::getrlimit64(libc::RLIMIT_NOFILE, &raw mut native) } < 0 {
            return Err(io::Error::last_os_error()).context("read native RLIMIT_NOFILE");
        }
        let host_target = Self::raise_host_soft_limit(native.rlim_cur, native.rlim_max);
        let host_cap = RawFd::try_from(host_target.min(HOST_NOFILE_CAP)).unwrap_or(i32::MAX);
        let reserve_floor = DEFAULT_RESERVE_FLOOR
            .min(host_cap.saturating_sub(MARGIN))
            .max(2 * MARGIN);
        let broker_base = host_cap.saturating_sub(BROKER_HEADROOM).max(reserve_floor);
        BROKER_FDS.set_high_base(broker_base);
        let _ = CONFIG.set(FdConfig {
            reserve_floor,
            broker_base,
        });
        GUEST_NOFILE_CUR.store(native.rlim_cur, Ordering::Release);
        GUEST_NOFILE_MAX.store(native.rlim_max, Ordering::Release);
        let max_inherited = inherited.iter().copied().max().unwrap_or(2);
        let initial_cap = max_inherited
            .saturating_add(1)
            .max(1024)
            .min(RawFd::try_from(HOST_NOFILE_CAP).unwrap_or(i32::MAX));
        SELECT_CAP.store(initial_cap, Ordering::Release);
        Ok(())
    }

    fn raise_host_soft_limit(cur: u64, max: u64) -> u64 {
        let nr_open = fs::read_to_string("/proc/sys/fs/nr_open")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(1_048_576);
        let target = if max == libc::RLIM64_INFINITY {
            nr_open.min(HOST_NOFILE_CAP).max(cur)
        } else {
            max
        };
        if target > cur {
            let raised = libc::rlimit64 {
                rlim_cur: target,
                rlim_max: max,
            };
            if unsafe { libc::setrlimit64(libc::RLIMIT_NOFILE, &raw const raised) } == 0 {
                return target;
            }
        }
        cur
    }

    pub(crate) fn save_limits() -> SavedFdLimits {
        let (cur, max) = Self::limits();
        let cfg = Self::config();
        SavedFdLimits {
            cur,
            max,
            reserve_floor: cfg.reserve_floor,
            broker_base: cfg.broker_base,
            select_cap: SELECT_CAP.load(Ordering::Acquire),
        }
    }

    pub(super) fn restore_limits(saved: SavedFdLimits) -> Result<()> {
        ensure!(
            saved.reserve_floor >= 2 * MARGIN && saved.broker_base >= saved.reserve_floor,
            "invalid saved descriptor limits"
        );
        BROKER_FDS.set_high_base(saved.broker_base);
        CONFIG
            .set(FdConfig {
                reserve_floor: saved.reserve_floor,
                broker_base: saved.broker_base,
            })
            .map_err(|_| anyhow::anyhow!("descriptor configuration already set"))?;
        GUEST_NOFILE_CUR.store(saved.cur, Ordering::Release);
        GUEST_NOFILE_MAX.store(saved.max, Ordering::Release);
        SELECT_CAP.store(saved.select_cap.max(1024), Ordering::Release);
        Ok(())
    }

    fn config() -> FdConfig {
        *CONFIG.get_or_init(|| {
            BROKER_FDS.set_high_base(DEFAULT_RESERVE_FLOOR);
            FdConfig {
                reserve_floor: DEFAULT_RESERVE_FLOOR,
                broker_base: DEFAULT_RESERVE_FLOOR,
            }
        })
    }

    pub(crate) fn reserve_floor() -> RawFd {
        Self::config().reserve_floor
    }

    pub(crate) fn broker_base() -> RawFd {
        Self::config().broker_base
    }

    pub(crate) fn limits() -> (u64, u64) {
        let _guard = GUEST_NOFILE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            GUEST_NOFILE_CUR.load(Ordering::Acquire),
            GUEST_NOFILE_MAX.load(Ordering::Acquire),
        )
    }

    pub(crate) fn soft_limit() -> u64 {
        GUEST_NOFILE_CUR.load(Ordering::Acquire)
    }

    pub(crate) fn set_limits(cur: u64, max: u64) -> std::result::Result<(), Errno> {
        if cur > max {
            return Err(Errno::EINVAL);
        }
        let nr_open = fs::read_to_string("/proc/sys/fs/nr_open")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(1_048_576);
        if cur > nr_open || max > nr_open {
            return Err(Errno::EPERM);
        }
        let _guard = GUEST_NOFILE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current_max = GUEST_NOFILE_MAX.load(Ordering::Acquire);
        if max > current_max {
            return Err(Errno::EPERM);
        }
        GUEST_NOFILE_CUR.store(cur, Ordering::Release);
        GUEST_NOFILE_MAX.store(max, Ordering::Release);
        Ok(())
    }

    pub(crate) fn select_cap() -> RawFd {
        SELECT_CAP.load(Ordering::Acquire)
    }

    pub(crate) fn note_guest_fd(fd: RawFd) {
        if fd < 0 {
            return;
        }
        let needed = fd
            .saturating_add(1)
            .min(RawFd::try_from(HOST_NOFILE_CAP).unwrap_or(i32::MAX));
        let mut current = SELECT_CAP.load(Ordering::Relaxed);
        while needed > current {
            match SELECT_CAP.compare_exchange_weak(
                current,
                needed,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    pub(crate) fn register_broker(fd: RawFd) {
        BROKER_FDS.insert(fd);
    }

    pub(crate) fn unregister_broker(fd: RawFd) {
        BROKER_FDS.remove(fd);
    }

    pub(crate) fn broker_fds_in(first: u32, last: u32) -> Vec<u32> {
        BROKER_FDS.in_range(first, last)
    }

    pub(crate) fn is_broker(self) -> bool {
        self.0 >= 0 && BROKER_FDS.contains(self.0)
    }

    pub(crate) fn valid(self) -> Option<RawFd> {
        (self.0 >= 0 && !self.is_broker()).then_some(self.0)
    }

    pub(crate) fn is_open(self) -> bool {
        self.valid()
            .is_some_and(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0)
    }

    pub(crate) fn has_cloexec(self) -> bool {
        self.valid().is_some_and(|fd| {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            flags >= 0 && flags & libc::FD_CLOEXEC != 0
        })
    }

    pub(crate) fn close_cloexec() {
        let mut candidates = Vec::new();
        if let Ok(entries) = fs::read_dir("/proc/self/fd") {
            for entry in entries.flatten() {
                if let Some(fd) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<RawFd>().ok())
                    && !Self(fd).is_broker()
                {
                    candidates.push(fd);
                }
            }
        }
        for fd in candidates {
            if Self(fd).is_broker() {
                continue;
            }
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags >= 0 && flags & libc::FD_CLOEXEC != 0 {
                unsafe { libc::close(fd) };
            }
        }
    }

    pub(crate) fn syscall_fd(self) -> u64 {
        self.valid()
            .and_then(|fd| u64::try_from(fd).ok())
            .unwrap_or(u64::MAX)
    }

    pub(crate) fn syscall_dirfd(self) -> u64 {
        if self.is_broker() {
            u64::MAX
        } else {
            i64::from(self.0).cast_unsigned()
        }
    }

    pub(crate) fn policy_dirfd(self) -> i64 {
        if self.is_broker() {
            -1
        } else {
            i64::from(self.0)
        }
    }

    pub(crate) fn within_soft_limit(fd: RawFd) -> bool {
        u64::try_from(fd).is_ok_and(|val| val < Self::soft_limit()) && !Self(fd).is_broker()
    }

    pub(crate) fn wait_occupy_idle() {
        let mut spins = 0u32;
        while OCCUPY_ACTIVE.load(Ordering::Acquire) != 0 {
            if spins < 64 {
                std::hint::spin_loop();
                spins += 1;
            } else {
                unsafe { libc::sched_yield() };
            }
        }
    }

    fn relocate_displaced(fd: RawFd, min_fd: RawFd) -> RawFd {
        let floor = Self::reserve_floor();
        let displaced = !Self::within_soft_limit(fd)
            || (fd >= floor && min_fd < floor && Self::select_cap() < floor);
        if !displaced {
            return fd;
        }
        Self::wait_occupy_idle();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return fd;
        }
        let cmd = if flags & libc::FD_CLOEXEC != 0 {
            libc::F_DUPFD_CLOEXEC
        } else {
            libc::F_DUPFD
        };
        let moved = unsafe { libc::fcntl(fd, cmd, min_fd) };
        if moved >= 0 && moved < fd {
            unsafe { libc::close(fd) };
            moved
        } else {
            if moved >= 0 {
                unsafe { libc::close(moved) };
            }
            fd
        }
    }

    pub(crate) fn guard_created(result: u64) -> u64 {
        Self::guard_created_from(result, 0)
    }

    pub(crate) fn guard_created_from(result: u64, min_fd: RawFd) -> u64 {
        let signed = i64::from_ne_bytes(result.to_ne_bytes());
        if signed < 0 {
            return result;
        }
        let Ok(fd) = RawFd::try_from(signed) else {
            return Errno::EMFILE.negated();
        };
        let fd = Self::relocate_displaced(fd, min_fd);
        if !Self::within_soft_limit(fd) {
            if !Self(fd).is_broker() {
                unsafe { libc::close(fd) };
            }
            return Errno::EMFILE.negated();
        }
        Self::note_guest_fd(fd);
        u64::from(fd.cast_unsigned())
    }

    pub(crate) fn guard_pair(fds: [RawFd; 2]) -> std::result::Result<[u8; 8], Errno> {
        let fds = [
            Self::relocate_displaced(fds[0], 0),
            Self::relocate_displaced(fds[1], 0),
        ];
        if !Self::within_soft_limit(fds[0]) || !Self::within_soft_limit(fds[1]) {
            for fd in fds {
                if !Self(fd).is_broker() {
                    unsafe { libc::close(fd) };
                }
            }
            return Err(Errno::EMFILE);
        }
        Self::note_guest_fd(fds[0]);
        Self::note_guest_fd(fds[1]);
        let mut raw = [0u8; 8];
        raw[..4].copy_from_slice(&fds[0].to_ne_bytes());
        raw[4..].copy_from_slice(&fds[1].to_ne_bytes());
        Ok(raw)
    }

    pub(crate) fn close(self) -> u64 {
        let Some(descriptor) = self.valid() else {
            return Errno::EBADF.negated();
        };
        if unsafe { libc::close(descriptor) } < 0 {
            return Errno::last_os(Errno::EIO).negated();
        }
        0
    }

    pub(crate) fn duplicate_above(fd: RawFd) -> io::Result<BrokerFd> {
        let base = Self::broker_base();
        let moved = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, base) };
        if moved < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(BrokerFd::register(unsafe { OwnedFd::from_raw_fd(moved) }))
    }

    pub(crate) fn relocate_above(fd: OwnedFd) -> io::Result<BrokerFd> {
        let base = Self::broker_base();
        if fd.as_raw_fd() >= base {
            return Ok(BrokerFd::register(fd));
        }
        Self::duplicate_above(fd.as_raw_fd())
    }
}

/// Descriptors that fill the low range while KVM creates its VM and vCPU
/// handles, so those land above normal guest allocations.
pub(crate) struct Range {
    held: Vec<RawFd>,
    fill: ManuallyDrop<OwnedFd>,
    occupying: bool,
}

impl Range {
    /// Closes uninherited caller descriptors and fills `3..reserve_floor` so
    /// KVM handles opened in this scope land at or above `reserve_floor`.
    pub(crate) fn reserve(inherited: &[RawFd]) -> Result<Self> {
        let floor = GuestFd::reserve_floor();
        let mut open_inherited = BTreeSet::new();
        for &fd in inherited {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags >= 0 {
                open_inherited.insert(fd);
                GuestFd::note_guest_fd(fd);
                if flags & libc::FD_CLOEXEC != 0
                    && unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
                {
                    bail!(
                        "clear close-on-exec on descriptor {fd}: {}",
                        io::Error::last_os_error()
                    );
                }
            }
        }
        Self::close_uninherited(&open_inherited)?;
        let fill = Self::fill(GuestFd::broker_base())?;
        GuestFd::register_broker(fill.as_raw_fd());
        let mut held = Vec::with_capacity(usize::try_from(floor).unwrap_or(0));
        for fd in 3..floor {
            if open_inherited.contains(&fd) || GuestFd(fd).is_broker() {
                continue;
            }
            if unsafe { libc::dup3(fill.as_raw_fd(), fd, libc::O_CLOEXEC) } < 0 {
                let err = io::Error::last_os_error();
                Self::release_held(&held, fill);
                bail!("reserve descriptor {fd}: {err}");
            }
            GuestFd::register_broker(fd);
            held.push(fd);
        }
        Ok(Self {
            held,
            fill: ManuallyDrop::new(fill),
            occupying: false,
        })
    }

    fn close_uninherited(inherited: &BTreeSet<RawFd>) -> Result<()> {
        let proc_fd = File::open("/proc/self/fd").context("open /proc/self/fd")?;
        let dir_raw = proc_fd.as_raw_fd();
        let mut to_close = Vec::new();
        for entry in fs::read_dir("/proc/self/fd").context("scan /proc/self/fd")? {
            let Ok(entry) = entry else {
                continue;
            };
            if let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<RawFd>().ok())
                && fd >= 3
                && fd != dir_raw
                && !inherited.contains(&fd)
                && !GuestFd(fd).is_broker()
            {
                to_close.push(fd);
            }
        }
        drop(proc_fd);
        for fd in to_close {
            if fd != dir_raw && !inherited.contains(&fd) && !GuestFd(fd).is_broker() {
                unsafe { libc::close(fd) };
            }
        }
        Ok(())
    }

    pub(crate) fn occupy_unused() -> Result<Self> {
        let floor = GuestFd::reserve_floor();
        let fill = Self::fill(GuestFd::broker_base())?;
        GuestFd::register_broker(fill.as_raw_fd());
        OCCUPY_ACTIVE.fetch_add(1, Ordering::AcqRel);
        let mut held = Vec::new();
        loop {
            let fd = unsafe { libc::fcntl(fill.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                Self::release_held(&held, fill);
                OCCUPY_ACTIVE.fetch_sub(1, Ordering::Release);
                bail!("occupy unused descriptor: {err}");
            }
            if fd >= floor {
                unsafe { libc::close(fd) };
                break;
            }
            GuestFd::register_broker(fd);
            held.push(fd);
        }
        Ok(Self {
            held,
            fill: ManuallyDrop::new(fill),
            occupying: true,
        })
    }

    fn release_held(held: &[RawFd], fill: OwnedFd) {
        for &fd in held {
            unsafe { libc::close(fd) };
            GuestFd::unregister_broker(fd);
        }
        let fill_raw = fill.as_raw_fd();
        drop(fill);
        GuestFd::unregister_broker(fill_raw);
    }

    fn fill(base: RawFd) -> Result<OwnedFd> {
        let null = File::open("/dev/null").context("open the descriptor fill")?;
        let moved = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD_CLOEXEC, base) };
        if moved < 0 {
            bail!(
                "move the descriptor fill above {base}: {}",
                io::Error::last_os_error()
            );
        }
        let fill = unsafe { OwnedFd::from_raw_fd(moved) };
        drop(null);
        Ok(fill)
    }
}

impl Drop for Range {
    fn drop(&mut self) {
        for &fd in &self.held {
            unsafe { libc::close(fd) };
            GuestFd::unregister_broker(fd);
        }
        let fill_raw = self.fill.as_raw_fd();
        // SAFETY: `self.fill` is dropped once here before clearing its bit.
        unsafe { ManuallyDrop::drop(&mut self.fill) };
        GuestFd::unregister_broker(fill_raw);
        if self.occupying {
            OCCUPY_ACTIVE.fetch_sub(1, Ordering::Release);
        }
    }
}
