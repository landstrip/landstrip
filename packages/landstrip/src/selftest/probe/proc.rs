// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::{CPath, OsResult, ProbeError, ProbeResult};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

mod groups;

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcProbe {
    SignalIsolation,
    NamespaceIsolation {
        host_pid: u32,
    },
    GroupIsolation {
        signal: bool,
    },
    GroupTarget {
        signal: bool,
    },
    IoPriorityIsolation {
        user: bool,
    },
    IoPriorityTarget {
        user: bool,
    },
    ExecSuite {
        dir: PathBuf,
        denied_script: PathBuf,
    },
    MmapSuite {
        dir: PathBuf,
    },
    SignalSuite,
}

impl ProcProbe {
    pub fn run(&self) -> ProbeResult {
        match self {
            Self::SignalIsolation => {
                let parent = unsafe { libc::getppid() };
                if parent > 1 && unsafe { libc::kill(parent, 0) } == 0 {
                    return Err(ProbeError::broken("parent process is signalable"));
                }
                Self::check_tgkill_and_uring()
            }
            Self::NamespaceIsolation { host_pid } => {
                Self::check_tgkill_and_uring()?;
                Self::check_pid_namespace(*host_pid)
            }
            Self::GroupIsolation { signal } => groups::guard(Self::GroupTarget { signal: *signal }),
            Self::GroupTarget { signal } => groups::target(*signal),
            Self::IoPriorityIsolation { user } => {
                groups::guard(Self::IoPriorityTarget { user: *user })
            }
            Self::IoPriorityTarget { user } => groups::io_target(*user),
            Self::ExecSuite { dir, denied_script } => Self::exec_suite(dir, denied_script),
            Self::MmapSuite { dir } => Self::mmap_suite(dir),
            Self::SignalSuite => SignalSuite::run(),
        }
    }

    fn check_tgkill_and_uring() -> ProbeResult {
        let main_tid = unsafe { libc::gettid() };
        let tgkill = std::thread::spawn(move || unsafe {
            libc::syscall(libc::SYS_tgkill, libc::getpid(), main_tid, 0)
        })
        .join()
        .map_err(|_| ProbeError::broken("tgkill thread panicked"))?;
        tgkill.os_result()?;
        let uring = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                1_u32,
                std::ptr::null::<libc::c_void>(),
            )
        };
        if uring != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            return Err(ProbeError::broken("io_uring_setup did not fail with EPERM"));
        }
        Ok(())
    }

    fn check_pid_namespace(host_pid: u32) -> ProbeResult {
        if unsafe { libc::getppid() } != 1 {
            return Err(ProbeError::broken("parent is visible inside PID namespace"));
        }
        match std::fs::read_to_string(format!("/proc/{host_pid}/status")) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
            _ => return Err(ProbeError::broken("host PID is visible in procfs")),
        }
        let tgid = std::fs::read_to_string("/proc/self/status")?
            .lines()
            .find_map(|line| line.strip_prefix("Tgid:"))
            .and_then(|rest| rest.trim().parse::<i32>().ok());
        if tgid != Some(unsafe { libc::getpid() }) {
            return Err(ProbeError::broken("procfs Tgid does not match getpid"));
        }
        if UdpSocket::bind("127.0.0.1:0").is_ok() {
            return Err(ProbeError::broken("UDP bind succeeded without network"));
        }
        Ok(())
    }

    fn exec_suite(dir: &Path, denied_script: &Path) -> ProbeResult {
        use std::os::unix::fs::PermissionsExt;
        let plain = dir.join("plain.txt");
        std::fs::write(&plain, b"#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644))?;
        if Self::exec(&plain)? != Err(libc::EACCES) {
            return Err(ProbeError::broken(
                "non-executable file did not fail with EACCES",
            ));
        }
        if Self::exec(dir)? != Err(libc::EACCES) {
            return Err(ProbeError::broken("directory did not fail with EACCES"));
        }
        let mut interpreter = PathBuf::from("/bin/sh");
        for level in 0..=5 {
            let script = dir.join(format!("chain_{level}.sh"));
            std::fs::write(&script, format!("#!{}\nexit 0\n", interpreter.display()))?;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
            let status = Self::exec(&script)?;
            if level <= 3 && status != Ok(()) {
                return Err(ProbeError::broken("shebang chain within limit failed"));
            }
            if level == 5 && status != Err(libc::ELOOP) {
                return Err(ProbeError::broken(
                    "shebang chain over limit did not fail with ELOOP",
                ));
            }
            interpreter = script;
        }
        if Self::exec(denied_script)?.is_ok() {
            return Err(ProbeError::broken("denyRead script executed"));
        }
        Ok(())
    }

    fn exec(path: &Path) -> io::Result<Result<(), i32>> {
        let path = path.c_path()?;
        let pid = unsafe { libc::fork() }.os_result()?;
        if pid == 0 {
            let argv = [path.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            let errno = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ENOENT);
            unsafe { libc::_exit(errno) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
        if !libc::WIFEXITED(status) {
            return Ok(Err(libc::EFAULT));
        }
        Ok(match libc::WEXITSTATUS(status) {
            0 => Ok(()),
            errno => Err(errno),
        })
    }

    fn mmap_suite(dir: &Path) -> ProbeResult {
        use std::os::fd::AsRawFd;
        const PAGE: usize = 4096;
        let path = dir.join("mmap_backing.bin");
        std::fs::write(&path, vec![b'A'; PAGE])?;
        let backing = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;
        let shared = Mapping::new(PAGE, libc::MAP_SHARED, backing.as_raw_fd())?;
        unsafe { std::ptr::copy_nonoverlapping(b"SYNCED".as_ptr(), shared.ptr.cast::<u8>(), 6) };
        unsafe { libc::msync(shared.ptr, PAGE, libc::MS_SYNC) }.os_result()?;
        drop(shared);
        if std::fs::read(&path)?.get(..6) != Some(b"SYNCED".as_slice()) {
            return Err(ProbeError::broken(
                "MAP_SHARED write did not reach the file",
            ));
        }

        let anon = Mapping::new(PAGE, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1)?;
        let pid = unsafe { libc::fork() }.os_result()?;
        if pid == 0 {
            unsafe {
                std::ptr::write_volatile(anon.ptr.cast::<u64>(), 0x55aa_1234_9876_fedc);
                libc::_exit(0);
            }
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
        if unsafe { std::ptr::read_volatile(anon.ptr.cast::<u64>()) } != 0x55aa_1234_9876_fedc {
            return Err(ProbeError::broken(
                "shared anonymous mapping lost child write",
            ));
        }

        let mut private = Mapping::new(PAGE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
        unsafe { std::ptr::write_volatile(private.ptr.cast::<u64>(), 0xcafe_babe_dead_beef) };
        private.grow(2 * PAGE)?;
        if unsafe { std::ptr::read_volatile(private.ptr.cast::<u64>()) } != 0xcafe_babe_dead_beef {
            return Err(ProbeError::broken("mremap lost mapping contents"));
        }
        Ok(())
    }
}

pub(super) struct Mapping {
    pub(super) ptr: *mut libc::c_void,
    len: usize,
}

impl Mapping {
    pub(super) fn new(len: usize, flags: i32, fd: i32) -> io::Result<Self> {
        Self::at(0, len, flags, fd)
    }

    pub(super) fn at(address: usize, len: usize, flags: i32, fd: i32) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { ptr, len })
    }

    fn grow(&mut self, len: usize) -> io::Result<()> {
        let ptr = unsafe { libc::mremap(self.ptr, self.len, len, libc::MREMAP_MAYMOVE) };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        self.ptr = ptr;
        self.len = len;
        Ok(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DaemonMode {
    Exit,
    Term,
    Cancel,
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExitProbe {
    Daemon { mode: DaemonMode },
    OrphanStorm,
    UnhandledSegv,
}

impl ExitProbe {
    pub const DAEMON_EXIT: i32 = 23;
    pub const TERM_EXIT: i32 = 42;
    pub const ORPHAN_EXIT: i32 = 37;

    pub fn run(&self) -> ProbeResult<i32> {
        match self {
            Self::Daemon { mode } => Self::daemon(*mode),
            Self::OrphanStorm => Ok(Self::orphan_storm()),
            Self::UnhandledSegv => Self::unhandled_segv(),
        }
    }

    extern "C" fn on_sigterm(_: i32) {
        unsafe { libc::_exit(Self::TERM_EXIT) };
    }

    fn daemon(mode: DaemonMode) -> ProbeResult<i32> {
        if matches!(mode, DaemonMode::Term)
            && unsafe { libc::signal(libc::SIGTERM, Self::on_sigterm as *const () as usize) }
                == libc::SIG_ERR
        {
            return Err(io::Error::last_os_error().into());
        }
        let mut ready = [0_i32; 2];
        unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) }.os_result()?;
        let [read_end, write_end] = ready;
        let mid = unsafe { libc::fork() }.os_result()?;
        if mid == 0 {
            unsafe { libc::close(read_end) };
            let _ = unsafe { libc::setsid() };
            let leaf = unsafe { libc::fork() };
            if leaf != 0 {
                unsafe { libc::_exit(i32::from(leaf < 0)) };
            }
            let marker = [1_u8];
            let _ = unsafe { libc::write(write_end, marker.as_ptr().cast(), 1) };
            unsafe { libc::close(write_end) };
            loop {
                unsafe { libc::pause() };
            }
        }
        unsafe { libc::close(write_end) };
        let mut status = 0;
        unsafe { libc::waitpid(mid, &raw mut status, 0) }.os_result()?;
        let mut byte = [0_u8; 1];
        let read = unsafe { libc::read(read_end, byte.as_mut_ptr().cast(), 1) };
        unsafe { libc::close(read_end) };
        if read != 1 {
            return Err(ProbeError::broken("daemon grandchild did not report ready"));
        }
        let mut stdout = io::stdout();
        stdout.write_all(&[1_u8])?;
        stdout.flush()?;
        if matches!(mode, DaemonMode::Exit) {
            return Ok(Self::DAEMON_EXIT);
        }
        loop {
            unsafe { libc::pause() };
        }
    }

    fn orphan_storm() -> i32 {
        for _ in 0..4 {
            let mid = unsafe { libc::fork() };
            if mid == 0 {
                for _ in 0..3 {
                    if unsafe { libc::fork() } == 0 {
                        std::thread::sleep(Duration::from_millis(20));
                        unsafe { libc::_exit(0) };
                    }
                }
                unsafe { libc::_exit(0) };
            }
            if mid > 0 {
                let mut status = 0;
                let _ = unsafe { libc::waitpid(mid, &raw mut status, 0) };
            }
        }
        std::thread::sleep(Duration::from_millis(80));
        Self::ORPHAN_EXIT
    }

    fn unhandled_segv() -> ProbeResult<i32> {
        let hole = Mapping::new(4096, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
        let addr = hole.ptr;
        drop(hole);
        unsafe {
            let _ = std::ptr::read_volatile(addr.cast::<u64>());
        }
        Err(ProbeError::broken("read from unmapped page did not fault"))
    }
}

struct SignalSuite;

static RT_SEQ: AtomicUsize = AtomicUsize::new(0);
static RT_VALS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static RT_TIDS: [AtomicI32; 4] = [const { AtomicI32::new(0) }; 4];
static SEGV_ADDR: AtomicUsize = AtomicUsize::new(0);
static SEGV_RECOVERED: AtomicBool = AtomicBool::new(false);

impl SignalSuite {
    const PAGE: usize = 4096;
    const ALT_STACK: usize = 65536;

    fn run() -> ProbeResult {
        Self::check_rt_fifo_and_threads()?;
        Self::check_altstack_and_mprotect()
    }

    fn read_token(info: *const libc::siginfo_t) -> usize {
        let mut raw = [0_u8; 8];
        unsafe { std::ptr::copy_nonoverlapping(info.cast::<u8>().add(24), raw.as_mut_ptr(), 8) };
        usize::from_ne_bytes(raw)
    }

    fn queue_info(sig: i32, pid: i32, uid: u32, token: usize) -> [u8; 128] {
        let mut raw = [0_u8; 128];
        raw[0..4].copy_from_slice(&sig.to_ne_bytes());
        raw[8..12].copy_from_slice(&(-1_i32).to_ne_bytes());
        raw[16..20].copy_from_slice(&pid.to_ne_bytes());
        raw[20..24].copy_from_slice(&uid.to_ne_bytes());
        raw[24..32].copy_from_slice(&token.to_ne_bytes());
        raw
    }

    extern "C" fn on_rt(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
        if info.is_null() {
            return;
        }
        let slot = RT_SEQ.fetch_add(1, Ordering::AcqRel);
        if let (Some(value), Some(tid)) = (RT_VALS.get(slot), RT_TIDS.get(slot)) {
            value.store(Self::read_token(info), Ordering::Release);
            tid.store(unsafe { libc::gettid() }, Ordering::Release);
        }
    }

    extern "C" fn on_segv(sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
        let expected = SEGV_ADDR.load(Ordering::Acquire);
        if sig != libc::SIGSEGV || info.is_null() {
            unsafe { libc::_exit(3) };
        }
        let code = unsafe { (*info).si_code };
        let addr = unsafe { (*info).si_addr() }.addr();
        if code != 2 || addr != expected {
            unsafe { libc::_exit(4) };
        }
        let page = std::ptr::with_exposed_provenance_mut::<libc::c_void>(expected);
        if unsafe { libc::mprotect(page, Self::PAGE, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
            unsafe { libc::_exit(5) };
        }
        SEGV_RECOVERED.store(true, Ordering::Release);
    }

    fn values(count: usize) -> Vec<usize> {
        RT_VALS
            .iter()
            .take(count)
            .map(|value| value.load(Ordering::Acquire))
            .collect()
    }

    fn check_rt_fifo_and_threads() -> ProbeResult {
        let sig = libc::SIGRTMIN() + 2;
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = Self::on_rt as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        unsafe { libc::sigemptyset(&raw mut action.sa_mask) };
        unsafe { libc::sigaction(sig, &raw const action, std::ptr::null_mut()) }.os_result()?;
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut prev: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&raw mut mask);
            libc::sigaddset(&raw mut mask, sig);
        }
        unsafe { libc::sigprocmask(libc::SIG_BLOCK, &raw const mask, &raw mut prev) }
            .os_result()?;
        RT_SEQ.store(0, Ordering::Release);
        let pid = unsafe { libc::getpid() };
        let uid = unsafe { libc::getuid() };
        for token in [0x101_usize, 0x202, 0x303] {
            let mut info = Self::queue_info(sig, pid, uid, token);
            unsafe { libc::syscall(libc::SYS_rt_sigqueueinfo, pid, sig, info.as_mut_ptr()) }
                .os_result()?;
        }
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &raw const prev, std::ptr::null_mut()) }
            .os_result()?;
        if RT_SEQ.load(Ordering::Acquire) != 3 || Self::values(3) != [0x101, 0x202, 0x303] {
            return Err(ProbeError::broken(
                "queued RT signals were not delivered in order",
            ));
        }

        unsafe { libc::sigprocmask(libc::SIG_BLOCK, &raw const mask, &raw mut prev) }
            .os_result()?;
        RT_SEQ.store(0, Ordering::Release);
        let thread_tid = Arc::new(AtomicI32::new(0));
        let ready = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let thread_tid = Arc::clone(&thread_tid);
            let ready = Arc::clone(&ready);
            move || {
                thread_tid.store(unsafe { libc::gettid() }, Ordering::Release);
                while !ready.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                let mut empty: libc::sigset_t = unsafe { std::mem::zeroed() };
                unsafe { libc::sigemptyset(&raw mut empty) };
                unsafe { libc::sigsuspend(&raw const empty) };
            }
        });
        while thread_tid.load(Ordering::Acquire) == 0 {
            std::hint::spin_loop();
        }
        let tid = thread_tid.load(Ordering::Acquire);
        let mut targeted = Self::queue_info(sig, pid, uid, 0x777);
        let queued = unsafe {
            libc::syscall(
                libc::SYS_rt_tgsigqueueinfo,
                pid,
                tid,
                sig,
                targeted.as_mut_ptr(),
            )
        }
        .os_result();
        queued?;
        ready.store(true, Ordering::Release);
        handle
            .join()
            .map_err(|_| ProbeError::broken("signal thread panicked"))?;
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &raw const prev, std::ptr::null_mut()) }
            .os_result()?;
        let delivered_to = RT_TIDS.first().map(|slot| slot.load(Ordering::Acquire));
        if RT_SEQ.load(Ordering::Acquire) != 1
            || delivered_to != Some(tid)
            || Self::values(1) != [0x777]
        {
            return Err(ProbeError::broken(
                "thread-directed RT signal was misrouted",
            ));
        }
        Ok(())
    }

    fn check_altstack_and_mprotect() -> ProbeResult {
        let alt = Mapping::new(Self::ALT_STACK, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
        let stack = libc::stack_t {
            ss_sp: alt.ptr,
            ss_flags: i32::MIN,
            ss_size: Self::ALT_STACK,
        };
        let installed =
            unsafe { libc::sigaltstack(&raw const stack, std::ptr::null_mut()) }.os_result();
        let disable = libc::stack_t {
            ss_sp: std::ptr::null_mut(),
            ss_flags: libc::SS_DISABLE,
            ss_size: 0,
        };
        let _ = unsafe { libc::sigaltstack(&raw const disable, std::ptr::null_mut()) };
        drop(alt);
        installed?;

        let page = Mapping::new(Self::PAGE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
        unsafe { std::ptr::write_volatile(page.ptr.cast::<u64>(), 0xaa55_cc33_f00d_cafe) };
        unsafe { libc::mprotect(page.ptr, Self::PAGE, libc::PROT_NONE) }.os_result()?;
        SEGV_ADDR.store(page.ptr.addr(), Ordering::Release);
        SEGV_RECOVERED.store(false, Ordering::Release);
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = Self::on_segv as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        unsafe { libc::sigemptyset(&raw mut action.sa_mask) };
        unsafe { libc::sigaction(libc::SIGSEGV, &raw const action, std::ptr::null_mut()) }
            .os_result()?;
        let value = unsafe { std::ptr::read_volatile(page.ptr.cast::<u64>()) };
        let _ = unsafe { libc::signal(libc::SIGSEGV, libc::SIG_DFL) };
        if value != 0xaa55_cc33_f00d_cafe || !SEGV_RECOVERED.load(Ordering::Acquire) {
            return Err(ProbeError::broken(
                "SIGSEGV handler did not recover the page",
            ));
        }
        Ok(())
    }
}
