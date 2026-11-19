// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Probes of ordinary system call behaviour. Each reports what it observed,
//! so the same probe run outside the sandbox is the reference.

use super::proc::Mapping;
use super::{CPath, OsResult, Probe, ProbeError, ProbeResult};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use strum::{Display, VariantArray};
use syscalls::Sysno;

mod exec;
mod futex;
mod groups;
mod inotify;
mod ioprio;
mod membarrier;
mod memory;
mod names;
mod robust;
mod scheduler;

mod timers;

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, VariantArray)]
#[strum(serialize_all = "kebab-case")]
pub enum SysCheck {
    IntervalTimer,
    Alarm,
    PosixTimer,
    IntervalTimerState,
    PosixTimerState,
    TimerOverrun,
    TimerFork,
    TimerExec,
    TimerThread,
    TimerInterrupt,
    CpuTimers,
    ExecWithThreads,
    ExecFromThread,
    ExecAfterLeaderExit,
    ExecThreadState,
    ExecBlockedRead,
    ExecBlockedFutex,
    ExecBlockedPoll,
    ExecCompeting,
    ExecCloneRace,
    ExecFailures,
    CurrentCpu,
    DiscardPages,
    HeapMappings,
    AdviceRanges,
    AdviceFiles,
    AdviceFork,
    AdviceReuse,
    AdviceRemap,
    AdviceHints,
    AdviceExec,
    Inotify,
    InotifyEvents,
    InotifyWatches,
    InotifyPaths,
    InotifyIo,
    InotifyErrors,
    InotifyFork,
    InotifyExec,
    SharedMemory,
    Semaphore,
    MessageQueue,
    Groups,
    SchedulerPriority,
    ProcessTimes,
    IoPriority,
    FutexState,
    RobustState,
    MembarrierState,
    Trace,
    FileLimit,
    ProcessName,
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SysProbe {
    Check {
        check: SysCheck,
        dir: PathBuf,
    },
    /// The second half of [`SysCheck::ProcessName`], run under the new name.
    ReportName,
    ExecName {
        path: PathBuf,
        via_fd: bool,
        threaded: bool,
    },
    AfterTimerExec {
        id: i32,
    },
    AfterAdviceExec,
    AfterMembarrierExec {
        observations: Vec<i64>,
    },
    AfterRobustExec,
    AfterThreadExec {
        pid: i32,
        keep: i32,
        closed: i32,
        check_signals: bool,
    },
    AfterInotifyExec {
        keep: i32,
        closed: i32,
        watch: i32,
        dir: PathBuf,
    },
    Sweep,
}

static ALARMED: AtomicBool = AtomicBool::new(false);

impl SysProbe {
    const SELF_EXE: &str = "/proc/self/exe";

    pub fn run(&self) -> ProbeResult<Vec<u8>> {
        match self {
            Self::Check { check, dir } => check.run(dir),
            Self::ReportName => names::report(),
            Self::ExecName {
                path,
                via_fd,
                threaded,
            } => names::replace(path, *via_fd, *threaded),
            Self::AfterTimerExec { id } => timers::after_exec(*id),
            Self::AfterAdviceExec => memory::after_exec(),
            Self::AfterMembarrierExec { observations } => membarrier::after_exec(observations),
            Self::AfterRobustExec => {
                // Run until the waiters have returned and stdin closes.
                io::copy(&mut io::stdin(), &mut io::sink()).map_err(ProbeError::Broken)?;
                Ok(Vec::new())
            }
            Self::AfterThreadExec {
                pid,
                keep,
                closed,
                check_signals,
            } => Self::after_thread_exec(*pid, *keep, *closed, *check_signals),
            Self::Sweep => Sweep::run(),
            Self::AfterInotifyExec {
                keep,
                closed,
                watch,
                dir,
            } => inotify::after_exec(*keep, *closed, *watch, dir),
        }
    }
}

impl SysCheck {
    fn run(self, dir: &Path) -> ProbeResult<Vec<u8>> {
        match self {
            Self::IntervalTimer => Self::interval_timer(),
            Self::Alarm => {
                Self::expect_alarm()?;
                unsafe { libc::alarm(1) };
                Self::await_alarm(Duration::from_secs(3))
            }
            Self::PosixTimer => Self::posix_timer(),
            Self::IntervalTimerState => timers::interval_state(),
            Self::PosixTimerState => timers::posix_state(),
            Self::TimerOverrun => timers::overrun(),
            Self::TimerFork => timers::fork(),
            Self::TimerExec => timers::exec(),
            Self::TimerThread => timers::thread(),
            Self::TimerInterrupt => timers::interrupt(),
            Self::CpuTimers => timers::cpu(),
            Self::ExecWithThreads => Self::exec_with_threads(),
            Self::ExecFromThread
            | Self::ExecAfterLeaderExit
            | Self::ExecThreadState
            | Self::ExecBlockedRead
            | Self::ExecBlockedFutex
            | Self::ExecBlockedPoll
            | Self::ExecCompeting
            | Self::ExecCloneRace
            | Self::ExecFailures => self.thread_exec(dir),
            Self::CurrentCpu => scheduler::cpu(),
            Self::DiscardPages => Self::discard_pages(),
            Self::HeapMappings => memory::heap(),
            Self::AdviceRanges => memory::ranges(),
            Self::AdviceFiles => memory::files(dir),
            Self::AdviceFork => memory::fork(),
            Self::AdviceReuse => memory::reuse(),
            Self::AdviceRemap => memory::remap(),
            Self::AdviceHints => memory::hints(),
            Self::AdviceExec => memory::exec(),
            Self::Inotify => Self::inotify(dir),
            Self::InotifyEvents
            | Self::InotifyWatches
            | Self::InotifyPaths
            | Self::InotifyIo
            | Self::InotifyErrors
            | Self::InotifyFork
            | Self::InotifyExec => inotify::run(self, dir),
            Self::SharedMemory => Self::shared_memory(),
            Self::Semaphore => Self::semaphore(),
            Self::MessageQueue => Self::message_queue(),
            Self::Groups => groups::run(),
            Self::SchedulerPriority => scheduler::priority(),
            Self::ProcessTimes => scheduler::times(),
            Self::IoPriority => ioprio::run(),
            Self::FutexState => futex::run(),
            Self::RobustState => robust::run(),
            Self::MembarrierState => membarrier::run(),
            Self::Trace => Self::trace(),
            Self::FileLimit => Self::file_limit(),
            Self::ProcessName => Self::process_name(dir),
        }
    }

    extern "C" fn on_alarm(_: i32) {
        ALARMED.store(true, Ordering::Release);
    }

    fn expect_alarm() -> io::Result<()> {
        ALARMED.store(false, Ordering::Release);
        if unsafe { libc::signal(libc::SIGALRM, Self::on_alarm as *const () as usize) }
            == libc::SIG_ERR
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn await_alarm(limit: Duration) -> ProbeResult<Vec<u8>> {
        let deadline = Instant::now() + limit;
        while !ALARMED.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                return Err(ProbeError::broken("SIGALRM was not delivered"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(b"SIGALRM delivered".to_vec())
    }

    fn interval_timer() -> ProbeResult<Vec<u8>> {
        Self::expect_alarm()?;
        let timer = libc::itimerval {
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: libc::timeval {
                tv_sec: 0,
                tv_usec: 20_000,
            },
        };
        unsafe { libc::setitimer(libc::ITIMER_REAL, &raw const timer, std::ptr::null_mut()) }
            .os_result()?;
        Self::await_alarm(Duration::from_secs(2))
    }

    fn posix_timer() -> ProbeResult<Vec<u8>> {
        Self::expect_alarm()?;
        let mut timer: libc::timer_t = std::ptr::null_mut();
        unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, std::ptr::null_mut(), &raw mut timer) }
            .os_result()?;
        let mut spec: libc::itimerspec = unsafe { std::mem::zeroed() };
        spec.it_value.tv_nsec = 20_000_000;
        let armed = unsafe { libc::timer_settime(timer, 0, &raw const spec, std::ptr::null_mut()) }
            .os_result();
        let fired = armed
            .map_err(ProbeError::from)
            .and_then(|_| Self::await_alarm(Duration::from_secs(2)));
        unsafe { libc::timer_delete(timer) };
        fired
    }

    /// Replaces the process while a second thread is alive, which the kernel
    /// allows by ending the other threads.
    fn exec_with_threads() -> ProbeResult<Vec<u8>> {
        let started = std::sync::Arc::new(std::sync::Barrier::new(2));
        std::thread::spawn({
            let started = std::sync::Arc::clone(&started);
            move || {
                started.wait();
                std::thread::sleep(Duration::from_secs(30));
            }
        });
        started.wait();
        let args = Probe::Noop
            .argv()
            .map_err(|_| ProbeError::broken("cannot encode the probe"))?;
        Err(Command::new(SysProbe::SELF_EXE).args(args).exec().into())
    }

    fn discard_pages() -> ProbeResult<Vec<u8>> {
        const PAGE: usize = 4096;
        let page = Mapping::new(PAGE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
        unsafe { std::ptr::write_volatile(page.ptr.cast::<u8>(), 0xab) };
        unsafe { libc::madvise(page.ptr, PAGE, libc::MADV_DONTNEED) }.os_result()?;
        let byte = unsafe { std::ptr::read_volatile(page.ptr.cast::<u8>()) };
        Ok(format!("page reads {byte:#04x} after MADV_DONTNEED").into_bytes())
    }

    fn inotify(dir: &Path) -> ProbeResult<Vec<u8>> {
        use std::os::fd::{FromRawFd, OwnedFd};
        const HEADER: usize = size_of::<libc::inotify_event>();
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) }.os_result()?;
        let mut watcher = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let path = dir.c_path()?;
        unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_CREATE) }.os_result()?;
        let created = dir.join("watched");
        std::fs::write(&created, b"")?;
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&raw mut poll_fd, 1, 2000) }.os_result();
        std::fs::remove_file(&created)?;
        if ready? == 0 {
            return Err(ProbeError::broken("no inotify event arrived"));
        }
        let mut event = [0_u8; 256];
        let length = watcher.read(&mut event)?;
        let name = event
            .get(HEADER..length)
            .ok_or_else(|| ProbeError::broken("short inotify event"))?;
        let name = name.split(|byte| *byte == 0).next().unwrap_or_default();
        Ok([b"created ", name].concat())
    }

    fn shared_memory() -> ProbeResult<Vec<u8>> {
        const VALUE: u64 = 0x5eed_cafe_f00d_beef;
        let id = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) }
            .os_result()?;
        let segment = unsafe { libc::shmat(id, std::ptr::null(), 0) };
        // Removal takes effect on detach, so nothing is left behind.
        unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
        if segment.addr() == usize::MAX {
            return Err(io::Error::last_os_error().into());
        }
        unsafe { std::ptr::write_volatile(segment.cast::<u64>(), VALUE) };
        let value = unsafe { std::ptr::read_volatile(segment.cast::<u64>()) };
        unsafe { libc::shmdt(segment) }.os_result()?;
        if value != VALUE {
            return Err(ProbeError::broken("shared memory lost a write"));
        }
        Ok(b"attached".to_vec())
    }

    fn semaphore() -> ProbeResult<Vec<u8>> {
        let id =
            unsafe { libc::semget(libc::IPC_PRIVATE, 1, libc::IPC_CREAT | 0o600) }.os_result()?;
        let mut raise = libc::sembuf {
            sem_num: 0,
            sem_op: 1,
            sem_flg: 0,
        };
        let raised = unsafe { libc::semop(id, &raw mut raise, 1) }.os_result();
        let value = unsafe { libc::semctl(id, 0, libc::GETVAL) }.os_result();
        unsafe { libc::semctl(id, 0, libc::IPC_RMID) };
        raised?;
        Ok(format!("value {}", value?).into_bytes())
    }

    fn message_queue() -> ProbeResult<Vec<u8>> {
        #[repr(C)]
        struct Message {
            kind: libc::c_long,
            text: [u8; 8],
        }
        let id = unsafe { libc::msgget(libc::IPC_PRIVATE, libc::IPC_CREAT | 0o600) }.os_result()?;
        let sent = Message {
            kind: 1,
            text: *b"queued!!",
        };
        let mut received = Message {
            kind: 0,
            text: [0; 8],
        };
        let exchanged = unsafe { libc::msgsnd(id, (&raw const sent).cast(), 8, 0) }
            .os_result()
            .and_then(|_| {
                unsafe { libc::msgrcv(id, (&raw mut received).cast(), 8, 0, libc::IPC_NOWAIT) }
                    .os_result()
            });
        unsafe { libc::msgctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
        exchanged?;
        Ok(received.text.to_vec())
    }

    /// A parent traces its own child, as a debugger does.
    fn trace() -> ProbeResult<Vec<u8>> {
        const TRACED_EXIT: i32 = 7;
        let pid = unsafe { libc::fork() }.os_result()?;
        if pid == 0 {
            // Stopping untraced would never be reported to the parent.
            if unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::raise(libc::SIGSTOP) };
            unsafe { libc::_exit(TRACED_EXIT) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
        if !libc::WIFSTOPPED(status) {
            return Err(ProbeError::broken("child could not ask to be traced"));
        }
        unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) }.os_result()?;
        unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != TRACED_EXIT {
            return Err(ProbeError::broken("traced child did not resume"));
        }
        Ok(b"child stopped and resumed".to_vec())
    }

    fn file_limit() -> ProbeResult<Vec<u8>> {
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) }.os_result()?;
        let mut raised_ok = false;
        if let Ok(soft_fd) = i32::try_from(limit.rlim_cur)
            && (16..=65_536).contains(&soft_fd)
        {
            let null = File::open("/dev/null")?;
            let top = soft_fd - 1;
            unsafe { libc::dup2(null.as_raw_fd(), top) }.os_result()?;
            unsafe { libc::close(top) };
            let over = unsafe { libc::dup2(null.as_raw_fd(), soft_fd) }.os_result();
            if over.err().and_then(|err| err.raw_os_error()) != Some(libc::EBADF) {
                return Err(ProbeError::broken(
                    "dup2 at soft RLIMIT_NOFILE did not fail with EBADF",
                ));
            }
            if limit.rlim_max > limit.rlim_cur {
                let raised = libc::rlimit {
                    rlim_cur: limit.rlim_cur.saturating_add(64).min(limit.rlim_max),
                    rlim_max: limit.rlim_max,
                };
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const raised) }.os_result()?;
                unsafe { libc::dup2(null.as_raw_fd(), soft_fd) }.os_result()?;
                unsafe { libc::close(soft_fd) };
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) }.os_result()?;
                raised_ok = true;
            }
        }
        Ok(format!(
            "soft {} hard {} raised {raised_ok}",
            limit.rlim_cur, limit.rlim_max
        )
        .into_bytes())
    }

    fn process_name(dir: &Path) -> ProbeResult<Vec<u8>> {
        names::run(dir)
    }
}

/// Calls every system call the architecture names with invalid arguments,
/// each in a child of its own, and reports how each one ended.
struct Sweep;

impl Sweep {
    /// Not called: these end or multiply the caller, never return, or reach
    /// beyond the caller even with invalid arguments.
    const SKIPPED: &[&str] = &[
        "exit",
        "exit_group",
        "rt_sigreturn",
        "fork",
        "vfork",
        "clone",
        "pause",
        "kill",
        "tkill",
        "tgkill",
        "rt_sigqueueinfo",
        "rt_tgsigqueueinfo",
        "pidfd_send_signal",
        "reboot",
        "vhangup",
        "sync",
        // With every flag set this creates a queue that outlives the test.
        "msgget",
        // Raise SIGILL outside the kernel's own trampolines.
        "uprobe",
        "uretprobe",
    ];
    const INVALID: usize = usize::MAX;
    const LIMIT_MS: i32 = 2000;

    fn run() -> ProbeResult<Vec<u8>> {
        let outcomes = Sysno::iter()
            .filter(|nr| !Self::SKIPPED.contains(&nr.name()))
            .map(|nr| Ok((nr.name(), Self::call(nr)?)))
            .collect::<io::Result<Vec<_>>>()?;
        serde_json::to_vec(&outcomes).map_err(|error| ProbeError::Broken(error.into()))
    }

    fn call(nr: Sysno) -> io::Result<String> {
        let (mut reader, writer) = io::pipe()?;
        let pid = unsafe { libc::fork() }.os_result()?;
        if pid == 0 {
            let invalid = Self::INVALID;
            let errno = unsafe {
                syscalls::syscall6(nr, invalid, invalid, invalid, invalid, invalid, invalid)
            }
            .map_or_else(syscalls::Errno::into_raw, |_| 0);
            let report = errno.to_ne_bytes();
            unsafe {
                libc::write(writer.as_raw_fd(), report.as_ptr().cast(), report.len());
                libc::_exit(0);
            }
        }
        drop(writer);
        let mut poll_fd = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let finished = unsafe { libc::poll(&raw mut poll_fd, 1, Self::LIMIT_MS) }.os_result()? > 0;
        if !finished {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        let mut report = [0_u8; 4];
        let reported = finished && reader.read_exact(&mut report).is_ok();
        let mut status = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
        Ok(if reported {
            match i32::from_ne_bytes(report) {
                0 => "succeeds".to_owned(),
                errno => syscalls::Errno::new(errno)
                    .name()
                    .map_or_else(|| format!("errno {errno}"), str::to_owned),
            }
        } else if !finished {
            "blocks".to_owned()
        } else if libc::WIFSIGNALED(status) {
            format!("dies of signal {}", libc::WTERMSIG(status))
        } else {
            "exits".to_owned()
        })
    }
}
