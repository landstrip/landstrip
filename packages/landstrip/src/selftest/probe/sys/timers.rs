// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Timer state, notifications and lifetime, compared with the host by `compat`.

use super::{OsResult, Probe, ProbeError, ProbeResult, SysCheck, SysProbe};
use std::io;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static FIRED: AtomicU32 = AtomicU32::new(0);
static SIGNAL_CODE: AtomicI32 = AtomicI32::new(0);
static SIGNAL_VALUE: AtomicUsize = AtomicUsize::new(0);
static SIGNAL_THREAD: AtomicI32 = AtomicI32::new(0);
const VALUE: usize = 0x5eed;
const PERIOD: Duration = Duration::from_millis(10);

extern "C" fn notified(_: i32, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // SAFETY: SA_SIGINFO supplies a live siginfo; gettid is async-signal-safe.
    unsafe {
        SIGNAL_CODE.store((*info).si_code, Ordering::Relaxed);
        SIGNAL_VALUE.store((*info).si_value().sival_ptr.addr(), Ordering::Relaxed);
        SIGNAL_THREAD.store(libc::gettid(), Ordering::Relaxed);
    }
    FIRED.fetch_add(1, Ordering::Release);
}

fn listen(restart: bool) -> io::Result<()> {
    FIRED.store(0, Ordering::Release);
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_flags = libc::SA_SIGINFO | if restart { libc::SA_RESTART } else { 0 };
    action.sa_sigaction = notified as *const () as usize;
    unsafe { libc::sigemptyset(&raw mut action.sa_mask) }.os_result()?;
    unsafe { libc::sigaction(libc::SIGALRM, &raw const action, std::ptr::null_mut()) }
        .os_result()?;
    Ok(())
}

pub(super) fn interrupt() -> ProbeResult<Vec<u8>> {
    for restart in [false, true] {
        listen(restart)?;
        let (reader, mut writer) = io::pipe()?;
        let mut notification = event(libc::SIGEV_THREAD_ID);
        notification.sigev_notify_thread_id = unsafe { libc::gettid() };
        with_timer(libc::CLOCK_MONOTONIC, &notification, |id| {
            let sender = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                writer.write_all(b"x")
            });
            let armed = arm(id, 0, &spec(PERIOD, Duration::ZERO));
            let mut byte = 0_u8;
            let read = if armed.is_ok() {
                unsafe { libc::read(reader.as_raw_fd(), (&raw mut byte).cast(), 1) }.os_result()
            } else {
                Err(io::Error::other("timer could not be armed"))
            };
            let sent = sender
                .join()
                .map_err(|_| ProbeError::broken("pipe writer panicked"))?;
            armed?;
            sent?;
            let correct = if restart {
                read.is_ok_and(|length| length == 1 && byte == b'x')
            } else {
                read.is_err_and(|error| error.raw_os_error() == Some(libc::EINTR))
            };
            if !correct || FIRED.load(Ordering::Acquire) == 0 {
                return Err(ProbeError::broken(
                    "timer did not interrupt or restart read as requested",
                ));
            }
            Ok(Vec::new())
        })?;
    }
    Ok(b"timer interrupts read; SA_RESTART resumes it".to_vec())
}

fn wait_for(count: u32, busy: bool) -> ProbeResult<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while FIRED.load(Ordering::Acquire) < count {
        if Instant::now() >= deadline {
            return Err(ProbeError::broken("timer notifications did not arrive"));
        }
        if busy {
            std::hint::spin_loop();
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}

fn spec(value: Duration, interval: Duration) -> libc::itimerspec {
    libc::itimerspec {
        it_value: libc::timespec {
            tv_sec: value.as_secs().try_into().unwrap_or(i64::MAX),
            tv_nsec: value.subsec_nanos().into(),
        },
        it_interval: libc::timespec {
            tv_sec: interval.as_secs().try_into().unwrap_or(i64::MAX),
            tv_nsec: interval.subsec_nanos().into(),
        },
    }
}

fn event(notify: i32) -> libc::sigevent {
    let mut event: libc::sigevent = unsafe { std::mem::zeroed() };
    event.sigev_notify = notify;
    event.sigev_signo = libc::SIGALRM;
    event.sigev_value.sival_ptr = std::ptr::without_provenance_mut(VALUE);
    event
}

/// Uses the kernel timer ABI, whose IDs are integers rather than libc pointers.
fn with_timer(
    clock: libc::clockid_t,
    event: &libc::sigevent,
    check: impl FnOnce(i32) -> ProbeResult<Vec<u8>>,
) -> ProbeResult<Vec<u8>> {
    let mut id = 0_i32;
    unsafe { libc::syscall(libc::SYS_timer_create, clock, event, &raw mut id) }.os_result()?;
    let result = check(id);
    let removed = unsafe { libc::syscall(libc::SYS_timer_delete, id) }.os_result();
    let output = result?;
    removed?;
    Ok(output)
}

fn arm(id: i32, flags: i32, timer: &libc::itimerspec) -> io::Result<()> {
    unsafe {
        libc::syscall(
            libc::SYS_timer_settime,
            id,
            flags,
            timer,
            std::ptr::null_mut::<libc::itimerspec>(),
        )
    }
    .os_result()?;
    Ok(())
}

fn remaining(id: i32) -> io::Result<libc::itimerspec> {
    let mut timer: libc::itimerspec = unsafe { std::mem::zeroed() };
    unsafe { libc::syscall(libc::SYS_timer_gettime, id, &raw mut timer) }.os_result()?;
    Ok(timer)
}

pub(super) fn interval_state() -> ProbeResult<Vec<u8>> {
    listen(false)?;
    let timer = libc::itimerval {
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 10_000,
        },
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 10_000,
        },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &raw const timer, std::ptr::null_mut()) }
        .os_result()?;
    let mut current: libc::itimerval = unsafe { std::mem::zeroed() };
    unsafe { libc::getitimer(libc::ITIMER_REAL, &raw mut current) }.os_result()?;
    if current.it_interval.tv_usec != 10_000 {
        return Err(ProbeError::broken("getitimer lost the period"));
    }
    let delivered = wait_for(3, false);
    let zero: libc::itimerval = unsafe { std::mem::zeroed() };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &raw const zero, &raw mut current) }.os_result()?;
    delivered?;
    if current.it_interval.tv_usec != 10_000 {
        return Err(ProbeError::broken(
            "setitimer did not return the old period",
        ));
    }
    std::thread::sleep(PERIOD * 2);
    let count = FIRED.load(Ordering::Acquire);
    std::thread::sleep(PERIOD * 3);
    if FIRED.load(Ordering::Acquire) != count {
        return Err(ProbeError::broken("cancelled interval timer still fires"));
    }
    unsafe { libc::alarm(2) };
    let replaced = unsafe { libc::alarm(1) };
    let cancelled = unsafe { libc::alarm(0) };
    if replaced == 0 || replaced > 2 || cancelled != 1 {
        return Err(ProbeError::broken("alarm lost the previous remaining time"));
    }
    Ok(b"periodic, queried, replaced and cancelled".to_vec())
}

pub(super) fn posix_state() -> ProbeResult<Vec<u8>> {
    listen(false)?;
    with_timer(libc::CLOCK_MONOTONIC, &event(libc::SIGEV_SIGNAL), |id| {
        arm(id, 0, &spec(PERIOD, PERIOD))?;
        if remaining(id)?.it_interval.tv_nsec != 10_000_000 {
            return Err(ProbeError::broken("timer_gettime lost the period"));
        }
        wait_for(3, false)?;
        if SIGNAL_CODE.load(Ordering::Relaxed) != libc::SI_TIMER
            || SIGNAL_VALUE.load(Ordering::Relaxed) != VALUE
        {
            return Err(ProbeError::broken("SI_TIMER or sigval was lost"));
        }
        let mut old: libc::itimerspec = unsafe { std::mem::zeroed() };
        let zero = spec(Duration::ZERO, Duration::ZERO);
        unsafe {
            libc::syscall(
                libc::SYS_timer_settime,
                id,
                0,
                &raw const zero,
                &raw mut old,
            )
        }
        .os_result()?;
        if old.it_interval.tv_nsec != 10_000_000 || remaining(id)?.it_value.tv_nsec != 0 {
            return Err(ProbeError::broken(
                "timer_settime lost the old state or cancellation",
            ));
        }
        std::thread::sleep(PERIOD * 2);
        let count = FIRED.load(Ordering::Acquire);
        std::thread::sleep(PERIOD * 3);
        if FIRED.load(Ordering::Acquire) != count {
            return Err(ProbeError::broken("cancelled POSIX timer still fires"));
        }
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) }.os_result()?;
        now.tv_sec += 1;
        let mut absolute = spec(Duration::ZERO, Duration::ZERO);
        absolute.it_value = now;
        arm(id, libc::TIMER_ABSTIME, &absolute)?;
        let left = remaining(id)?.it_value;
        if left.tv_sec < 0 || left.tv_sec > 1 || (left.tv_sec == 0 && left.tv_nsec == 0) {
            return Err(ProbeError::broken("absolute timer has no remaining time"));
        }
        Ok(b"periodic, queried, cancelled, absolute; SI_TIMER and sigval preserved".to_vec())
    })
}

pub(super) fn overrun() -> ProbeResult<Vec<u8>> {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&raw mut mask) }.os_result()?;
    unsafe { libc::sigaddset(&raw mut mask, libc::SIGALRM) }.os_result()?;
    unsafe { libc::sigprocmask(libc::SIG_BLOCK, &raw const mask, &raw mut old) }.os_result()?;
    let result = with_timer(libc::CLOCK_MONOTONIC, &event(libc::SIGEV_SIGNAL), |id| {
        arm(
            id,
            0,
            &spec(Duration::from_millis(1), Duration::from_millis(1)),
        )?;
        std::thread::sleep(Duration::from_millis(50));
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let limit = spec(Duration::from_secs(1), Duration::ZERO).it_value;
        unsafe { libc::sigtimedwait(&raw const mask, &raw mut info, &raw const limit) }
            .os_result()?;
        let missed = unsafe { libc::syscall(libc::SYS_timer_getoverrun, id) }.os_result()?;
        if missed == 0
            || info.si_code != libc::SI_TIMER
            || unsafe { info.si_value().sival_ptr.addr() } != VALUE
        {
            return Err(ProbeError::broken("timer overrun or notification was lost"));
        }
        Ok(b"blocked timer reports overruns and sigval".to_vec())
    });
    let restored =
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &raw const old, std::ptr::null_mut()) }
            .os_result();
    let output = result?;
    restored?;
    Ok(output)
}

pub(super) fn fork() -> ProbeResult<Vec<u8>> {
    with_timer(libc::CLOCK_MONOTONIC, &event(libc::SIGEV_NONE), |id| {
        arm(id, 0, &spec(Duration::from_secs(5), Duration::ZERO))?;
        unsafe { libc::alarm(5) };
        let pid = unsafe { libc::fork() }.os_result()?;
        if pid == 0 {
            let not_inherited =
                remaining(id).is_err_and(|e| e.raw_os_error() == Some(libc::EINVAL));
            let interval_absent = unsafe { libc::alarm(0) } == 0;
            unsafe { libc::_exit(i32::from(!not_inherited || !interval_absent)) };
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result();
        let parent_alarm = unsafe { libc::alarm(0) };
        waited?;
        if !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 0
            || parent_alarm == 0
            || remaining(id)?.it_value.tv_sec == 0
        {
            return Err(ProbeError::broken("fork did not isolate timers"));
        }
        Ok(b"child inherits no timers; parent timers survive".to_vec())
    })
}

pub(super) fn exec() -> ProbeResult<Vec<u8>> {
    with_timer(libc::CLOCK_MONOTONIC, &event(libc::SIGEV_NONE), |id| {
        arm(id, 0, &spec(Duration::from_secs(10), Duration::ZERO))?;
        unsafe { libc::alarm(10) };
        let args = Probe::from(SysProbe::AfterTimerExec { id })
            .argv()
            .map_err(|_| ProbeError::broken("cannot encode the timer exec probe"))?;
        let error = Command::new(SysProbe::SELF_EXE).args(args).exec();
        unsafe { libc::alarm(0) };
        Err(error.into())
    })
}

pub(super) fn after_exec(id: i32) -> ProbeResult<Vec<u8>> {
    let interval = unsafe { libc::alarm(0) };
    if !remaining(id).is_err_and(|e| e.raw_os_error() == Some(libc::EINVAL)) || interval == 0 {
        return Err(ProbeError::broken(
            "exec must delete POSIX timers but preserve alarm",
        ));
    }
    Ok(b"exec deletes POSIX timers and preserves alarm".to_vec())
}

pub(super) fn thread() -> ProbeResult<Vec<u8>> {
    listen(false)?;
    let worker = std::thread::spawn(|| {
        let tid = unsafe { libc::gettid() };
        let mut notification = event(libc::SIGEV_THREAD_ID);
        notification.sigev_notify_thread_id = tid;
        with_timer(libc::CLOCK_MONOTONIC, &notification, |id| {
            arm(id, 0, &spec(PERIOD, Duration::ZERO))?;
            wait_for(1, false)?;
            if SIGNAL_THREAD.load(Ordering::Relaxed) != tid {
                return Err(ProbeError::broken("timer notified the wrong thread"));
            }
            Ok(b"SIGEV_THREAD_ID reaches the requested thread".to_vec())
        })
    });
    worker
        .join()
        .map_err(|_| ProbeError::broken("timer thread panicked"))?
}

pub(super) fn cpu() -> ProbeResult<Vec<u8>> {
    for clock in [
        libc::CLOCK_PROCESS_CPUTIME_ID,
        libc::CLOCK_THREAD_CPUTIME_ID,
    ] {
        listen(false)?;
        with_timer(clock, &event(libc::SIGEV_SIGNAL), |id| {
            arm(id, 0, &spec(PERIOD, Duration::ZERO))?;
            wait_for(1, true)?;
            Ok(Vec::new())
        })?;
    }
    for (which, signal) in [
        (libc::ITIMER_VIRTUAL, libc::SIGVTALRM),
        (libc::ITIMER_PROF, libc::SIGPROF),
    ] {
        SysCheck::expect_alarm()?;
        // Use the same minimal handler as the original alarm probe.
        if unsafe { libc::signal(signal, SysCheck::on_alarm as *const () as usize) }
            == libc::SIG_ERR
        {
            return Err(io::Error::last_os_error().into());
        }
        let timer = libc::itimerval {
            it_value: libc::timeval {
                tv_sec: 0,
                tv_usec: 10_000,
            },
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        };
        unsafe { libc::setitimer(which, &raw const timer, std::ptr::null_mut()) }.os_result()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while !super::ALARMED.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                return Err(ProbeError::broken("CPU interval timer did not fire"));
            }
            std::hint::spin_loop();
        }
    }
    Ok(b"process and thread CPU timers; virtual and profiling interval timers".to_vec())
}
