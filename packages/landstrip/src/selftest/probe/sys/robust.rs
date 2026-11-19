// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Registration and owner-death state models: thread exit, exec and a killed process.

use super::super::proc::Mapping;
use super::{OsResult, Probe, ProbeError, ProbeResult, SysProbe};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Offset of the futex word in `pthread_mutex_t`.
#[cfg(target_env = "musl")]
const LOCK_WORD: usize = 4;
#[cfg(not(target_env = "musl"))]
const LOCK_WORD: usize = 0;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;

/// Whether locking a robust mutex registers a kernel robust list; musl
/// releases process-private robust mutexes itself at thread exit.
const fn kernel_list(shared: bool) -> bool {
    shared || cfg!(not(target_env = "musl"))
}

fn query(tid: i32) -> ProbeResult<(usize, usize)> {
    let mut head = 0usize;
    let mut length = 0usize;
    unsafe {
        libc::syscall(
            libc::SYS_get_robust_list,
            tid,
            &raw mut head,
            &raw mut length,
        )
    }
    .os_result()?;
    Ok((head, length))
}

fn register(head: usize, length: usize) -> Result<libc::c_long, i32> {
    unsafe { libc::syscall(libc::SYS_set_robust_list, head, length) }
        .os_result()
        .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
}

fn check(result: i32, expected: i32) -> ProbeResult<()> {
    if result != expected {
        return Err(ProbeError::broken(&format!(
            "robust mutex: expected {expected}, observed {result}"
        )));
    }
    Ok(())
}

fn registration() -> ProbeResult<Vec<Result<libc::c_long, i32>>> {
    let original = query(0)?;
    if original.1 != 24 {
        return Err(ProbeError::broken("wrong robust-list ABI size"));
    }
    let mut results = Vec::new();
    for length in [0, 23, 25, usize::MAX] {
        results.push(register(1, length));
        if query(0)? != original {
            return Err(ProbeError::broken(
                "failed registration changed the robust list",
            ));
        }
    }
    for pointer in [0, 1, usize::MAX] {
        let result = register(pointer, 24);
        let observed = query(0);
        register(original.0, original.1).map_err(io::Error::from_raw_os_error)?;
        if result != Ok(0) {
            return Err(ProbeError::broken(
                "registration incorrectly dereferenced the robust head",
            ));
        }
        results.push(match observed {
            Ok(head) if head == (pointer, 24) => Ok(0),
            Ok(_) => {
                return Err(ProbeError::broken(
                    "registered robust head did not round-trip",
                ));
            }
            Err(ProbeError::Denied(error) | ProbeError::Broken(error)) => {
                Err(error.raw_os_error().unwrap_or(libc::EIO))
            }
        });
    }
    for tid in [-1, i32::MAX] {
        let mut head = 0usize;
        let mut length = 0usize;
        let result = unsafe {
            libc::syscall(
                libc::SYS_get_robust_list,
                tid,
                &raw mut head,
                &raw mut length,
            )
        };
        results.push(
            result
                .os_result()
                .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO)),
        );
    }
    for (head, length) in [(0usize, 0usize), (1, 0), (0, 1)] {
        let result = unsafe { libc::syscall(libc::SYS_get_robust_list, 0, head, length) };
        results.push(
            result
                .os_result()
                .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO)),
        );
    }
    Ok(results)
}

fn initialize(shared: bool, pi: bool) -> ProbeResult<Mapping> {
    let mapping = Mapping::new(4096, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1)?;
    let mut attribute = MaybeUninit::<libc::pthread_mutexattr_t>::uninit();
    check(
        unsafe { libc::pthread_mutexattr_init(attribute.as_mut_ptr()) },
        0,
    )?;
    let mut attribute = unsafe { attribute.assume_init() };
    let result = (|| {
        check(
            unsafe {
                libc::pthread_mutexattr_setrobust(&raw mut attribute, libc::PTHREAD_MUTEX_ROBUST)
            },
            0,
        )?;
        check(
            unsafe { libc::pthread_mutexattr_setpshared(&raw mut attribute, i32::from(shared)) },
            0,
        )?;
        if pi {
            check(
                unsafe {
                    libc::pthread_mutexattr_setprotocol(
                        &raw mut attribute,
                        libc::PTHREAD_PRIO_INHERIT,
                    )
                },
                0,
            )?;
        }
        check(
            unsafe { libc::pthread_mutex_init(mapping.ptr.cast(), &raw const attribute) },
            0,
        )
    })();
    let destroyed = unsafe { libc::pthread_mutexattr_destroy(&raw mut attribute) };
    result?;
    check(destroyed, 0)?;
    Ok(mapping)
}

fn timed_lock(pointer: usize) -> ProbeResult<i32> {
    timed_lock_for(pointer, 1)
}

fn timed_lock_for(pointer: usize, seconds: u8) -> ProbeResult<i32> {
    let mut timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &raw mut timeout) }.os_result()?;
    timeout.tv_sec += i64::from(seconds);
    Ok(unsafe {
        libc::pthread_mutex_timedlock(pointer as *mut libc::pthread_mutex_t, &raw const timeout)
    })
}

fn recover(pointer: usize, consistent: bool) -> ProbeResult<()> {
    check(timed_lock(pointer)?, libc::EOWNERDEAD)?;
    if consistent {
        check(
            unsafe { libc::pthread_mutex_consistent(pointer as *mut _) },
            0,
        )?;
    }
    check(unsafe { libc::pthread_mutex_unlock(pointer as *mut _) }, 0)?;
    let expected = if consistent { 0 } else { libc::ENOTRECOVERABLE };
    check(timed_lock(pointer)?, expected)?;
    if consistent {
        check(unsafe { libc::pthread_mutex_unlock(pointer as *mut _) }, 0)?;
    }
    check(unsafe { libc::pthread_mutex_destroy(pointer as *mut _) }, 0)
}

fn thread_death(shared: bool, pi: bool, consistent: bool) -> ProbeResult<()> {
    let mapping = initialize(shared, pi)?;
    let pointer = mapping.ptr.addr();
    let parent = query(0)?;
    let owner = std::thread::spawn(move || {
        let locked = unsafe { libc::pthread_mutex_lock(pointer as *mut _) };
        let registered = query(0).map(|head| (head.0 != 0) == kernel_list(shared) && head.1 == 24);
        (locked, registered)
    });
    let (locked, registered) = owner
        .join()
        .map_err(|_| ProbeError::broken("robust owner panicked"))?;
    check(locked, 0)?;
    if !registered? || query(0)? != parent {
        return Err(ProbeError::broken(
            "robust registration is not thread-local",
        ));
    }
    recover(pointer, consistent)
}

fn killed_owner() -> ProbeResult<Result<bool, i32>> {
    let mapping = initialize(true, false)?;
    let mut descriptors = [-1; 2];
    unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) }.os_result()?;
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let pid = unsafe { libc::fork() }.os_result()?;
    if pid == 0 {
        let locked = unsafe { libc::pthread_mutex_lock(mapping.ptr.cast()) };
        let ready = u8::from(locked == 0);
        let wrote = unsafe { libc::write(writer.as_raw_fd(), (&raw const ready).cast(), 1) };
        if ready == 0 || wrote != 1 {
            unsafe { libc::_exit(1) }
        }
        loop {
            std::hint::spin_loop();
        }
    }
    drop(writer);
    let mut ready = 0u8;
    let read = unsafe { libc::read(reader.as_raw_fd(), (&raw mut ready).cast(), 1) };
    // Always reap the child, including a failed setup.
    let queried = query(pid)
        .map(|head| head.0 != 0 && head.1 == 24)
        .map_err(|error| match error {
            ProbeError::Denied(error) | ProbeError::Broken(error) => {
                error.raw_os_error().unwrap_or(libc::EIO)
            }
        });
    let killed = unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
    killed.os_result()?;
    if read != 1
        || ready != 1
        || queried == Ok(false)
        || !libc::WIFSIGNALED(status)
        || libc::WTERMSIG(status) != libc::SIGKILL
    {
        return Err(ProbeError::broken(
            "killed robust owner was not registered or reaped",
        ));
    }
    recover(mapping.ptr.addr(), true)?;
    Ok(queried)
}

/// A hand-built list of three locks with the second one pending, whose last
/// node links to the head or, if `faulting`, to an unmapped address. Its
/// owner is killed, and each lock reports whether the kernel released it.
fn killed_list(faulting: bool) -> ProbeResult<[bool; 3]> {
    const NODES: [usize; 3] = [64, 128, 192];
    const OFFSET: usize = 1024;
    let mapping = Mapping::new(4096, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1)?;
    let base = mapping.ptr.addr();
    let word =
        |offset: usize| unsafe { &*std::ptr::with_exposed_provenance::<AtomicU32>(base + offset) };
    let link = |offset: usize, value: usize| {
        unsafe { std::ptr::with_exposed_provenance_mut::<usize>(base + offset).write(value) };
    };
    // The first link carries the PI bit, which must not change the outcome.
    link(0, (base + NODES[0]) | 1);
    link(8, OFFSET);
    link(16, base + NODES[1]);
    link(NODES[0], base + NODES[1]);
    link(NODES[1], base + NODES[2]);
    link(NODES[2], if faulting { 8 } else { base });
    let (reader, writer) = pipe()?;
    let pid = unsafe { libc::fork() }.os_result()?;
    if pid == 0 {
        let tid = u32::try_from(unsafe { libc::gettid() }).unwrap_or(0);
        for node in NODES {
            word(node + OFFSET).store(tid, Ordering::Release);
        }
        let ready = u8::from(register(base, 24).is_ok());
        let wrote = unsafe { libc::write(writer.as_raw_fd(), (&raw const ready).cast(), 1) };
        if ready == 0 || wrote != 1 {
            unsafe { libc::_exit(1) }
        }
        loop {
            std::hint::spin_loop();
        }
    }
    drop(writer);
    let mut ready = 0u8;
    let read = unsafe { libc::read(reader.as_raw_fd(), (&raw mut ready).cast(), 1) };
    let killed = unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
    killed.os_result()?;
    if read != 1 || ready != 1 || !libc::WIFSIGNALED(status) {
        return Err(ProbeError::broken("hand-built list owner was not killed"));
    }
    Ok(NODES.map(|node| word(node + OFFSET).load(Ordering::Acquire) == FUTEX_OWNER_DIED))
}

fn pipe() -> ProbeResult<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) }.os_result()?;
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

/// Waits until a waiter has marked both locks contended, then replaces the
/// image, whose report goes to `output` and which runs until `hold` closes.
/// Runs in a forked child, so it never returns.
fn exec_contended(locks: [usize; 2], output: OwnedFd, hold: OwnedFd) -> ! {
    let contended = |lock: usize| {
        let word = unsafe { &*std::ptr::with_exposed_provenance::<AtomicU32>(lock + LOCK_WORD) };
        word.load(Ordering::Acquire) & FUTEX_WAITERS != 0
    };
    while !locks.into_iter().all(contended) {
        std::thread::sleep(Duration::from_millis(1));
    }
    if let Ok(args) = Probe::from(SysProbe::AfterRobustExec).argv() {
        let _ = Command::new(SysProbe::SELF_EXE)
            .args(args)
            .stdin(Stdio::from(hold))
            .stdout(Stdio::from(output))
            .exec();
    }
    unsafe { libc::_exit(1) }
}

/// Owners of two contended locks exec: the leader holds the first and, from
/// a second thread if `from_thread`, the exec caller holds the second. The
/// replaced image outlives the waiters, so exec itself must release the locks.
fn exec_owner(from_thread: bool, pi: bool) -> ProbeResult<[i32; 2]> {
    let first = initialize(true, pi)?;
    let second = initialize(true, pi)?;
    let locks = [first.ptr.addr(), second.ptr.addr()];
    let (reader, writer) = pipe()?;
    let (hold, release) = pipe()?;
    let pid = unsafe { libc::fork() }.os_result()?;
    if pid == 0 {
        drop(reader);
        drop(release);
        // The pipe signals readiness, then takes the replaced image's report.
        let lock_and_exec = move || {
            let ready = 1u8;
            if unsafe { libc::pthread_mutex_lock(locks[1] as *mut _) } == 0
                && unsafe { libc::write(writer.as_raw_fd(), (&raw const ready).cast(), 1) } == 1
            {
                exec_contended(locks, writer, hold);
            }
            unsafe { libc::_exit(1) }
        };
        if unsafe { libc::pthread_mutex_lock(locks[0] as *mut _) } != 0 {
            unsafe { libc::_exit(1) }
        }
        if !from_thread {
            lock_and_exec();
        }
        std::thread::spawn(lock_and_exec);
        loop {
            std::thread::park();
        }
    }
    drop(writer);
    drop(hold);
    let mut ready = 0u8;
    let read = unsafe { libc::read(reader.as_raw_fd(), (&raw mut ready).cast(), 1) };
    let results = if read == 1 {
        let waiters = locks.map(|lock| std::thread::spawn(move || timed_lock_for(lock, 2)));
        Some(waiters.map(std::thread::JoinHandle::join))
    } else {
        None
    };
    drop(release);
    // The reader stays open until the replaced image has reported.
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
    let Some([Ok(first), Ok(second)]) = results else {
        return Err(ProbeError::broken("exec owner did not take its locks"));
    };
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(ProbeError::broken("exec owner did not replace its image"));
    }
    Ok([first?, second?])
}

pub(super) fn run() -> ProbeResult<Vec<u8>> {
    let errors =
        registration().map_err(|error| ProbeError::broken(&format!("registration: {error:?}")))?;
    for shared in [false, true] {
        for pi in [false, true] {
            for consistent in [false, true] {
                thread_death(shared, pi, consistent).map_err(|error| {
                    ProbeError::broken(&format!("thread {shared}/{pi}/{consistent}: {error:?}"))
                })?;
            }
        }
    }
    let mut exec = Vec::new();
    for from_thread in [false, true] {
        for pi in [false, true] {
            exec.push(exec_owner(from_thread, pi).map_err(|error| {
                ProbeError::broken(&format!("exec owner {from_thread}/{pi}: {error:?}"))
            })?);
        }
    }
    let query =
        killed_owner().map_err(|error| ProbeError::broken(&format!("killed owner: {error:?}")))?;
    let lists = [false, true].map(killed_list);
    Ok(format!("robust registration is thread-local; private/shared and PI mutexes recover or become unrecoverable; exec owners (leader, thread) x (plain, PI) end {exec:?}; SIGKILL releases a shared owner; cross-process query {query:?}; killed hand-built lists (ending, faulting) release {lists:?}; errors {errors:?}").into_bytes())
}
