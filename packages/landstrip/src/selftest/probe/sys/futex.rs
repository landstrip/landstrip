// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Bounded futex state transitions, using the native kernel as the reference.

use super::{OsResult, ProbeError, ProbeResult};
use crate::selftest::probe::proc::Mapping;
use std::io;
use std::sync::atomic::AtomicU32;
use std::time::{Duration, Instant};
use syscalls::Sysno;

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Waiter {
    value: u64,
    address: u64,
    flags: u32,
    reserved: u32,
}

fn call(number: Sysno, arguments: [usize; 6]) -> Result<libc::c_long, i32> {
    unsafe {
        libc::syscall(
            number as libc::c_long,
            arguments[0],
            arguments[1],
            arguments[2],
            arguments[3],
            arguments[4],
            arguments[5],
        )
    }
    .os_result()
    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
}

fn expect(result: Result<libc::c_long, i32>, wanted: Result<libc::c_long, i32>) -> ProbeResult<()> {
    if result != wanted {
        return Err(ProbeError::broken(&format!(
            "futex transition: expected {wanted:?}, observed {result:?}"
        )));
    }
    Ok(())
}

/// How long a transition may wait for its waiters to block; generous so that
/// a loaded host does not turn a slow waiter into a lost one.
const PATIENCE: Duration = Duration::from_secs(25);

/// The waiters' own timeout, after `PATIENCE` has expired.
fn deadline() -> ProbeResult<libc::timespec> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut time) }.os_result()?;
    time.tv_sec += 60;
    Ok(time)
}

fn wake(word: &AtomicU32, private: usize, count: usize) -> Result<libc::c_long, i32> {
    call(
        Sysno::futex,
        [
            word.as_ptr().addr(),
            libc::FUTEX_WAKE as usize | private,
            count,
            0,
            0,
            0,
        ],
    )
}

fn wait(
    words: &[AtomicU32; 2],
    kind: usize,
    private: usize,
    timeout: &libc::timespec,
) -> Result<libc::c_long, i32> {
    let address = words[0].as_ptr().addr();
    let flags = 2 | u32::try_from(private).map_err(|_| libc::EINVAL)?;
    match kind {
        0 => call(
            Sysno::futex,
            [
                address,
                libc::FUTEX_WAIT_BITSET as usize | private,
                0,
                std::ptr::from_ref(timeout).addr(),
                0,
                u32::MAX as usize,
            ],
        ),
        1 => call(
            Sysno::futex_wait,
            [
                address,
                0,
                u32::MAX as usize,
                2 | private,
                std::ptr::from_ref(timeout).addr(),
                libc::CLOCK_MONOTONIC as usize,
            ],
        ),
        _ => {
            let waiters = words.each_ref().map(|word| Waiter {
                address: word.as_ptr().addr() as u64,
                flags,
                ..Waiter::default()
            });
            call(
                Sysno::futex_waitv,
                [
                    waiters.as_ptr().addr(),
                    waiters.len(),
                    0,
                    std::ptr::from_ref(timeout).addr(),
                    libc::CLOCK_MONOTONIC as usize,
                    0,
                ],
            )
        }
    }
}

fn wake_transition(kind: usize, private: usize) -> ProbeResult<()> {
    let words = [AtomicU32::new(0), AtomicU32::new(0)];
    let timeout = deadline()?;
    std::thread::scope(|scope| {
        let waiting = scope.spawn(|| wait(&words, kind, private, &timeout));
        let end = Instant::now() + PATIENCE;
        let index = usize::from(kind == 2);
        let mut awakened = false;
        while Instant::now() < end {
            let result = call(
                Sysno::futex_wake,
                [
                    words[index].as_ptr().addr(),
                    u32::MAX as usize,
                    1,
                    2 | private,
                    0,
                    0,
                ],
            );
            if result == Ok(1) {
                awakened = true;
                break;
            }
            expect(result, Ok(0))?;
            std::thread::yield_now();
        }
        let result = waiting
            .join()
            .map_err(|_| ProbeError::broken("futex waiter panicked"))?;
        if !awakened {
            return Err(ProbeError::broken(
                "futex waiter was not woken before its deadline",
            ));
        }
        expect(result, Ok(libc::c_long::from(kind == 2)))
    })
}

fn requeue_transition(private: usize) -> ProbeResult<()> {
    let flags = 2 | u32::try_from(private).map_err(io::Error::other)?;
    let words = [AtomicU32::new(0), AtomicU32::new(0)];
    let timeout = deadline()?;
    std::thread::scope(|scope| {
        let first = scope.spawn(|| wait(&words, 1, private, &timeout));
        let second = scope.spawn(|| wait(&words, 0, private, &timeout));
        let waiters = words.each_ref().map(|word| Waiter {
            address: word.as_ptr().addr() as u64,
            flags,
            ..Waiter::default()
        });
        let end = Instant::now() + PATIENCE;
        let mut moved = 0;
        while moved < 2 && Instant::now() < end {
            let result = call(
                Sysno::futex_requeue,
                [waiters.as_ptr().addr(), 0, 0, 2 - moved, 0, 0],
            )
            .map_err(io::Error::from_raw_os_error)?;
            moved += usize::try_from(result).map_err(io::Error::other)?;
            std::thread::yield_now();
        }
        // A spuriously woken waiter waits again on the futex it named, so a
        // requeued waiter may return to the first word; none may be lost.
        let mut woken = [0; 2];
        while woken[0] + woken[1] < 2 && Instant::now() < end {
            for (count, word) in woken.iter_mut().zip(&words).rev() {
                *count += wake(word, private, 2).map_err(io::Error::from_raw_os_error)?;
            }
            std::thread::yield_now();
        }
        let waits = [first, second].map(std::thread::ScopedJoinHandle::join);
        if moved != 2 || woken[1] == 0 || woken[0] + woken[1] != 2 {
            return Err(ProbeError::broken(&format!(
                "futex requeue moved {moved} waiters and woke {woken:?}"
            )));
        }
        for wait in waits {
            expect(
                wait.map_err(|_| ProbeError::broken("futex waiter panicked"))?,
                Ok(0),
            )?;
        }
        Ok(())
    })
}

fn errors() -> ProbeResult<Vec<Result<libc::c_long, i32>>> {
    let word = AtomicU32::new(1);
    let pointer = word.as_ptr().addr();
    let expired = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let invalid = libc::timespec {
        tv_sec: -1,
        tv_nsec: 1_000_000_000,
    };
    let mut results = Vec::new();
    for private in [0, libc::FUTEX_PRIVATE_FLAG as usize] {
        for address in [0, 1, 4, usize::MAX, pointer + 1] {
            results.push(call(
                Sysno::futex,
                [address, libc::FUTEX_WAIT as usize | private, 0, 0, 0, 0],
            ));
            results.push(call(
                Sysno::futex_wait,
                [address, 0, u32::MAX as usize, 2 | private, 0, 0],
            ));
        }
        for flags in [2 | private, 0, 1, 3, 4, usize::MAX] {
            results.push(call(
                Sysno::futex_wait,
                [pointer, 0, u32::MAX as usize, flags, 0, usize::MAX],
            ));
            results.push(call(
                Sysno::futex_wake,
                [pointer, u32::MAX as usize, 0, flags, 0, 0],
            ));
        }
        for clock in [
            libc::CLOCK_MONOTONIC as usize,
            libc::CLOCK_REALTIME as usize,
            usize::MAX,
        ] {
            for time in [
                0,
                1,
                std::ptr::from_ref(&expired).addr(),
                std::ptr::from_ref(&invalid).addr(),
            ] {
                results.push(call(
                    Sysno::futex_wait,
                    [pointer, 0, u32::MAX as usize, 2 | private, time, clock],
                ));
            }
        }
        results.push(call(
            Sysno::futex_wait,
            [pointer, usize::MAX, u32::MAX as usize, 2 | private, 0, 0],
        ));
        results.push(call(Sysno::futex_wait, [pointer, 0, 0, 2 | private, 0, 0]));
        results.push(call(Sysno::futex_wake, [pointer, 0, 1, 2 | private, 0, 0]));
    }
    vector_errors(pointer, results)
}

fn vector_errors(
    pointer: usize,
    mut results: Vec<Result<libc::c_long, i32>>,
) -> ProbeResult<Vec<Result<libc::c_long, i32>>> {
    let mut waiters = [Waiter {
        address: pointer as u64,
        flags: 2,
        ..Waiter::default()
    }; 2];
    for count in [0, 1, 2, 128, 129, usize::MAX] {
        // Oversized valid counts use a complete array, never adjacent stack memory.
        let array = [waiters[0]; 128];
        results.push(call(
            Sysno::futex_waitv,
            [array.as_ptr().addr(), count, 0, 0, 0, 0],
        ));
    }
    for flags in [1, usize::MAX] {
        results.push(call(Sysno::futex_waitv, [0, 1, flags, 1, usize::MAX, 0]));
        results.push(call(Sysno::futex_requeue, [0, flags, 0, 0, 0, 0]));
    }
    for (flags, reserved, value) in [(0, 0, 0), (2, 1, 0), (2, 0, u64::MAX)] {
        waiters[0].flags = flags;
        waiters[0].reserved = reserved;
        waiters[0].value = value;
        results.push(call(
            Sysno::futex_waitv,
            [waiters.as_ptr().addr(), 2, 0, 0, 0, 0],
        ));
        results.push(call(
            Sysno::futex_requeue,
            [waiters.as_ptr().addr(), 0, 0, 0, 0, 0],
        ));
    }
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.os_result()?)
        .map_err(io::Error::other)?;
    let mapping = Mapping::new(2 * page, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    unsafe { libc::mprotect(mapping.ptr.byte_add(page), page, libc::PROT_NONE) }.os_result()?;
    let edge = unsafe {
        mapping
            .ptr
            .byte_add(page - std::mem::size_of::<Waiter>())
            .cast::<Waiter>()
    };
    for flags in [0, 2] {
        unsafe {
            edge.write(Waiter {
                address: pointer as u64,
                flags,
                ..Waiter::default()
            });
        };
        results.push(call(Sysno::futex_waitv, [edge.addr(), 2, 0, 0, 0, 0]));
        results.push(call(Sysno::futex_requeue, [edge.addr(), 0, 0, 0, 0, 0]));
    }
    Ok(results)
}

pub(super) fn run() -> ProbeResult<Vec<u8>> {
    let errors = errors()?;
    for private in [0, libc::FUTEX_PRIVATE_FLAG as usize] {
        for kind in 0..3 {
            wake_transition(kind, private)?;
        }
        requeue_transition(private)?;
    }
    Ok(format!("legacy and modern futex wait/wake, vector selection and requeue conserve waiters; errors {errors:?}").into_bytes())
}
