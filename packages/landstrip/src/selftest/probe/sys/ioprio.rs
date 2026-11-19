// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Per-thread I/O priority and inheritance, compared with the host by `compat`.

use super::{OsResult, ProbeError, ProbeResult};
use std::io;

const PROCESS: i32 = 1;
const GROUP: i32 = 2;
const USER: i32 = 3;
const BEST_EFFORT: i32 = 2 << 13;
const IDLE: i32 = 3 << 13;

fn get(which: i32, who: i32) -> io::Result<libc::c_long> {
    unsafe { libc::syscall(libc::SYS_ioprio_get, which, who) }.os_result()
}

fn set(which: i32, who: i32, priority: i32) -> io::Result<libc::c_long> {
    unsafe { libc::syscall(libc::SYS_ioprio_set, which, who, priority) }.os_result()
}

fn expect(who: i32, priority: i32) -> ProbeResult {
    if get(PROCESS, who)? != libc::c_long::from(priority) {
        return Err(ProbeError::broken("unexpected per-thread I/O priority"));
    }
    Ok(())
}

fn inheritance() -> ProbeResult {
    set(PROCESS, 0, BEST_EFFORT | 4)?;
    let main = unsafe { libc::gettid() };
    std::thread::spawn(move || {
        expect(0, BEST_EFFORT | 4)?;
        expect(unsafe { libc::gettid() }, BEST_EFFORT | 4)?;
        expect(main, BEST_EFFORT | 4)?;
        set(PROCESS, 0, IDLE)?;
        expect(0, IDLE)?;
        expect(main, BEST_EFFORT | 4)?;
        set(PROCESS, main, BEST_EFFORT | 6)?;
        expect(0, IDLE)
    })
    .join()
    .map_err(|_| ProbeError::broken("I/O priority thread panicked"))??;
    expect(0, BEST_EFFORT | 6)?;

    let child = unsafe { libc::fork() }.os_result()?;
    if child == 0 {
        let checked = (|| {
            expect(0, BEST_EFFORT | 6)?;
            set(PROCESS, 0, BEST_EFFORT | 7)?;
            expect(0, BEST_EFFORT | 7)
        })();
        unsafe { libc::_exit(i32::from(checked.is_err())) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(child, &raw mut status, 0) }.os_result()?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(ProbeError::broken(
            "child lost or shared its parent's I/O priority",
        ));
    }
    expect(0, BEST_EFFORT | 6)
}

pub(super) fn run() -> ProbeResult<Vec<u8>> {
    for priority in [IDLE, BEST_EFFORT | 4, 0] {
        set(PROCESS, 0, priority)?;
        expect(0, priority)?;
        expect(unsafe { libc::getpid() }, priority)?;
    }
    // Group/user reads may include other tasks, so compare selector aliases,
    // not their environment-dependent aggregate priority with the host's.
    for (which, who) in [
        (GROUP, unsafe { libc::getpgrp() }),
        (USER, unsafe { libc::getuid() }.cast_signed()),
    ] {
        if who <= 0 && which == GROUP {
            return Err(ProbeError::broken(
                "I/O priority group is outside the PID namespace",
            ));
        }
        if get(which, 0)? != get(which, who)? {
            return Err(ProbeError::broken("I/O priority selector aliases disagree"));
        }
    }
    inheritance()?;

    let mut errors = Vec::new();
    for (which, who) in [
        (0, 0),
        (-1, 0),
        (4, 0),
        (i32::MAX, 0),
        (PROCESS, -1),
        (GROUP, -1),
        (USER, -1),
    ] {
        for result in [get(which, who), set(which, who, BEST_EFFORT | 4)] {
            errors.push(result.map_err(|error| error.raw_os_error().unwrap_or(libc::EIO)));
        }
        expect(0, BEST_EFFORT | 6)?;
    }
    for priority in [-1, 1, 1 << 13, 7 << 13] {
        let before = get(PROCESS, 0)?;
        let result = set(PROCESS, 0, priority);
        if result.is_err() && get(PROCESS, 0)? != before {
            return Err(ProbeError::broken(
                "failed I/O priority update changed state",
            ));
        }
        errors.push(result.map_err(|error| error.raw_os_error().unwrap_or(libc::EIO)));
        set(PROCESS, 0, BEST_EFFORT | 6)?;
    }
    let high = 1_u64 << 32;
    unsafe {
        libc::syscall(
            libc::SYS_ioprio_set,
            high | 1,
            high,
            high | u64::from(IDLE.cast_unsigned()),
        )
    }
    .os_result()?;
    expect(0, IDLE)?;
    let query = unsafe { libc::syscall(libc::SYS_ioprio_get, high | 1, high) }.os_result()?;
    if query != libc::c_long::from(IDLE) {
        return Err(ProbeError::broken(
            "I/O priority arguments were not narrowed to int",
        ));
    }
    Ok(format!("self/group/user queries; updates; independent thread/fork inheritance; int ABI; invalid requests {errors:?}").into_bytes())
}
