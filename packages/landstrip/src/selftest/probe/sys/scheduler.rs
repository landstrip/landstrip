// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Read-only CPU, scheduler and process-accounting queries, compared with the host.

use super::super::proc::Mapping;
use super::{OsResult, ProbeError, ProbeResult};
use std::io;
use std::time::{Duration, Instant};

fn answer(result: libc::c_long) -> Result<libc::c_long, i32> {
    result
        .os_result()
        .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
}

/// One writable output page followed by an inaccessible guard page.
fn output_pages() -> ProbeResult<(Mapping, usize)> {
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.os_result()?)
        .map_err(io::Error::other)?;
    let pages = Mapping::new(2 * page, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1)?;
    unsafe { libc::mprotect(pages.ptr.byte_add(page), page, libc::PROT_NONE) }.os_result()?;
    Ok((pages, page))
}

pub(super) fn cpu() -> ProbeResult<Vec<u8>> {
    let allowed =
        nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0)).map_err(io::Error::from)?;
    for (with_cpu, with_node) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut cpu = u32::MAX;
        let mut node = u32::MAX;
        let cpu_ptr = if with_cpu {
            &raw mut cpu
        } else {
            std::ptr::null_mut()
        };
        let node_ptr = if with_node {
            &raw mut node
        } else {
            std::ptr::null_mut()
        };
        // Linux ignores the obsolete third argument, even when it is not a valid pointer.
        unsafe { libc::syscall(libc::SYS_getcpu, cpu_ptr, node_ptr, usize::MAX) }.os_result()?;
        if (with_cpu && !allowed.is_set(cpu as usize).map_err(io::Error::from)?)
            || (with_node && node == u32::MAX)
        {
            return Err(ProbeError::broken(
                "getcpu did not initialize its requested outputs",
            ));
        }
    }
    let cpu =
        usize::try_from(unsafe { libc::sched_getcpu() }.os_result()?).map_err(io::Error::other)?;
    if !allowed.is_set(cpu).map_err(io::Error::from)? {
        return Err(ProbeError::broken(
            "sched_getcpu returned a CPU outside the affinity mask",
        ));
    }

    let (pages, page) = output_pages()?;
    let mut errors = Vec::new();
    for address in [
        1,
        usize::MAX,
        pages.ptr.addr() + page,
        pages.ptr.addr() + page - 2,
    ] {
        let mut cpu = u32::MAX;
        let mut node = u32::MAX;
        let result = unsafe { libc::syscall(libc::SYS_getcpu, address, &raw mut node, 0usize) };
        errors.push((answer(result), false, node != u32::MAX));
        let result = unsafe { libc::syscall(libc::SYS_getcpu, &raw mut cpu, address, 0usize) };
        errors.push((answer(result), cpu != u32::MAX, false));
    }
    unsafe { libc::mprotect(pages.ptr, page, libc::PROT_READ) }.os_result()?;
    errors.push((
        answer(unsafe {
            libc::syscall(
                libc::SYS_getcpu,
                pages.ptr,
                std::ptr::null_mut::<u32>(),
                0usize,
            )
        }),
        false,
        false,
    ));
    errors.push((
        answer(unsafe {
            libc::syscall(
                libc::SYS_getcpu,
                std::ptr::null_mut::<u32>(),
                pages.ptr,
                0usize,
            )
        }),
        false,
        false,
    ));
    Ok(
        format!("CPU and node outputs initialized; affinity respected; output errors {errors:?}")
            .into_bytes(),
    )
}

fn interval(pid: libc::pid_t) -> ProbeResult<()> {
    let mut slice = libc::timespec {
        tv_sec: -1,
        tv_nsec: -1,
    };
    unsafe { libc::syscall(libc::SYS_sched_rr_get_interval, pid, &raw mut slice) }.os_result()?;
    if slice.tv_sec < 0 || !(0..1_000_000_000).contains(&slice.tv_nsec) {
        return Err(ProbeError::broken(
            "sched_rr_get_interval returned an invalid timespec",
        ));
    }
    Ok(())
}

pub(super) fn priority() -> ProbeResult<Vec<u8>> {
    let mut ranges = Vec::new();
    for policy in [
        libc::SCHED_OTHER,
        libc::SCHED_FIFO,
        libc::SCHED_RR,
        libc::SCHED_BATCH,
        libc::SCHED_IDLE,
        libc::SCHED_DEADLINE,
    ] {
        let low = unsafe { libc::sched_get_priority_min(policy) }.os_result()?;
        let high = unsafe { libc::sched_get_priority_max(policy) }.os_result()?;
        if low > high {
            return Err(ProbeError::broken("scheduler priority range is reversed"));
        }
        ranges.push((low, high));
    }
    let mut errors = Vec::new();
    for policy in [-1, i32::MAX, libc::SCHED_FIFO | libc::SCHED_RESET_ON_FORK] {
        errors.push(answer(unsafe {
            libc::syscall(libc::SYS_sched_get_priority_min, policy)
        }));
        errors.push(answer(unsafe {
            libc::syscall(libc::SYS_sched_get_priority_max, policy)
        }));
    }
    interval(0)?;
    interval(unsafe { libc::getpid() })?;
    std::thread::spawn(|| {
        interval(0)?;
        interval(unsafe { libc::gettid() })?;
        interval(unsafe { libc::getpid() })
    })
    .join()
    .map_err(|_| ProbeError::broken("scheduler query thread panicked"))??;

    let mut slice = libc::timespec {
        tv_sec: -1,
        tv_nsec: -1,
    };
    for pid in [-1, i32::MAX] {
        errors.push(answer(unsafe {
            libc::syscall(libc::SYS_sched_rr_get_interval, pid, &raw mut slice)
        }));
    }
    let (pages, page) = output_pages()?;
    for address in [
        0,
        1,
        usize::MAX,
        pages.ptr.addr() + page,
        pages.ptr.addr() + page - std::mem::size_of::<libc::timespec>() + 1,
    ] {
        errors.push(answer(unsafe {
            libc::syscall(libc::SYS_sched_rr_get_interval, 0, address)
        }));
    }
    unsafe { libc::mprotect(pages.ptr, page, libc::PROT_READ) }.os_result()?;
    errors.push(answer(unsafe {
        libc::syscall(libc::SYS_sched_rr_get_interval, 0, pages.ptr)
    }));
    Ok(
        format!("priority ranges {ranges:?}; main/thread intervals valid; query errors {errors:?}")
            .into_bytes(),
    )
}

struct Accounting {
    elapsed: libc::clock_t,
    cpu: [libc::clock_t; 4],
}

impl Accounting {
    fn read() -> ProbeResult<Self> {
        let mut output = libc::tms {
            tms_utime: -1,
            tms_stime: -1,
            tms_cutime: -1,
            tms_cstime: -1,
        };
        let elapsed = unsafe { libc::syscall(libc::SYS_times, &raw mut output) }.os_result()?;
        let cpu = [
            output.tms_utime,
            output.tms_stime,
            output.tms_cutime,
            output.tms_cstime,
        ];
        if cpu.iter().any(|&ticks| ticks < 0) {
            return Err(ProbeError::broken(
                "times did not initialize its CPU counters",
            ));
        }
        Ok(Self { elapsed, cpu })
    }

    fn follows(&self, before: &Self) -> bool {
        self.elapsed >= before.elapsed
            && self
                .cpu
                .iter()
                .zip(before.cpu)
                .all(|(&after, before)| after >= before)
    }

    fn own(&self) -> libc::clock_t {
        self.cpu[0] + self.cpu[1]
    }

    fn children(&self) -> libc::clock_t {
        self.cpu[2] + self.cpu[3]
    }
}

fn thread_cpu() -> ProbeResult<i128> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut time) }.os_result()?;
    Ok(i128::from(time.tv_sec) * 1_000_000_000 + i128::from(time.tv_nsec))
}

/// Consume three accounting ticks, bounded by a separate wall-clock deadline.
fn burn_ticks(hz: libc::c_long) -> ProbeResult {
    let start = thread_cpu()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while thread_cpu()? - start < 3_000_000_000 / i128::from(hz) {
        for value in 0_u64..4096 {
            std::hint::black_box(value.wrapping_mul(1_234_567));
        }
        if Instant::now() >= deadline {
            return Err(ProbeError::broken("CPU accounting workload timed out"));
        }
    }
    Ok(())
}

fn own_accounting(hz: libc::c_long) -> ProbeResult {
    let before = Accounting::read()?;
    burn_ticks(hz)?;
    let after = Accounting::read()?;
    if !after.follows(&before) || after.own() <= before.own() {
        return Err(ProbeError::broken(
            "times did not account for the running process/thread",
        ));
    }
    Ok(())
}

fn child_accounting(hz: libc::c_long) -> ProbeResult {
    // Reap twice: the second child must reset nonzero parental child counters.
    for _ in 0..2 {
        let before = Accounting::read()?;
        let child = unsafe { libc::fork() }.os_result()?;
        if child == 0 {
            let checked = (|| {
                if Accounting::read()?.children() != 0 {
                    return Err(ProbeError::broken("fork inherited child CPU accounting"));
                }
                own_accounting(hz)
            })();
            unsafe { libc::_exit(i32::from(checked.is_err())) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(child, &raw mut status, 0) }.os_result()?;
        let after = Accounting::read()?;
        if !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 0
            || !after.follows(&before)
            || after.children() <= before.children()
        {
            return Err(ProbeError::broken("times lost the waited child's CPU time"));
        }
    }
    Ok(())
}

pub(super) fn times() -> ProbeResult<Vec<u8>> {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.os_result()?;
    if hz <= 0 {
        return Err(ProbeError::broken("invalid accounting clock frequency"));
    }
    own_accounting(hz)?;
    let before = Accounting::read()?;
    std::thread::spawn(move || own_accounting(hz))
        .join()
        .map_err(|_| ProbeError::broken("CPU accounting thread panicked"))??;
    let after = Accounting::read()?;
    if !after.follows(&before) || after.own() <= before.own() {
        return Err(ProbeError::broken(
            "times lost the joined thread's CPU time",
        ));
    }

    child_accounting(hz)?;
    let before = Accounting::read()?;
    let elapsed =
        unsafe { libc::syscall(libc::SYS_times, std::ptr::null_mut::<libc::tms>()) }.os_result()?;
    if !(before.elapsed..=Accounting::read()?.elapsed).contains(&elapsed) {
        return Err(ProbeError::broken(
            "times(NULL) returned an inconsistent elapsed time",
        ));
    }

    let (pages, page) = output_pages()?;
    let mut errors = Vec::new();
    for address in [1, usize::MAX, pages.ptr.addr() + page] {
        errors.push(answer(unsafe { libc::syscall(libc::SYS_times, address) }).map(|_| ()));
    }
    let word = size_of::<libc::clock_t>();
    let mut writes = Vec::new();
    for words in 1..=4 {
        let output = unsafe {
            pages
                .ptr
                .byte_add(page - words * word)
                .cast::<libc::clock_t>()
        };
        unsafe { output.write_bytes(0xff, words) };
        let result = if words == 4 {
            // glibc's times wrapper does not translate syscall errors into errno.
            // Exercise it only with a valid output, bounding its clock result.
            let before = Accounting::read()?;
            let elapsed = unsafe { libc::times(output.cast()) };
            if !(before.elapsed..=Accounting::read()?.elapsed).contains(&elapsed) {
                return Err(ProbeError::broken(
                    "libc times returned an inconsistent elapsed time",
                ));
            }
            Ok(())
        } else {
            answer(unsafe { libc::syscall(libc::SYS_times, output) }).map(|_| ())
        };
        let changed: Vec<_> = (0..words)
            .map(|i| unsafe { output.add(i).read() } != -1)
            .collect();
        writes.push((result, changed));
    }
    let output = unsafe { pages.ptr.byte_add(1).cast::<libc::tms>() };
    unsafe { libc::syscall(libc::SYS_times, output) }.os_result()?;
    let output = unsafe { output.read_unaligned() };
    if [
        output.tms_utime,
        output.tms_stime,
        output.tms_cutime,
        output.tms_cstime,
    ]
    .iter()
    .any(|&ticks| ticks < 0)
    {
        return Err(ProbeError::broken(
            "times did not initialize an unaligned output",
        ));
    }
    unsafe { pages.ptr.write_bytes(0xff, size_of::<libc::tms>()) };
    unsafe { libc::mprotect(pages.ptr, page, libc::PROT_READ) }.os_result()?;
    errors.push(answer(unsafe { libc::syscall(libc::SYS_times, pages.ptr) }).map(|_| ()));
    if unsafe { std::slice::from_raw_parts(pages.ptr.cast::<u8>(), size_of::<libc::tms>()) }
        .iter()
        .any(|&byte| byte != 0xff)
    {
        return Err(ProbeError::broken("times modified a read-only output"));
    }
    Ok(format!("monotonic counters; main/joined-thread/waited-child CPU time; null/unaligned output; errors {errors:?}; boundary writes {writes:?}").into_bytes())
}
