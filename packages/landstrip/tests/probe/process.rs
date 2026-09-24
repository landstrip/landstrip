// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#[cfg(target_os = "linux")]
pub fn landlock_abi() -> i64 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
    // SAFETY: a NULL attr with size 0 and the version flag is the documented
    // Landlock ABI query form.
    unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    }
}

/// Re-exec probe: signal the parent process. Exit 0 when Landlock denies
/// (EPERM/EACCES) or when Landlock ABI < 6 (feature unsupported),
/// 1 when the signal unexpectedly succeeds.
#[cfg(target_os = "linux")]
pub fn signal_outside_probe() -> i32 {
    if landlock_abi() < 6 {
        return 0;
    }
    // SAFETY: getppid/kill with signal 0 have no preconditions.
    let rc = unsafe { libc::kill(libc::getppid(), 0) };
    if rc == 0 {
        return 1;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => 0,
        _ => 2,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn signal_outside_probe() -> i32 {
    2
}

/// Re-exec probe: a thread signals the main thread of the same process.
/// Exit 0 when that works. Landstrip restricts then execs, so both threads
/// share one domain and erratum 2 does not apply.
#[cfg(target_os = "linux")]
pub fn signal_thread_probe() -> i32 {
    if landlock_abi() < 6 {
        return 0;
    }
    // SAFETY: gettid(2) has no preconditions.
    let main_tid = unsafe { libc::gettid() };
    let result = std::thread::spawn(move || {
        // SAFETY: tgkill with signal 0 only checks permission.
        unsafe { libc::tgkill(libc::getpid(), main_tid, 0) }
    })
    .join();
    match result {
        Ok(0) => 0,
        _ => 1,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn signal_thread_probe() -> i32 {
    2
}

#[cfg(target_os = "linux")]
pub fn io_uring_probe() -> i32 {
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            1_u32,
            std::ptr::null::<libc::c_void>(),
        )
    };
    i32::from(result != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM))
}

#[cfg(not(target_os = "linux"))]
pub fn io_uring_probe() -> i32 {
    2
}

#[cfg(target_os = "linux")]
pub fn daemon_probe(pid_file: Option<std::ffi::OsString>) -> i32 {
    let Some(pid_file) = pid_file else {
        return 2;
    };
    let mut ready = [0; 2];
    // SAFETY: ready points to two writable file-descriptor slots.
    if unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return 2;
    }

    // SAFETY: the probe is single-threaded and both children call _exit or pause.
    let first = unsafe { libc::fork() };
    if first == -1 {
        return 2;
    }
    if first == 0 {
        // SAFETY: these descriptors were returned by pipe2 above.
        unsafe { libc::close(ready[0]) };
        // SAFETY: setsid has no pointer preconditions.
        if unsafe { libc::setsid() } == -1 {
            // SAFETY: terminate without running duplicated cleanup.
            unsafe { libc::_exit(2) };
        }
        // SAFETY: this process is still single-threaded.
        let daemon = unsafe { libc::fork() };
        if daemon != 0 {
            // SAFETY: terminate the intermediate process after a successful or failed fork.
            unsafe { libc::_exit(if daemon == -1 { 2 } else { 0 }) };
        }

        // Do not keep Command::output's pipes open after landstrip exits.
        for fd in 0..=2 {
            // SAFETY: close accepts any integer descriptor.
            unsafe { libc::close(fd) };
        }
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { libc::getpid() };
        if std::fs::write(pid_file, format!("{pid}\n")).is_err() {
            // SAFETY: terminate without running duplicated cleanup.
            unsafe { libc::_exit(2) };
        }
        let byte = [1_u8];
        // SAFETY: ready[1] is open and byte points to one readable byte.
        let _ = unsafe { libc::write(ready[1], byte.as_ptr().cast(), byte.len()) };
        // SAFETY: close accepts the pipe descriptor and pause waits for cleanup's SIGKILL.
        unsafe {
            libc::close(ready[1]);
            loop {
                libc::pause();
            }
        }
    }

    // SAFETY: parent owns both pipe descriptors and the read buffer is valid.
    unsafe { libc::close(ready[1]) };
    let mut byte = [0_u8];
    // SAFETY: ready[0] is open and byte points to one writable byte.
    let synchronized = unsafe { libc::read(ready[0], byte.as_mut_ptr().cast(), byte.len()) } == 1;
    // SAFETY: close accepts the pipe descriptor.
    unsafe { libc::close(ready[0]) };
    loop {
        // SAFETY: first is this process's child and the status is intentionally discarded.
        let waited = unsafe { libc::waitpid(first, std::ptr::null_mut(), 0) };
        if waited == first {
            break;
        }
        if waited == -1 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 2;
        }
    }
    if synchronized { 23 } else { 2 }
}

#[cfg(not(target_os = "linux"))]
pub fn daemon_probe(_pid_file: Option<std::ffi::OsString>) -> i32 {
    2
}
