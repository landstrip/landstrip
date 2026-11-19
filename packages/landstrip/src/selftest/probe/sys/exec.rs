// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::{OsResult, Probe, ProbeError, ProbeResult, SysCheck, SysProbe};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

impl SysCheck {
    pub(super) fn thread_exec(self, dir: &Path) -> ProbeResult<Vec<u8>> {
        match self {
            Self::ExecFailures => return Self::exec_failures(dir),
            Self::ExecFromThread | Self::ExecAfterLeaderExit | Self::ExecThreadState => {
                let barrier = Arc::new(std::sync::Barrier::new(2));
                let ready = Arc::clone(&barrier);
                let exited = Arc::new(AtomicU32::new(unsafe { libc::gettid() }.cast_unsigned()));
                let executable = std::env::current_exe()?;
                if self == Self::ExecAfterLeaderExit {
                    unsafe { libc::syscall(libc::SYS_set_tid_address, exited.as_ptr()) }
                        .os_result()?;
                }
                let leader = Arc::clone(&exited);
                std::thread::spawn(move || {
                    ready.wait();
                    if self == Self::ExecAfterLeaderExit {
                        loop {
                            let tid = leader.load(Ordering::Acquire);
                            if tid == 0 {
                                break;
                            }
                            unsafe {
                                libc::syscall(
                                    libc::SYS_futex,
                                    leader.as_ptr(),
                                    libc::FUTEX_WAIT,
                                    tid,
                                    std::ptr::null::<libc::timespec>(),
                                );
                            }
                        }
                    }
                    let result =
                        Self::replace_thread_image(self == Self::ExecThreadState, &executable);
                    let code = super::super::ProbeReply::from(result).send();
                    let code = io::stdout().flush().map_or(1, |()| code);
                    unsafe { libc::_exit(code) }
                });
                barrier.wait();
                if self == Self::ExecAfterLeaderExit {
                    unsafe {
                        libc::syscall(libc::SYS_exit, 0);
                    }
                }
                loop {
                    std::thread::park();
                }
            }
            Self::ExecCompeting => {
                let barrier = Arc::new(std::sync::Barrier::new(3));
                for _ in 0..2 {
                    let ready = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        ready.wait();
                        let result =
                            Self::replace_thread_image(false, Path::new(SysProbe::SELF_EXE));
                        let code = super::super::ProbeReply::from(result).send();
                        let code = io::stdout().flush().map_or(1, |()| code);
                        unsafe { libc::_exit(code) }
                    });
                }
                barrier.wait();
                loop {
                    std::thread::park();
                }
            }
            Self::ExecCloneRace => {
                let barrier = Arc::new(std::sync::Barrier::new(2));
                let ready = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    ready.wait();
                    loop {
                        match std::thread::Builder::new().spawn(|| {}) {
                            Ok(worker) => {
                                if worker.join().is_err() {
                                    unsafe { libc::_exit(1) }
                                }
                            }
                            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {
                                std::thread::yield_now();
                            }
                            Err(_) => unsafe { libc::_exit(1) },
                        }
                    }
                });
                barrier.wait();
            }
            Self::ExecBlockedRead | Self::ExecBlockedFutex | Self::ExecBlockedPoll => {
                self.blocked_exec_sibling()?;
            }
            _ => return Err(ProbeError::broken("not a thread exec check")),
        }
        Self::replace_thread_image(false, Path::new(SysProbe::SELF_EXE))
    }

    fn blocked_exec_sibling(self) -> ProbeResult<()> {
        let mut pipe = [0; 2];
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) }.os_result()?;
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        std::thread::spawn(move || {
            let mask = u64::MAX;
            let result = unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    &raw const mask,
                    std::ptr::null_mut::<u64>(),
                    8,
                )
            };
            if result < 0 || tx.send(()).is_err() {
                unsafe { libc::_exit(1) }
            }
            match self {
                Self::ExecBlockedRead => {
                    let mut byte = 0u8;
                    unsafe {
                        libc::read(pipe[0], (&raw mut byte).cast(), 1);
                    }
                }
                Self::ExecBlockedFutex => {
                    let word = AtomicU32::new(0);
                    unsafe {
                        libc::syscall(
                            libc::SYS_futex,
                            word.as_ptr(),
                            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                            0,
                            std::ptr::null::<libc::timespec>(),
                        );
                    }
                }
                _ => {
                    let mut poll = libc::pollfd {
                        fd: pipe[0],
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe {
                        libc::syscall(
                            libc::SYS_ppoll,
                            &raw mut poll,
                            1,
                            std::ptr::null::<libc::timespec>(),
                            &raw const mask,
                            8,
                        );
                    }
                }
            }
            unsafe { libc::_exit(2) }
        });
        rx.recv_timeout(Duration::from_secs(3))
            .map_err(|_| ProbeError::broken("blocked exec sibling did not start"))?;
        Ok(())
    }

    fn replace_thread_image(check_signals: bool, executable: &Path) -> ProbeResult<Vec<u8>> {
        let file = std::fs::File::open("/dev/null")?;
        let keep = file.as_raw_fd();
        unsafe { libc::fcntl(keep, libc::F_SETFD, 0) }.os_result()?;
        let closed = unsafe { libc::fcntl(keep, libc::F_DUPFD_CLOEXEC, keep + 1) }.os_result()?;
        if check_signals {
            unsafe {
                libc::signal(libc::SIGUSR1, libc::SIG_IGN);
                libc::signal(
                    libc::SIGUSR2,
                    Self::on_alarm as *const () as libc::sighandler_t,
                );
                libc::signal(
                    libc::SIGWINCH,
                    Self::on_alarm as *const () as libc::sighandler_t,
                );
                let mask = (1u64 << (libc::SIGUSR2 - 1))
                    | (1u64 << (libc::SIGWINCH - 1))
                    | (1u64 << (libc::SIGRTMIN() - 1));
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    &raw const mask,
                    std::ptr::null_mut::<u64>(),
                    8,
                );
                libc::raise(libc::SIGWINCH);
                for _ in 0..96 {
                    libc::raise(libc::SIGRTMIN()).os_result()?;
                }
            }
        }
        let probe = Probe::from(SysProbe::AfterThreadExec {
            pid: unsafe { libc::getpid() },
            keep,
            closed,
            check_signals,
        });
        let arguments = probe
            .argv()
            .map_err(|_| ProbeError::broken("encode exec report"))?;
        Err(Command::new(executable)
            .args(arguments)
            .env("LANDSTRIP_THREAD_EXEC", "preserved")
            .exec()
            .into())
    }

    fn exec_failures(dir: &Path) -> ProbeResult<Vec<u8>> {
        let malformed = dir.join("exec-malformed");
        let noexec = dir.join("exec-not-executable");
        std::fs::write(&malformed, b"not an ELF image")?;
        std::fs::set_permissions(&malformed, std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(&noexec, b"not executable")?;
        std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o600))?;
        let running = Arc::new(AtomicBool::new(true));
        let counter = Arc::new(AtomicU32::new(0));
        let active = Arc::clone(&running);
        let count = Arc::clone(&counter);
        let worker = std::thread::spawn(move || {
            while active.load(Ordering::Acquire) {
                count.fetch_add(1, Ordering::Release);
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let mut errors = Vec::new();
        for path in [
            dir.join("exec-missing"),
            noexec.clone(),
            malformed.clone(),
            Path::new(SysProbe::SELF_EXE).to_path_buf(),
        ] {
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| ProbeError::broken("NUL in exec path"))?;
            let arguments = [name.as_ptr(), std::ptr::null()];
            let argv = if path == Path::new(SysProbe::SELF_EXE) {
                std::ptr::dangling::<*const libc::c_char>()
            } else {
                arguments.as_ptr()
            };
            unsafe {
                libc::execve(name.as_ptr(), argv, std::ptr::null());
            }
            errors.push(io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        let before = counter.load(Ordering::Acquire);
        let deadline = Instant::now() + Duration::from_secs(3);
        while counter.load(Ordering::Acquire) == before && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let survived = counter.load(Ordering::Acquire) > before;
        running.store(false, Ordering::Release);
        worker
            .join()
            .map_err(|_| ProbeError::broken("exec failure sibling panicked"))?;
        std::fs::remove_file(malformed)?;
        std::fs::remove_file(noexec)?;
        if !survived {
            return Err(ProbeError::broken("failed exec stopped its sibling"));
        }
        Ok(format!("failed exec errno {errors:?}; sibling survives").into_bytes())
    }
}

impl SysProbe {
    pub(super) fn after_thread_exec(
        pid: i32,
        keep: i32,
        closed: i32,
        check_signals: bool,
    ) -> ProbeResult<Vec<u8>> {
        let identity = unsafe { libc::getpid() == pid && libc::gettid() == pid };
        let descriptors = unsafe {
            libc::fcntl(keep, libc::F_GETFD) >= 0 && libc::fcntl(closed, libc::F_GETFD) == -1
        };
        let environment = std::env::var("LANDSTRIP_THREAD_EXEC").as_deref() == Ok("preserved");
        if !identity || !descriptors || !environment {
            return Err(ProbeError::broken(
                "exec lost identity, descriptors or environment",
            ));
        }
        if check_signals {
            let mut mask = 0u64;
            let mut pending = 0u64;
            let mut ignored: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut caught: libc::sigaction = unsafe { std::mem::zeroed() };
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    std::ptr::null::<u64>(),
                    &raw mut mask,
                    8,
                );
                libc::syscall(libc::SYS_rt_sigpending, &raw mut pending, 8);
                libc::sigaction(libc::SIGUSR1, std::ptr::null(), &raw mut ignored);
                libc::sigaction(libc::SIGUSR2, std::ptr::null(), &raw mut caught);
            }
            let realtime = 1u64 << (libc::SIGRTMIN() - 1);
            let expected =
                (1u64 << (libc::SIGUSR2 - 1)) | (1u64 << (libc::SIGWINCH - 1)) | realtime;
            if mask != expected
                || pending & (1u64 << (libc::SIGWINCH - 1)) == 0
                || ignored.sa_sigaction != libc::SIG_IGN
                || caught.sa_sigaction != libc::SIG_DFL
            {
                return Err(ProbeError::broken("exec lost caller signal state"));
            }
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            for _ in 0..96 {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let signal = unsafe {
                    libc::syscall(
                        libc::SYS_rt_sigtimedwait,
                        &raw const realtime,
                        &raw mut info,
                        &raw const timeout,
                        8,
                    )
                }
                .os_result()?;
                if signal != i64::from(libc::SIGRTMIN()) || info.si_code != libc::SI_TKILL {
                    return Err(ProbeError::broken("exec lost queued realtime signals"));
                }
            }
        }
        Ok(b"exec preserves identity, descriptors, environment and caller signal state".to_vec())
    }
}
