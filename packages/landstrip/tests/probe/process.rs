// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::Probe;

#[cfg(target_os = "linux")]
fn landlock_abi() -> i64 {
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
pub struct SignalOutside;

impl Probe for SignalOutside {
    #[cfg(target_os = "linux")]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
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
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

/// Re-exec probe: a thread signals the main thread of the same process.
/// Exit 0 when that works. Landstrip restricts then execs, so both threads
/// share one domain and erratum 2 does not apply.
pub struct SignalThread;

impl Probe for SignalThread {
    #[cfg(target_os = "linux")]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        if landlock_abi() < 6 {
            return 0;
        }
        // SAFETY: gettid(2) has no preconditions.
        let main_tid = unsafe { libc::gettid() };
        let result = std::thread::spawn(move || {
            // SAFETY: tgkill with signal 0 only checks permission.
            unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), main_tid, 0) }
        })
        .join();
        match result {
            Ok(0) => 0,
            _ => 1,
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

pub struct IoUring;

impl Probe for IoUring {
    #[cfg(target_os = "linux")]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                1_u32,
                std::ptr::null::<libc::c_void>(),
            )
        };
        i32::from(
            result != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM),
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

pub struct Daemon;

impl Probe for Daemon {
    #[cfg(target_os = "linux")]
    fn run(&self, args: &mut std::env::ArgsOs) -> i32 {
        let pid_file = args.next();
        let lifetime = args.next();
        extern "C" fn terminated(_: i32) {
            // SAFETY: the lifetime probe deliberately exits from its signal handler.
            unsafe { libc::_exit(42) }
        }
        if lifetime.as_deref() == Some(std::ffi::OsStr::new("term"))
            && unsafe { libc::signal(libc::SIGTERM, terminated as *const () as usize) }
                == libc::SIG_ERR
        {
            return 2;
        }
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

            // Lifetime tests retain stdout as a liveness pipe, not a host PID.
            for fd in 0..=2 {
                if fd != 1 || lifetime.is_none() {
                    // SAFETY: close accepts any integer descriptor.
                    unsafe { libc::close(fd) };
                }
            }
            // SAFETY: getpid has no preconditions.
            let pid = unsafe { libc::getpid() };
            if std::fs::write(pid_file, format!("{pid}\n")).is_err() {
                // SAFETY: terminate without running duplicated cleanup.
                unsafe { libc::_exit(2) };
            }
            let byte = [1_u8];
            if lifetime.is_some() {
                // SAFETY: stdout is the lifetime observer's pipe.
                if unsafe { libc::write(1, byte.as_ptr().cast(), 1) } != 1 {
                    unsafe { libc::_exit(2) };
                }
            }
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
        let synchronized =
            unsafe { libc::read(ready[0], byte.as_mut_ptr().cast(), byte.len()) } == 1;
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
        if synchronized
            && lifetime
                .as_deref()
                .is_some_and(|mode| mode == "cancel" || mode == "term")
        {
            // SAFETY: wait for the lifetime observer to kill the sandbox broker.
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        if synchronized { 23 } else { 2 }
    }

    #[cfg(not(target_os = "linux"))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

pub struct NamespaceProc;

impl Probe for NamespaceProc {
    #[cfg(target_os = "linux")]
    fn run(&self, args: &mut std::env::ArgsOs) -> i32 {
        use std::io::{Read, Result};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::path::PathBuf;

        let host_pid = args.next();
        let alias = args.next();

        fn open_at(dir: &std::fs::File, path: &str) -> Result<std::fs::File> {
            let path = std::ffi::CString::new(path)?;
            // SAFETY: dir is live and path is NUL-terminated.
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if fd == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: openat returned a new owned descriptor.
            Ok(unsafe { std::fs::File::from_raw_fd(fd) })
        }

        fn identity(mut status: std::fs::File, tgid: i32, tid: i32) -> Result<()> {
            let mut text = String::new();
            status.read_to_string(&mut text)?;
            let field = |name: &str| -> Result<Vec<i32>> {
                text.lines()
                    .find_map(|line| line.strip_prefix(name))
                    .ok_or_else(|| std::io::Error::other(format!("missing {name}: {text}")))?
                    .split_whitespace()
                    .map(|value| value.parse().map_err(std::io::Error::other))
                    .collect()
            };
            for (name, expected) in [("Tgid:", tgid), ("Pid:", tid)] {
                if field(name)?[0] != expected {
                    return Err(std::io::Error::other(format!(
                        "{name} expected local {expected}, got {text}"
                    )));
                }
            }
            Ok(())
        }

        let result = (|| -> Result<()> {
            let host_pid: i32 = host_pid
                .and_then(|s| s.into_string().ok())
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| std::io::Error::other("host PID required"))?;
            let alias =
                PathBuf::from(alias.ok_or_else(|| std::io::Error::other("proc alias required"))?);
            // SAFETY: process ID queries have no preconditions.
            let tgid = unsafe { libc::getpid() };
            if unsafe { libc::getppid() } != 1 {
                return Err(std::io::Error::other(
                    "tool is not a child of namespace init",
                ));
            }
            let proc = std::fs::File::open(&alias)?;
            let outside = format!("{host_pid}/status");
            for root in [
                PathBuf::from("/proc"),
                alias.clone(),
                PathBuf::from("/proc/self/root/proc"),
            ] {
                match std::fs::read_to_string(root.join(&outside)) {
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                    result => {
                        return Err(std::io::Error::other(format!(
                            "host proc visibility via {}: {result:?}",
                            root.display()
                        )));
                    }
                }
            }
            match open_at(&proc, &outside) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                result => {
                    return Err(std::io::Error::other(format!(
                        "host proc via dirfd: {result:?}"
                    )));
                }
            }
            for entry in std::fs::read_dir(&alias)? {
                if entry?.file_name() == host_pid.to_string().as_str() {
                    return Err(std::io::Error::other("host PID listed in private proc"));
                }
            }
            identity(open_at(&proc, "self/status")?, tgid, tgid)?;
            let self_alias = alias.with_extension("self");
            let thread_alias = alias.with_extension("thread");
            std::os::unix::fs::symlink("/proc/self/status", &self_alias)?;
            std::os::unix::fs::symlink("/proc/thread-self/status", &thread_alias)?;
            std::thread::spawn(move || -> Result<()> {
                // SAFETY: gettid has no preconditions.
                let tid = unsafe { libc::gettid() };
                if tid == tgid {
                    return Err(std::io::Error::other(
                        "probe did not create a distinct thread",
                    ));
                }
                // /proc/self identifies the thread group, thread-self this worker.
                identity(std::fs::File::open("/proc/self/status")?, tgid, tgid)?;
                identity(std::fs::File::open(self_alias)?, tgid, tgid)?;
                identity(std::fs::File::open(thread_alias)?, tgid, tid)?;
                identity(open_at(&proc, "self/status")?, tgid, tgid)?;
                identity(
                    std::fs::File::open(alias.join("thread-self/status"))?,
                    tgid,
                    tid,
                )?;
                identity(open_at(&proc, "thread-self/status")?, tgid, tid)?;
                let thread = open_at(&proc, "thread-self")?;
                identity(open_at(&thread, "status")?, tgid, tid)?;
                identity(
                    std::fs::File::open(format!("/proc/self/fd/{}/status", thread.as_raw_fd()))?,
                    tgid,
                    tid,
                )?;
                let link = std::fs::read_link("/proc/thread-self")?;
                identity(
                    std::fs::File::open(PathBuf::from("/proc").join(link).join("status"))?,
                    tgid,
                    tid,
                )
            })
            .join()
            .map_err(|_| std::io::Error::other("proc worker panicked"))?
        })();
        match result {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("namespace proc probe: {error}");
                1
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

pub struct NamespaceNetworkDenied;

impl Probe for NamespaceNetworkDenied {
    #[cfg(target_os = "linux")]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        match std::net::UdpSocket::bind("127.0.0.1:0") {
            // The socket-family seccomp filter uses EAFNOSUPPORT for denied UDP.
            Err(error) if matches!(error.raw_os_error(), Some(libc::EAFNOSUPPORT)) => 0,
            result => {
                eprintln!("expected network permission denial, got {result:?}");
                1
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}

/// Runs outside the sandbox via launcher=. EOF on the daemon's retained stdout
/// proves death without interpreting a namespace-local PID as a host PID.
pub struct NamespaceLifetime;

impl Probe for NamespaceLifetime {
    #[cfg(target_os = "linux")]
    fn run(&self, args: &mut std::env::ArgsOs) -> i32 {
        use std::io::{Read, Result};
        use std::os::fd::AsRawFd;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let policy = args.next();
        let mode = args.next();

        let result = (|| -> Result<()> {
            let policy = std::path::PathBuf::from(
                policy.ok_or_else(|| std::io::Error::other("policy required"))?,
            );
            let mode = mode.ok_or_else(|| std::io::Error::other("lifetime mode required"))?;
            let mut child = Command::new(env!("CARGO_BIN_EXE_landstrip"))
                .arg("run")
                .arg("-p")
                .arg(&policy)
                .arg("--")
                .arg(std::env::current_exe()?)
                .arg("daemon")
                .arg(policy.with_extension("pid"))
                .arg(&mode)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let result = (|| -> Result<()> {
                let mut stdout = child.stdout.take().unwrap();
                let mut byte = [0_u8];
                let mut poll = libc::pollfd {
                    fd: stdout.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: poll points to one initialized descriptor entry.
                if unsafe { libc::poll(&mut poll, 1, 5000) } <= 0
                    || stdout.read(&mut byte)? != 1
                    || byte != [1]
                {
                    return Err(std::io::Error::other("daemon did not become ready"));
                }
                if mode == "cancel" {
                    // Kill only the broker, not its process group: descendants must
                    // die through the namespace's parent-death/lifetime machinery.
                    child.kill()?;
                }
                if mode == "term" {
                    // Signal the broker alone; the tool must receive the forwarded TERM.
                    let pid = i32::try_from(child.id()).map_err(std::io::Error::other)?;
                    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                let deadline = Instant::now() + Duration::from_secs(5);
                let status = loop {
                    if let Some(status) = child.try_wait()? {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::other("broker did not exit"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                let expected = if mode == "term" { 42 } else { 23 };
                if mode != "cancel" && status.code() != Some(expected) {
                    return Err(std::io::Error::other(format!(
                        "foreground exit was {status}, expected {expected}"
                    )));
                }
                // POLLHUP plus EOF proves even the setsid/double-fork child is gone.
                if unsafe { libc::poll(&mut poll, 1, 5000) } <= 0 || stdout.read(&mut byte)? != 0 {
                    return Err(std::io::Error::other("daemon survived broker exit"));
                }
                Ok(())
            })();
            if result.is_err() {
                // Reap the broker on failed assertions too; never signal a local PID.
                if child.try_wait()?.is_none() {
                    child.kill()?;
                }
                child.wait()?;
            }
            result
        })();
        match result {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("namespace lifetime probe: {error}");
                1
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn run(&self, _args: &mut std::env::ArgsOs) -> i32 {
        2
    }
}
