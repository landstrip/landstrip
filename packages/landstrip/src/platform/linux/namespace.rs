// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::platform::unix::close_inherited_fds;
use anyhow::{Context, Result, bail, ensure};
use nix::errno::Errno;
use nix::mount::{MsFlags, mount};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::prctl;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, getgid, getpid, getuid};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

pub(super) enum ForkResult {
    Parent { child: Pid },
    Child(NamespaceChild),
}

pub(super) struct Launch {
    uid: libc::uid_t,
    gid: libc::gid_t,
    broker: OwnedFd,
}

impl Launch {
    pub(super) fn new() -> Result<Self> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0_u32) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open broker pidfd");
        }
        let broker = unsafe { OwnedFd::from_raw_fd(RawFd::try_from(fd)?) };
        Ok(Self {
            uid: getuid().as_raw(),
            gid: getgid().as_raw(),
            broker,
        })
    }

    /// # Safety
    /// The launcher must be single-threaded, and the child must exec or _exit.
    pub(super) unsafe fn fork(self) -> Result<ForkResult> {
        let pid = unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::SIGCHLD,
                0_usize,
                0_usize,
                0_usize,
                0_usize,
            )
        };
        if pid < 0 {
            return Err(std::io::Error::last_os_error()).context("clone sandbox namespaces");
        }
        if pid == 0 {
            Ok(ForkResult::Child(NamespaceChild {
                uid: self.uid,
                gid: self.gid,
                broker: self.broker,
            }))
        } else {
            Ok(ForkResult::Parent {
                child: Pid::from_raw(libc::pid_t::try_from(pid)?),
            })
        }
    }
}

pub(super) struct NamespaceChild {
    uid: libc::uid_t,
    gid: libc::gid_t,
    broker: OwnedFd,
}

impl NamespaceChild {
    pub(super) fn spawn_tool(self, retained: &[RawFd]) -> Result<()> {
        ensure!(getpid() == Pid::from_raw(1), "namespace child is not PID 1");
        prctl::set_pdeathsig(Signal::SIGKILL).context("set namespace parent-death signal")?;
        self.wait_for_broker()?;
        nix::unistd::setsid().context("isolate sandbox session and process group")?;
        self.configure_id_maps()?;
        mount_filesystems()?;
        drop_capabilities()?;
        prctl::set_no_new_privs().context("set namespace no_new_privs")?;
        prctl::set_dumpable(true).context("restore broker ptrace access")?;

        let signals = InitSignals::install()?;
        // SAFETY: namespace init is single-threaded; the tool child execs or _exits.
        match unsafe { nix::unistd::fork() }.context("fork namespace tool")? {
            nix::unistd::ForkResult::Child => {
                prctl::set_pdeathsig(Signal::SIGKILL)
                    .context("set namespace parent-death signal")?;
                ensure!(unsafe { libc::getppid() } == 1, "namespace init exited");
                signals.restore()?;
                Ok(())
            }
            nix::unistd::ForkResult::Parent { child } => {
                prctl::set_dumpable(false).context("protect namespace init from ptrace")?;
                close_inherited_fds(retained, &[]).context("close namespace init descriptors")?;
                signals.reap(child)
            }
        }
    }

    fn wait_for_broker(&self) -> Result<()> {
        let mut pfd = [PollFd::new(self.broker.as_fd(), PollFlags::POLLIN)];
        loop {
            match poll(&mut pfd, PollTimeout::ZERO) {
                Ok(0) => break Ok(()),
                Ok(_) => bail!("broker exited before namespace setup"),
                Err(Errno::EINTR) => {}
                Err(error) => return Err(error).context("check broker pidfd"),
            }
        }
    }

    fn configure_id_maps(&self) -> Result<()> {
        fs::write("/proc/self/setgroups", "deny").context("deny namespace setgroups")?;
        fs::write(
            "/proc/self/uid_map",
            format!("{} {} 1\n", self.uid, self.uid),
        )
        .context("map namespace uid")?;
        fs::write(
            "/proc/self/gid_map",
            format!("{} {} 1\n", self.gid, self.gid),
        )
        .context("map namespace gid")
    }
}

fn mount_filesystems() -> Result<()> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("make mount propagation private")?;

    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount namespace procfs")
}

fn drop_capabilities() -> Result<()> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    for capability in 0..64 {
        let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) };
        if present < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(error).context("read namespace capability bounding set");
        }
        if present != 0 {
            Errno::result(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) })
                .map(drop)
                .context("drop namespace capability bounding set")?;
        }
    }
    Errno::result(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    })
    .map(drop)
    .context("clear namespace ambient capabilities")?;

    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [0_u32; 6];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error())
            .context("clear namespace process capabilities");
    }
    Ok(())
}

const INIT_SIGNALS: [Signal; 5] = [
    Signal::SIGTERM,
    Signal::SIGINT,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGCHLD,
];

extern "C" fn init_signal_noop(_: libc::c_int) {}

struct InitSignals {
    set: SigSet,
    old_mask: SigSet,
    old_actions: Vec<(Signal, SigAction)>,
}

impl InitSignals {
    fn install() -> Result<Self> {
        let mut set = SigSet::empty();
        for &sig in &INIT_SIGNALS {
            set.add(sig);
        }
        let mut old_mask = SigSet::empty();
        signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&set), Some(&mut old_mask))
            .context("block init signals")?;

        let action = SigAction::new(
            SigHandler::Handler(init_signal_noop),
            SaFlags::empty(),
            SigSet::empty(),
        );
        let mut old_actions = Vec::with_capacity(INIT_SIGNALS.len());
        for &sig in &INIT_SIGNALS {
            let prev = unsafe { signal::sigaction(sig, &action) }
                .context("install namespace init signal handler")?;
            old_actions.push((sig, prev));
        }

        Ok(Self {
            set,
            old_mask,
            old_actions,
        })
    }

    fn restore(&self) -> Result<()> {
        for &(sig, ref old) in &self.old_actions {
            unsafe { signal::sigaction(sig, old) }.context("restore tool signal handler")?;
        }
        signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&self.old_mask), None)
            .context("restore tool signal mask")
    }

    fn reap(&self, main: Pid) -> Result<()> {
        loop {
            loop {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(pid, code)) if pid == main => unsafe {
                        libc::_exit(code)
                    },
                    Ok(WaitStatus::Signaled(pid, sig, _)) if pid == main => unsafe {
                        libc::_exit(128 + sig as i32)
                    },
                    Ok(WaitStatus::StillAlive) => break,
                    Ok(_) | Err(Errno::EINTR) => {}
                    Err(error) => return Err(error).context("reap namespace children"),
                }
            }
            let sig = self.set.wait().context("wait for namespace init signal")?;
            if sig != Signal::SIGCHLD {
                let _ = signal::kill(Pid::from_raw(-1), sig);
            }
        }
    }
}

pub(super) fn probe() -> Result<()> {
    let launch = Launch::new()?;
    let (reader, writer) = UnixStream::pair().context("create namespace probe channel")?;
    let mut reader = File::from(OwnedFd::from(reader));
    let mut writer = File::from(OwnedFd::from(writer));
    // SAFETY: the launcher probes before starting threads; every child _exits.
    match unsafe { launch.fork() }? {
        ForkResult::Child(child) => {
            drop(reader);
            let result = child.spawn_tool(&[writer.as_raw_fd()]);
            let code = match result {
                Ok(()) => 0,
                Err(error) => {
                    if write!(writer, "{error:#}").is_ok() {
                        1
                    } else {
                        2
                    }
                }
            };
            unsafe { libc::_exit(code) }
        }
        ForkResult::Parent { child } => {
            drop(writer);
            let mut message = String::new();
            let received = reader.read_to_string(&mut message);
            let status = loop {
                match waitpid(child, None) {
                    Err(Errno::EINTR) => {}
                    result => break result.context("wait for namespace probe"),
                }
            }?;
            received.context("read namespace probe result")?;
            if !message.is_empty() {
                bail!("namespace probe: {message}");
            }
            ensure!(
                matches!(status, WaitStatus::Exited(_, 0)),
                "namespace probe failed: {status:?}"
            );
            Ok(())
        }
    }
}
