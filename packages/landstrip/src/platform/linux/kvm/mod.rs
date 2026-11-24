// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! KVM sandbox backend.
//!
//! The payload runs unprivileged in a kernel-less x86-64 or AArch64 guest of
//! the host architecture. The privileged level is a stub entered by the system
//! call instruction, which exits to the VMM. Because guest and host share one
//! ABI, each trapped syscall is brokered to the host kernel with guest
//! addresses translated, instead of being emulated.
//!
//! Filesystem and network rules are mediated by the syscall broker: every path
//! the payload names is resolved against the rules before the syscall reaches
//! the host kernel, and both socket endpoints and datagram destinations are
//! checked against the network rules. System calls that reach files or the
//! network without a brokered path -- `io_uring` and the mount family -- fail
//! with `EPERM`, and the x86-64 x32 ABI is rejected because the broker cannot
//! decode its numbering.
//!
//! The payload runs in its own user, PID and mount namespaces, so it sees a
//! private `/proc` and cannot reach a host process, and it cannot reach the
//! privileged layout either, which is mapped supervisor-only.
mod cancel;
mod dbus;
pub(crate) mod fds;
mod handoff;
mod machine;
mod memory;
mod network;
mod payload;
mod policy;
mod ptrace;
mod robust;
mod service;

use super::namespace::{ForkResult, Launch};
use super::signals::ForwardSignals;
use crate::error::{Error, Mechanism};
use crate::policy::AccessPolicy;
use crate::trap_fd::TrapFd;
use anyhow::{Context, Result, bail};
use memory::GuestMemory;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const RAM_SIZE: usize = machine::ADDRESS_SPACE_SIZE;

pub(crate) trait ErrnoExt {
    fn negated(self) -> u64;
    fn from_io(error: &std::io::Error, fallback: syscalls::Errno) -> syscalls::Errno;
    fn last_os(fallback: syscalls::Errno) -> syscalls::Errno;
}

impl ErrnoExt for syscalls::Errno {
    fn negated(self) -> u64 {
        u64::from(self.into_raw().unsigned_abs()).wrapping_neg()
    }

    fn from_io(error: &std::io::Error, fallback: syscalls::Errno) -> syscalls::Errno {
        error
            .raw_os_error()
            .filter(|&code| code > 0)
            .map_or(fallback, syscalls::Errno::new)
    }

    fn last_os(fallback: syscalls::Errno) -> syscalls::Errno {
        Self::from_io(&std::io::Error::last_os_error(), fallback)
    }
}

pub(super) struct Sandbox;

impl Sandbox {
    pub(crate) fn resume_if_requested() -> Option<Result<i32>> {
        let mut args = std::env::args_os().skip(1);
        if args.next().as_deref() != Some(OsStr::new(handoff::RESUME)) {
            return None;
        }
        Some((|| {
            let number = args.next().context("missing broker handoff descriptor")?;
            anyhow::ensure!(args.next().is_none(), "unexpected broker handoff argument");
            service::RestartState::resume(
                number
                    .to_str()
                    .context("invalid broker handoff descriptor")?
                    .parse()?,
            )
        })())
    }

    pub(super) fn probe() -> Result<()> {
        machine::Machine::probe()
    }

    pub(super) fn execute(
        policy: &AccessPolicy,
        cwd: &Path,
        tool: &OsStr,
        args: &[OsString],
        trap_fd: Option<&mut TrapFd>,
        inherited: &[RawFd],
    ) -> Result<i32> {
        let path = Self::resolve(cwd, tool)?;
        let target_cwd = if cwd.is_absolute() {
            cwd.to_path_buf()
        } else {
            std::env::current_dir().map_or_else(|_| cwd.to_path_buf(), |base| base.join(cwd))
        };
        let cwd_fd = nix::fcntl::open(
            &target_cwd,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|errno| {
            Error::launch(
                path.clone(),
                std::io::Error::from_raw_os_error(errno as i32),
            )
        })?;
        let mut arguments = Vec::with_capacity(args.len() + 1);
        arguments.push(tool.to_os_string());
        arguments.extend_from_slice(args);
        let loaded = payload::LoadRequest::initial(cwd_fd.as_raw_fd(), &path, &arguments)
            .load(|_| None)
            .map_err(|error| match error {
                payload::LoadError::Io(io_err) => Error::launch(path.clone(), io_err),
                payload::LoadError::InvalidElf(elf_err) => {
                    Error::launch(path.clone(), elf_err.to_string())
                }
                payload::LoadError::Denied(_) => Error::launch(
                    path.clone(),
                    std::io::Error::from_raw_os_error(libc::EACCES),
                ),
            })?;

        let launch = Launch::new().map_err(Self::namespace_error)?;
        let (mut reader, writer) = UnixStream::pair().context("create the payload channel")?;
        let (supervisor, cancellation) = cancel::Client::pair()?;

        match unsafe { launch.fork() }.map_err(Self::namespace_error)? {
            ForkResult::Child(child) => {
                drop(reader);
                drop(supervisor);
                let code = Self::run_child(
                    child,
                    writer,
                    cwd_fd,
                    &target_cwd,
                    cwd,
                    &path,
                    &loaded,
                    policy,
                    trap_fd,
                    inherited,
                    cancellation,
                )
                .unwrap_or(127);
                unsafe { libc::_exit(code) }
            }
            ForkResult::Parent { child } => {
                drop(cwd_fd);
                drop(writer);
                drop(cancellation);
                let mut supervisor = cancel::Supervisor::new(supervisor, child.as_raw());
                let code = Self::wait_code(child, &mut supervisor)?;
                let mut message = String::new();
                reader
                    .read_to_string(&mut message)
                    .context("read the payload result")?;
                if message.is_empty() {
                    Ok(code)
                } else {
                    Err(anyhow::anyhow!("{message}"))
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_child(
        child: super::namespace::NamespaceChild,
        writer: UnixStream,
        cwd_fd: OwnedFd,
        target_cwd: &Path,
        cwd: &Path,
        path: &Path,
        loaded: &payload::LoadedProgram,
        policy: &AccessPolicy,
        trap_fd: Option<&mut TrapFd>,
        inherited: &[RawFd],
        cancellation: cancel::PendingClient,
    ) -> Result<i32> {
        fds::GuestFd::init_limits(inherited)?;
        let cancellation = cancellation.relocate_above()?;
        let writer =
            fds::GuestFd::relocate_above(OwnedFd::from(writer))?.map_same_fd(UnixStream::from);
        let cwd_fd = fds::GuestFd::relocate_above(cwd_fd)?;
        let error_pipe = writer.get().try_clone().ok().and_then(|clone| {
            fds::GuestFd::relocate_above(OwnedFd::from(clone))
                .ok()
                .map(|fd| fd.map_same_fd(UnixStream::from))
        });
        let exe_path = if loaded.executable.as_os_str().is_empty() {
            path
        } else {
            &loaded.executable
        };
        let outcome = child
            .spawn_tool(&[])
            .and_then(|()| {
                std::env::set_current_dir(target_cwd)
                    .or_else(|_| nix::unistd::fchdir(cwd_fd.as_fd()).map_err(std::io::Error::from))
                    .context("enter payload working directory")
            })
            .and_then(|()| {
                drop(cwd_fd);
                let active_cwd = std::env::current_dir().unwrap_or_else(|_| cwd.to_path_buf());
                Self::run(
                    loaded,
                    path.as_os_str(),
                    policy::Policy::new(policy, &active_cwd, exe_path),
                    trap_fd,
                    inherited,
                    error_pipe,
                    cancellation,
                )
            });
        if let Err(error) = &outcome {
            let formatted = format!("{error:#}");
            unsafe {
                let _ = libc::send(
                    writer.as_raw_fd(),
                    formatted.as_ptr().cast(),
                    formatted.len(),
                    libc::MSG_NOSIGNAL,
                );
            }
        }
        outcome
    }

    fn run(
        loaded: &payload::LoadedProgram,
        execfn: &OsStr,
        policy: policy::Policy,
        mut trap_fd: Option<&mut TrapFd>,
        inherited: &[RawFd],
        error_pipe: Option<fds::BrokerHandle<UnixStream>>,
        cancellation: cancel::Client,
    ) -> Result<i32> {
        let restart_image = handoff::RestartImage::pin()?;
        if let Some(fd) = trap_fd.as_mut() {
            fd.hide(fds::GuestFd::broker_base())?;
        }
        let broker_trap = trap_fd
            .as_deref()
            .map(|fd| fd.clone_above(fds::GuestFd::broker_base()))
            .transpose()?;
        let ptrace = ptrace::PtraceTable::new()?;
        let channel = service::Channel::new()?;
        let (machine, vcpu, mqueue) = {
            let _range = fds::Range::reserve(inherited)?;
            let mqueue = service::MqueueNamespace::probe();
            let memory = GuestMemory::new(RAM_SIZE)?;
            let (machine, vcpu) = machine::Machine::create(memory).map_err(Self::kvm_error)?;
            (machine, vcpu, mqueue)
        };
        let launch = loaded.payload.load(&machine.memory)?;
        let stack = launch.initial_stack(
            &machine.memory,
            execfn,
            &loaded.arguments,
            &payload::Launch::inherited_environment(),
        )?;
        machine::Machine::set_regs(vcpu.get(), &machine::Regs::start(launch.start, stack))?;
        nix::sys::prctl::set_name(&loaded.comm).context("set payload exec name")?;
        let broker = service::Broker::new(
            (machine, vcpu),
            &launch,
            policy,
            service::BrokerFiles {
                trap: broker_trap,
                channel,
                error_pipe,
                cancellation,
                mqueue,
                ptrace,
                restart_image,
            },
        )?;
        broker.run()
    }

    fn namespace_error(error: anyhow::Error) -> anyhow::Error {
        Error::sandbox_setup(Mechanism::Namespace, error.into_boxed_dyn_error()).into()
    }

    fn kvm_error(error: anyhow::Error) -> anyhow::Error {
        Error::sandbox_setup(Mechanism::Kvm, error.into_boxed_dyn_error()).into()
    }

    fn wait_code(child: Pid, supervisor: &mut cancel::Supervisor) -> Result<i32> {
        let outcome = Self::wait_payload(child, supervisor);
        if let Err(error) = outcome {
            if supervisor.take_exit().is_some() {
                return Err(error);
            }
            if let Err(cause) = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL)
                && cause != Errno::ESRCH
            {
                return Err(error.context(format!("kill failed payload: {cause}")));
            }
            loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) | Err(Errno::ECHILD) => {
                        break;
                    }
                    Err(Errno::EINTR) | Ok(_) => {}
                    Err(cause) => {
                        return Err(error.context(format!("reap failed payload: {cause}")));
                    }
                }
            }
            return Err(error);
        }
        outcome
    }

    fn wait_payload(child: Pid, supervisor: &mut cancel::Supervisor) -> Result<i32> {
        let mut signals = ForwardSignals::new(child)?;
        let raw = unsafe {
            syscalls::syscall!(
                syscalls::Sysno::pidfd_open,
                child.as_raw().cast_unsigned() as usize,
                0_usize
            )
        }
        .map_err(|errno| std::io::Error::from_raw_os_error(errno.into_raw()))
        .context("open child pidfd")?;
        let pidfd = unsafe { OwnedFd::from_raw_fd(RawFd::try_from(raw)?) };
        loop {
            supervisor.progress()?;
            let (exited, request) = {
                let mut fds = [
                    PollFd::new(signals.as_fd(), PollFlags::POLLIN),
                    PollFd::new(pidfd.as_fd(), PollFlags::POLLIN),
                    PollFd::new(supervisor.as_fd(), PollFlags::POLLIN),
                ];
                // `SIGCHLD` on the signalfd reports every tracee stop.
                match poll(&mut fds, PollTimeout::NONE) {
                    Ok(_) => {
                        let exited = fds[1]
                            .revents()
                            .is_some_and(|events| events.contains(PollFlags::POLLIN));
                        let request = fds[2]
                            .revents()
                            .is_some_and(|events| events.contains(PollFlags::POLLIN));
                        (exited, request)
                    }
                    Err(Errno::EINTR) => continue,
                    Err(error) => return Err(error).context("poll payload status"),
                }
            };
            if request {
                supervisor.receive()?;
            }
            signals.process_pending()?;
            if exited {
                break;
            }
        }
        if let Some(status) = supervisor.take_exit() {
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(128 + libc::WTERMSIG(status));
            }
            bail!("unexpected traced payload status: {status}");
        }
        loop {
            match waitpid(child, None) {
                Err(Errno::EINTR) => {}
                Ok(WaitStatus::Exited(_, code)) => return Ok(code),
                Ok(WaitStatus::Signaled(_, signal, _)) => return Ok(128 + signal as i32),
                Ok(status) => bail!("unexpected payload status: {status:?}"),
                Err(error) => return Err(error).context("wait for the payload"),
            }
        }
    }

    fn resolve(cwd: &Path, tool: &OsStr) -> Result<PathBuf> {
        if tool.is_empty() {
            bail!("empty program name");
        }
        let candidate = Path::new(tool);
        let path = if candidate.is_absolute() || tool.to_string_lossy().contains('/') {
            cwd.join(candidate)
        } else {
            which::which_in(tool, std::env::var_os("PATH"), cwd)
                .map_err(|error| Error::launch(cwd.join(tool), error))?
        };
        let path = std::path::absolute(&path).unwrap_or(path);
        Ok(path)
    }
}
