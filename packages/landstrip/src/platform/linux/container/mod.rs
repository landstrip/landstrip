// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

mod dbus;
mod error;
mod filter;
mod fs;
mod grant;
mod landlock;
mod network;
mod notify;
mod process;
mod procfs;
mod subreaper;
mod supervise;

use super::namespace::{ForkResult, Launch};
use super::signals::ForwardSignals;
use crate::error::{Error as LandstripError, Mechanism};
use crate::platform::unix::close_inherited_fds;
use crate::policy::{AccessPolicy, ReadAccess};
use crate::trap::Trap;
use crate::trap_fd::TrapFd;
use anyhow::Result;
use filter::FilterSet;
use landlock::LandlockRuleset;
use nix::errno::Errno;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg, setsockopt, sockopt};
use nix::unistd::Pid;
use notify::NotificationChannel;
use process::TargetProcess;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, IoSliceMut, Read, Write};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use subreaper::Subreaper;
use supervise::{NamespaceId, Supervisor, SyscallClass};

enum NotifyStartup<'a> {
    Ready(BorrowedFd<'a>, NamespaceId),
    Trap(String),
}

struct NotifySocket {
    socket: File,
}

impl AsRawFd for NotifySocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl NotifySocket {
    fn pair() -> Result<(Self, Self)> {
        let (parent, child) = UnixStream::pair().map_err(LandstripError::supervise)?;
        setsockopt(&parent, sockopt::PassCred, &true).map_err(LandstripError::supervise_errno)?;
        Ok((
            Self {
                socket: File::from(OwnedFd::from(parent)),
            },
            Self {
                socket: File::from(OwnedFd::from(child)),
            },
        ))
    }

    fn send_listener(&mut self, fd: BorrowedFd<'_>) -> Result<()> {
        let fd_bytes = fd.as_raw_fd().to_ne_bytes();
        let packet = [0_u8, fd_bytes[0], fd_bytes[1], fd_bytes[2], fd_bytes[3]];
        self.socket
            .write_all(&packet)
            .map_err(LandstripError::supervise)?;
        let mut ack = [0_u8];
        self.socket
            .read_exact(&mut ack)
            .map_err(LandstripError::supervise)?;
        if ack != [0] {
            return Err(LandstripError::supervise("notify: invalid acknowledgment").into());
        }
        Ok(())
    }

    fn send_trap(&mut self, trap: &Trap) -> Result<()> {
        let payload = trap.to_string();
        let length = u32::try_from(payload.len())
            .map_err(|_| LandstripError::supervise("notify: trap is too large"))?;

        self.socket
            .write_all(&[1_u8])
            .map_err(LandstripError::supervise)?;
        self.socket
            .write_all(&length.to_be_bytes())
            .map_err(LandstripError::supervise)?;
        self.socket
            .write_all(payload.as_bytes())
            .map_err(LandstripError::supervise)?;
        Ok(())
    }

    fn receive<'a>(&mut self, subreaper: &'a mut Subreaper) -> Result<NotifyStartup<'a>> {
        let mut marker = [0_u8];
        let mut iov = [IoSliceMut::new(&mut marker)];
        let mut control = nix::cmsg_space!(libc::ucred);
        let sender = loop {
            let message = match recvmsg::<()>(
                self.socket.as_raw_fd(),
                &mut iov,
                Some(&mut control),
                MsgFlags::empty(),
            ) {
                Ok(message) => message,
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(LandstripError::supervise_errno(error).into()),
            };
            let mut sender = None;
            for control in message.cmsgs().map_err(LandstripError::supervise_errno)? {
                if let ControlMessageOwned::ScmCredentials(credentials) = control {
                    sender = Some(credentials.pid());
                }
            }
            if message.bytes == 0 {
                return Err(LandstripError::supervise("notify: unexpected eof").into());
            }
            break sender;
        };

        match marker[0] {
            0 => {
                let sender = sender.ok_or_else(|| {
                    LandstripError::supervise("notify: missing sender credentials")
                })?;
                let mut number = [0_u8; mem::size_of::<RawFd>()];
                self.socket
                    .read_exact(&mut number)
                    .map_err(LandstripError::supervise)?;
                let target = TargetProcess::new(Pid::from_raw(sender));
                let notify =
                    target
                        .duplicate_fd(RawFd::from_ne_bytes(number))
                        .map_err(|error| {
                            LandstripError::supervise(io::Error::from_raw_os_error(error.errno()))
                        })?;
                let notify = subreaper.retain_listener(notify);
                let namespace = NamespaceId::try_from(&TargetProcess::new(Pid::from_raw(sender)))
                    .map_err(LandstripError::supervise)?;
                self.socket
                    .write_all(&[0_u8])
                    .map_err(LandstripError::supervise)?;
                Ok(NotifyStartup::Ready(notify, namespace))
            }
            1 => {
                let mut length = [0_u8; 4];
                self.socket
                    .read_exact(&mut length)
                    .map_err(LandstripError::supervise)?;
                let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
                if length > 1_048_576 {
                    return Err(LandstripError::supervise("notify: trap is too large").into());
                }
                let mut payload = vec![0_u8; length];
                self.socket
                    .read_exact(&mut payload)
                    .map_err(LandstripError::supervise)?;
                let trap = String::from_utf8(payload).map_err(|error| {
                    LandstripError::supervise(format!("notify: invalid trap: {error}"))
                })?;
                Ok(NotifyStartup::Trap(trap))
            }
            _ => Err(LandstripError::supervise("notify: invalid marker").into()),
        }
    }
}

pub(super) struct Sandbox;

impl Sandbox {
    pub(super) fn probe() -> Result<()> {
        LandlockRuleset::probe()?;
        NotificationChannel::ensure_supported()
    }

    pub(super) fn check_host() -> crate::error::Result<()> {
        LandlockRuleset::probe().map_err(|error| {
            LandstripError::sandbox_setup(Mechanism::Landlock, error.into_boxed_dyn_error())
        })?;
        NotificationChannel::ensure_supported().map_err(|error| {
            if let Some(LandstripError::SandboxSetupFailed { .. }) = LandstripError::find_in(&error)
            {
                LandstripError::sandbox_setup(Mechanism::Seccomp, error.to_string())
            } else {
                LandstripError::sandbox_setup(Mechanism::Seccomp, error.into_boxed_dyn_error())
            }
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "broker setup and fork branches share one lifecycle"
    )]
    pub(super) fn execute(
        policy: &AccessPolicy,
        cwd: &Path,
        tool: &OsStr,
        args: &[OsString],
        trap_fd: Option<&TrapFd>,
        inherited_fds: &[RawFd],
    ) -> Result<i32> {
        NotificationChannel::ensure_supported()?;

        let needs_filesystem = !policy.write_roots.is_empty()
            || !policy.write_denials.roots.is_empty()
            || !policy.write_denials.patterns.is_empty()
            || policy.write_denials.carveouts.has_patterns()
            || !matches!(policy.read_access, ReadAccess::Unrestricted)
            || trap_fd.is_some();

        let filters = FilterSet::new(policy, SyscallClass::notified(policy, needs_filesystem))?;
        let (mut parent, mut child_sock) = NotifySocket::pair()?;
        let launch = Launch::new().map_err(|error| {
            LandstripError::sandbox_setup(Mechanism::Namespace, error.into_boxed_dyn_error())
        })?;
        let mut subreaper = Subreaper::acquire()?;

        let fork_result = unsafe { launch.fork() }.map_err(|error| {
            LandstripError::sandbox_setup(Mechanism::Namespace, error.into_boxed_dyn_error())
        })?;
        match fork_result {
            ForkResult::Child(child) => {
                drop(parent);
                let mut handed_off = false;

                let result = (|| -> Result<()> {
                    child.spawn_tool(&[]).map_err(|error| {
                        LandstripError::sandbox_setup(
                            Mechanism::Namespace,
                            error.into_boxed_dyn_error(),
                        )
                    })?;
                    std::env::set_current_dir(cwd)
                        .map_err(|error| LandstripError::launch(tool, error))?;
                    LandlockRuleset::try_from(policy)?.enforce()?;

                    {
                        let notify = filters.install()?;
                        child_sock.send_listener(notify.as_fd())?;
                        handed_off = true;
                    }

                    let mut excluded = vec![child_sock.as_raw_fd()];
                    if let Some(trap_fd) = trap_fd {
                        excluded.push(trap_fd.as_raw_fd());
                    }
                    close_inherited_fds(&excluded, inherited_fds)
                        .map_err(LandstripError::supervise)?;

                    let mut child_tool = Command::new(tool);
                    child_tool.args(args);

                    let error = child_tool.exec();
                    Err(LandstripError::launch(tool, error).into())
                })();

                if let Err(error) = result {
                    let trap = Trap::from(&error);
                    if handed_off || child_sock.send_trap(&trap).is_err() {
                        trap.emit_with_fd(trap_fd);
                    }
                }

                unsafe { libc::_exit(127) }
            }
            ForkResult::Parent { child } => {
                subreaper.track_descendants();
                drop(child_sock);
                let mut signals = ForwardSignals::new(child)
                    .map_err(|error| LandstripError::supervise(error.into_boxed_dyn_error()))?;
                let result = (|| match parent.receive(&mut subreaper)? {
                    NotifyStartup::Ready(notify, namespace) => {
                        signals.process_pending()?;
                        Supervisor::new(
                            policy,
                            child,
                            notify,
                            needs_filesystem,
                            trap_fd,
                            namespace,
                            &mut signals,
                        )
                        .run()
                    }
                    NotifyStartup::Trap(trap) => {
                        Trap::emit_record(&trap, trap_fd);
                        Ok(1)
                    }
                })();
                drop(parent);
                subreaper.finish()?;
                result
            }
        }
    }
}
