// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::super::{
    RAM_SIZE,
    dbus::ExecProxies,
    fds::{BrokerHandle, Range, SavedFdLimits},
    handoff::{Inherited, RestartImage, SealedFile},
    payload::ExecProgram,
    policy::ExecPolicy,
    ptrace::PtraceTable,
    robust::RobustMirror,
};
use super::{
    Broker, BrokerFiles, Channel, Client, GuestFd, GuestMemory, GuestSignals, Machine,
    MqueueNamespace, PendingDenials, PreparedExec, Process, QueryState, Regs, SIGNAL_QUEUE,
    ThreadState, TrapFd,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::ffi::OsString;
use std::io::Write;
use std::os::fd::{AsFd, RawFd};
use std::os::unix::net::UnixStream;

#[derive(Deserialize, Serialize)]
pub(in super::super) struct State {
    fd_limits: SavedFdLimits,
    mqueue_device: Result<libc::dev_t, i32>,
    ptrace: RawFd,
    image: RawFd,
    error: Option<RawFd>,
    channel: [RawFd; 2],
    cancellation: [RawFd; 3],
    trap: Option<RawFd>,
    policy: ExecPolicy,
    proxies: ExecProxies,
    query: QueryState,
    seen: std::collections::HashSet<String>,
    pending: PendingDenials,
    root: bool,
    program: ExecProgram,
    invoked: OsString,
    environment: Vec<OsString>,
    signal_mask: u64,
    ignored: u64,
    signals: Vec<(u32, Vec<u8>)>,
    closed_stdio: Vec<RawFd>,
}

impl Process {
    pub(super) fn restart(
        &self,
        prepared: PreparedExec,
        image: &RestartImage,
    ) -> Result<Infallible> {
        let PreparedExec {
            invoked,
            loaded,
            environment,
            signal_mask,
            ..
        } = prepared;
        if !loaded.executable.as_os_str().is_empty() {
            self.policy.set_exe(&loaded.executable);
        }
        let mut inherit = Inherited::default();
        let error = self
            .error_pipe
            .as_ref()
            .map(|pipe| {
                let pipe = pipe
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                inherit.keep(pipe.as_fd())
            })
            .transpose()?;
        let tid = ThreadState::current_tid();
        let ignored = self.signals.ignored_mask();
        let signals = SIGNAL_QUEUE.snapshot_for_exec(tid);
        let state = State {
            fd_limits: GuestFd::save_limits(),
            mqueue_device: self.mqueue.save(),
            ptrace: self.ptrace.keep(&mut inherit)?,
            image: image.keep(&mut inherit)?,
            error,
            channel: self.denials.keep_channel(&mut inherit)?,
            cancellation: self.cancellation.exec_descriptors(&mut inherit)?,
            trap: self.denials.keep_trap(&mut inherit)?,
            policy: self.policy.exec_state(),
            proxies: self.dbus_proxies.exec_state(&mut inherit)?,
            query: self.denials.query_snapshot(),
            seen: self.denials.seen_snapshot(),
            pending: self.denials.pending_snapshot(),
            root: self.denials.is_root(),
            program: ExecProgram::save(loaded, &mut inherit)?,
            invoked,
            environment,
            signal_mask,
            ignored,
            signals,
            closed_stdio: (0..3)
                .filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } != 0)
                .collect(),
        };
        let capsule = inherit.save(&state)?;
        RobustMirror::prepare_exec(&self.machine.memory)?;
        image.exec(capsule)
    }
}

impl State {
    pub(in super::super) fn resume(capsule: RawFd) -> Result<i32> {
        ensure!(
            RestartImage::can_restart_self(),
            "broker restart requires an executable without runtime library search paths"
        );
        let state: Self = SealedFile::load_json(Inherited::adopt(capsule, 3)?)?;
        let floor = state.fd_limits.broker_base;
        GuestFd::restore_limits(state.fd_limits)?;
        let error = state
            .error
            .map(|fd| {
                Inherited::adopt(fd, floor).map(|handle| handle.map_same_fd(UnixStream::from))
            })
            .transpose()?;
        let result = state.run(error.as_ref());
        if let (Some(error_pipe), Err(error)) = (error.as_ref(), result.as_ref()) {
            let _ = write!(error_pipe.get(), "{error:#}");
        }
        result
    }

    fn run(self, error: Option<&BrokerHandle<UnixStream>>) -> Result<i32> {
        let floor = self.fd_limits.broker_base;
        let mqueue = MqueueNamespace::from_saved(self.mqueue_device);
        let ptrace = PtraceTable::from_handoff(self.ptrace, floor)?;
        let image = RestartImage::from_handoff(self.image, floor)?;
        let channel = Channel::from_exec(self.channel, floor)?;
        let cancellation = Client::from_exec(self.cancellation, floor)?;
        let trap = self
            .trap
            .map(|fd| Inherited::adopt(fd, floor).map(TrapFd::from))
            .transpose()?;
        let policy = self.policy.restore()?;
        let proxies = self.proxies.restore(floor)?;
        let loaded = self.program.restore(floor)?;
        let error_pipe = error
            .map(|stream| Process::clone_stream_above(stream.get()))
            .transpose()?;
        let (machine, vcpu) = {
            let _range = Range::occupy_unused()?;
            Machine::create(GuestMemory::new(RAM_SIZE)?)?
        };
        Self::restore_stdio(self.closed_stdio)?;
        let launch = loaded.payload.load(&machine.memory)?;
        let stack = launch.initial_stack(
            &machine.memory,
            &self.invoked,
            &loaded.arguments,
            &self.environment,
        )?;
        Machine::set_regs(vcpu.get(), &Regs::start(launch.start, stack))?;
        nix::sys::prctl::set_name(&loaded.comm).context("set resumed payload name")?;
        let mut broker = Broker::new(
            (machine, vcpu),
            &launch,
            policy,
            BrokerFiles {
                trap,
                channel,
                error_pipe,
                cancellation,
                mqueue,
                ptrace,
                restart_image: Some(image),
            },
        )?;
        let process =
            std::sync::Arc::get_mut(&mut broker.process).context("broker shared before resume")?;
        process.dbus_proxies = proxies;
        process
            .denials
            .restore_exec(self.seen, self.pending, self.query, self.root);
        process.signals.restore_ignored(self.ignored);
        let tid = ThreadState::current_tid();
        for (sig, info) in self.signals {
            ensure!((1..=64).contains(&sig), "invalid pending signal");
            let info = info
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid pending signal length"))?;
            SIGNAL_QUEUE.push(sig, tid, false, &info);
        }
        GuestSignals::set_thread_mask(self.signal_mask);
        broker.run()
    }

    fn restore_stdio(closed: Vec<RawFd>) -> Result<()> {
        for fd in closed {
            ensure!((0..3).contains(&fd), "invalid stdio descriptor");
            match nix::unistd::close(fd) {
                Ok(()) | Err(nix::errno::Errno::EBADF) => (),
                Err(error) => {
                    return Err(error).context("restore closed guest standard descriptor");
                }
            }
        }
        Ok(())
    }
}
