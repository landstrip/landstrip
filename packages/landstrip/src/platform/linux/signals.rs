// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::Error;
use anyhow::{Context, Result};
use nix::sys::signal::{self, SigSet, SigmaskHow, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::unistd::Pid;
use std::os::fd::{AsFd, BorrowedFd};

const FORWARDED_SIGNALS: [Signal; 4] = [
    Signal::SIGTERM,
    Signal::SIGINT,
    Signal::SIGHUP,
    Signal::SIGQUIT,
];

/// Forwards termination signals to the payload. The signalfd also receives
/// `SIGCHLD`, which only wakes the caller for child and tracee stops.
pub(super) struct ForwardSignals {
    child: Pid,
    sfd: SignalFd,
    old_mask: SigSet,
}

impl ForwardSignals {
    pub(super) fn new(child: Pid) -> Result<Self> {
        let mut mask = SigSet::empty();
        for &sig in &FORWARDED_SIGNALS {
            mask.add(sig);
        }
        mask.add(Signal::SIGCHLD);
        let mut old_mask = SigSet::empty();
        signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&mask), Some(&mut old_mask))
            .context("block forwarded signals")?;

        let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
            .inspect_err(|_| {
                if let Err(error) =
                    signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&old_mask), None)
                {
                    log::error!("restore forwarded signal mask: {error}");
                }
            })
            .context("create signalfd")?;

        Ok(Self {
            child,
            sfd,
            old_mask,
        })
    }

    pub(super) fn as_fd(&self) -> BorrowedFd<'_> {
        self.sfd.as_fd()
    }

    pub(super) fn process_pending(&mut self) -> Result<()> {
        while let Some(info) = self.sfd.read_signal().map_err(Error::supervise)? {
            if let Ok(sig) = Signal::try_from(info.ssi_signo.cast_signed())
                && FORWARDED_SIGNALS.contains(&sig)
            {
                let _ = signal::kill(self.child, sig);
            }
        }
        Ok(())
    }
}

impl Drop for ForwardSignals {
    fn drop(&mut self) {
        if let Err(error) = signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&self.old_mask), None)
        {
            log::error!("restore forwarded signal mask: {error}");
        }
    }
}
