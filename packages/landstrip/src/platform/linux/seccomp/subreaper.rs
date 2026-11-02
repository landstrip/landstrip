// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::Error as LandstripError;
use anyhow::Result;
use nix::errno::Errno;
use nix::sys::prctl;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

pub(super) struct Subreaper {
    restore_needed: bool,
    cleanup_pending: bool,
    listener: Option<OwnedFd>,
}

impl Subreaper {
    pub(super) fn acquire() -> Result<Self> {
        let was_subreaper =
            prctl::get_child_subreaper().map_err(LandstripError::supervise_errno)?;
        if !was_subreaper {
            prctl::set_child_subreaper(true).map_err(LandstripError::supervise_errno)?;
        }
        Ok(Self {
            restore_needed: !was_subreaper,
            cleanup_pending: false,
            listener: None,
        })
    }

    pub(super) fn track_descendants(&mut self) {
        self.cleanup_pending = true;
    }

    pub(super) fn retain_listener(&mut self, listener: OwnedFd) -> BorrowedFd<'_> {
        let listener: &OwnedFd = self.listener.insert(listener);
        listener.as_fd()
    }

    pub(super) fn finish(mut self) -> Result<()> {
        self.teardown()
    }

    fn teardown(&mut self) -> Result<()> {
        let cleanup = if mem::take(&mut self.cleanup_pending) {
            Self::cleanup_descendants()
        } else {
            Ok(())
        };
        let restore = if mem::take(&mut self.restore_needed) {
            prctl::set_child_subreaper(false)
                .map_err(LandstripError::supervise_errno)
                .map_err(Into::into)
        } else {
            Ok(())
        };
        if cleanup.is_err()
            && let Err(error) = &restore
        {
            log::error!("restore subreaper: {error:#}");
        }
        cleanup.and(restore)
    }

    fn child_pids() -> Result<Vec<Pid>> {
        let children =
            fs::read_to_string("/proc/thread-self/children").map_err(LandstripError::supervise)?;
        children
            .split_whitespace()
            .map(|pid| {
                pid.parse::<i32>().map(Pid::from_raw).map_err(|error| {
                    LandstripError::supervise(io::Error::new(io::ErrorKind::InvalidData, error))
                        .into()
                })
            })
            .collect()
    }

    fn cleanup_descendants() -> Result<()> {
        loop {
            let children = Self::child_pids()?;
            if children.is_empty() {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Err(Errno::ECHILD) => return Ok(()),
                    Ok(_) | Err(Errno::EINTR) => continue,
                    Err(error) => return Err(LandstripError::supervise_errno(error).into()),
                }
            }

            let mut kill_error = None;
            for child in children {
                // SAFETY: child came from the kernel's direct-child list.
                if unsafe { libc::kill(child.as_raw(), libc::SIGKILL) } == -1 {
                    let error = Errno::last();
                    if error != Errno::ESRCH && kill_error.is_none() {
                        kill_error = Some(error);
                    }
                }
            }
            if let Some(error) = kill_error {
                return Err(LandstripError::supervise_errno(error).into());
            }

            loop {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => break,
                    Ok(_) | Err(Errno::EINTR) => {}
                    Err(error) => return Err(LandstripError::supervise_errno(error).into()),
                }
            }
            std::thread::yield_now();
        }
    }
}

impl Drop for Subreaper {
    fn drop(&mut self) {
        if let Err(error) = self.teardown() {
            log::error!("subreaper teardown: {error:#}");
        }
    }
}
