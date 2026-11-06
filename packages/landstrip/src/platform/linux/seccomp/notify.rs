// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::grant::Grant;
use crate::error::{Error as LandstripError, Mechanism};
use crate::trap::Trap;
use anyhow::Result;
use nix::errno::Errno;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;

const SECCOMP_IOC_MAGIC: u8 = b'!';
const USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

nix::ioctl_readwrite!(
    seccomp_notif_recv,
    SECCOMP_IOC_MAGIC,
    0,
    libc::seccomp_notif
);
nix::ioctl_readwrite!(
    seccomp_notif_send,
    SECCOMP_IOC_MAGIC,
    1,
    libc::seccomp_notif_resp
);
nix::ioctl_write_ptr!(seccomp_notif_id_valid, SECCOMP_IOC_MAGIC, 2, u64);
nix::ioctl_write_ptr!(
    seccomp_notif_addfd,
    SECCOMP_IOC_MAGIC,
    3,
    libc::seccomp_notif_addfd
);

pub(super) struct NotificationResponse;

impl NotificationResponse {
    pub(super) fn success(id: u64, value: i64) -> libc::seccomp_notif_resp {
        libc::seccomp_notif_resp {
            id,
            val: value,
            error: 0,
            flags: 0,
        }
    }

    pub(super) fn continue_syscall(id: u64) -> libc::seccomp_notif_resp {
        libc::seccomp_notif_resp {
            id,
            val: 0,
            error: 0,
            flags: USER_NOTIF_FLAG_CONTINUE,
        }
    }

    pub(super) fn error(id: u64, error: i32) -> libc::seccomp_notif_resp {
        libc::seccomp_notif_resp {
            id,
            val: 0,
            error: -error.abs(),
            flags: 0,
        }
    }
}

pub(super) enum NotificationResult {
    Continue,
    Grant(Grant),
    Query(QueryDecision),
}

pub(super) struct QueryDecision {
    pub(super) query_id: u64,
    pub(super) trap: Trap,
    pub(super) grant: Option<Grant>,
}

impl NotificationResult {
    pub(super) fn grant(grant: impl Into<Grant>) -> Self {
        Self::Grant(grant.into())
    }

    pub(super) fn query(query_id: u64, trap: Trap, grant: Option<Grant>) -> Self {
        Self::Query(QueryDecision {
            query_id,
            trap,
            grant,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct NotificationChannel<'a>(BorrowedFd<'a>);

impl<'a> NotificationChannel<'a> {
    pub(super) fn new(fd: BorrowedFd<'a>) -> Self {
        Self(fd)
    }

    pub(super) fn receive(&self) -> Result<Option<libc::seccomp_notif>> {
        loop {
            // SAFETY: zero is a valid initial byte pattern for this plain kernel UAPI struct.
            let mut request = unsafe { mem::zeroed::<libc::seccomp_notif>() };
            // SAFETY: request points to writable storage for SECCOMP_IOCTL_NOTIF_RECV.
            match unsafe { seccomp_notif_recv(self.0.as_raw_fd(), ptr::addr_of_mut!(request)) } {
                Ok(_) => return Ok(Some(request)),
                Err(Errno::EINTR) => {}
                // A signal can cancel the target syscall before we receive it.
                // Return to polling so child exit and forwarded signals are still handled.
                Err(Errno::ENOENT) => return Ok(None),
                Err(error) => return Err(LandstripError::supervise_errno(error).into()),
            }
        }
    }

    pub(super) fn is_id_valid(&self, id: u64) -> Result<bool> {
        loop {
            // SAFETY: id points to initialized storage for SECCOMP_IOCTL_NOTIF_ID_VALID.
            match unsafe { seccomp_notif_id_valid(self.0.as_raw_fd(), ptr::addr_of!(id)) } {
                Ok(_) => return Ok(true),
                Err(Errno::EINTR) => {}
                Err(Errno::ENOENT) => return Ok(false),
                Err(error) => return Err(LandstripError::supervise_errno(error).into()),
            }
        }
    }

    pub(super) fn respond(&self, mut response: libc::seccomp_notif_resp) -> Result<()> {
        loop {
            // SAFETY: response points to initialized storage for SECCOMP_IOCTL_NOTIF_SEND.
            match unsafe { seccomp_notif_send(self.0.as_raw_fd(), ptr::addr_of_mut!(response)) } {
                // The target can cancel after the supervisor's final ID_VALID check.
                Ok(_) | Err(Errno::ENOENT) => return Ok(()),
                Err(Errno::EINTR) => {}
                Err(error) => return Err(LandstripError::supervise_errno(error).into()),
            }
        }
    }

    pub(super) fn add_fd(self, addfd: &libc::seccomp_notif_addfd) -> Result<()> {
        // SAFETY: addfd points to an initialized struct.
        unsafe { seccomp_notif_addfd(self.0.as_raw_fd(), addfd) }
            .map(|_| ())
            .map_err(|error| LandstripError::supervise_errno(error).into())
    }
}

fn seccomp_probe(operation: libc::c_uint, data: *mut libc::c_void) -> Result<()> {
    // SAFETY: seccomp(2) copies the operation-specific data pointer before returning.
    let rc = unsafe { libc::syscall(libc::SYS_seccomp, operation, 0, data) };
    if rc < 0 {
        return Err(
            LandstripError::sandbox_setup(Mechanism::Seccomp, io::Error::last_os_error()).into(),
        );
    }
    Ok(())
}

pub(crate) fn ensure_notification_supported() -> Result<()> {
    let mut action = libc::SECCOMP_RET_USER_NOTIF;
    seccomp_probe(
        libc::SECCOMP_GET_ACTION_AVAIL,
        ptr::addr_of_mut!(action).cast::<libc::c_void>(),
    )?;

    // SAFETY: zero is a valid initial byte pattern for this plain kernel UAPI struct.
    let mut sizes = unsafe { mem::zeroed::<libc::seccomp_notif_sizes>() };
    seccomp_probe(
        libc::SECCOMP_GET_NOTIF_SIZES,
        ptr::addr_of_mut!(sizes).cast::<libc::c_void>(),
    )
}
