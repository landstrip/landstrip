// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use nix::errno::Errno;
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BrokerError {
    AddressFamilyNotSupported,
    BadAddress,
    BadFileDescriptor,
    InvalidAddress,
    NameTooLong,
    PolicyDenied,
    SystemCall { errno: i32 },
}

impl BrokerError {
    pub(crate) const fn syscall(errno: i32) -> Self {
        Self::SystemCall { errno }
    }

    pub(crate) fn errno(self) -> i32 {
        match self {
            Self::PolicyDenied => libc::EACCES,
            Self::AddressFamilyNotSupported => libc::EAFNOSUPPORT,
            Self::InvalidAddress => libc::EINVAL,
            Self::BadFileDescriptor => libc::EBADF,
            Self::BadAddress => libc::EFAULT,
            Self::NameTooLong => libc::ENAMETOOLONG,
            Self::SystemCall { errno } => errno,
        }
    }
}

impl From<Errno> for BrokerError {
    fn from(errno: Errno) -> Self {
        Self::SystemCall {
            errno: errno as i32,
        }
    }
}

impl From<io::Error> for BrokerError {
    fn from(error: io::Error) -> Self {
        Self::SystemCall {
            errno: error.raw_os_error().unwrap_or(libc::EIO),
        }
    }
}

impl From<std::ffi::NulError> for BrokerError {
    fn from(_: std::ffi::NulError) -> Self {
        Self::InvalidAddress
    }
}

impl From<std::str::Utf8Error> for BrokerError {
    fn from(_: std::str::Utf8Error) -> Self {
        Self::InvalidAddress
    }
}

impl From<std::num::TryFromIntError> for BrokerError {
    fn from(_: std::num::TryFromIntError) -> Self {
        Self::InvalidAddress
    }
}

pub(crate) type SysResult<T> = std::result::Result<T, BrokerError>;
