// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Typed requests that steps send to the sandboxed `__worker`, and the
//! typed reply it writes back on stdout.

mod fs;
#[cfg(unix)]
mod net;
#[cfg(target_os = "linux")]
mod proc;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(unix)]
pub use self::fs::ChmodVia;
pub use self::fs::FsProbe;
#[cfg(target_os = "linux")]
pub use self::fs::XattrOp;
#[cfg(unix)]
pub use self::net::NetProbe;
#[cfg(target_os = "linux")]
pub use self::proc::{DaemonMode, ExitProbe, ProcProbe};
#[cfg(target_os = "linux")]
pub use self::sys::{SysCheck, SysProbe};

use super::WorkerArgs;
use super::context::RunResult;
use super::machine::Require;
use proptest::test_runner::TestCaseError;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Probe {
    Noop,
    Fs(FsProbe),
    #[cfg(unix)]
    Net(NetProbe),
    #[cfg(target_os = "linux")]
    Proc(ProcProbe),
    #[cfg(target_os = "linux")]
    Exit(ExitProbe),
    #[cfg(target_os = "linux")]
    Sys(SysProbe),
}

impl Probe {
    pub fn argv(&self) -> Result<Vec<String>, TestCaseError> {
        let encoded = serde_json::to_string(self).require("encode probe")?;
        Ok(vec![WorkerArgs::SUBCOMMAND.to_owned(), encoded])
    }

    /// Runs the probe and returns the worker's exit status. Only exit
    /// probes choose their status; everything else is in the reply.
    pub fn run(&self) -> i32 {
        let result = match self {
            Self::Noop => Ok(Vec::new()),
            Self::Fs(probe) => probe.run(),
            #[cfg(unix)]
            Self::Net(probe) => probe.run().map(|()| Vec::new()),
            #[cfg(target_os = "linux")]
            Self::Proc(probe) => probe.run().map(|()| Vec::new()),
            #[cfg(target_os = "linux")]
            Self::Exit(probe) => match probe.run() {
                Ok(code) => return code,
                Err(error) => Err(error),
            },
            #[cfg(target_os = "linux")]
            Self::Sys(probe) => probe.run(),
        };
        ProbeReply::from(result).send()
    }
}

impl FromStr for Probe {
    type Err = serde_json::Error;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(encoded)
    }
}

impl From<FsProbe> for Probe {
    fn from(probe: FsProbe) -> Self {
        Self::Fs(probe)
    }
}

#[cfg(unix)]
impl From<NetProbe> for Probe {
    fn from(probe: NetProbe) -> Self {
        Self::Net(probe)
    }
}

#[cfg(target_os = "linux")]
impl From<ProcProbe> for Probe {
    fn from(probe: ProcProbe) -> Self {
        Self::Proc(probe)
    }
}

#[cfg(target_os = "linux")]
impl From<ExitProbe> for Probe {
    fn from(probe: ExitProbe) -> Self {
        Self::Exit(probe)
    }
}

#[cfg(target_os = "linux")]
impl From<SysProbe> for Probe {
    fn from(probe: SysProbe) -> Self {
        Self::Sys(probe)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Allowed,
    Denied,
}

impl From<bool> for ProbeOutcome {
    fn from(allowed: bool) -> Self {
        if allowed { Self::Allowed } else { Self::Denied }
    }
}

impl TryFrom<&RunResult> for ProbeOutcome {
    type Error = TestCaseError;

    fn try_from(result: &RunResult) -> Result<Self, Self::Error> {
        match ProbeReply::try_from(result)? {
            ProbeReply::Allowed { .. } => Ok(Self::Allowed),
            ProbeReply::Denied { .. } => Ok(Self::Denied),
            ProbeReply::Broken { reason } => {
                Err(TestCaseError::fail(format!("probe broken: {reason}")))
            }
        }
    }
}

/// The worker's only output on stdout.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeReply {
    Allowed { output: Vec<u8> },
    Denied { errno: Option<i32> },
    Broken { reason: String },
}

impl ProbeReply {
    /// What an allowed probe produced; empty for any other reply.
    pub fn into_output(self) -> Vec<u8> {
        match self {
            Self::Allowed { output } => output,
            Self::Denied { .. } | Self::Broken { .. } => Vec::new(),
        }
    }

    fn send(&self) -> i32 {
        match serde_json::to_writer(io::stdout().lock(), self) {
            Ok(()) => 0,
            Err(error) => {
                let _ = writeln!(io::stderr(), "cannot send probe reply: {error}");
                1
            }
        }
    }
}

impl From<ProbeResult<Vec<u8>>> for ProbeReply {
    fn from(result: ProbeResult<Vec<u8>>) -> Self {
        match result {
            Ok(output) => Self::Allowed { output },
            Err(ProbeError::Denied(error)) => Self::Denied {
                errno: error.raw_os_error(),
            },
            Err(ProbeError::Broken(error)) => Self::Broken {
                reason: error.to_string(),
            },
        }
    }
}

impl TryFrom<&[u8]> for ProbeReply {
    type Error = TestCaseError;

    fn try_from(stdout: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(stdout).map_err(|error| {
            TestCaseError::fail(format!(
                "worker sent no reply ({error}): stdout={}",
                String::from_utf8_lossy(stdout)
            ))
        })
    }
}

impl TryFrom<&RunResult> for ProbeReply {
    type Error = TestCaseError;

    /// A missing reply means the worker never finished, e.g. it panicked
    /// or was killed, so the exit status and stderr are reported instead.
    fn try_from(result: &RunResult) -> Result<Self, Self::Error> {
        Self::try_from(result.stdout.as_slice()).map_err(|error| {
            TestCaseError::fail(format!(
                "{error} code={} signal={:?} stderr={}",
                result.code, result.signal, result.stderr
            ))
        })
    }
}

#[derive(Debug)]
pub enum ProbeError {
    Denied(io::Error),
    Broken(io::Error),
}

impl ProbeError {
    #[cfg(unix)]
    fn broken(reason: &str) -> Self {
        Self::Broken(io::Error::other(reason.to_owned()))
    }

    #[cfg(unix)]
    fn denied_on(errnos: &'static [i32]) -> impl FnOnce(io::Error) -> Self {
        move |error| {
            if error
                .raw_os_error()
                .is_some_and(|errno| errnos.contains(&errno))
            {
                Self::Denied(error)
            } else {
                Self::Broken(error)
            }
        }
    }
}

impl From<io::Error> for ProbeError {
    fn from(error: io::Error) -> Self {
        Self::Broken(error)
    }
}

type ProbeResult<T = ()> = Result<T, ProbeError>;

#[cfg(unix)]
trait OsResult: Sized {
    fn os_result(self) -> io::Result<Self>;
}

#[cfg(unix)]
macro_rules! impl_os_result {
    ($($ty:ty),*) => {$(
        impl OsResult for $ty {
            fn os_result(self) -> io::Result<Self> {
                if self < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(self)
                }
            }
        }
    )*};
}

#[cfg(unix)]
impl_os_result!(i32, i64, isize);

#[cfg(unix)]
trait CPath {
    fn c_path(&self) -> io::Result<std::ffi::CString>;
}

#[cfg(unix)]
impl CPath for std::path::Path {
    fn c_path(&self) -> io::Result<std::ffi::CString> {
        use std::os::unix::ffi::OsStrExt;
        Ok(std::ffi::CString::new(self.as_os_str().as_bytes())?)
    }
}
