// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Registration gates barriers, survives thread creation and resets on exec.

use super::{OsResult, Probe, ProbeError, ProbeResult, SysProbe};
use std::os::unix::process::CommandExt;
use std::process::Command;

fn call(command: i32, flags: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_membarrier, command, flags, 0) }
        .os_result()
        .unwrap_or_else(|error| -i64::from(error.raw_os_error().unwrap_or(libc::EIO)))
}

pub(super) fn run() -> ProbeResult<Vec<u8>> {
    let supported = call(0, 0);
    if supported < 0 {
        return Err(ProbeError::broken(&format!(
            "membarrier query failed: {supported}"
        )));
    }
    let mut observations = vec![supported, call(512, 0)];
    for command in [-1, 3, 1024] {
        observations.push(call(command, 0));
    }
    observations.push(call(0, 1));
    for (execute, register) in [(2, 4), (8, 16), (32, 64), (128, 256)] {
        if supported & i64::from(execute | register) != i64::from(execute | register) {
            continue;
        }
        observations.push(call(execute, 0));
        observations.push(call(register, 1));
        let result = call(register, 0);
        observations.push(result);
        if result != 0 {
            return Err(ProbeError::broken("membarrier registration failed"));
        }
        observations.push(call(register, 0));
        observations.push(call(512, 0));
        let worker = std::thread::spawn(move || call(execute, 0));
        let result = worker
            .join()
            .map_err(|_| ProbeError::broken("barrier worker panicked"))?;
        if result != 0 {
            return Err(ProbeError::broken(
                "registered barrier failed in another thread",
            ));
        }
        observations.push(result);
    }
    inherited_by_fork()?;
    let args = Probe::from(SysProbe::AfterMembarrierExec { observations })
        .argv()
        .map_err(|_| ProbeError::broken("cannot encode barrier exec probe"))?;
    Err(Command::new(SysProbe::SELF_EXE).args(args).exec().into())
}

/// A forked child shares no memory but inherits every registration.
fn inherited_by_fork() -> ProbeResult<()> {
    let registrations = call(512, 0);
    let pid = unsafe { libc::fork() }.os_result()?;
    if pid == 0 {
        let usable = [(8, 16), (32, 64), (128, 256)]
            .into_iter()
            .all(|(execute, register)| registrations & register == 0 || call(execute, 0) == 0);
        let code = i32::from(call(512, 0) != registrations || !usable);
        unsafe { libc::_exit(code) }
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) }.os_result()?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(ProbeError::broken(
            "fork did not inherit membarrier registrations",
        ));
    }
    Ok(())
}

pub(super) fn after_exec(observations: &[i64]) -> ProbeResult<Vec<u8>> {
    let registrations = call(512, 0);
    if registrations != 0 && registrations != -i64::from(libc::EINVAL) {
        return Err(ProbeError::broken("membarrier registrations survived exec"));
    }
    for command in [8, 32, 128] {
        if call(0, 0) & i64::from(command) != 0 && call(command, 0) != -i64::from(libc::EPERM) {
            return Err(ProbeError::broken(
                "private barrier remained registered after exec",
            ));
        }
    }
    Ok(format!("barriers gated by process registration, shared with threads, inherited by fork, reset by exec; observations {observations:?}").into_bytes())
}
