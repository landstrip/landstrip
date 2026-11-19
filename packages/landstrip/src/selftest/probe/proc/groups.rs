// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! An outside sentinel shares the launcher's group, never the test runner's.

use super::super::{Probe, ProbeReply};
use super::{OsResult, ProbeError, ProbeResult, ProcProbe};
use nix::sys::signal::{SigSet, Signal};
use std::io::{self, Write};
use std::process::{Command, Stdio};

fn priority() -> io::Result<libc::c_long> {
    unsafe { libc::syscall(libc::SYS_getpriority, libc::PRIO_PROCESS, 0) }.os_result()
}

fn io_priority() -> io::Result<libc::c_long> {
    unsafe { libc::syscall(libc::SYS_ioprio_get, 1, 0) }.os_result()
}

fn block_signal() -> io::Result<()> {
    let mut set = SigSet::empty();
    set.add(Signal::SIGUSR1);
    set.thread_block().map_err(io::Error::from)
}

fn pending() -> io::Result<bool> {
    let mut set = *SigSet::empty().as_ref();
    unsafe { libc::sigpending(&raw mut set) }.os_result()?;
    Ok(unsafe { libc::sigismember(&raw const set, libc::SIGUSR1) }.os_result()? == 1)
}

pub(super) fn guard(target: ProcProbe) -> ProbeResult {
    // SandboxContext gives this disposable native worker its own group. Do not
    // run the potentially leaking operation if it could reach the test runner.
    if unsafe { libc::getpgrp() } != unsafe { libc::getpid() } {
        return Err(ProbeError::broken(
            "group sentinel is not its own group leader",
        ));
    }
    block_signal()?;
    let before = priority()?;
    let before_io = io_priority()?;
    let exe = std::env::current_exe()?;
    let args = Probe::from(target)
        .argv()
        .map_err(|error| ProbeError::broken(&error.to_string()))?;
    let mut child = Command::new(&exe)
        .args(["run", "--policy-format", "json", "-p", "-", "--"])
        .arg(&exe)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let sent = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing policy input"))
        .and_then(|mut stdin| stdin.write_all(br#"{"filesystem":{"allowRead":["/"]}}"#));
    let output = child.wait_with_output()?;
    sent?;
    if priority()? != before {
        return Err(ProbeError::broken(
            "guest group priority changed the outside sentinel",
        ));
    }
    if io_priority()? != before_io {
        return Err(ProbeError::broken(
            "guest I/O priority changed the outside sentinel",
        ));
    }
    if pending()? {
        return Err(ProbeError::broken(
            "guest group signal reached the outside sentinel",
        ));
    }
    let reply = ProbeReply::try_from(output.stdout.as_slice()).map_err(|error| {
        ProbeError::broken(&format!(
            "{error}; status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    })?;
    if !output.status.success() || !matches!(reply, ProbeReply::Allowed { .. }) {
        return Err(ProbeError::broken(&format!(
            "group target failed: {reply:?}"
        )));
    }
    Ok(())
}

pub(super) fn target(signal: bool) -> ProbeResult {
    if signal {
        block_signal()?;
        unsafe { libc::kill(0, libc::SIGUSR1) }.os_result()?;
        if !pending()? {
            return Err(ProbeError::broken("group signal did not reach its sender"));
        }
    } else {
        let nice = (21 - priority()?).min(19);
        let nice = i32::try_from(nice).map_err(io::Error::other)?;
        unsafe { libc::setpriority(libc::PRIO_PGRP, 0, nice) }.os_result()?;
        if priority()? != libc::c_long::from(20 - nice) {
            return Err(ProbeError::broken(
                "group priority did not change its sender",
            ));
        }
    }
    Ok(())
}

pub(super) fn io_target(user: bool) -> ProbeResult {
    // Linux 6.12 resolves USER/0 literally, unlike the current-user query.
    // Use the mapped UID for user-wide updates, and both group selectors.
    let (which, selectors) = if user {
        (3, vec![unsafe { libc::getuid() }.cast_signed()])
    } else {
        (2, vec![0, unsafe { libc::getpgrp() }])
    };
    for who in selectors {
        for priority in [(2 << 13) | 4, 3 << 13] {
            unsafe { libc::syscall(libc::SYS_ioprio_set, which, who, priority) }
                .os_result()
                .map_err(|error| {
                    ProbeError::broken(&format!("ioprio_set({which}, {who}, {priority}): {error}"))
                })?;
            if io_priority()? != libc::c_long::from(priority) {
                return Err(ProbeError::broken(
                    "I/O priority selector did not change its sender",
                ));
            }
        }
    }
    Ok(())
}
