// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Exec names are observed on the host rather than inferred from argv or ELF paths.

use super::super::ProbeReply;
use super::{OsResult, Probe, ProbeError, ProbeResult, SysProbe};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

pub(super) fn report() -> ProbeResult<Vec<u8>> {
    let mut name = [0u8; 16];
    unsafe { libc::prctl(libc::PR_GET_NAME, name.as_mut_ptr()) }.os_result()?;
    let name = CStr::from_bytes_until_nul(&name)
        .map_err(io::Error::other)?
        .to_bytes();
    let mut proc = std::fs::read("/proc/self/comm")?;
    if proc.pop() != Some(b'\n') || proc != name {
        return Err(ProbeError::broken("prctl and proc exec names disagree"));
    }
    Ok(name.to_vec())
}

pub(super) fn replace(path: &Path, via_fd: bool, threaded: bool) -> ProbeResult<Vec<u8>> {
    unsafe { libc::prctl(libc::PR_SET_NAME, c"before-exec".as_ptr()) }.os_result()?;
    if threaded {
        let path = path.to_path_buf();
        return std::thread::spawn(move || replace(&path, via_fd, false))
            .join()
            .map_err(|_| ProbeError::broken("name exec thread panicked"))?;
    }
    let args = Probe::from(SysProbe::ReportName)
        .argv()
        .map_err(|_| ProbeError::broken("encode name report"))?;
    if !via_fd {
        return Err(Command::new(path)
            .arg0("not-the-executable-name")
            .args(args)
            .exec()
            .into());
    }
    let file = std::fs::File::open(path)?;
    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) }.os_result()?;
    let args = std::iter::once("not-the-executable-name".to_owned())
        .chain(args)
        .map(CString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let never = nix::unistd::fexecve(&file, &args, &[] as &[CString]).map_err(io::Error::from)?;
    match never {}
}

fn exec_output(exe: &Path, path: &Path, via_fd: bool, threaded: bool) -> ProbeResult<Vec<u8>> {
    let args = Probe::from(SysProbe::ExecName {
        path: path.to_path_buf(),
        via_fd,
        threaded,
    })
    .argv()
    .map_err(|_| ProbeError::broken("encode name exec"))?;
    let output = Command::new(exe).args(args).output()?;
    if !output.status.success() {
        return Err(ProbeError::broken("name exec worker failed"));
    }
    Ok(output.stdout)
}

pub(super) fn run(dir: &Path) -> ProbeResult<Vec<u8>> {
    let exe = std::fs::read_link(SysProbe::SELF_EXE)?;
    let mut results = Vec::new();
    for (label, path) in [
        ("direct", exe.clone()),
        ("symlink", dir.join("compat-tool")),
        ("truncated", dir.join("12345678901234é-tool")),
    ] {
        if label != "direct" {
            if path.try_exists()? {
                std::fs::remove_file(&path)?;
            }
            std::os::unix::fs::symlink(&exe, &path)?;
        }
        for (via_fd, threaded) in [(false, false), (false, true), (true, false), (true, true)] {
            let output = exec_output(&exe, &path, via_fd, threaded)?;
            let reply: ProbeReply = serde_json::from_slice(&output).map_err(io::Error::other)?;
            match reply {
                ProbeReply::Allowed { output } => results.push((label, via_fd, threaded, output)),
                _ => return Err(ProbeError::broken(&format!("name exec: {reply:?}"))),
            }
        }
    }
    let script = dir.join("named-script");
    std::fs::write(
        &script,
        b"#!/bin/sh\nIFS= read -r name < /proc/self/comm\nprintf '%s' \"$name\"\n",
    )?;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
    for (via_fd, threaded) in [(false, false), (false, true), (true, false), (true, true)] {
        results.push((
            "script",
            via_fd,
            threaded,
            exec_output(&exe, &script, via_fd, threaded)?,
        ));
    }
    unsafe { libc::prctl(libc::PR_SET_NAME, c"kept-on-failure".as_ptr()) }.os_result()?;
    let before = report()?;
    let error = Command::new(dir.join("missing-name-target")).exec();
    if error.raw_os_error() != Some(libc::ENOENT) || report()? != before {
        return Err(ProbeError::broken("failed exec changed the process name"));
    }
    Ok(format!("exec names {results:?}; failed exec preserved name").into_bytes())
}
