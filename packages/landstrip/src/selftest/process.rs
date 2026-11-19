// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::context::{RunSpec, SandboxContext};
use super::machine::{Require, Step};
use super::probe::{DaemonMode, ExitProbe, Probe, ProbeOutcome, ProcProbe};
use super::state::SandboxState;
use proptest::prelude::*;
use proptest::test_runner::TestCaseResult;
use serde_json::json;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SignalAndUringIsolationCmd;

impl Arbitrary for SignalAndUringIsolationCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

impl Step for SignalAndUringIsolationCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let pol = vec![json!({
            "filesystem": { "allowRead": ["/"] },
            "network": { "allowNetwork": true }
        })];
        prop_assert_eq!(
            state.probe(&pol, ProcProbe::SignalIsolation)?,
            ProbeOutcome::Allowed,
            "signal/tgkill/io_uring isolation check failed"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NamespaceIsolationCmd;

impl Arbitrary for NamespaceIsolationCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

impl Step for NamespaceIsolationCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let pol = vec![json!({
            "filesystem": { "allowRead": ["/"] },
            "network": {}
        })];
        let probe = ProcProbe::NamespaceIsolation {
            host_pid: std::process::id(),
        };
        prop_assert_eq!(
            state.probe(&pol, probe)?,
            ProbeOutcome::Allowed,
            "PID/procfs namespace isolation check failed"
        );
        for probe in [
            ProcProbe::GroupIsolation { signal: false },
            ProcProbe::GroupIsolation { signal: true },
            ProcProbe::IoPriorityIsolation { user: false },
            ProcProbe::IoPriorityIsolation { user: true },
        ] {
            let probe = Probe::from(probe);
            let argv = probe.argv()?;
            let argv: Vec<_> = argv.iter().map(String::as_str).collect();
            let result = state.ctx.run_subcommand(&argv, None, &[]);
            prop_assert_eq!(
                ProbeOutcome::try_from(&result)?,
                ProbeOutcome::Allowed,
                "outside sentinel failed for {:?}",
                probe
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DaemonAndOrphanLifetimeCmd {
    pub mode_idx: usize,
}

impl Arbitrary for DaemonAndOrphanLifetimeCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..4usize).prop_map(|mode_idx| Self { mode_idx }).boxed()
    }
}

impl Step for DaemonAndOrphanLifetimeCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let pol_file = state.root.join("writable/lifetime_pol.json");
        let pol_json = json!({
            "filesystem": { "allowRead": ["/"], "allowWrite": ["/dev/null"] },
            "network": { "allowNetwork": true }
        });
        let _ = std::fs::write(&pol_file, pol_json.to_string());

        match self.mode_idx % 4 {
            0 => Self::verify_daemon_mode(
                &state.ctx,
                &pol_file,
                DaemonMode::Exit,
                Some(ExitProbe::DAEMON_EXIT),
            )?,
            1 => Self::verify_daemon_mode(
                &state.ctx,
                &pol_file,
                DaemonMode::Term,
                Some(ExitProbe::TERM_EXIT),
            )?,
            2 => Self::verify_daemon_mode(&state.ctx, &pol_file, DaemonMode::Cancel, None)?,
            _ => {
                let orphan_pol = vec![pol_json];
                let orphan_res = state.ctx.execute(&RunSpec::worker(
                    &state.root,
                    &orphan_pol,
                    &ExitProbe::OrphanStorm.into(),
                    &state.ctx,
                )?);
                prop_assert_eq!(
                    orphan_res.code,
                    ExitProbe::ORPHAN_EXIT,
                    "orphan storm foreground exit mismatch: {}",
                    orphan_res.stderr
                );
            }
        }
        Ok(())
    }
}

impl DaemonAndOrphanLifetimeCmd {
    fn verify_daemon_mode(
        ctx: &SandboxContext,
        pol_file: &std::path::Path,
        mode: DaemonMode,
        expected_code: Option<i32>,
    ) -> TestCaseResult {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::process::{Command, Stdio};

        let mut child = Command::new(&ctx.exe)
            .args(["run", "-p"])
            .arg(pol_file)
            .arg("--")
            .arg(&ctx.exe)
            .args(Probe::from(ExitProbe::Daemon { mode }).argv()?)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .require("spawn daemon mode")?;

        let mut stdout = child.stdout.take().require("child stdout")?;
        let mut poll_fd = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let mut ready = [0_u8; 1];
        prop_assert!(
            unsafe { libc::poll(&raw mut poll_fd, 1, 5000) } > 0
                && stdout.read(&mut ready).ok() == Some(1)
                && ready == [1],
            "daemon mode {mode:?} did not signal readiness"
        );

        if matches!(mode, DaemonMode::Cancel) {
            let _ = child.kill();
        } else if matches!(mode, DaemonMode::Term)
            && let Ok(pid) = i32::try_from(child.id())
        {
            unsafe {
                let _ = libc::kill(pid, libc::SIGTERM);
            }
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(st) = child.try_wait().require("poll child")? {
                break st;
            }
            prop_assert!(
                Instant::now() < deadline,
                "broker hung in daemon mode {mode:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        if let Some(code) = expected_code {
            prop_assert_eq!(
                status.code(),
                Some(code),
                "daemon mode {mode:?} exit status",
                mode = mode
            );
        }
        prop_assert!(
            unsafe { libc::poll(&raw mut poll_fd, 1, 5000) } > 0
                && stdout.read(&mut ready).ok() == Some(0),
            "double-forked daemon survived broker teardown in mode {mode:?}"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ExecAndShebangCmd;

impl Arbitrary for ExecAndShebangCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

impl Step for ExecAndShebangCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        use std::os::unix::fs::PermissionsExt;

        state.host_mkdir("writable/exec_work");
        let denied_interp = state.abs_path("vault/denied_interp.sh");
        let _ = std::fs::write(&denied_interp, b"#!/bin/sh\nexit 0\n");
        let _ = std::fs::set_permissions(&denied_interp, std::fs::Permissions::from_mode(0o755));

        let pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "denyRead": [denied_interp],
                "allowWrite": [state.abs_path("writable")]
            },
            "network": { "allowNetwork": true }
        })];
        let probe = ProcProbe::ExecSuite {
            dir: state.abs_path("writable/exec_work"),
            denied_script: denied_interp.clone(),
        };
        prop_assert_eq!(
            state.probe(&pol, probe)?,
            ProbeOutcome::Allowed,
            "execve / shebang recursion / denyRead interpreter suite failed"
        );
        let _ = std::fs::remove_dir_all(state.abs_path("writable/exec_work"));
        state.nodes.remove("writable/exec_work");
        let _ = std::fs::remove_file(denied_interp);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MmapAndSignalFaultCmd {
    pub sub_idx: usize,
}

impl Arbitrary for MmapAndSignalFaultCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..3usize).prop_map(|sub_idx| Self { sub_idx }).boxed()
    }
}

impl Step for MmapAndSignalFaultCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable")]
            },
            "network": { "allowNetwork": true }
        })];
        match self.sub_idx % 3 {
            0 => {
                state.host_mkdir("writable/mmap_work");
                let probe = ProcProbe::MmapSuite {
                    dir: state.abs_path("writable/mmap_work"),
                };
                prop_assert_eq!(
                    state.probe(&pol, probe)?,
                    ProbeOutcome::Allowed,
                    "mmap/mremap suite failed"
                );
                let _ = std::fs::remove_dir_all(state.abs_path("writable/mmap_work"));
                state.nodes.remove("writable/mmap_work");
            }
            1 => {
                prop_assert_eq!(
                    state.probe(&pol, ProcProbe::SignalSuite)?,
                    ProbeOutcome::Allowed,
                    "RT signal / thread routing / sigaltstack / mprotect SIGSEGV recovery failed"
                );
            }
            _ => {
                let segv_res = state.ctx.execute(&RunSpec::worker(
                    &state.root,
                    &pol,
                    &ExitProbe::UnhandledSegv.into(),
                    &state.ctx,
                )?);
                prop_assert!(
                    segv_res.code == 139 || segv_res.signal == Some(libc::SIGSEGV),
                    "expected unhandled guest SIGSEGV to exit 139, got code={} signal={:?} reply={}",
                    segv_res.code,
                    segv_res.signal,
                    segv_res.stdout_str()
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum ProcessStep {
    SignalAndUringIsolation(SignalAndUringIsolationCmd),
    NamespaceIsolation(NamespaceIsolationCmd),
    DaemonAndOrphanLifetime(DaemonAndOrphanLifetimeCmd),
    ExecAndShebang(ExecAndShebangCmd),
    MmapAndSignalFault(MmapAndSignalFaultCmd),
}

impl Arbitrary for ProcessStep {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        prop_oneof![
            any::<SignalAndUringIsolationCmd>().prop_map(Self::SignalAndUringIsolation),
            any::<NamespaceIsolationCmd>().prop_map(Self::NamespaceIsolation),
            any::<DaemonAndOrphanLifetimeCmd>().prop_map(Self::DaemonAndOrphanLifetime),
            any::<ExecAndShebangCmd>().prop_map(Self::ExecAndShebang),
            any::<MmapAndSignalFaultCmd>().prop_map(Self::MmapAndSignalFault),
        ]
        .boxed()
    }
}

impl AsRef<dyn Step> for ProcessStep {
    fn as_ref(&self) -> &(dyn Step + 'static) {
        match self {
            Self::SignalAndUringIsolation(step) => step,
            Self::NamespaceIsolation(step) => step,
            Self::DaemonAndOrphanLifetime(step) => step,
            Self::ExecAndShebang(step) => step,
            Self::MmapAndSignalFault(step) => step,
        }
    }
}
