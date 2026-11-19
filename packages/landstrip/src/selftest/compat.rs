// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Compatibility with the host: a system call the policy does not concern
//! behaves in the sandbox as it does outside it. The reference is the same
//! probe run unsandboxed, so nothing here states what the kernel should do.

use super::context::{RunResult, RunSpec};
use super::machine::{Require, Step};
use super::probe::{Probe, ProbeReply, SysCheck, SysProbe};
use super::state::SandboxState;
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestCaseResult};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;
use strum::VariantArray;

#[derive(Debug, Clone)]
pub struct HostParityCmd;

impl Arbitrary for HostParityCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

impl Step for HostParityCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        const WORK: &str = "writable/compat";
        state.host_mkdir(WORK);
        let policy = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable")]
            },
            "network": { "allowNetwork": true }
        })];
        let mut differences = Vec::new();
        for &check in SysCheck::VARIANTS {
            let probe = Probe::from(SysProbe::Check {
                check,
                dir: state.abs_path(WORK),
            });
            let host = Self::observe(&Self::on_host(state, &probe)?);
            let sandbox = Self::observe(&Self::in_sandbox(state, &policy, &probe)?);
            if sandbox != host {
                differences.push(format!(
                    "{check}: {sandbox} in the sandbox, {host} on the host"
                ));
            }
        }
        let sweep = Probe::from(SysProbe::Sweep);
        let host = Self::sweep(&Self::on_host(state, &sweep)?)?;
        let sandbox = Self::sweep(&Self::in_sandbox(state, &policy, &sweep)?)?;
        for (name, host) in &host {
            let sandbox = sandbox.get(name).map_or("is not reported", String::as_str);
            let agrees = match Self::ANSWERS.iter().find(|(answered, _)| answered == name) {
                Some((_, answer)) => sandbox == *answer,
                None => Self::kind(sandbox) == Self::kind(host),
            };
            if !agrees {
                differences.push(format!(
                    "syscall {name}: {sandbox} in the sandbox, {host} on the host"
                ));
            }
        }
        let _ = std::fs::remove_dir_all(state.abs_path(WORK));
        state.nodes.remove(WORK);
        prop_assert!(
            differences.is_empty(),
            "{} differences from the host:\n    {}",
            differences.len(),
            differences.join("\n    ")
        );
        Ok(())
    }
}

impl HostParityCmd {
    /// What the sandbox answers whatever the host does. The `EPERM` ones
    /// reach files or the network without naming a path or an address, or
    /// leave the namespaces the sandbox runs in. `clone3` is refused so that
    /// the C library falls back to `clone`, whose flags can be inspected.
    const ANSWERS: &[(&str, &str)] = &[
        ("io_uring_setup", "EPERM"),
        ("io_uring_enter", "EPERM"),
        ("io_uring_register", "EPERM"),
        ("unshare", "EPERM"),
        ("setns", "EPERM"),
        ("mount", "EPERM"),
        ("umount2", "EPERM"),
        ("pivot_root", "EPERM"),
        ("chroot", "EPERM"),
        ("move_mount", "EPERM"),
        ("fsopen", "EPERM"),
        ("fsconfig", "EPERM"),
        ("fsmount", "EPERM"),
        ("fspick", "EPERM"),
        ("open_tree", "EPERM"),
        ("mount_setattr", "EPERM"),
        ("clone3", "ENOSYS"),
    ];
    const SWEEP_LIMIT: Duration = Duration::from_mins(2);

    fn on_host(state: &SandboxState, probe: &Probe) -> Result<RunResult, TestCaseError> {
        let args = probe.argv()?;
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        Ok(state.ctx.run_subcommand(&args, None, &[]))
    }

    fn in_sandbox(
        state: &SandboxState,
        policy: &[Value],
        probe: &Probe,
    ) -> Result<RunResult, TestCaseError> {
        let mut spec = RunSpec::worker(&state.root, policy, probe, &state.ctx)?;
        spec.timeout = Self::SWEEP_LIMIT;
        Ok(state.ctx.execute(&spec))
    }

    /// What a probe saw, in words that read after its name.
    fn observe(result: &RunResult) -> String {
        match ProbeReply::try_from(result) {
            Ok(ProbeReply::Allowed { output }) if output.is_empty() => "succeeds".to_owned(),
            Ok(ProbeReply::Allowed { output }) => {
                String::from_utf8_lossy(&output).trim().to_owned()
            }
            Ok(ProbeReply::Denied { errno }) => format!("is denied (errno {errno:?})"),
            Ok(ProbeReply::Broken { reason }) => format!("fails ({reason})"),
            Err(_) => format!(
                "ends without a reply (exit {}, signal {:?})",
                result.code, result.signal
            ),
        }
    }

    /// Which error a call with invalid arguments reports depends on the
    /// order its arguments are checked in, so only the kind of outcome is
    /// compared: whether the call exists, and whether it fails.
    fn kind(outcome: &str) -> &str {
        let is_errno = outcome.starts_with('E') || outcome.starts_with("errno ");
        if is_errno && outcome != "ENOSYS" {
            "fails"
        } else {
            outcome
        }
    }

    fn sweep(result: &RunResult) -> Result<BTreeMap<String, String>, TestCaseError> {
        let outcomes = ProbeReply::try_from(result)?.into_output();
        serde_json::from_slice::<Vec<(String, String)>>(&outcomes)
            .map(BTreeMap::from_iter)
            .require("decode the system call sweep")
    }
}

#[derive(Debug, Clone)]
pub enum CompatStep {
    HostParity(HostParityCmd),
}

impl Arbitrary for CompatStep {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        any::<HostParityCmd>().prop_map(Self::HostParity).boxed()
    }
}

impl AsRef<dyn Step> for CompatStep {
    fn as_ref(&self) -> &(dyn Step + 'static) {
        match self {
            Self::HostParity(step) => step,
        }
    }
}
