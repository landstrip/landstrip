// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::context::{PolicyDelivery, ResponderMode, RunSpec};
use super::machine::{Require, Step};
#[cfg(unix)]
use super::probe::FsProbe;
use super::probe::Probe;
#[cfg(unix)]
use super::probe::ProbeReply;
use super::state::SandboxState;
use proptest::prelude::*;
use proptest::strategy::Union;
use proptest::test_runner::TestCaseResult;
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DoctorContractCmd;

impl Arbitrary for DoctorContractCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

impl Step for DoctorContractCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let res = state.ctx.run_subcommand(&["doctor"], None, &[]);
        prop_assert!(res.success(), "landstrip doctor failed: {}", res.stderr);
        let doc: Value = serde_json::from_slice(&res.stdout).require("doctor JSON output")?;
        prop_assert_eq!(doc.get("ok").and_then(Value::as_bool), Some(true));
        let tiers = doc
            .pointer("/supported/filesystemTiers")
            .and_then(Value::as_array)
            .require("supported.filesystemTiers")?;
        for expected in [
            "allowWrite",
            "denyWrite",
            "allowRead",
            "denyRead",
            "denyReadAlways",
            "denyWriteAlways",
        ] {
            prop_assert!(
                tiers.iter().any(|item| item.as_str() == Some(expected)),
                "doctor missing tier {expected}"
            );
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct InvalidCliUsageCmd {
    pub variant: usize,
}

#[cfg(unix)]
impl Arbitrary for InvalidCliUsageCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..10usize).prop_map(|variant| Self { variant }).boxed()
    }
}

#[cfg(unix)]
impl Step for InvalidCliUsageCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let bad_cases: &[&[&str]] = &[
            &["run"],
            &["run", "--trap", "0", "--", "/bin/true"],
            &["run", "--trap", "1", "--", "/bin/true"],
            &["run", "--trap", "2", "--", "/bin/true"],
            &["run", "--trap", "-1", "--", "/bin/true"],
            &["run", "--trap", "99", "--", "/bin/true"],
            &["run", "--trap", "3,4", "--", "/bin/true"],
            &["run", "--inherit", "0", "--", "/bin/true"],
            &["run", "--inherit", "4,4", "--", "/bin/true"],
            &["run", "--trap", "4", "--inherit", "4", "--", "/bin/true"],
        ];
        let args = bad_cases[self.variant % bad_cases.len()];
        let res = state.ctx.run_subcommand(args, None, &[]);
        prop_assert_eq!(
            res.code,
            2,
            "expected exit 2 for usage error `{args:?}`",
            args = args
        );
        prop_assert!(
            res.has_trap(|t| t.get("code") == Some("USAGE_ERROR")),
            "missing USAGE_ERROR trap for `{args:?}`: {}",
            res.stderr
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PolicyValidationTrapCmd {
    pub case_idx: usize,
}

impl Arbitrary for PolicyValidationTrapCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..8usize).prop_map(|case_idx| Self { case_idx }).boxed()
    }
}

impl Step for PolicyValidationTrapCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let noop = Probe::Noop.argv()?;
        let exe = state.ctx.exe.to_string_lossy();
        let run_noop = |policy: &Path| {
            let policy = policy.to_string_lossy();
            let mut args = vec!["run", "-p", &policy, "--", &exe];
            args.extend(noop.iter().map(String::as_str));
            state.ctx.run_subcommand(&args, None, &[])
        };
        match self.case_idx % 8 {
            0 => {
                let bad_json = state.root.join("malformed.json");
                let _ = std::fs::write(&bad_json, b"{invalid");
                let parse_res = run_noop(&bad_json);
                prop_assert!(!parse_res.success());
                prop_assert!(parse_res.stderr.contains("POLICY_PARSE_FAILED"));
            }
            1 => {
                let missing_res = run_noop(&state.root.join("no-such-policy.json"));
                prop_assert!(!missing_res.success());
                prop_assert!(missing_res.stderr.contains("POLICY_IO_FAILED"));
            }
            2 => {
                let bad_port = vec![json!({ "network": { "httpProxyPort": 0 } })];
                let mut spec = RunSpec::worker(&state.root, &bad_port, &Probe::Noop, &state.ctx)?;
                spec.responder = ResponderMode::ObserveFd;
                let port_res = state.ctx.execute(&spec);
                prop_assert!(!port_res.success());
                prop_assert!(port_res.has_trap(|t| t.get("code") == Some("POLICY_INVALID_PORT")));
            }
            tag_case => {
                let bad_tags = ["", "bad\"quote", "bad\\slash", "bad\nline", "bad\u{7f}"];
                let bad_tag = bad_tags[(tag_case - 3) % bad_tags.len()];
                let tag_pol = vec![json!({ "macos": { "logTag": bad_tag } })];
                let tag_spec = RunSpec::worker(&state.root, &tag_pol, &Probe::Noop, &state.ctx)?;
                let tag_res = state.ctx.execute(&tag_spec);
                prop_assert!(!tag_res.success());
                prop_assert!(tag_res.stderr.contains("POLICY_INVALID_LOG_TAG"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LaunchFailureTrapCmd;

impl Arbitrary for LaunchFailureTrapCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

impl Step for LaunchFailureTrapCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let missing = state.root.join("missing-executable-tool");
        let pol = vec![json!({
            "filesystem": { "allowRead": ["/"] },
            "network": { "allowNetwork": true }
        })];
        let spec = RunSpec {
            workdir: &state.root,
            cwd: None,
            policies: &pol,
            delivery: PolicyDelivery::JsonSingle,
            responder: ResponderMode::ObserveSocket,
            rename_on_query: None,
            inherited_fds: &[],
            env_overrides: &[],
            tool: &missing,
            args: Vec::new(),
            timeout: Duration::from_secs(10),
        };
        let res = state.ctx.execute(&spec);
        prop_assert!(!res.success());
        prop_assert!(
            res.has_trap(|t| t.get("code") == Some("LAUNCH_FAILED")),
            "expected LAUNCH_FAILED trap on missing tool: stderr={} traps={:?}",
            res.stderr,
            res.traps
        );
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct DescriptorInheritanceCmd;

#[cfg(unix)]
impl Arbitrary for DescriptorInheritanceCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

#[cfg(unix)]
impl Step for DescriptorInheritanceCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::process::CommandExt;

        let sink_path = state.root.join("writable/inherited_sink.txt");
        let sink = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&sink_path)
            .require("open sink")?;
        let owned_sink: OwnedFd = sink.into();

        let pol_path = state.root.join("writable/fd_policy.json");
        let pol_json = json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable"), "/dev/null"]
            },
            "network": { "allowNetwork": true }
        });
        let _ = std::fs::write(&pol_path, pol_json.to_string());

        let trap_path = state.root.join("writable/trap_sink.stanzas");
        let trap_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&trap_path)
            .require("open trap")?;
        let owned_trap: OwnedFd = trap_file.into();

        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        let can_use_high_fd = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0
            && limit.rlim_max > 5002;
        let inherit_arg = if can_use_high_fd { "4,6,5000" } else { "4,6" };

        let mut cmd = std::process::Command::new(&state.ctx.exe);
        cmd.args(["run", "--trap", "3", "--inherit", inherit_arg, "-p"])
            .arg(&pol_path)
            .arg("--")
            .arg(&state.ctx.exe)
            .args(Probe::from(FsProbe::OpenFds { write: true }).argv()?)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        unsafe {
            cmd.pre_exec(move || {
                Self::prepare_descriptors(
                    owned_trap.as_raw_fd(),
                    owned_sink.as_raw_fd(),
                    limit,
                    can_use_high_fd,
                )
            });
        }

        let out = cmd.output().require("spawn fd-probe")?;
        prop_assert!(
            out.status.success(),
            "fd-probe failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let expected_open: &[u8] = if can_use_high_fd {
            b"open=4,6,5000"
        } else {
            b"open=4,6"
        };
        prop_assert_eq!(
            ProbeReply::try_from(out.stdout.as_slice())?,
            ProbeReply::Allowed {
                output: expected_open.into()
            },
            "expected only inherited fds open (not trap fd 3 or unlisted fds 5, 5001)"
        );
        let written = std::fs::read_to_string(&sink_path).unwrap_or_default();
        let expected_written = if can_use_high_fd {
            "fd4;fd6;fd5000;"
        } else {
            "fd4;fd6;"
        };
        prop_assert_eq!(written, expected_written);
        let trap_contents = std::fs::read_to_string(&trap_path).unwrap_or_default();
        prop_assert!(trap_contents.is_empty(), "trap fd 3 leaked payload output");
        Ok(())
    }
}

#[cfg(unix)]
impl DescriptorInheritanceCmd {
    unsafe fn prepare_descriptors(
        trap_fd: std::os::fd::RawFd,
        sink_fd: std::os::fd::RawFd,
        limit: libc::rlimit,
        can_use_high_fd: bool,
    ) -> std::io::Result<()> {
        let trap_src = unsafe { libc::fcntl(trap_fd, libc::F_DUPFD_CLOEXEC, 32) };
        let sink_src = unsafe { libc::fcntl(sink_fd, libc::F_DUPFD_CLOEXEC, 32) };
        if trap_src < 0 || sink_src < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::dup2(trap_src, 3) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        for target_fd in [4, 5, 6] {
            if unsafe { libc::dup2(sink_src, target_fd) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        for fd in [3, 4, 5, 6] {
            if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        if can_use_high_fd {
            let raised = libc::rlimit {
                rlim_cur: limit.rlim_cur.max(5010).min(limit.rlim_max),
                rlim_max: limit.rlim_max,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const raised) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for target_fd in [5000, 5001] {
                if unsafe { libc::dup2(sink_src, target_fd) } < 0
                    || unsafe { libc::fcntl(target_fd, libc::F_SETFD, 0) } < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct ExecutablePolicyCwdCmd {
    pub case_idx: usize,
}

#[cfg(unix)]
impl Arbitrary for ExecutablePolicyCwdCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..4usize).prop_map(|case_idx| Self { case_idx }).boxed()
    }
}

#[cfg(unix)]
impl Step for ExecutablePolicyCwdCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        use std::os::unix::fs::PermissionsExt;

        let caller = state.root.join("exec_pol_caller");
        let target = state.root.join("exec_pol_target");
        let _ = std::fs::create_dir_all(caller.join("bin"));
        let _ = std::fs::create_dir_all(target.join("bin"));
        let secret = state.root.join("exec_pol_secret");
        let public = state.root.join("exec_pol_public");
        let _ = std::fs::write(&secret, b"hidden\n");
        let _ = std::fs::write(&public, b"visible\n");

        let valid_pol = json!({
            "filesystem": {
                "denyRead": [secret],
                "allowWrite": ["/dev/null"]
            },
            "macos": { "allowPty": true }
        });
        let invalid_pol = json!({ "unknownFieldShouldFail": true });
        let script = format!(
            "#!/bin/sh\n/bin/cat \"{}\" >/dev/null || exit 41\nif /bin/cat \"{}\" >/dev/null 2>&1; then exit 42; fi\nprintf 'cwd-ok\\n'\n",
            public.display(),
            secret.display()
        );

        for (dir, pol) in [(&caller, &invalid_pol), (&target, &valid_pol)] {
            for rel in ["tool", "bin/tool"] {
                let exe = dir.join(rel);
                let _ = std::fs::write(&exe, &script);
                let _ = std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755));
                Self::attach_exec_policy(&exe, &pol.to_string());
            }
            let _ = std::fs::remove_file(dir.join("link"));
            let _ = std::os::unix::fs::symlink("bin/tool", dir.join("link"));
        }
        let _ = std::fs::write(caller.join("policy.json"), valid_pol.to_string());
        let _ = std::fs::write(target.join("policy.json"), invalid_pol.to_string());

        let target_s = target.to_string_lossy().into_owned();
        let cases = [
            ("./tool", "/bin"),
            ("bin/tool", "/bin"),
            ("tool", "bin"),
            ("./link", "/bin"),
        ];
        let (tool, path_env) = cases[self.case_idx % cases.len()];
        let run_res = state.ctx.run_subcommand(
            &["run", "--cwd", &target_s, "--", tool],
            Some(&caller),
            &[("PATH", path_env)],
        );
        prop_assert!(
            run_res.success() && run_res.stdout_str() == "cwd-ok\n",
            "executable policy run failed for {tool} PATH={path_env}: {}",
            run_res.stderr
        );
        let check_res = state.ctx.run_subcommand(
            &["check", "--cwd", &target_s, "--tool", tool],
            Some(&caller),
            &[("PATH", path_env)],
        );
        prop_assert!(check_res.success());
        let parsed: Value = serde_json::from_slice(&check_res.stdout).require("check JSON")?;
        prop_assert_eq!(parsed.get("valid").and_then(Value::as_bool), Some(true));

        let resolve_res = state.ctx.run_subcommand(
            &["resolve", "--cwd", &target_s, "--tool", tool],
            Some(&caller),
            &[("PATH", path_env)],
        );
        prop_assert!(resolve_res.success());
        let resolved: Value =
            serde_json::from_slice(&resolve_res.stdout).require("resolve JSON")?;
        prop_assert_eq!(
            resolved.pointer("/macos/allowPty").and_then(Value::as_bool),
            Some(true)
        );
        #[cfg(target_os = "linux")]
        Self::deleted_executable_policy(state, &valid_pol, &script)?;
        Ok(())
    }
}

#[cfg(unix)]
impl ExecutablePolicyCwdCmd {
    #[cfg(target_os = "linux")]
    fn deleted_executable_policy(
        state: &SandboxState,
        policy: &Value,
        script: &str,
    ) -> TestCaseResult {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use xattr::FileExt;

        let path = state.root.join("deleted-executable");
        std::fs::write(&path, script).require("write deleted executable")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .require("make deleted executable runnable")?;
        let file = std::fs::File::open(&path).require("open deleted executable")?;
        nix::fcntl::fcntl(
            &file,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .require("inherit deleted executable descriptor")?;
        std::fs::remove_file(&path).require("unlink open executable")?;
        let inherited = [file.as_raw_fd()];
        let tool = Path::new("/proc/self/fd").join(file.as_raw_fd().to_string());
        prop_assert_eq!(
            tool.canonicalize().err().map(|error| error.kind()),
            Some(std::io::ErrorKind::NotFound)
        );
        let policies = [json!({ "filesystem": { "allowRead": ["/"] } })];
        let spec = RunSpec {
            workdir: &state.root,
            cwd: None,
            policies: &policies,
            delivery: PolicyDelivery::JsonSingle,
            responder: ResponderMode::None,
            rename_on_query: None,
            inherited_fds: &inherited,
            env_overrides: &[],
            tool: &tool,
            args: Vec::new(),
            timeout: Duration::from_secs(15),
        };
        file.set_xattr("user.landstrip.policy", policy.to_string().as_bytes())
            .require("attach policy to deleted executable")?;
        let result = state.ctx.execute(&spec);
        prop_assert!(
            result.success() && result.stdout_str() == "cwd-ok\n",
            "deleted executable lost its policy: {}",
            result.stderr
        );
        for invalid in ["{invalid", r#"{"unknownFieldShouldFail":true}"#] {
            file.set_xattr("user.landstrip.policy", invalid.as_bytes())
                .require("attach invalid policy to deleted executable")?;
            let result = state.ctx.execute(&spec);
            prop_assert!(!result.success());
            prop_assert!(
                result.stderr.contains("POLICY_PARSE_FAILED"),
                "invalid deleted-executable policy was not rejected: {}",
                result.stderr
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn attach_exec_policy(path: &Path, json_str: &str) {
        use std::os::unix::ffi::OsStrExt;
        if let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
            unsafe {
                let _ = libc::setxattr(
                    cpath.as_ptr(),
                    c"user.landstrip.policy".as_ptr(),
                    json_str.as_ptr().cast(),
                    json_str.len(),
                    0,
                );
            }
        }
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn attach_exec_policy(path: &Path, json_str: &str) {
        let _ = std::process::Command::new("/usr/bin/xattr")
            .args(["-w", "user.landstrip.policy", json_str])
            .arg(path)
            .status();
    }
}

#[derive(Debug, Clone)]
pub enum CliAndFdsStep {
    DoctorContract(DoctorContractCmd),
    #[cfg(unix)]
    InvalidCliUsage(InvalidCliUsageCmd),
    PolicyValidationTrap(PolicyValidationTrapCmd),
    LaunchFailureTrap(LaunchFailureTrapCmd),
    #[cfg(unix)]
    DescriptorInheritance(DescriptorInheritanceCmd),
    #[cfg(unix)]
    ExecutablePolicyCwd(ExecutablePolicyCwdCmd),
}

impl Arbitrary for CliAndFdsStep {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        let mut steps = Vec::new();
        steps.extend([
            any::<DoctorContractCmd>()
                .prop_map(Self::DoctorContract)
                .boxed(),
            any::<PolicyValidationTrapCmd>()
                .prop_map(Self::PolicyValidationTrap)
                .boxed(),
            any::<LaunchFailureTrapCmd>()
                .prop_map(Self::LaunchFailureTrap)
                .boxed(),
        ]);
        #[cfg(unix)]
        steps.push(
            any::<InvalidCliUsageCmd>()
                .prop_map(Self::InvalidCliUsage)
                .boxed(),
        );
        #[cfg(unix)]
        steps.push(
            any::<DescriptorInheritanceCmd>()
                .prop_map(Self::DescriptorInheritance)
                .boxed(),
        );
        #[cfg(unix)]
        steps.push(
            any::<ExecutablePolicyCwdCmd>()
                .prop_map(Self::ExecutablePolicyCwd)
                .boxed(),
        );
        Union::new(steps).boxed()
    }
}

impl AsRef<dyn Step> for CliAndFdsStep {
    fn as_ref(&self) -> &(dyn Step + 'static) {
        match self {
            Self::DoctorContract(step) => step,
            #[cfg(unix)]
            Self::InvalidCliUsage(step) => step,
            Self::PolicyValidationTrap(step) => step,
            Self::LaunchFailureTrap(step) => step,
            #[cfg(unix)]
            Self::DescriptorInheritance(step) => step,
            #[cfg(unix)]
            Self::ExecutablePolicyCwd(step) => step,
        }
    }
}
