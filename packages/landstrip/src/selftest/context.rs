// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::probe::Probe;
use proptest::test_runner::TestCaseError;
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static INVOCATION_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyDelivery {
    #[default]
    JsonSingle,
    YamlSingle,
    MergedJson,
    StdinJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponderMode {
    #[default]
    None,
    ObserveFd,
    ObserveSocket,
    GrantAllow,
    GrantDeny,
}

#[derive(Debug, Clone)]
pub struct SandboxContext {
    pub exe: PathBuf,
    pub scratch_root: PathBuf,
}

impl Default for SandboxContext {
    fn default() -> Self {
        let scratch_root = Self::scratch_root();
        let _ = std::fs::create_dir_all(&scratch_root);
        #[cfg(target_os = "linux")]
        let exe = PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let exe = std::env::current_exe().unwrap_or_default();
        Self { exe, scratch_root }
    }
}

#[derive(Debug)]
pub struct RunResult {
    pub code: i32,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub traps: Vec<Value>,
}

impl RunResult {
    pub fn success(&self) -> bool {
        self.code == 0 && self.signal.is_none()
    }

    #[cfg(unix)]
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn has_trap(&self, pred: impl Fn(&Value) -> bool) -> bool {
        self.traps.iter().any(&pred) || self.stderr_traps().iter().any(&pred)
    }

    pub fn stderr_traps(&self) -> Vec<Value> {
        self.stderr
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect()
    }
}

pub struct RunSpec<'a> {
    pub workdir: &'a Path,
    pub cwd: Option<&'a Path>,
    pub policies: &'a [Value],
    pub delivery: PolicyDelivery,
    pub responder: ResponderMode,
    pub rename_on_query: Option<(PathBuf, PathBuf)>,
    pub inherited_fds: &'a [i32],
    pub env_overrides: &'a [(&'a str, &'a str)],
    pub tool: &'a Path,
    pub args: Vec<String>,
    pub timeout: Duration,
}

impl<'a> RunSpec<'a> {
    pub fn worker(
        workdir: &'a Path,
        policies: &'a [Value],
        probe: &Probe,
        ctx: &'a SandboxContext,
    ) -> Result<Self, TestCaseError> {
        Ok(Self {
            workdir,
            cwd: None,
            policies,
            delivery: PolicyDelivery::JsonSingle,
            responder: ResponderMode::None,
            rename_on_query: None,
            inherited_fds: &[],
            env_overrides: &[],
            tool: &ctx.exe,
            args: probe.argv()?,
            timeout: Duration::from_secs(15),
        })
    }
}

impl SandboxContext {
    pub fn scratch_root() -> PathBuf {
        std::env::temp_dir().join(format!("landstrip-selftest-{}", std::process::id()))
    }

    pub fn next_id() -> u64 {
        INVOCATION_SEQ.fetch_add(1, Ordering::Relaxed)
    }

    pub fn run_subcommand(
        &self,
        subcmd: &[&str],
        cwd: Option<&Path>,
        env_overrides: &[(&str, &str)],
    ) -> RunResult {
        let mut cmd = Command::new(&self.exe);
        cmd.args(subcmd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        for &(key, val) in env_overrides {
            cmd.env(key, val);
        }
        Self::collect_child(cmd, None, None, Duration::from_secs(15))
    }

    pub fn execute(&self, spec: &RunSpec<'_>) -> RunResult {
        let seq = Self::next_id();
        let stage = spec.workdir.join(format!(".invoke-{seq}"));
        let _ = std::fs::create_dir_all(&stage);
        let mut cmd = Command::new(&self.exe);
        cmd.arg("run");
        for &(key, val) in spec.env_overrides {
            cmd.env(key, val);
        }
        if let Some(cwd) = spec.cwd {
            cmd.arg("--cwd").arg(cwd);
        }
        if !spec.inherited_fds.is_empty() {
            let list = spec
                .inherited_fds
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            cmd.args(["--inherit", &list]);
        }
        let stdin_payload =
            Self::configure_policies(&mut cmd, &stage, spec.policies, spec.delivery);
        let trap_handle = Self::configure_trap(
            &mut cmd,
            &stage,
            spec.responder,
            spec.rename_on_query.clone(),
        );
        cmd.arg("--").arg(spec.tool).args(&spec.args);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.stdin(if stdin_payload.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let result = Self::collect_child(cmd, stdin_payload, trap_handle, spec.timeout);
        let _ = std::fs::remove_dir_all(&stage);
        result
    }

    fn configure_policies(
        cmd: &mut Command,
        stage: &Path,
        policies: &[Value],
        delivery: PolicyDelivery,
    ) -> Option<Vec<u8>> {
        match delivery {
            PolicyDelivery::JsonSingle => {
                let merged = Self::first_or_empty(policies);
                let file = stage.join("policy.json");
                let _ = std::fs::write(&file, merged.to_string());
                cmd.arg("-p").arg(file);
                None
            }
            PolicyDelivery::YamlSingle => {
                let merged = Self::first_or_empty(policies);
                let yaml = serde_yml::to_string(&merged).unwrap_or_else(|_| "{}".to_owned());
                let file = stage.join("policy.yaml");
                let _ = std::fs::write(&file, yaml);
                cmd.args(["--policy-format", "yaml", "-p"]).arg(file);
                None
            }
            PolicyDelivery::MergedJson => {
                if policies.is_empty() {
                    let file = stage.join("policy-0.json");
                    let _ = std::fs::write(&file, "{}");
                    cmd.arg("-p").arg(file);
                } else {
                    for (idx, pol) in policies.iter().enumerate() {
                        let file = stage.join(format!("policy-{idx}.json"));
                        let _ = std::fs::write(&file, pol.to_string());
                        cmd.arg("-p").arg(file);
                    }
                }
                None
            }
            PolicyDelivery::StdinJson => {
                let merged = Self::first_or_empty(policies);
                cmd.args(["--policy-format", "json", "-p", "-"]);
                Some(merged.to_string().into_bytes())
            }
        }
    }

    fn first_or_empty(policies: &[Value]) -> Value {
        policies
            .first()
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}))
    }

    #[cfg(unix)]
    fn configure_trap(
        cmd: &mut Command,
        stage: &Path,
        responder: ResponderMode,
        mut rename_on_query: Option<(PathBuf, PathBuf)>,
    ) -> Option<TrapCollector> {
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::os::unix::process::CommandExt;

        match responder {
            ResponderMode::None => None,
            ResponderMode::ObserveFd => {
                let trap_file = stage.join("trap.jsonl");
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&trap_file)
                    .ok()?;
                let owned: OwnedFd = file.into();
                cmd.args(["--trap", "3"]);
                unsafe {
                    cmd.pre_exec(move || {
                        if libc::dup2(owned.as_raw_fd(), 3) < 0
                            || libc::fcntl(3, libc::F_SETFD, 0) < 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                Some(TrapCollector::File(trap_file))
            }
            ResponderMode::ObserveSocket | ResponderMode::GrantAllow | ResponderMode::GrantDeny => {
                let action = match responder {
                    ResponderMode::GrantAllow => Some("allow"),
                    ResponderMode::ObserveSocket | ResponderMode::GrantDeny => Some("deny"),
                    _ => None,
                };
                if responder == ResponderMode::ObserveSocket {
                    let sock_path = stage.join("trap.sock");
                    let listener = UnixListener::bind(&sock_path).ok()?;
                    let _ = listener.set_nonblocking(false);
                    cmd.arg("--trap").arg(&sock_path);
                    let handle = std::thread::spawn(move || {
                        let mut records = Vec::new();
                        let mut pfd = libc::pollfd {
                            fd: listener.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        if unsafe { libc::poll(&raw mut pfd, 1, 5000) } > 0
                            && let Ok((mut stream, _)) = listener.accept()
                        {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                            Self::drain_trap_stream(
                                &mut stream,
                                action,
                                &mut rename_on_query,
                                &mut records,
                            );
                        }
                        records
                    });
                    Some(TrapCollector::Thread(handle))
                } else {
                    let (mut host_end, child_end) = UnixStream::pair().ok()?;
                    let _ = host_end.set_read_timeout(Some(Duration::from_secs(10)));
                    let owned: OwnedFd = child_end.into();
                    cmd.args(["--trap", "3"]);
                    unsafe {
                        cmd.pre_exec(move || {
                            if libc::dup2(owned.as_raw_fd(), 3) < 0
                                || libc::fcntl(3, libc::F_SETFD, 0) < 0
                            {
                                return Err(std::io::Error::last_os_error());
                            }
                            Ok(())
                        });
                    }
                    let handle = std::thread::spawn(move || {
                        let mut records = Vec::new();
                        Self::drain_trap_stream(
                            &mut host_end,
                            action,
                            &mut rename_on_query,
                            &mut records,
                        );
                        records
                    });
                    Some(TrapCollector::Thread(handle))
                }
            }
        }
    }

    #[cfg(unix)]
    fn drain_trap_stream(
        stream: &mut std::os::unix::net::UnixStream,
        action: Option<&str>,
        rename_on_query: &mut Option<(PathBuf, PathBuf)>,
        records: &mut Vec<Value>,
    ) {
        use std::io::{BufRead, BufReader};
        let Ok(cloned) = stream.try_clone() else {
            return;
        };
        let reader = BufReader::new(cloned);
        for line in reader.lines() {
            let Ok(line) = line else {
                break;
            };
            let Ok(trap) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if trap.get("state").and_then(Value::as_str) == Some("query")
                && let Some(reply_action) = action
            {
                if let Some((from, to)) = rename_on_query.take() {
                    let _ = std::fs::rename(from, to);
                }
                let reply = serde_json::json!({
                    "query_id": trap["query_id"],
                    "action": reply_action,
                });
                let _ = writeln!(stream, "{reply}");
            }
            records.push(trap);
        }
    }

    #[cfg(not(unix))]
    fn configure_trap(
        _cmd: &mut Command,
        _stage: &Path,
        _responder: ResponderMode,
        _rename_on_query: Option<(PathBuf, PathBuf)>,
    ) -> Option<TrapCollector> {
        None
    }

    fn collect_child(
        mut cmd: Command,
        stdin_payload: Option<Vec<u8>>,
        trap_collector: Option<TrapCollector>,
        timeout: Duration,
    ) -> RunResult {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let Ok(mut child) = cmd.spawn() else {
            return RunResult {
                code: -1,
                signal: None,
                stdout: Vec::new(),
                stderr: "failed to spawn landstrip".to_owned(),
                traps: Vec::new(),
            };
        };
        drop(cmd);
        if let Some(payload) = stdin_payload
            && let Some(mut stdin) = child.stdin.take()
        {
            let _ = stdin.write_all(&payload);
        }
        let deadline = Instant::now() + timeout;
        while let Ok(None) = child.try_wait() {
            if Instant::now() >= deadline {
                #[cfg(target_os = "linux")]
                if let Ok(pid) = i32::try_from(child.id()) {
                    unsafe {
                        let _ = libc::kill(-pid, libc::SIGKILL);
                    }
                }
                let _ = child.kill();
                let _ = child.wait();
                return RunResult {
                    code: -2,
                    signal: None,
                    stdout: Vec::new(),
                    stderr: "landstrip timed out".to_owned(),
                    traps: Vec::new(),
                };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let Ok(output) = child.wait_with_output() else {
            return RunResult {
                code: -1,
                signal: None,
                stdout: Vec::new(),
                stderr: "wait_with_output failed".to_owned(),
                traps: Vec::new(),
            };
        };
        let traps = trap_collector.map_or_else(Vec::new, TrapCollector::finish);
        #[cfg(unix)]
        let signal = std::os::unix::process::ExitStatusExt::signal(&output.status);
        #[cfg(not(unix))]
        let signal = None;
        RunResult {
            code: output.status.code().unwrap_or(-1),
            signal,
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            traps,
        }
    }
}

enum TrapCollector {
    #[cfg(unix)]
    File(PathBuf),
    #[cfg(unix)]
    Thread(std::thread::JoinHandle<Vec<Value>>),
}

impl TrapCollector {
    fn finish(self) -> Vec<Value> {
        match self {
            #[cfg(unix)]
            Self::File(path) => std::fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .collect(),
            #[cfg(unix)]
            Self::Thread(handle) => handle.join().unwrap_or_default(),
        }
    }
}
