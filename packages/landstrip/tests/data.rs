// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Data-driven sandbox integration tests. See tests/data.txt for the field
//! syntax. Each line drives one `landstrip` invocation: a policy is written,
//! the filesystem is staged, the tool runs under the sandbox, and the exit
//! status plus captured output are matched against the expectations.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

const DATA: &str = include_str!("data.txt");

/// Re-exec argument marker for `fs=opath` probes (see [`opath_probe`]).
const OPATH_PROBE_ARG: &str = "--test-opath";
const FUTIMENS_PROBE_ARG: &str = "--test-futimens";
const TRUNCATE_PROBE_ARG: &str = "--test-truncate";
const EXCLUSIVE_OPEN_PROBE_ARG: &str = "--test-exclusive-open";
const OPENAT2_PROBE_ARG: &str = "--test-openat2";
const FD_METADATA_PROBE_ARG: &str = "--test-fd-metadata";
const ABSTRACT_UNIX_PROBE_ARG: &str = "--test-abstract-connect";
const SIGNAL_OUTSIDE_PROBE_ARG: &str = "--test-signal-outside";
const SIGNAL_THREAD_PROBE_ARG: &str = "--test-signal-thread";
const IO_URING_PROBE_ARG: &str = "--test-io-uring";
const DAEMON_PROBE_ARG: &str = "--test-daemon";

fn main() {
    let mut args = std::env::args_os();
    match args.nth(1).as_deref() {
        Some(value) if value == std::ffi::OsStr::new(OPATH_PROBE_ARG) => {
            std::process::exit(opath_probe(args.next()));
        }
        Some(value) if value == std::ffi::OsStr::new(FUTIMENS_PROBE_ARG) => {
            std::process::exit(futimens_probe(args.next()));
        }
        Some(value) if value == std::ffi::OsStr::new(TRUNCATE_PROBE_ARG) => {
            std::process::exit(truncate_probe(args.next()));
        }
        Some(value) if value == std::ffi::OsStr::new(EXCLUSIVE_OPEN_PROBE_ARG) => {
            std::process::exit(exclusive_open_probe(args.next()));
        }
        Some(value) if value == std::ffi::OsStr::new(OPENAT2_PROBE_ARG) => {
            std::process::exit(openat2_probe(args.next(), args.next()));
        }
        Some(value) if value == std::ffi::OsStr::new(FD_METADATA_PROBE_ARG) => {
            std::process::exit(fd_metadata_probe(args.next(), args.next()));
        }
        Some(value) if value == std::ffi::OsStr::new(ABSTRACT_UNIX_PROBE_ARG) => {
            std::process::exit(abstract_connect_probe(args.next()));
        }
        Some(value) if value == std::ffi::OsStr::new(SIGNAL_OUTSIDE_PROBE_ARG) => {
            std::process::exit(signal_outside_probe());
        }
        Some(value) if value == std::ffi::OsStr::new(SIGNAL_THREAD_PROBE_ARG) => {
            std::process::exit(signal_thread_probe());
        }
        Some(value) if value == std::ffi::OsStr::new(IO_URING_PROBE_ARG) => {
            std::process::exit(io_uring_probe());
        }
        Some(value) if value == std::ffi::OsStr::new(DAEMON_PROBE_ARG) => {
            std::process::exit(daemon_probe(args.next()));
        }
        _ => {}
    }
    let ctx = Context::new();
    let mut failed = 0u32;
    let mut ran = 0u32;
    let mut skipped = 0u32;

    for raw in DATA.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let case = Case::parse(line);
        if !case.runs_here() {
            skipped += 1;
            continue;
        }

        ran += 1;
        print!("Test {} ... ", case.name);
        std::io::stdout().flush().expect("flush stdout");
        match case.run(&ctx) {
            Ok(()) => println!("ok"),
            Err(reason) => {
                println!("FAILED");
                eprintln!("  {}: {reason}", case.name);
                failed += 1;
            }
        }
    }

    eprintln!("\n{ran} run, {skipped} skipped (other platforms).");
    if failed > 0 {
        eprintln!("{failed} test(s) failed.");
        std::process::exit(1);
    }
    eprintln!("All tests passed.");
}

/// Per-run constants shared by every case.
struct Context {
    bin: PathBuf,
    tmp_root: PathBuf,
    home: PathBuf,
    repo: PathBuf,
    shell: String,
    nc: String,
    pid: u32,
}

impl Context {
    fn new() -> Self {
        let tmp_root = test_tmp_root();
        let _ = robust_remove(&tmp_root);
        std::fs::create_dir_all(&tmp_root).expect("create tmp root");
        Self {
            bin: PathBuf::from(env!("CARGO_BIN_EXE_landstrip")),
            tmp_root,
            home: home_dir(),
            repo: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            shell: host_shell(),
            nc: std::env::var("NC").unwrap_or_else(|_| "nc".to_owned()),
            pid: std::process::id(),
        }
    }
}

#[cfg(unix)]
fn test_tmp_root() -> PathBuf {
    PathBuf::from(format!("/tmp/ls-data-{}", std::process::id()))
}

#[cfg(not(unix))]
fn test_tmp_root() -> PathBuf {
    std::env::temp_dir().join(format!("landstrip-data-{}", std::process::id()))
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn host_shell() -> String {
    if cfg!(target_os = "macos") {
        "/bin/bash".to_owned()
    } else if cfg!(target_os = "windows") {
        // Resolved lazily to a tmp copy in Context staging; cmd.exe path here.
        std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".to_owned())
    } else {
        "/bin/sh".to_owned()
    }
}

fn host_os() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "other"
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Zero,
    NonZero,
    Eq(i32),
}

#[derive(Clone, Copy)]
enum Channel {
    Out,
    TrapFd,
}

/// Serialization of a policy file and the value passed to `--policy-format`.
#[derive(Clone, Copy, Default, PartialEq)]
enum PolicyFormat {
    #[default]
    Json,
    Yaml,
}

struct Check {
    channel: Channel,
    contains: bool,
    needle: String,
}

enum Net {
    ListenerDenied,
    ListenerAllowed,
    ConnectDenied,
    ConnectAllowed,
    LoopbackAllowed,
    UnixAllowed,
    UnixDenied,
    UnixAbstractDenied,
    SignalOutsideDenied,
    SignalThreadAllowed,
    IoUringDenied,
    DaemonCleaned,
}

/// Fs action driven natively by the harness (no shell/tool can O_PATH portably).
enum Fs {
    /// O_PATH directory open of `path`; `allowed` selects the expected result.
    OPath { path: String, allowed: bool },
    /// fd-only utimensat of `path`; `allowed` selects the expected result.
    UtimensatFd { path: String, allowed: bool },
    /// fd-based metadata mutation of `path`; `allowed` selects the expected result.
    FdMetadata {
        operation: String,
        path: String,
        allowed: bool,
    },
    /// truncate(2) of `path`; `allowed` selects the expected result.
    Truncate { path: String, allowed: bool },
    /// Exclusive creation of an existing `path`; success means `EEXIST` preserved its contents.
    ExclusiveOpen { path: String, allowed: bool },
    /// Native openat2 semantic probe; `allowed` selects the expected result.
    Openat2 {
        operation: String,
        path: String,
        allowed: bool,
    },
}

struct Case {
    name: String,
    os: Vec<String>,
    setup: Vec<String>,
    policies: Vec<String>,
    format: PolicyFormat,
    stdin_policy: bool,
    trap_fd: bool,
    fd3: Option<String>,
    cwd: Option<String>,
    cmd: Option<String>,
    net: Option<Net>,
    fs: Option<Fs>,
    unixsock: Option<String>,
    status: Status,
    checks: Vec<Check>,
    trapfd_empty: bool,
}

impl Case {
    fn parse(line: &str) -> Self {
        let mut case = Case {
            name: String::new(),
            os: Vec::new(),
            setup: Vec::new(),
            policies: Vec::new(),
            format: PolicyFormat::Json,
            stdin_policy: false,
            trap_fd: false,
            fd3: None,
            cwd: None,
            cmd: None,
            net: None,
            fs: None,
            unixsock: None,
            status: Status::Zero,
            checks: Vec::new(),
            trapfd_empty: false,
        };
        for field in line.split(" | ") {
            let (key, value) = field.split_once('=').unwrap_or((field, ""));
            match key {
                "name" => case.name = value.to_owned(),
                "os" => case.os = value.split(',').map(str::to_owned).collect(),
                "setup" => case.setup = value.split(';').map(str::to_owned).collect(),
                "policy" => case.policies.push(value.to_owned()),
                "format" => case.format = parse_format(value),
                "stdin_policy" => case.stdin_policy = true,
                "trap" => case.trap_fd = true,
                "fd3" => case.fd3 = Some(value.to_owned()),
                "cwd" => case.cwd = Some(value.to_owned()),
                "cmd" => case.cmd = Some(value.to_owned()),
                "net" => case.net = Some(parse_net(value)),
                "fs" => case.fs = Some(parse_fs(value)),
                "unixsock" => case.unixsock = Some(value.to_owned()),
                "status" => case.status = parse_status(value),
                "out" | "out!" | "trapfd" | "trapfd!" => {
                    let channel = if key.starts_with("trapfd") {
                        Channel::TrapFd
                    } else {
                        Channel::Out
                    };
                    case.checks.push(Check {
                        channel,
                        contains: !key.ends_with('!'),
                        needle: value.to_owned(),
                    });
                }
                "trapfd_empty" => case.trapfd_empty = true,
                other => panic!("{}: unknown field `{other}`", case.name),
            }
        }
        case
    }

    fn runs_here(&self) -> bool {
        self.os.is_empty() || self.os.iter().any(|os| os == host_os())
    }

    fn run(&self, ctx: &Context) -> Result<(), String> {
        let dir = ctx.tmp_root.join(slug(&self.name));
        let _ = robust_remove(&dir);
        std::fs::create_dir_all(dir.join("allowed")).expect("create allowed");
        std::fs::create_dir_all(dir.join("denied")).expect("create denied");

        let shell = self.stage_shell(ctx, &dir);
        let resolver = Resolver {
            tmp: &dir,
            home: &ctx.home,
            repo: &ctx.repo,
            shell: &shell,
            nc: &ctx.nc,
            pid: ctx.pid,
        };

        let mut home_dirs = Vec::new();
        let result = self.stage(&resolver, &dir, &mut home_dirs);
        let result = result.and_then(|()| self.invoke(ctx, &resolver, &dir));

        let _ = robust_remove(&dir);
        for home in home_dirs {
            let _ = robust_remove(&home);
        }
        result
    }

    /// Windows runs the tool through a copy of cmd.exe placed in the readable
    /// tmp tree; other platforms use the system shell directly.
    fn stage_shell(&self, ctx: &Context, dir: &Path) -> String {
        if cfg!(target_os = "windows") {
            let target = dir.join("cmd.exe");
            let _ = std::fs::copy(&ctx.shell, &target);
            target.to_string_lossy().into_owned()
        } else {
            ctx.shell.clone()
        }
    }

    fn stage(
        &self,
        resolver: &Resolver,
        dir: &Path,
        home_dirs: &mut Vec<PathBuf>,
    ) -> Result<(), String> {
        for step in &self.setup {
            let step = step.trim();
            if step.is_empty() {
                continue;
            }
            let (verb, rest) = step.split_once(':').unwrap_or((step, ""));
            match verb {
                "mkdir" => {
                    let path = dir.join(resolver.subst(rest));
                    std::fs::create_dir_all(&path).map_err(|e| format!("mkdir {rest}: {e}"))?;
                }
                "write" => {
                    let (rel, content) = rest.split_once(':').unwrap_or((rest, ""));
                    let path = dir.join(resolver.subst(rel));
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    std::fs::write(&path, unescape(content))
                        .map_err(|e| format!("write {rel}: {e}"))?;
                }
                "chmod" => {
                    let (rel, mode) = rest.split_once(':').unwrap_or((rest, "0"));
                    set_mode(&dir.join(resolver.subst(rel)), mode)?;
                }
                "symlink" => {
                    let (target, link) = rest.split_once(':').unwrap_or((rest, ""));
                    make_symlink(&resolver.subst(target), &dir.join(resolver.subst(link)))?;
                }
                "homedir" => {
                    let path = resolver.home.join(resolver.subst(rest));
                    std::fs::create_dir_all(&path).map_err(|e| format!("homedir {rest}: {e}"))?;
                    home_dirs.push(path);
                }
                other => return Err(format!("unknown setup verb `{other}`")),
            }
        }
        Ok(())
    }

    fn policy_files(&self, resolver: &Resolver, dir: &Path) -> Vec<PathBuf> {
        let ext = if self.format == PolicyFormat::Yaml {
            "yaml"
        } else {
            "json"
        };
        self.policies
            .iter()
            .enumerate()
            .map(|(index, policy)| {
                let path = dir.join(format!("policy-{index}.{ext}"));
                std::fs::write(&path, self.render_policy(resolver, policy)).expect("write policy");
                path
            })
            .collect()
    }

    /// YAML policies carry author newline escapes and embed paths verbatim;
    /// JSON policies embed paths with backslashes and quotes escaped so Windows
    /// roots stay valid JSON.
    fn render_policy(&self, resolver: &Resolver, template: &str) -> String {
        if self.format == PolicyFormat::Yaml {
            resolver.subst(&unescape_str(template))
        } else {
            resolver.subst_json(template)
        }
    }

    fn invoke(&self, ctx: &Context, resolver: &Resolver, dir: &Path) -> Result<(), String> {
        let policies = if self.stdin_policy {
            Vec::new()
        } else {
            self.policy_files(resolver, dir)
        };

        if let Some(net) = &self.net {
            return run_net(
                ctx,
                net,
                self.format,
                &policies,
                resolver,
                dir,
                &self.unixsock,
            );
        }

        if let Some(fs) = &self.fs {
            return run_fs(ctx, fs, self.format, &policies, resolver);
        }

        let mut command = Command::new(&ctx.bin);
        command.arg("run");
        if self.format == PolicyFormat::Yaml || self.stdin_policy {
            command
                .arg("--policy-format")
                .arg(if self.format == PolicyFormat::Yaml {
                    "yaml"
                } else {
                    "json"
                });
        }
        if self.trap_fd {
            command.args(["--trap-fd", "3"]);
        }
        if self.stdin_policy {
            command.args(["-p", "-"]);
        } else {
            for policy in &policies {
                command.arg("-p").arg(policy);
            }
        }
        command.arg("--");
        if let Some(cmd) = &self.cmd {
            for token in tokenize(cmd) {
                command.arg(resolver.subst(&token));
            }
        }
        if let Some(cwd) = &self.cwd {
            command.current_dir(dir.join(resolver.subst(cwd)));
        }

        let trapfd_path = self.trapfd_path(dir);
        attach_fd3(&mut command, trapfd_path.as_deref());

        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command.stdin(if self.stdin_policy {
            Stdio::piped()
        } else {
            Stdio::null()
        });

        let mut child = command
            .spawn()
            .map_err(|e| format!("spawn landstrip: {e}"))?;
        if self.stdin_policy {
            let body =
                self.render_policy(resolver, self.policies.first().map_or("", String::as_str));
            child
                .stdin
                .take()
                .unwrap()
                .write_all(body.as_bytes())
                .map_err(|e| format!("write stdin policy: {e}"))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| format!("wait landstrip: {e}"))?;

        let merged = merge(&output.stdout, &output.stderr);
        let code = output.status.code().unwrap_or(-1);
        self.check_status(code, &merged)?;
        self.check_output(&merged, trapfd_path.as_deref())
    }

    fn trapfd_path(&self, dir: &Path) -> Option<PathBuf> {
        if self.trap_fd {
            Some(dir.join("trap.out"))
        } else {
            self.fd3.as_ref().map(|rel| dir.join(rel))
        }
    }

    fn check_status(&self, code: i32, merged: &str) -> Result<(), String> {
        let ok = match self.status {
            Status::Zero => code == 0,
            Status::NonZero => code != 0,
            Status::Eq(expected) => code == expected,
        };
        if ok {
            Ok(())
        } else {
            Err(format!("exit {code}; output={}", merged.trim()))
        }
    }

    fn check_output(&self, merged: &str, trapfd_path: Option<&Path>) -> Result<(), String> {
        let trapfd = trapfd_path
            .map(|path| std::fs::read_to_string(path).unwrap_or_default())
            .unwrap_or_default();

        for check in &self.checks {
            let haystack = match check.channel {
                Channel::Out => merged,
                Channel::TrapFd => &trapfd,
            };
            if haystack.contains(&check.needle) != check.contains {
                let want = if check.contains {
                    "missing"
                } else {
                    "unexpected"
                };
                return Err(format!(
                    "{want} `{}`; output={} trapfd={}",
                    check.needle,
                    merged.trim(),
                    trapfd.trim()
                ));
            }
        }

        if self.trapfd_empty && !trapfd.is_empty() {
            return Err(format!("trap fd not empty: {}", trapfd.trim()));
        }
        Ok(())
    }
}

/// Resolves `%PLACEHOLDER%` tokens against a case's staged directories.
struct Resolver<'a> {
    tmp: &'a Path,
    home: &'a Path,
    repo: &'a Path,
    shell: &'a str,
    nc: &'a str,
    pid: u32,
}

impl Resolver<'_> {
    fn subst(&self, text: &str) -> String {
        self.expand(text, |value| value.to_owned())
    }

    /// Like [`subst`] but escapes inserted values for a JSON string literal, so
    /// Windows paths (backslashes) survive as valid JSON.
    fn subst_json(&self, text: &str) -> String {
        self.expand(text, json_escape)
    }

    fn expand(&self, text: &str, encode: impl Fn(&str) -> String) -> String {
        text.replace("%TMP%", &encode(&self.tmp.to_string_lossy()))
            .replace("%HOME%", &encode(&self.home.to_string_lossy()))
            .replace("%REPO%", &encode(&self.repo.to_string_lossy()))
            .replace("%SHELL%", &encode(self.shell))
            .replace("%NC%", &encode(self.nc))
            .replace("%PID%", &self.pid.to_string())
    }
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_net(value: &str) -> Net {
    match value {
        "listener-denied" => Net::ListenerDenied,
        "listener-allowed" => Net::ListenerAllowed,
        "connect-denied" => Net::ConnectDenied,
        "connect-allowed" => Net::ConnectAllowed,
        "loopback-allowed" => Net::LoopbackAllowed,
        "unix-allowed" => Net::UnixAllowed,
        "unix-denied" => Net::UnixDenied,
        "unix-abstract-denied" => Net::UnixAbstractDenied,
        "signal-outside-denied" => Net::SignalOutsideDenied,
        "signal-thread-allowed" => Net::SignalThreadAllowed,
        "io-uring-denied" => Net::IoUringDenied,
        "daemon-cleaned" => Net::DaemonCleaned,
        other => panic!("unknown net kind `{other}`"),
    }
}

/// `fs=<operation>:<path>:<allowed|denied>`, where operation is one of
/// `opath`, `utimensat-fd`, fd metadata calls, or `truncate`.
fn parse_fs(value: &str) -> Fs {
    let (kind, spec) = value
        .split_once(':')
        .unwrap_or_else(|| panic!("fs action `{value}` lacks an operation"));
    let (path, want) = spec
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("fs action `{value}` lacks a result marker"));
    let allowed = match want {
        "allowed" => true,
        "denied" => false,
        other => panic!("unknown fs result `{other}`"),
    };
    match kind {
        "opath" => Fs::OPath {
            path: path.to_owned(),
            allowed,
        },
        "utimensat-fd" => Fs::UtimensatFd {
            path: path.to_owned(),
            allowed,
        },
        "legacy-utimes" | "x32-fchmod" => Fs::FdMetadata {
            operation: kind.to_owned(),
            path: path.to_owned(),
            allowed,
        },
        "truncate" => Fs::Truncate {
            path: path.to_owned(),
            allowed,
        },
        "exclusive-open" => Fs::ExclusiveOpen {
            path: path.to_owned(),
            allowed,
        },
        "openat2-beneath" | "openat2-in-root" | "openat2-no-symlinks" | "openat2-short" => {
            Fs::Openat2 {
                operation: kind.to_owned(),
                path: path.to_owned(),
                allowed,
            }
        }
        _ => panic!("unknown fs kind `{kind}`"),
    }
}

/// Runs an fs action as a re-exec of this test binary under landstrip.
fn run_fs(
    ctx: &Context,
    fs: &Fs,
    format: PolicyFormat,
    policies: &[PathBuf],
    resolver: &Resolver,
) -> Result<(), String> {
    let (marker, path, allowed, operation) = match fs {
        Fs::OPath { path, allowed } => (OPATH_PROBE_ARG, path, allowed, None),
        Fs::UtimensatFd { path, allowed } => (FUTIMENS_PROBE_ARG, path, allowed, None),
        Fs::FdMetadata {
            operation,
            path,
            allowed,
        } => (FD_METADATA_PROBE_ARG, path, allowed, Some(operation)),
        Fs::Truncate { path, allowed } => (TRUNCATE_PROBE_ARG, path, allowed, None),
        Fs::ExclusiveOpen { path, allowed } => (EXCLUSIVE_OPEN_PROBE_ARG, path, allowed, None),
        Fs::Openat2 {
            operation,
            path,
            allowed,
        } => (OPENAT2_PROBE_ARG, path, allowed, Some(operation)),
    };
    let exe = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
    let mut command = landstrip_net(ctx, format, policies);
    command.arg(exe).arg(marker).arg(resolver.subst(path));
    if let Some(operation) = operation {
        command.arg(operation);
    }
    let output = command
        .output()
        .map_err(|e| format!("spawn fs probe: {e}"))?;
    if output.status.success() != *allowed {
        return Err(format!(
            "fs probe {marker} of {path} {}denied; output={}",
            if *allowed { "" } else { "not " },
            merge(&output.stdout, &output.stderr).trim()
        ));
    }
    Ok(())
}

/// Re-exec probe for `fs=opath` cases: performs an O_PATH directory open of
/// the given path, exiting 0 on success and 1 on failure.
#[cfg(unix)]
fn opath_probe(path: Option<std::ffi::OsString>) -> i32 {
    use std::os::unix::fs::OpenOptionsExt;

    // Linux O_PATH | O_DIRECTORY.
    const O_PATH_DIRECTORY: i32 = 0o10000000 | 0o200000;
    let Some(path) = path else {
        return 2;
    };
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH_DIRECTORY)
        .open(path)
    {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[cfg(not(unix))]
fn opath_probe(_path: Option<std::ffi::OsString>) -> i32 {
    2
}

/// Re-exec probe for the fd-only form of utimensat used by futimens.
#[cfg(target_os = "linux")]
fn futimens_probe(path: Option<std::ffi::OsString>) -> i32 {
    use std::os::fd::AsRawFd;

    let Some(path) = path else {
        return 2;
    };
    let Ok(file) = std::fs::File::open(path) else {
        return 1;
    };
    let times = [
        libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 2,
            tv_nsec: 0,
        },
    ];
    // SAFETY: file is live, times points to two initialized timespecs, and a null
    // pathname selects the fd-only Linux utimensat form used by glibc futimens.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_utimensat,
            file.as_raw_fd(),
            std::ptr::null::<libc::c_char>(),
            times.as_ptr(),
            0,
        )
    };
    if rc == 0 { 0 } else { 1 }
}

#[cfg(not(target_os = "linux"))]
fn futimens_probe(_path: Option<std::ffi::OsString>) -> i32 {
    2
}

#[cfg(target_os = "linux")]
fn fd_metadata_probe(
    path: Option<std::ffi::OsString>,
    operation: Option<std::ffi::OsString>,
) -> i32 {
    use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

    let (Some(path), Some(operation)) = (path, operation) else {
        return 2;
    };
    let Ok(file) = std::fs::File::open(&path) else {
        return 1;
    };
    let Ok(_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return 2;
    };
    let rc = match operation.to_str() {
        Some("legacy-utimes") => {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            unsafe {
                libc::syscall(
                    libc::SYS_utimes,
                    _path.as_ptr(),
                    std::ptr::null::<libc::timeval>(),
                ) as i32
            }
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            {
                -1
            }
        }
        Some("x32-fchmod") => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let _ = libc::syscall(libc::SYS_fchmod | 0x4000_0000, file.as_raw_fd(), 0o600);
                // Returning means the BPF filter did not reject the x32 ABI.
                return 0;
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                -1
            }
        }
        Some("fchmod") => unsafe { libc::fchmod(file.as_raw_fd(), 0o600) },
        _ => return 2,
    };
    if rc == 0 { 0 } else { 1 }
}

#[cfg(not(target_os = "linux"))]
fn fd_metadata_probe(
    _path: Option<std::ffi::OsString>,
    _operation: Option<std::ffi::OsString>,
) -> i32 {
    2
}

#[cfg(target_os = "linux")]
fn exclusive_open_probe(path: Option<std::ffi::OsString>) -> i32 {
    use std::os::unix::ffi::OsStrExt;

    let Some(path) = path else {
        return 2;
    };
    let Ok(c_path) = std::ffi::CString::new(path.as_bytes()) else {
        return 2;
    };
    // SAFETY: c_path is NUL-terminated and the mode is valid for O_CREAT.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd >= 0 {
        // SAFETY: open returned a new descriptor.
        unsafe { libc::close(fd) };
        return 1;
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        return 1;
    }
    match std::fs::read(path) {
        Ok(contents) if contents == b"keep\n" => 0,
        _ => 1,
    }
}

#[cfg(not(target_os = "linux"))]
fn exclusive_open_probe(_path: Option<std::ffi::OsString>) -> i32 {
    2
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct TestOpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
fn test_openat2(
    dirfd: libc::c_int,
    path: &std::ffi::CStr,
    how: &TestOpenHow,
    size: usize,
) -> Result<std::os::fd::OwnedFd, i32> {
    use std::os::fd::FromRawFd;

    // SAFETY: path and how remain valid for the duration of the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            std::ptr::from_ref(how),
            size,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    let fd = i32::try_from(fd).map_err(|_| libc::EBADF)?;
    // SAFETY: openat2 returned a new owned descriptor.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn openat2_probe(path: Option<std::ffi::OsString>, operation: Option<std::ffi::OsString>) -> i32 {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let (Some(path), Some(operation)) = (path, operation) else {
        return 2;
    };
    let Ok(c_path) = std::ffi::CString::new(path.as_bytes()) else {
        return 2;
    };
    let readonly = 0_u64;
    match operation.to_str() {
        Some("openat2-no-symlinks") => test_openat2(
            libc::AT_FDCWD,
            &c_path,
            &TestOpenHow {
                flags: readonly,
                mode: 0,
                resolve: 0x04,
            },
            24,
        )
        .map_or_else(|errno| i32::from(errno != libc::ELOOP), |_| 1),
        Some("openat2-short") => test_openat2(
            libc::AT_FDCWD,
            &c_path,
            &TestOpenHow {
                flags: readonly,
                mode: 0,
                resolve: 0,
            },
            16,
        )
        .map_or_else(|errno| i32::from(errno != libc::EINVAL), |_| 1),
        Some("openat2-beneath") => {
            let Ok(dir) = std::fs::File::open(&path) else {
                return 2;
            };
            test_openat2(
                dir.as_raw_fd(),
                c"../outside.txt",
                &TestOpenHow {
                    flags: readonly,
                    mode: 0,
                    resolve: 0x08,
                },
                24,
            )
            .map_or_else(|errno| i32::from(errno != libc::EXDEV), |_| 1)
        }
        Some("openat2-in-root") => {
            let Ok(dir) = std::fs::File::open(&path) else {
                return 2;
            };
            let opened = test_openat2(
                dir.as_raw_fd(),
                c"/inside.txt",
                &TestOpenHow {
                    flags: readonly,
                    mode: 0,
                    resolve: 0x10,
                },
                24,
            );
            match opened {
                Ok(fd) => {
                    let mut file = std::fs::File::from(fd);
                    let mut contents = String::new();
                    i32::from(file.read_to_string(&mut contents).is_err() || contents != "inside\n")
                }
                Err(_) => 1,
            }
        }
        _ => 2,
    }
}

#[cfg(not(target_os = "linux"))]
fn openat2_probe(_path: Option<std::ffi::OsString>, _operation: Option<std::ffi::OsString>) -> i32 {
    2
}

#[cfg(target_os = "linux")]
fn truncate_probe(path: Option<std::ffi::OsString>) -> i32 {
    use std::os::unix::ffi::OsStrExt;

    let Some(path) = path else {
        return 2;
    };
    let Ok(path) = std::ffi::CString::new(path.as_bytes()) else {
        return 2;
    };
    // SAFETY: path is NUL-terminated and length is nonnegative.
    if unsafe { libc::truncate(path.as_ptr(), 1) } == 0 {
        0
    } else {
        1
    }
}

#[cfg(not(target_os = "linux"))]
fn truncate_probe(_path: Option<std::ffi::OsString>) -> i32 {
    2
}

fn parse_status(value: &str) -> Status {
    match value {
        "0" => Status::Zero,
        "!0" => Status::NonZero,
        other => Status::Eq(other.parse().expect("status must be 0, !0 or an integer")),
    }
}

fn parse_format(value: &str) -> PolicyFormat {
    match value {
        "json" => PolicyFormat::Json,
        "yaml" => PolicyFormat::Yaml,
        other => panic!("unknown format `{other}`"),
    }
}

fn next_port() -> u16 {
    static PORT: OnceLock<AtomicU16> = OnceLock::new();
    let counter = PORT.get_or_init(|| AtomicU16::new(49152 + (std::process::id() as u16 % 10000)));
    let port = counter.fetch_add(1, Ordering::Relaxed);
    if port >= 60999 {
        counter.store(49152, Ordering::Relaxed);
        return 49152;
    }
    port
}

fn non_loopback_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(address) if !address.is_loopback() && !address.is_unspecified() => Some(address),
        _ => None,
    }
}

fn landstrip_net(ctx: &Context, format: PolicyFormat, policies: &[PathBuf]) -> Command {
    let mut command = Command::new(&ctx.bin);
    command.arg("run");
    if format == PolicyFormat::Yaml {
        command.args(["--policy-format", "yaml"]);
    }
    for policy in policies {
        command.arg("-p").arg(policy);
    }
    command.arg("--");
    command.stdin(Stdio::null());
    command
}

fn run_net(
    ctx: &Context,
    net: &Net,
    format: PolicyFormat,
    policies: &[PathBuf],
    resolver: &Resolver,
    dir: &Path,
    unixsock: &Option<String>,
) -> Result<(), String> {
    match net {
        Net::ListenerDenied | Net::ListenerAllowed => {
            let allowed = matches!(net, Net::ListenerAllowed);
            run_listener(ctx, format, policies, allowed)
        }
        Net::ConnectDenied => run_connect_denied(ctx, format, policies),
        Net::ConnectAllowed => run_connect_allowed(ctx, dir),
        Net::LoopbackAllowed => run_loopback_allowed(ctx, format, policies),
        Net::UnixAllowed => {
            let rel = unixsock
                .as_ref()
                .ok_or_else(|| "unix-allowed needs unixsock".to_owned())?;
            run_unix_allowed(ctx, format, policies, &dir.join(resolver.subst(rel)))
        }
        Net::UnixDenied => run_unix_denied(ctx, format, policies, dir),
        Net::UnixAbstractDenied => run_unix_abstract_denied(ctx, format, policies),
        Net::SignalOutsideDenied => run_signal_outside_denied(ctx, format, policies),
        Net::SignalThreadAllowed => run_signal_thread_allowed(ctx, format, policies),
        Net::IoUringDenied => run_io_uring_denied(ctx, format, policies),
        Net::DaemonCleaned => run_daemon_cleaned(ctx, format, policies, dir),
    }
}

fn run_listener(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
    allowed: bool,
) -> Result<(), String> {
    let port = next_port();
    let mut child = landstrip_net(ctx, format, policies)
        .args([&ctx.nc, "-l", "127.0.0.1", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nc listener: {e}"))?;
    std::thread::sleep(std::time::Duration::from_secs(1));

    let alive = matches!(child.try_wait(), Ok(None));
    if !allowed {
        if alive {
            stop(&mut child);
            return Err("listener still running under deny policy".to_owned());
        }
        let status = child.wait().map_err(|e| e.to_string())?;
        return if status.success() {
            Err("listener exited successfully under deny policy".to_owned())
        } else {
            Ok(())
        };
    }

    if !alive {
        let status = child.wait().map_err(|e| e.to_string())?;
        return Err(format!("listener exited early status={status:?}"));
    }
    let connected = Command::new(&ctx.nc)
        .args(["-z", "127.0.0.1", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    stop(&mut child);
    if connected {
        Ok(())
    } else {
        Err(format!("connect to allowed listener failed on port {port}"))
    }
}

fn run_connect_denied(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
) -> Result<(), String> {
    let port = next_port();
    let output = landstrip_net(ctx, format, policies)
        .args([&ctx.nc, "-z", "-w1", "127.0.0.1", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("spawn nc connect: {e}"))?;
    let merged = merge(&output.stdout, &output.stderr);
    let denied = !output.status.success()
        && merged.contains(r#""kind":"network","code":"NETWORK_DENIED""#)
        && merged.contains(&format!("\"127.0.0.1:{port}\""))
        && merged.contains("\"seccomp\"");
    if denied {
        Ok(())
    } else {
        Err(format!("connect not denied; output={}", merged.trim()))
    }
}

/// Proves the loopback proxy-port allow rule: a sandboxed connect to the
/// configured `httpProxyPort` succeeds, while a connect to a different live
/// port under the same policy is refused because direct TCP stays denied.
fn run_connect_allowed(ctx: &Context, dir: &Path) -> Result<(), String> {
    let proxy_port = next_port();
    let other_port = next_port();
    let policy = dir.join("connect-allowed.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"filesystem":{{"denyRead":["/"],"allowRead":["/"]}},"network":{{"httpProxyPort":{proxy_port}}}}}"#
        ),
    )
    .map_err(|e| format!("write connect policy: {e}"))?;
    let policies = [policy];

    let mut proxy = listen(ctx, proxy_port)?;
    let mut other = listen(ctx, other_port)?;
    std::thread::sleep(Duration::from_secs(1));

    let result = (|| {
        if !sandbox_connect(ctx, PolicyFormat::Json, &policies, proxy_port) {
            return Err(format!("connect to proxy port {proxy_port} was denied"));
        }
        if sandbox_connect(ctx, PolicyFormat::Json, &policies, other_port) {
            return Err(format!("direct connect to port {other_port} was allowed"));
        }
        Ok(())
    })();

    stop(&mut proxy);
    stop(&mut other);
    result
}

fn run_loopback_allowed(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
) -> Result<(), String> {
    let port = next_port();
    let mut listener = listen(ctx, port)?;
    std::thread::sleep(Duration::from_secs(1));

    let connected = sandbox_connect(ctx, format, policies, port);
    stop(&mut listener);
    if !connected {
        return Err(format!("loopback connect was denied on port {port}"));
    }

    if let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
        let port = listener
            .local_addr()
            .map_err(|error| format!("read IPv6 loopback listener address: {error}"))?
            .port();
        let connected = landstrip_net(ctx, format, policies)
            .args([&ctx.nc, "-z", "-w1", "::1", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !connected {
            return Err(format!("IPv6 loopback connect was denied on port {port}"));
        }
    }

    if cfg!(target_os = "linux")
        && let Some(address) = non_loopback_ipv4()
    {
        let listener = TcpListener::bind((address, 0))
            .map_err(|error| format!("bind non-loopback listener: {error}"))?;
        let denied_port = listener
            .local_addr()
            .map_err(|error| format!("read non-loopback listener address: {error}"))?
            .port();
        let output = landstrip_net(ctx, format, policies)
            .args([
                &ctx.nc,
                "-z",
                "-w1",
                &address.to_string(),
                &denied_port.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| format!("spawn non-loopback connect: {error}"))?;
        let merged = merge(&output.stdout, &output.stderr);
        if output.status.success() {
            return Err(format!(
                "non-loopback connect to {address}:{denied_port} was allowed"
            ));
        }
        if !merged.contains(r#""kind":"network","code":"NETWORK_DENIED""#)
            || !merged.contains(&format!("\"{address}:{denied_port}\""))
        {
            return Err(format!(
                "non-loopback connect was not denied by policy; output={}",
                merged.trim()
            ));
        }
    }

    if cfg!(target_os = "macos") {
        let output = landstrip_net(ctx, format, policies)
            .args([&ctx.nc, "-z", "-v", "-w1", "1.1.1.1", "443"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| format!("spawn public connect: {error}"))?;
        let merged = merge(&output.stdout, &output.stderr);
        if output.status.success() || !merged.contains("Operation not permitted") {
            return Err(format!(
                "public connect was not denied by policy; output={}",
                merged.trim()
            ));
        }
    }

    Ok(())
}

fn listen(ctx: &Context, port: u16) -> Result<Child, String> {
    Command::new(&ctx.nc)
        .args(["-l", "127.0.0.1", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn nc listener on {port}: {e}"))
}

fn sandbox_connect(ctx: &Context, format: PolicyFormat, policies: &[PathBuf], port: u16) -> bool {
    landstrip_net(ctx, format, policies)
        .args([&ctx.nc, "-z", "-w1", "127.0.0.1", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_unix_allowed(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
    sock: &Path,
) -> Result<(), String> {
    let _ = std::fs::remove_file(sock);
    let mut server = Command::new(&ctx.nc)
        .args(["-l", "-U"])
        .arg(sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn unix server: {e}"))?;
    wait_for_unix_socket(&mut server, sock)?;

    let output = landstrip_net(ctx, format, policies)
        .arg(&ctx.nc)
        .arg("-U")
        .arg(sock)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    stop(&mut server);
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!(
            "unix connect failed status={:?}; output={}",
            output.status,
            merge(&output.stdout, &output.stderr).trim()
        )),
        Err(error) => Err(format!("unix connect spawn: {error}")),
    }
}

/// Denies socket(AF_UNIX) at connect/bind, not creation. Under a default-deny
/// unix-socket policy the connect must fail with EACCES ("Permission denied")
/// rather than EAFNOSUPPORT ("Address family not supported by protocol").
fn run_unix_denied(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
    dir: &Path,
) -> Result<(), String> {
    let sock = dir.join("denied.sock");
    let _ = std::fs::remove_file(&sock);
    let mut server = Command::new(&ctx.nc)
        .args(["-l", "-U"])
        .arg(&sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn unix server: {e}"))?;
    wait_for_unix_socket(&mut server, &sock)?;

    let output = landstrip_net(ctx, format, policies)
        .arg(&ctx.nc)
        .arg("-U")
        .arg(&sock)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    stop(&mut server);
    let output = output.map_err(|e| format!("unix connect spawn: {e}"))?;
    let merged = merge(&output.stdout, &output.stderr);

    let denied = !output.status.success()
        && merged.contains("Permission denied")
        && !merged.contains("Address family not supported");
    if denied {
        Ok(())
    } else {
        Err(format!(
            "unix connect not denied with EACCES; status={:?} output={}",
            output.status,
            merged.trim()
        ))
    }
}

#[cfg(target_os = "linux")]
fn landlock_abi() -> i64 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
    // SAFETY: a NULL attr with size 0 and the version flag is the documented
    // Landlock ABI query form.
    unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    }
}

#[cfg(target_os = "linux")]
fn skip_old_landlock() -> bool {
    let abi = landlock_abi();
    if abi < 6 {
        eprint!("skipped Landlock ABI {abi} < 6; ");
        true
    } else {
        false
    }
}

#[cfg(target_os = "linux")]
fn run_self_probe(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
    probe: &str,
    extra: Option<&std::ffi::OsStr>,
    spawn_err: &str,
    fail: &str,
) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
    let mut command = landstrip_net(ctx, format, policies);
    command.arg(exe).arg(probe);
    if let Some(extra) = extra {
        command.arg(extra);
    }
    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("{spawn_err}: {e}"))?;
    if output.status.code() == Some(0) {
        return Ok(());
    }
    Err(format!(
        "{fail}; status={:?} output={}",
        output.status,
        merge(&output.stdout, &output.stderr).trim()
    ))
}

#[cfg(target_os = "linux")]
fn io_uring_probe() -> i32 {
    let result = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            1_u32,
            std::ptr::null::<libc::c_void>(),
        )
    };
    i32::from(result != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM))
}

#[cfg(not(target_os = "linux"))]
fn io_uring_probe() -> i32 {
    2
}

#[cfg(target_os = "linux")]
fn run_io_uring_denied(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
) -> Result<(), String> {
    run_self_probe(
        ctx,
        format,
        policies,
        IO_URING_PROBE_ARG,
        None,
        "io_uring probe spawn",
        "io_uring setup not denied",
    )
}

#[cfg(not(target_os = "linux"))]
fn run_io_uring_denied(
    _ctx: &Context,
    _format: PolicyFormat,
    _policies: &[PathBuf],
) -> Result<(), String> {
    Err("io-uring-denied is linux-only".to_owned())
}

#[cfg(target_os = "linux")]
fn daemon_probe(pid_file: Option<std::ffi::OsString>) -> i32 {
    let Some(pid_file) = pid_file else {
        return 2;
    };
    let mut ready = [0; 2];
    // SAFETY: ready points to two writable file-descriptor slots.
    if unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return 2;
    }

    // SAFETY: the probe is single-threaded and both children call _exit or pause.
    let first = unsafe { libc::fork() };
    if first == -1 {
        return 2;
    }
    if first == 0 {
        // SAFETY: these descriptors were returned by pipe2 above.
        unsafe { libc::close(ready[0]) };
        // SAFETY: setsid has no pointer preconditions.
        if unsafe { libc::setsid() } == -1 {
            // SAFETY: terminate without running duplicated cleanup.
            unsafe { libc::_exit(2) };
        }
        // SAFETY: this process is still single-threaded.
        let daemon = unsafe { libc::fork() };
        if daemon != 0 {
            // SAFETY: terminate the intermediate process after a successful or failed fork.
            unsafe { libc::_exit(if daemon == -1 { 2 } else { 0 }) };
        }

        // Do not keep Command::output's pipes open after landstrip exits.
        for fd in 0..=2 {
            // SAFETY: close accepts any integer descriptor.
            unsafe { libc::close(fd) };
        }
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { libc::getpid() };
        if std::fs::write(pid_file, format!("{pid}\n")).is_err() {
            // SAFETY: terminate without running duplicated cleanup.
            unsafe { libc::_exit(2) };
        }
        let byte = [1_u8];
        // SAFETY: ready[1] is open and byte points to one readable byte.
        let _ = unsafe { libc::write(ready[1], byte.as_ptr().cast(), byte.len()) };
        // SAFETY: close accepts the pipe descriptor and pause waits for cleanup's SIGKILL.
        unsafe {
            libc::close(ready[1]);
            loop {
                libc::pause();
            }
        }
    }

    // SAFETY: parent owns both pipe descriptors and the read buffer is valid.
    unsafe { libc::close(ready[1]) };
    let mut byte = [0_u8];
    // SAFETY: ready[0] is open and byte points to one writable byte.
    let synchronized = unsafe { libc::read(ready[0], byte.as_mut_ptr().cast(), byte.len()) } == 1;
    // SAFETY: close accepts the pipe descriptor.
    unsafe { libc::close(ready[0]) };
    loop {
        // SAFETY: first is this process's child and the status is intentionally discarded.
        let waited = unsafe { libc::waitpid(first, std::ptr::null_mut(), 0) };
        if waited == first {
            break;
        }
        if waited == -1 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 2;
        }
    }
    if synchronized { 23 } else { 2 }
}

#[cfg(not(target_os = "linux"))]
fn daemon_probe(_pid_file: Option<std::ffi::OsString>) -> i32 {
    2
}

#[cfg(target_os = "linux")]
fn run_daemon_cleaned(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
    dir: &Path,
) -> Result<(), String> {
    let pid_file = dir.join("daemon.pid");
    let exe = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
    let output = landstrip_net(ctx, format, policies)
        .arg(exe)
        .arg(DAEMON_PROBE_ARG)
        .arg(&pid_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("daemon probe spawn: {e}"))?;
    let pid = std::fs::read_to_string(&pid_file)
        .map_err(|e| format!("read daemon pid: {e}"))?
        .trim()
        .parse::<i32>()
        .map_err(|e| format!("parse daemon pid: {e}"))?;
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    if proc_path.exists() {
        // Test hygiene on regressions: do not leave the probe daemon behind.
        // SAFETY: pid came from the probe and SIGKILL has no pointer arguments.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return Err(format!(
            "daemonized descendant {pid} survived landstrip exit"
        ));
    }
    if output.status.code() != Some(23) {
        return Err(format!(
            "foreground exit status not preserved; status={:?} output={}",
            output.status,
            merge(&output.stdout, &output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_daemon_cleaned(
    _ctx: &Context,
    _format: PolicyFormat,
    _policies: &[PathBuf],
    _dir: &Path,
) -> Result<(), String> {
    Err("daemon-cleaned is linux-only".to_owned())
}

/// Re-exec probe: connect to a host-created abstract Unix socket. Exit 0 when
/// Landlock denies the connect (EPERM/EACCES), 1 when it unexpectedly succeeds.
#[cfg(target_os = "linux")]
fn abstract_connect_probe(name: Option<std::ffi::OsString>) -> i32 {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixStream};

    let Some(name) = name else {
        return 2;
    };
    let Ok(addr) = SocketAddr::from_abstract_name(name.as_bytes()) else {
        return 2;
    };
    match UnixStream::connect_addr(&addr) {
        Ok(_) => 1,
        Err(error) => match error.raw_os_error() {
            Some(libc::EACCES | libc::EPERM) => 0,
            _ => 2,
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn abstract_connect_probe(_name: Option<std::ffi::OsString>) -> i32 {
    2
}

/// Denies connect to an abstract Unix socket created by the harness before the
/// sandbox started. Landlock ABI 6+ (Linux 6.12+) enforces the abstract-socket
/// scope; older kernels are skipped because seccomp cannot tell a host socket
/// from one the child created itself.
#[cfg(target_os = "linux")]
fn run_unix_abstract_denied(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
) -> Result<(), String> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};

    if skip_old_landlock() {
        return Ok(());
    }

    let name = format!("landstrip-abs-{}", ctx.pid);
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).map_err(|e| e.to_string())?;
    let _listener =
        UnixListener::bind_addr(&addr).map_err(|e| format!("bind abstract unix socket: {e}"))?;

    run_self_probe(
        ctx,
        format,
        policies,
        ABSTRACT_UNIX_PROBE_ARG,
        Some(std::ffi::OsStr::new(&name)),
        "abstract unix connect spawn",
        "host abstract unix connect not denied",
    )
}

#[cfg(not(target_os = "linux"))]
fn run_unix_abstract_denied(
    _ctx: &Context,
    _format: PolicyFormat,
    _policies: &[PathBuf],
) -> Result<(), String> {
    Err("unix-abstract-denied is linux-only".to_owned())
}

/// Re-exec probe: signal the parent process. Exit 0 when Landlock denies
/// (EPERM/EACCES), 1 when the signal unexpectedly succeeds.
#[cfg(target_os = "linux")]
fn signal_outside_probe() -> i32 {
    // SAFETY: getppid/kill with signal 0 have no preconditions.
    let rc = unsafe { libc::kill(libc::getppid(), 0) };
    if rc == 0 {
        return 1;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => 0,
        _ => 2,
    }
}

#[cfg(not(target_os = "linux"))]
fn signal_outside_probe() -> i32 {
    2
}

/// Denies signaling a process outside the sandbox (the landstrip parent).
/// Landlock ABI 6+ (Linux 6.12+) enforces signal scope; older kernels skip.
#[cfg(target_os = "linux")]
fn run_signal_outside_denied(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
) -> Result<(), String> {
    if skip_old_landlock() {
        return Ok(());
    }
    run_self_probe(
        ctx,
        format,
        policies,
        SIGNAL_OUTSIDE_PROBE_ARG,
        None,
        "signal-outside spawn",
        "signal to parent not denied",
    )
}

#[cfg(not(target_os = "linux"))]
fn run_signal_outside_denied(
    _ctx: &Context,
    _format: PolicyFormat,
    _policies: &[PathBuf],
) -> Result<(), String> {
    Err("signal-outside-denied is linux-only".to_owned())
}

/// Re-exec probe: a thread signals the main thread of the same process.
/// Exit 0 when that works. Landstrip restricts then execs, so both threads
/// share one domain and erratum 2 does not apply.
#[cfg(target_os = "linux")]
fn signal_thread_probe() -> i32 {
    // SAFETY: gettid(2) has no preconditions.
    let main_tid = unsafe { libc::gettid() };
    let result = std::thread::spawn(move || {
        // SAFETY: tgkill with signal 0 only checks permission.
        unsafe { libc::tgkill(libc::getpid(), main_tid, 0) }
    })
    .join();
    match result {
        Ok(0) => 0,
        _ => 1,
    }
}

#[cfg(not(target_os = "linux"))]
fn signal_thread_probe() -> i32 {
    2
}

#[cfg(target_os = "linux")]
fn run_signal_thread_allowed(
    ctx: &Context,
    format: PolicyFormat,
    policies: &[PathBuf],
) -> Result<(), String> {
    if skip_old_landlock() {
        return Ok(());
    }
    run_self_probe(
        ctx,
        format,
        policies,
        SIGNAL_THREAD_PROBE_ARG,
        None,
        "signal-thread spawn",
        "same-process thread signal failed",
    )
}

#[cfg(not(target_os = "linux"))]
fn run_signal_thread_allowed(
    _ctx: &Context,
    _format: PolicyFormat,
    _policies: &[PathBuf],
) -> Result<(), String> {
    Err("signal-thread-allowed is linux-only".to_owned())
}

fn wait_for_unix_socket(server: &mut Child, sock: &Path) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if is_unix_socket(sock) {
            return Ok(());
        }

        if let Some(status) = server
            .try_wait()
            .map_err(|e| format!("poll unix server: {e}"))?
        {
            return Err(format!(
                "unix server exited before socket was ready status={status:?}"
            ));
        }

        if Instant::now() >= deadline {
            return Err(format!("unix socket was not ready: {}", sock.display()));
        }

        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
fn is_unix_socket(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_unix_socket(path: &Path) -> bool {
    path.exists()
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Tokenizes a command line, honoring single and double quotes the way a POSIX
/// shell would, so embedded scripts survive as one argument.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current: Option<String> = None;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if let Some(token) = current.take() {
                    tokens.push(token);
                }
            }
            '\'' | '"' => {
                let quote = c;
                let buf = current.get_or_insert_with(String::new);
                for inner in chars.by_ref() {
                    if inner == quote {
                        break;
                    }
                    buf.push(inner);
                }
            }
            _ => current.get_or_insert_with(String::new).push(c),
        }
    }
    if let Some(token) = current {
        tokens.push(token);
    }
    tokens
}

fn unescape_str(text: &str) -> String {
    String::from_utf8(unescape(text)).expect("escaped policy is not UTF-8")
}

fn unescape(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match chars.next() {
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('r') => out.push(b'\r'),
            Some('\\') => out.push(b'\\'),
            Some(other) => {
                out.push(b'\\');
                let mut buf = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
            None => out.push(b'\\'),
        }
    }
    out
}

fn merge(stdout: &[u8], stderr: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(stderr));
    text
}

fn slug(name: &str) -> String {
    name.replace(|c: char| !c.is_ascii_alphanumeric(), "-")
}

#[cfg(unix)]
fn attach_fd3(command: &mut Command, path: Option<&Path>) {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let Some(path) = path else { return };
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("open fd3 file");
    // SAFETY: dup2 duplicates the open descriptor onto fd 3 in the forked child
    // before exec; the source descriptor stays valid for the closure's lifetime.
    // FD_CLOEXEC is cleared explicitly so fd 3 survives exec even when the source
    // descriptor already happens to be fd 3 (dup2 is then a no-op that preserves
    // the flag, which would otherwise close it).
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(file.as_raw_fd(), 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn attach_fd3(_command: &mut Command, _path: Option<&Path>) {}

#[cfg(unix)]
fn set_mode(path: &Path, mode: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let bits = u32::from_str_radix(mode, 8).map_err(|_| format!("bad mode {mode}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits))
        .map_err(|e| format!("chmod {mode}: {e}"))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn make_symlink(target: &str, link: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, link).map_err(|e| format!("symlink: {e}"))
}

#[cfg(not(unix))]
fn make_symlink(_target: &str, _link: &Path) -> Result<(), String> {
    Ok(())
}

/// Removes a tree even when a case left a directory mode 000 behind.
fn robust_remove(path: &Path) -> std::io::Result<()> {
    if std::fs::remove_dir_all(path).is_ok() {
        return Ok(());
    }
    relax_modes(path);
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn relax_modes(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let child = entry.path();
            if child.is_dir() && !child.is_symlink() {
                relax_modes(&child);
            }
        }
    }
}

#[cfg(not(unix))]
fn relax_modes(_path: &Path) {}
