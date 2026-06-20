// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Data-driven sandbox integration tests. See tests/data.txt for the field
//! syntax. Each line drives one `landstrip` invocation: a policy is written,
//! the filesystem is staged, the tool runs under the sandbox, and the exit
//! status plus captured output are matched against the expectations.

use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

const DATA: &str = include_str!("data.txt");

fn main() {
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

/// Serialization of a policy file and the value passed to `--format`.
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
    UnixAllowed,
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

        let mut command = Command::new(&ctx.bin);
        if self.format == PolicyFormat::Yaml {
            command.args(["--format", "yaml"]);
        }
        if self.trap_fd {
            command.args(["--trap-fd", "3"]);
        }
        if !self.stdin_policy {
            for policy in &policies {
                command.arg("-p").arg(policy);
            }
        }
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
        "unix-allowed" => Net::UnixAllowed,
        other => panic!("unknown net kind `{other}`"),
    }
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

fn landstrip_net(ctx: &Context, format: PolicyFormat, policies: &[PathBuf]) -> Command {
    let mut command = Command::new(&ctx.bin);
    if format == PolicyFormat::Yaml {
        command.args(["--format", "yaml"]);
    }
    for policy in policies {
        command.arg("-p").arg(policy);
    }
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
        Net::UnixAllowed => {
            let rel = unixsock
                .as_ref()
                .ok_or_else(|| "unix-allowed needs unixsock".to_owned())?;
            run_unix_allowed(ctx, format, policies, &dir.join(resolver.subst(rel)))
        }
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
        .env("LANDSTRIP_DUMP_SBPL", "1")
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
