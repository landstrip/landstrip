<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) Jarkko Sakkinen 2026 -->

# landstrip

`landstrip` runs commands in an OS-level sandbox using Landlock LSM on Linux,
Seatbelt on macOS, and LPAC AppContainer on Windows. It accepts the Anthropic
Sandbox Runtime policy subset in JSON or YAML.

## Installation

### npm

```sh
npm install --save-dev @landstrip/landstrip
```

```sh
npx landstrip -p policy.json cargo test
```

The npm package installs a small Node.js wrapper and a platform-specific native
binary package.

### Agent extensions

The bundled extensions integrate Landstrip with Pi and OpenCode. The Pi
extension sandboxes Bash execution, provides OpenCode-compatible primary-agent
selection, and runs subagents as full Pi RPC processes. Subagents normally run
inside an outer Landstrip sandbox; explicitly disabling sandboxing emits a
warning and uses a process-only fallback:

```sh
pi install npm:pi-landstrip
opencode plugin install opencode-landstrip
```

See [pi-landstrip](packages/pi-landstrip/README.md) and
[opencode-landstrip](packages/opencode-landstrip/README.md) for configuration
details.

## Platforms

| Area         | macOS                   | Linux                       | Windows                   |
| ------------ | ----------------------- | --------------------------- | ------------------------- |
| Policy       | path-based rules        | file-based rules            | per-run AppContainer ACLs |
| Timing       | dynamic path subset     | static file-based ruleset   | per-run ACL grants        |
| TCP          | proxy or loopback       | proxy or loopback           | allow all or deny all     |
| Unix sockets | allowlist               | seccomp-brokered allowlist  | allow all or deny all     |

### Linux

Landlock carves the denied subtrees out of the allowed roots, and then grants
`PATH_BENEATH` rules only for the surviving fragments. The denied path is never
added to the ruleset, and the kernel enforces the path directly.

Seccomp is applied when a policy needs more than Landlock can express
statically, such as filesystem mutator filtering or denial reporting. The broker
intercepts `openat` and `openat2` through seccomp user notifications, resolves
the real path, and validates it.

Landlock and seccomp cover mostly disjoint filesystem operations: Landlock
handles kernel-enforced path access, while seccomp mediates unsupported mutators
and reports broker decisions.

### Windows

Windows provides AppContainer for application-level sandboxing. Landstrip
creates a per-run LPAC AppContainer profile, grants its SID access to the lowered
read and write roots, and removes those grants after the sandboxed process tree
exits. Windows policies must use explicit read allowlists.

Landstrip assigns the sandboxed process to a Job Object with
`KILL_ON_JOB_CLOSE`, so child processes are kept in the sandbox process tree and
are terminated when the launcher exits.

`allowNetwork` grants the internet and private-network AppContainer
capabilities, while the default container holds none and denies all network
access.

AppContainer capabilities are coarse. Fine-grained TCP policies by host or port
require elevated Windows Filtering Platform rules keyed by the AppContainer SID,
which is unsuitable for an unprivileged agent sandbox runtime.

## Policy format

JSON is the default policy format. Use `--format yaml` for YAML policy files or
YAML read from standard input.

```sh
landstrip --format yaml -p policy.yaml cargo test
```

YAML path fields can use normal lists or one statement per line:

```yaml
filesystem:
  allowWrite: |
    .
    ~/.cargo
  denyRead: |
    ~/.ssh
  allowRead: |
    ~/.ssh/config
network:
  allowNetwork: true
```

## Filesystem policy

Write access is denied by default. `allowWrite` paths grant write access and
`denyWrite` paths subtract from them, with the most specific rule winning when
allow and deny rules overlap. Read access is unrestricted by default; setting
`denyRead` lowers it to an allowlist, and `allowRead` adds paths back.

### Write-denial semantics

Concrete (non-glob) `denyWrite` paths are canonicalized and enforced
eagerly on all platforms.

Glob `denyWrite` patterns (`**/.env`, `**/*.pem`, and so on) behave differently
by platform:

- **Linux**: Globs are evaluated dynamically by the seccomp broker at each write
  attempt. Files created after sandbox startup that match a `denyWrite` glob are
  blocked. Globs are not walked at startup, avoiding latency on large trees.
- **macOS**: Globs are snapshot-expanded when the Seatbelt profile is compiled.
  Files created after `sandbox_init` are not protected by glob denies; use
  concrete paths for them. A warning is logged when glob deny patterns are used.
- **Windows**: Glob `denyWrite` entries are not enforced by the AppContainer
  backend.

## Network policy

Sandbox mode denies direct network access by default. Proxy ports, loopback TCP
binding and connections, and Unix sockets can be allowed with the Anthropic
Sandbox Runtime network fields. `allowLocalBinding` permits both binding to and
connecting to loopback TCP addresses, including listeners started outside the
sandbox. Linux denies non-loopback connections. On macOS, Seatbelt's required
`localhost` matcher can also include addresses assigned to other local
interfaces, but public remote addresses remain denied.

For a filesystem-only sandbox with unrestricted direct network access, set:

```json
{
  "network": {
    "allowNetwork": true
  }
}
```

`allowNetwork` disables Landstrip network enforcement while leaving filesystem
policy enforcement in place. On Windows this grants the AppContainer its network
capabilities; without it the container denies all network access.

## Traps

Every Landstrip event, whether a sandbox denial or a failure that prevents the
tool from running, is reported as one JSON object per line, with a fixed `kind`
discriminant and stable `code`. Consumers route on `kind` for the record shape
and `code` for the event. Failures and completed denials go to standard error by
default. On Linux, pending query traps go only to `--trap-fd FD`, which must name
an already-open descriptor.

```sh
landstrip --trap-fd 3 -p policy.json cargo test 3>landstrip-traps.txt
```

The trap kinds are:

- `filesystem` (`code` `FILESYSTEM_DENIED`): `operation` is `read` or `write`,
  `path` is the resolved path, `requested_path` is the tool's original path when
  available, and `syscall`, `errno`, `flags`, `reason`, `suggested_grant`, and
  `process` carry routing context.
- `network` (`code` `NETWORK_DENIED`): `operation` is `connect` or `bind` and
  `target` is `address:port`, with `syscall`, `errno`, and `process` context.
- `launch` (`code` `LAUNCH_FAILED`): the sandbox was installed but the tool did
  not start. `program` is the tool, `errno` its symbolic errno where the platform
  has one, and `message` the system's text.
- `usage` (`code` `USAGE_ERROR`): the command line was rejected. Exits with
  status 2, and reaches standard error only — the trap descriptor is part of the
  arguments that failed to parse.
- `internal`: everything that fails before the tool runs. `code` names the stage:
  `POLICY_PARSE_FAILED`, `POLICY_IO_FAILED`, `SANDBOX_SETUP_FAILED`,
  `SUPERVISE_FAILED`, `PLATFORM_UNSUPPORTED`, `INTEGER_TOO_LARGE`, a
  `POLICY_*` validation rejection (`POLICY_UNRESTRICTED_READ`,
  `POLICY_TCP_BIND_UNSUPPORTED`, `POLICY_UNIX_SOCKET_UNSUPPORTED`,
  `POLICY_UNIX_SOCKET_PATH`, `POLICY_DENY_WRITE_SYMLINK_ANCESTOR`,
  `POLICY_INVALID_PORT`, `POLICY_EMPTY_PATH`, `POLICY_HOME_UNAVAILABLE`,
  `POLICY_TRAVERSAL_DEPTH`), or `INTERNAL_ERROR` for a failure the code space
  does not name.

A code names the stage that failed, not the operating system that reported it:
the same `LAUNCH_FAILED` or `SANDBOX_SETUP_FAILED` is raised by every backend
that has that stage. The platform detail rides along in the record instead.

`mechanism` records the kernel layer an event is attributed to: `landlock`,
`seccomp`, `seatbelt`, or `appcontainer`. Per-denial traps are always `seccomp`,
the only layer with a per-denial callback; Landlock enforces in-kernel without
one. `SANDBOX_SETUP_FAILED` carries the mechanism that could not be installed.

`reason` is a platform-independent classification of a filesystem decision,
derived from the policy and the requested path:

- `allow_miss`: the path matched no allow root and was denied by default.
- `deny_match`: the path matched an explicit deny root that overrides an allow.

```json
{
  "kind": "filesystem",
  "code": "FILESYSTEM_DENIED",
  "state": "info",
  "query_id": "0",
  "operation": "write",
  "path": "/repo/out",
  "requested_path": "out",
  "syscall": "openat",
  "errno": "EACCES",
  "flags": ["O_WRONLY", "O_CREAT", "O_TRUNC"],
  "reason": "allow_miss",
  "suggested_grant": { "allowWrite": "/repo/out" },
  "mechanism": "seccomp",
  "process": { "pid": 1234, "exe": "/usr/bin/sh", "cwd": "/repo" }
}
{
  "kind": "network",
  "code": "NETWORK_DENIED",
  "state": "info",
  "query_id": "0",
  "operation": "connect",
  "target": "127.0.0.1:9999",
  "syscall": "connect",
  "errno": "EACCES",
  "mechanism": "seccomp",
  "process": { "pid": 1234, "exe": "/usr/bin/nc", "cwd": "/repo" }
}
{
  "kind": "launch",
  "code": "LAUNCH_FAILED",
  "program": "/usr/bin/cargo",
  "errno": "ENOENT",
  "message": "No such file or directory (os error 2)"
}
{
  "kind": "internal",
  "code": "SANDBOX_SETUP_FAILED",
  "mechanism": "landlock",
  "message": "not enforced by the kernel (Linux 5.13+ with CONFIG_SECURITY_LANDLOCK required, and not disabled via the lsm= boot parameter)"
}
```

Denial traps are informational; the configured policy always applies. Landstrip
is otherwise quiet on success: standard error belongs to Landstrip and standard
output to the sandboxed tool. Failure traps include a human-readable log line;
machines should read the JSON. Usage errors exit with status 2, other Landstrip
failures with 1, and the tool's own status is otherwise passed through.

Writing to `--trap-fd` is best-effort: it needs an already-open descriptor (3 or
greater; 0-2 are reserved), and if the write fails the trap is dropped while the
policy stays in effect. On Linux, a broker launch failure also reaches
`--trap-fd` while the descriptor remains open.

## Development

### Commit messages

- Use `<subsystem>: <message>` as the subject.
- Add a body for non-trivial changes.
- Follow kernel-style commit message conventions.
- Include a `Signed-off-by:` trailer.

### Documenting errors

The following snippet demonstrates the recommended pattern for documenting
the return values on error:

```rust
/// # Errors
///
/// Returns [`Variant`] when ...
```

## Licensing

The JavaScript npm wrapper is licensed under `Apache-2.0`. The Rust source and
native binaries are licensed under `LGPL-2.1-or-later`.
Corresponding source for each published native binary is available from the
GitHub repository tag that matches the package version.
