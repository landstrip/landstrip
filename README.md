<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) Jarkko Sakkinen 2026 -->

# landstrip

`landstrip` runs commands in an OS-level sandbox using Landlock LSM on Linux,
Seatbelt on macOS, and AppContainer or restricted local users on Windows. It
accepts the Anthropic Sandbox Runtime policy subset in JSON or YAML.

## Installation

### npm

```sh
npm install --save-dev @landstrip/landstrip
```

```sh
npx landstrip run -p policy.json -- cargo test
```

The npm package installs a small Node.js wrapper and a platform-specific native
binary package.

## Command line

Landstrip uses explicit commands:

```text
landstrip run [OPTIONS] -- <PROGRAM> [ARGS...]
landstrip policy validate [OPTIONS]
landstrip policy resolve [OPTIONS]
landstrip doctor
landstrip windows install [OPTIONS]
landstrip windows status
landstrip windows uninstall
```

The `windows` command family is available only in Windows builds.

Policy options are `-p, --policy <FILE>`, repeated in merge order, and
`--policy-format <json|yaml>`. Use `-p -` to read standard input; its format
must be explicit. `policy validate` checks the merged policy and current platform
support, returning `valid: true` or `valid: false` with a coded error. `policy
resolve` prints the normalized merged policy. Add `--tool <PROGRAM>` to either
policy command to include executable-attached policy.

Policy inspection, `doctor`, and Windows management commands each write one JSON
document to standard output. An invalid policy, an unhealthy `doctor` report, or
an unhealthy `windows status` exits with status 1. Operational failures emit a
coded trap on standard error. `run` returns the sandboxed program's exit status.

### Agent extensions

The bundled extensions integrate Landstrip with Pi and OpenCode. The Pi extension
sandboxes Bash, supports primary agents, and runs subagents as separate Pi RPC
processes. Subagents normally run inside a Landstrip sandbox. Disabling sandboxing
shows a warning and uses process isolation only:

```sh
pi install npm:pi-landstrip
opencode plugin install opencode-landstrip
```

See [pi-landstrip](packages/pi-landstrip/README.md) and
[opencode-landstrip](packages/opencode-landstrip/README.md) for configuration
details.

## Platforms

| Area         | macOS                  | Linux                      | Windows                            |
| ------------ | ---------------------- | -------------------------- | ---------------------------------- |
| Policy       | path-based rules       | file-based rules           | per-run ACL grants                 |
| Timing       | dynamic path subset    | static file-based ruleset  | per-run grants with cleanup        |
| TCP          | proxy or loopback      | proxy or loopback          | capabilities or account-scoped WFP |
| Unix sockets | allowlist              | seccomp-brokered allowlist | allow all or deny all              |

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

Landstrip has two internal Windows implementations. AppContainer needs no
installation and is used by default. `landstrip windows install` provisions
and activates restricted-user execution for programs such as Git Bash/MSYS
that cannot initialize inside AppContainer. `landstrip windows uninstall`
returns to AppContainer. There is no implementation selector in the command
line or policy. An unhealthy restricted-user installation causes failure
rather than silent fallback, and `landstrip windows status` reports the active
implementation and health. Policies containing the removed `windows.backend`
field are rejected; use the Windows commands to select the implementation.

Both implementations use explicit read allowlists. Ancestors receive
traversal-only, non-inheriting access; unrelated siblings are not exposed.

#### AppContainer

Landstrip creates a per-run profile, grants its SID access to the lowered read
and write roots, and removes those grants after the sandboxed process tree
exits.

`windows.appContainerMode` selects `"lpac"` (the default) or `"standard"`.
LPAC provides the stricter boundary. Standard AppContainer can also access
resources already granted to `ALL APPLICATION PACKAGES`, so selecting it is an
explicit security downgrade. Landstrip never retries an LPAC launch in
standard mode.

Landstrip assigns the sandboxed process to a Job Object with
`KILL_ON_JOB_CLOSE`, so child processes are kept in the sandbox process tree
and terminated when the launcher exits. When a restrictive host Job Object
prevents safe breakaway, Landstrip fails with `HOST_JOB_INCOMPATIBLE`; it never
launches without its own job.

`allowNetwork` grants the internet and private-network AppContainer
capabilities, while the default container holds none. `windows.allowLoopback`
is a separate, explicit opt-in that temporarily exempts only the per-run
AppContainer SID. The exemption permits every local loopback service, not a
single proxy port. Existing system exemptions are preserved and the per-run
exemption is removed at exit.

AppContainer capabilities are coarse. Fine-grained direct TCP policies by host
or port require elevated Windows Filtering Platform rules keyed by the
AppContainer SID, which is unsuitable for an unprivileged agent sandbox
runtime.

#### Restricted user

Install restricted-user execution once from the intended host account. Install
requests elevation through UAC, provisions dedicated local accounts, installs
account-scoped persistent WFP rules, and copies a protected runner executable:

```powershell
landstrip windows install
landstrip windows status
landstrip run -p policy.json -- cargo test
landstrip windows uninstall
```

The default pool has eight restricted-network accounts and two
unrestricted-network accounts. Use `landstrip windows install --help` to
configure pool sizes and the loopback proxy port range. Install replaces an
existing installation; uninstall revokes recorded ACL grants, removes WFP
policy and accounts, and deletes the installed runner.

Each run exclusively leases an account, journals its filesystem grants before
applying them, launches the command through a restricted token and Job Object,
then revokes the grants. A later lease or uninstall recovers stale journaled
grants after a crash. Account credentials are random, stored with Windows
DPAPI, and never placed in policy files.

Restricted-network accounts are blocked by WFP except for loopback connections
to the proxy port range chosen during installation. Proxy ports in a policy
must fall in that range. `network.allowLocalBinding` and
`windows.allowLoopback` are unsupported by this implementation.
`network.allowNetwork: true` instead leases an account and therefore requires
at least one such account in the installed pool.

The restricted token enforces the per-run account-SID grants while retaining
the standard `ALL APPLICATION PACKAGES` read/execute baseline for Windows and
Program Files. As with standard AppContainer, resources exposed to that SID
remain visible.

## Policy format

JSON is the default policy format for files. Use `--policy-format yaml` for YAML
or specify the format explicitly whenever policy is read from standard input.

```sh
landstrip run --policy-format yaml -p policy.yaml -- cargo test
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

### Executable policy

Supplementary policy can be attached directly to a tool's executable inode:
- **Unix**: `user.landstrip.policy` extended attribute (`xattr`).
- **Windows**: `landstrip.policy` NTFS alternate data stream (`ADS`).

When present, the attribute contents are parsed and merged to the policy. The
executable is resolved via `PATH` lookup and canonicalized so policy attributes
are always read from the real binary inode. If an attribute exists but is
unreadable or malformed, tool execution is aborted.

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
- **Windows**: Glob `denyWrite` entries are not enforced by AppContainer.

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
policy enforcement in place. On Windows, AppContainer receives its network
capabilities while restricted-user isolation leases an unrestricted-network
account. With `allowNetwork: false`, AppContainer denies network unless
`windows.allowLoopback` enables the all-loopback exemption described above;
restricted-user isolation permits only the installed loopback proxy port range.

A Windows runtime that requires standard AppContainer and loopback can opt in with
the following policy:

```json
{
  "windows": {
    "appContainerMode": "standard",
    "allowLoopback": true
  }
}
```

Core Landstrip defaults to LPAC with loopback disabled.

## Traps

Every Landstrip event, whether a sandbox denial or a failure that prevents the
tool from running, is reported as one JSON object per line, with a fixed `kind`
discriminant and stable `code`. Consumers route on `kind` for the record shape
and `code` for the event. Failures and completed denials go to standard error by
default. The `--trap-fd FD` option is available only in Unix builds and names an
already-open descriptor. On Linux, pending query traps go only to that descriptor.

```sh
landstrip run --trap-fd 3 -p policy.json -- cargo test 3>landstrip-traps.txt
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
the same `LAUNCH_FAILED` or `SANDBOX_SETUP_FAILED` is raised by every
implementation that has that stage. The platform detail rides along in the
record instead.

`mechanism` records the kernel layer an event is attributed to: `landlock`,
`seccomp`, `seatbelt`, `appcontainer`, or `windowsuser`. Per-denial traps are
always `seccomp`, the only layer with a per-denial callback; Landlock enforces
in-kernel without one. `SANDBOX_SETUP_FAILED` carries the mechanism that could
not be installed.

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
output to the sandboxed tool. Failures are emitted as coded JSON traps. Usage
errors exit with status 2, other Landstrip failures with 1, and the tool's own
status is otherwise passed through.

On Unix, writing to `--trap-fd` is best-effort: it needs an already-open
descriptor (3 or greater; 0-2 are reserved), and if the write fails the trap is
dropped while the policy stays in effect. On Linux, a broker launch failure also
reaches `--trap-fd` while the descriptor remains open.

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
