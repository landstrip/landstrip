<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) Jarkko Sakkinen 2026 -->

# landstrip

`landstrip` runs a tool in an OS-level sandbox using Landlock LSM on Linux,
Seatbelt on macOS, and LPAC AppContainer on Windows.  It accepts the Anthropic
Sandbox Runtime JSON subset as the policy, in JSON or YAML syntax.

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

## Platforms

| Area         | macOS                    | Linux                        | Windows                         |
| ------------ | ------------------------ | ---------------------------- | ------------------------------- |
| Policy       | path based rules         | file based rules             | per-run AppContainer ACLs       |
| Timing       | dynamic subset of paths  | file based static ruleset    | per-run ACL grants              |
| TCP          | localhost proxy ports    | loopback proxy ports         | allow all or deny all           |
| Unix sockets | allowlist                | allowlist via seccomp broker | allow all or deny all           |

### Linux

Landlock carves the denied subtrees out of the allowed roots, and then grants
`PATH_BENEATH` rules only for the surviving fragments. The denied path is never
added to the ruleset, and the kernel enforces the path in-process.

Seccomp is applied when a policy needs more than Landlock can express
statically, e.g. for many filesystem mutator syscalls, or when denials must be
reported back to the launcher. The broker intercepts `openat`/`openat2` via
seccomp user-notifications, resolves the real path, and validates it

Finally there's some logic to deduce that Landlock and Seccomp (mostly for
mutator syscall, which take fd) are fairly disjoint entities.

### Windows

Win32 API provides AppContainer for application level sandboxing. The platform
creates a per-run LPAC AppContainer profile, grants its SID access to the lowered
read and write roots, and removes those grants after the sandboxed process tree
exits. Windows policies must use explicit read allowlists.

Landstrip assigns the sandboxed process to a Job Object with
`KILL_ON_JOB_CLOSE`, so child processes are kept in the sandbox process tree and
are terminated when the launcher exits.

`allowNetwork` grants the internet and private-network AppContainer
capabilities, while the default container holds none and denies all network
access.

AppContainer capabilities are coarse: fine-grained TCP policies by host or port
require Windows Filtering Platform rules keyed by the AppContainer SID. I.e.,
this would require elevated privileges, which is not sustainable for a agent
sandbox runtime, which should rely on unprivileged tools and techniques.

## Policy Format

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

Windows-only hardening options live under `windows`. They are optional because
some tools, shells, JITs, and GUI helpers may rely on the blocked behaviors:

```json
{
  "windows": {
    "disableWin32k": true,
    "disableExtensionPoints": true,
    "strictHandleChecks": true,
    "imageLoadNoRemote": true,
    "imageLoadNoLowLabel": true,
    "imageLoadPreferSystem32": true
  }
}
```

## Filesystem Policy

Write access is denied by default.  `allowWrite` paths grant write access and
`denyWrite` paths subtract from them, with the most specific rule winning where
an allow and a deny overlap. Read access is unrestricted by default; setting
`denyRead` lowers it to an allowlist, and `allowRead` adds paths back.

### Write Denial Semantics

Concrete (non-glob) `denyWrite` paths are canonicalized and enforced
eagerly on all platforms.

Glob `denyWrite` patterns (`**/.env`, `**/*.pem`, etc.) behave differently
by platform:

- **Linux**: Globs are evaluated dynamically by the seccomp broker at each write
  attempt. Files created after sandbox startup that match a denyWrite glob are
  blocked. The glob is never walked at startup, so large trees do not cause
  startup latency.
- **macOS**: Globs are snapshot-expanded when the Seatbelt profile is compiled.
  Files created after `sandbox_init` are not protected by glob denies — use
  concrete paths for those. A warning is logged when glob deny patterns are
  used.
- **Windows**: Glob denyWrite entries are not enforced by the AppContainer
  backend.


## Network Policy

Sandbox mode denies direct network access by default. Proxy ports, local binding,
and Unix sockets can be allowed with the Anthropic Sandbox Runtime network fields.

For a filesystem-only sandbox with unrestricted direct network access, set:

```json
{
  "network": {
    "allowNetwork": true
  }
}
```

`allowNetwork` disables landstrip network enforcement while leaving filesystem
policy enforcement in place. On Windows this grants the AppContainer its network
capabilities; without it the container denies all network access.

## Denial Traps

Sandbox denials are reported as JSON objects, one per line, each with a fixed
`kind` discriminant and a stable `code`. Consumers route on `kind` for coarse
grouping and on `code` for the policy denial class. Traps go to standard error
by default; `--trap-fd FD` writes them to an already-open descriptor instead.

```sh
landstrip --trap-fd 3 -p policy.json cargo test 3>landstrip-traps.txt
```

The two trap kinds are:

- `filesystem` (`code` `FILESYSTEM_DENIED`): `operation` is `read` or `write`,
  `path` is the resolved path, `requested_path` is the tool's original path when
  available, and `syscall`, `errno`, `flags`, `reason`, `suggested_grant`, and
  `process` carry routing context.
- `network` (`code` `NETWORK_DENIED`): `operation` is `connect` or `bind` and
  `target` is `address:port`, with `syscall`, `errno`, and `process` context.

`reason` is a platform-independent classification of the decision, derived from
the policy and the requested path:

- `allow_miss`: the path matched no allow root and was denied by default.
- `deny_match`: the path matched an explicit deny root that overrides an allow.

`mechanism` records the kernel layer that detected the denial. Per-denial traps
are always `seccomp`, the only layer with a per-denial callback; Landlock
enforces in-kernel without one.

```json
{
  "kind": "filesystem",
  "code": "FILESYSTEM_DENIED",
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
  "operation": "connect",
  "target": "127.0.0.1:9999",
  "syscall": "connect",
  "errno": "EACCES",
  "mechanism": "seccomp",
  "process": { "pid": 1234, "exe": "/usr/bin/nc", "cwd": "/repo" }
}
```

Traps are informational; the configured policy always applies. landstrip is
otherwise quiet on success — standard error belongs to landstrip, standard
output to the sandboxed tool. Usage, policy, launch, and platform errors are
printed as plain text; usage errors exit with status 2. Writing to `--trap-fd`
is best-effort: it needs an already-open descriptor (3 or greater; 0-2 are
reserved), and if the write fails the denial is dropped while the policy stays
in effect.

## Development

### Commit messages

- **`<subsystem>: <message>`**
- Long description for non-trivial changes.
- Kernel style commit messages.
- **`Signed-off-by`**

### Documenting errors

The following snippet demonstrates the recommended pattern for documenting
the return values on error:

```
/// # Errors
///
/// Returns [`<variant's unqualified name>`](<variant's unqualified name>)
/// Returns ...
```

## Licensing

The JavaScript npm wrapper is licensed under `Apache-2.0`. The Rust source and
native binaries are licensed under `LGPL-2.1-or-later`.
Corresponding source for each published native binary is available from the
GitHub repository tag that matches the package version.
