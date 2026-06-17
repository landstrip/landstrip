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

### Windows AppContainer

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

## Error Output

Failures reported by `landstrip` are printed as JSON objects on standard
error, one object per line. Each object is tagged by the trap kind, with the
kind name as the single top-level key. Every kind carries a stable `code`, so
consumers can route on a single field.

```json
{"Internal":{"code":"INTERNAL_ERROR","detail":{"file":"policy.json","source":"expected value at line 1 column 1"}}}
```

```json
{"Launch":{"code":"LAUNCH_FAILED","program":"cargo","message":"No such file or directory"}}
```

The trap kinds are:

- `Filesystem`: a filesystem access denial object. The stable `code` is
  `FS_READ_DENIED` or `FS_WRITE_DENIED`; `operation` is `read` or `write`;
  `path` is the resolved path; `requested_path` is the original path supplied by
  the tool when available; `syscall`, `errno`, `flags`, `reason`,
  `suggested_grant`, and `process` provide machine-readable routing context.
- `Network`: a denied TCP connect or bind object. The stable `code` is
  `NET_CONNECT_DENIED` or `NET_BIND_DENIED`; `operation` is `connect` or `bind`;
  `target` is `address:port`; `syscall`, `errno`, and `process` provide routing
  context.
- `Launch`: the tool could not be started. The stable `code` is `LAUNCH_FAILED`;
  `program` and `message` give the program and the failure detail.
- `Usage`: a command-line usage error. The stable `code` is `USAGE_ERROR`;
  `message` is the error text. Usage errors exit with status 2.
- `Internal`: any other policy, platform, or system error. The stable `code` is
  `INTERNAL_ERROR`; `detail` is an object of diagnostic key/value pairs (for
  example `source`, `file`, or platform API details).

The `reason` field is a platform-independent classification of the policy
decision, derived from the policy and the requested path rather than from the
enforcement mechanism. Its stable values are:

- `allow_miss`: the path matched no allow root and was denied by default.
- `deny_match`: the path matched an explicit deny root that overrides an allow.
- `unclassified`: a denial occurred but landstrip could not attribute it to a
  specific rule.

Example of a filesystem denial:

```json
{
  "Filesystem": {
    "code": "FS_WRITE_DENIED",
    "operation": "write",
    "path": "/repo/out",
    "requested_path": "out",
    "syscall": "openat",
    "errno": "EACCES",
    "flags": [
      "O_WRONLY",
      "O_CREAT",
      "O_TRUNC"
    ],
    "reason": "allow_miss",
    "suggested_grant": {
      "allowWrite": "/repo/out"
    },
    "mechanism": "seccomp",
    "process": {
      "pid": 1234,
      "exe": "/usr/bin/sh",
      "cwd": "/repo"
    }
  }
}
```

Logs and sandboxed tool output are not part of the response. Normal successful
tool execution does not print a landstrip response unless a write denial was
observed, because standard error belongs to landstrip; standard output belongs
to the sandboxed tool.

## Trap FD

Use `--trap-fd FD` to write landstrip trap denial blocks to an
already-open file descriptor as JSON objects, one per line followed by
a newline.

```sh
landstrip --trap-fd 3 -p policy.json cargo test 3>landstrip-traps.txt
```

Linux filesystem and network denials observed by the seccomp broker are
emitted with the same object shapes as standard error:

```json
{
  "Filesystem": {
    "code": "FS_WRITE_DENIED",
    "operation": "write",
    "path": "/repo/out",
    "requested_path": "out",
    "syscall": "openat",
    "errno": "EACCES",
    "flags": [
      "O_WRONLY",
      "O_CREAT",
      "O_TRUNC"
    ],
    "reason": "allow_miss",
    "suggested_grant": {
      "allowWrite": "/repo/out"
    },
    "mechanism": "seccomp",
    "process": {
      "pid": 1234,
      "exe": "/usr/bin/sh",
      "cwd": "/repo"
    }
  }
}
{
  "Network": {
    "code": "NET_CONNECT_DENIED",
    "operation": "connect",
    "target": "127.0.0.1:9999",
    "syscall": "connect",
    "errno": "EACCES",
    "mechanism": "seccomp",
    "process": {
      "pid": 1234,
      "exe": "/usr/bin/nc",
      "cwd": "/repo"
    }
  }
}
```

The `mechanism` field records the kernel enforcement layer that detected the
denial. Per-denial `Filesystem` and `Network` traps are always `seccomp`,
because the user-notification broker is the only layer with a per-denial
callback; Landlock enforces in-kernel without one. The `landlock` value
appears only as a `mechanism` detail in an `Internal` trap when Landlock
ruleset setup fails.

This stream is separate from the sandboxed tool's output. If the option is
omitted, landstrip is quiet unless it has to report a policy, launch, or
platform error. These long-lived error messages remain on standard error
and are not duplicated in the trap stream.

Trap responses are informational. The configured sandbox policy always
applies. However, writing trap responses requires an already-open file
descriptor and a readable file path. If the sandbox blocks writing to the
descriptor, or if writing fails, the denial is quietly dropped and the
policy remains in effect. On backends without per-denial callbacks the
option is best-effort.

The descriptor must be 3 or greater (standard I/O descriptors 0-2 are
reserved).

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
