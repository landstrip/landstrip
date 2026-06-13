# landstrip

`landstrip` runs a tool in an OS-level sandbox using Landlock LSM on Linux,
Seatbelt on macOS, and LPAC AppContainer on Windows.  It accepts the Anthropic
Sandbox Runtime JSON subset as the policy, in JSON or YAML syntax.

## Installation

### npm

```sh
npm install --save-dev @jarkkojs/landstrip
```

```sh
npx landstrip -p policy.json cargo test
```

The npm package installs a small Node.js wrapper and a platform-specific native
binary package.

## Platforms

| Area         | macOS                    | Linux                        | Windows                         |
| ------------ | ------------------------ | ---------------------------- | ------------------------------- |
| Policy       | path based rules         | file based rules             | access control list (ACL)       |
| Timing       | dynamic subset of paths  | file based static ruleset    | persistent ACLs                 |
| TCP          | localhost proxy ports    | loopback proxy ports         | unsupported                     |
| Unix sockets | allowlist                | allowlist via seccomp broker | unsupported                     |

Windows uses an AppContainer. The platform grants the generated AppContainer SID
access to the lowered read and write roots, so Windows policies must use
explicit read allowlists. Fine-grained TCP and Unix socket policies are rejected
until Windows enforcement exists.

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

On Linux and macOS, `allowNetwork` disables landstrip network enforcement while
leaving filesystem policy enforcement in place. Windows rejects unrestricted
network policies until Windows network support exists.

## Error Output

Failures reported by `landstrip` are printed as `field: value` lines on standard
error, one line per field. Fields with no value are omitted.  This covers
policy, tool launch, platform, and system errors. Usage errors are not formatted
responses; they remain on standard error and exit with status 2.

```
reason: Other
file: policy.json
source: expected value at line 1 column 1
```

```
reason: LaunchFailed
program: cargo
type: launch
source: No such file or directory
```

The `reason` field describes the error kind (e.g. `Other`, `AccessDenied`,
`LaunchFailed`, `SetupFailed`, `Usage`). The `file` field is present when a
policy error is tied to a policy file or filesystem access denial. The `program`
field is present when landstrip could not start or encode a tool. The `type`
field is present for policy or tool errors and is either `filesystem`, `network`,
or `platform` for policy errors, or `launch` (failed to start the tool) or
`encoding` (failed to encode the command line) for tool errors. Filesystem access
denials may include `operation: read` or `operation: write`.

Logs and sandboxed tool output are not part of the response. Normal successful
tool execution does not print a landstrip response unless a write denial was
observed, because standard error belongs to landstrip; standard output belongs
to the sandboxed tool.

## Error FD

Use `--error-fd FD` to write landstrip error response blocks to an
already-open file descriptor. This side channel is intended for wrappers that
need to react to sandbox denials without parsing the sandboxed tool's stderr.

```sh
landstrip --error-fd 3 -p policy.json cargo test 3>landstrip-errors.txt
```

Linux emits filesystem denials observed by the seccomp broker using the same
field format as landstrip's stderr responses:

```text
reason: AccessDenied
type: filesystem
file: /repo/out
operation: write
mechanism: seccomp
```

The option is best-effort on other backends; macOS Seatbelt and Windows
AppContainer do not currently provide per-access denial callbacks.

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
