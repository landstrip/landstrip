# landstrip

`landstrip` runs a tool in an OS-level sandbox using Landlock LSM on Linux,
Seatbelt on macOS, and LPAC AppContainer on Windows.  It accepts the Anthropic
Sandbox Runtime JSON subset as the policy.

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

## Backends

| Area         | macOS                    | Linux                        | Windows                         |
| ------------ | ------------------------ | ---------------------------- | ------------------------------- |
| Policy       | path based rules         | file based rules             | access control list (ACL)       |
| Timing       | dynamic subset of paths  | file based static ruleset    | persistent ACLs                 |
| TCP          | localhost proxy ports    | loopback proxy ports         | unsupported                     |
| Unix sockets | allowlist                | allowlist via seccomp broker | unsupported                     |

Windows uses an AppContainer. The backend grants the generated AppContainer SID
access to the lowered read and write roots, so Windows policies must use
explicit read allowlists. Fine-grained TCP and Unix socket policies are rejected
until Windows enforcement exists.

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

## JSON Output

Failures reported by `landstrip` are printed as one compact JSON object on
standard output. This covers policy, tool launch, capability, and system
errors. Usage errors are not JSON responses; they remain on standard error and
exit with status 2.

```json
{"code":"policy","file":"policy.json","message":"expected value at line 1 column 1"}
```

```json
{"code":"tool","program":"cargo","message":"No such file or directory"}
```

The `code` field is one of `policy`, `tool`, `capability`, or `system`. The
`file` field is present when a policy error is tied to a policy file. The
`program` field is present when landstrip could not start or encode a tool.

Logs and sandboxed tool output are not part of the JSON response. Normal
successful tool execution does not print a landstrip JSON response because
standard output belongs to the sandboxed tool.

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
