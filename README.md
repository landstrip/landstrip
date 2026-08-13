<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
<!-- Copyright (C) Jarkko Sakkinen 2026 -->

# landstrip

`landstrip` runs a command inside an OS sandbox: Landlock on Linux, Seatbelt on
macOS, and AppContainer or a restricted user on Windows. Its policy format is
the supported subset of the Anthropic Sandbox Runtime format.

## Install

```sh
npm install --save-dev @landstrip/landstrip
npx landstrip run -p policy.json -- cargo test
```

The npm package selects the native binary for the current platform.

## Commands

```text
landstrip run [OPTIONS] -- <PROGRAM> [ARGS...]
landstrip policy validate [OPTIONS]
landstrip policy resolve [OPTIONS]
landstrip doctor
landstrip windows install [OPTIONS]
landstrip windows status
landstrip windows uninstall
```

The `windows` commands are available only in Windows builds. `doctor` checks
whether the platform sandbox is usable. Inspection commands print one JSON
document. `run` returns the program's exit status; usage errors return 2 and
other Landstrip failures return 1.

Pass a policy with `-p, --policy <FILE>`. Repeat the option to merge policies
from left to right: objects merge recursively, arrays combine without duplicate
entries, and later scalar values replace earlier values. JSON is the default;
use `--policy-format yaml` for YAML and always specify a format with `-p -`.

`policy validate` parses and resolves the policy and checks platform support.
`policy resolve` prints the normalized result; `--tool <PROGRAM>` also merges
policy attached to that executable. Executable policy is applied last from the
`user.landstrip.policy` extended attribute on Unix or the `landstrip.policy`
NTFS alternate data stream on Windows.

## Policy

```json
{
  "filesystem": {
    "allowWrite": ["."],
    "denyWrite": ["**/.env", "**/*.pem"],
    "denyRead": ["~/.ssh"],
    "allowRead": ["~/.ssh/config"]
  },
  "network": {
    "allowNetwork": false,
    "httpProxyPort": 8080,
    "socksProxyPort": 1080,
    "allowLocalBinding": false,
    "allowAllUnixSockets": false,
    "allowUnixSockets": []
  },
  "windows": {
    "appContainerMode": "lpac",
    "allowLoopback": false
  }
}
```

Paths may be absolute, relative to the command's starting directory, or start
with `~`. Path fields accept arrays or newline-separated strings. Entries accept
`*`, `**`, `?`, and character-class globs.

### Filesystem

| Field | Default | Effect |
| --- | --- | --- |
| `allowWrite` | `[]` | Writable roots |
| `denyWrite` | `[]` | Hard write denials; takes precedence over `allowWrite` |
| `denyRead` | `[]` | Read restrictions; empty means unrestricted reads |
| `allowRead` | `[]` | Exceptions to `denyRead` |

When read rules overlap, the most specific rule wins. Concrete `denyWrite` paths
work on every platform. Linux and macOS also enforce glob denials at access time,
including for newly created files; Windows does not enforce glob `denyWrite`.

### Network

| Field | Default | Effect |
| --- | --- | --- |
| `allowNetwork` | `false` | Disables network enforcement when `true` |
| `httpProxyPort` | unset | Allows loopback connection to this port |
| `socksProxyPort` | unset | Allows loopback connection to this port |
| `allowLocalBinding` | `false` | Allows local TCP binding and loopback connections |
| `allowAllUnixSockets` | `false` | Allows every Unix socket |
| `allowUnixSockets` | `[]` | Allows listed pathname Unix sockets |

Landstrip does not start a proxy or filter domains. Direct TCP and new Unix
sockets are denied unless allowed by these fields.

### Windows

`windows.appContainerMode` is `"lpac"` by default; `"standard"` is weaker
because it can read resources granted to `ALL APPLICATION PACKAGES`.
`windows.allowLoopback` exposes every local loopback service in AppContainer;
without it, proxy ports are blocked. The removed `windows.backend` field is an
error.

Windows requires explicit read roots. ACL allow roots must exist when policy is
resolved; missing `allowRead` and `allowWrite` targets are omitted and remain
inaccessible. Windows does not support `allowLocalBinding` or Unix socket
policy.

Use `landstrip windows install` when software such as Git Bash cannot start in
AppContainer. It provisions restricted local users and activates that mode.
`windows uninstall` removes it. An unhealthy installation fails closed; inspect
it with `windows status`. Restricted-user mode permits proxy ports only from the
range selected at installation and does not support `windows.allowLoopback`.

## Platform enforcement

| Platform | Filesystem | Network |
| --- | --- | --- |
| Linux | Landlock and seccomp | TCP and Unix socket rules |
| macOS | Seatbelt | TCP and Unix socket rules |
| Windows | AppContainer or restricted user | AppContainer capabilities or account-scoped WFP |

## Agent extensions

[pi-landstrip](packages/pi-landstrip/README.md) and
[opencode-landstrip](packages/opencode-landstrip/README.md) integrate Landstrip
with coding agents.

- **Agent permissions** authorize tool dispatch.
- **Sandbox permissions** authorize filesystem and network access.

An agent approval does not bypass the sandbox. Each plugin documents its prompt
order, approval scopes, and configuration files.

```sh
pi install npm:pi-landstrip
opencode plugin install opencode-landstrip
```

## Traps

Landstrip failures and broker-reported denials are JSON objects with stable
`kind` and `code` fields. Completed records go to standard error.

On Unix, `--trap-fd FD` writes structured events to an already-open descriptor
numbered 3 or higher. On Linux, a socket trap descriptor can receive a
filesystem or network event with `state: "query"`; the operation waits for its
host to answer. Kernel-only and static-profile denials do not always emit a
per-access event. Trap kinds are `filesystem`, `network`, `launch`, `usage`, and
`internal`.

## Development

```sh
make ci
CI_MSRV=1 make ci
make package
make package PLATFORMS='linux-x64 win32-x64'
PACKAGE_STRICT=1 make package
```

`scripts/ci.sh` checks Rust and every agent-extension workspace, stages the host
binary, and smoke-tests the npm wrapper. Packaging uses `cross` and Docker for
cross targets. macOS targets build natively on macOS; Linux hosts require local
osxcross images. Windows Arm64 requires the local
`ghcr.io/cross-rs/aarch64-pc-windows-msvc-cross:local` image.

After `scripts/release.sh <version>` and pushing the tag:

```sh
make ci
PACKAGE_STRICT=1 make package
make publish
```

`make publish` publishes the crates.io and npm packages and uploads release
archives from locally packaged artifacts.

## Licensing

The JavaScript wrapper is `Apache-2.0`. Rust source and native binaries are
`LGPL-2.1-or-later`; corresponding source is available from the matching tag.
