<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) Jarkko Sakkinen 2026 -->

# landstrip

`landstrip` runs commands in an OS-level sandbox using Landlock on Linux,
Seatbelt on macOS, and AppContainer or restricted users on Windows. Policies use
the supported subset of the Anthropic Sandbox Runtime format.

## Installation

```sh
npm install --save-dev @landstrip/landstrip
npx landstrip run -p policy.json -- cargo test
```

The npm package installs a Node.js wrapper and a native binary for the current
platform.

## Command line

```text
landstrip run [OPTIONS] -- <PROGRAM> [ARGS...]
landstrip policy validate [OPTIONS]
landstrip policy resolve [OPTIONS]
landstrip doctor
landstrip windows install [OPTIONS]
landstrip windows status
landstrip windows uninstall
```

The `windows` commands exist only in Windows builds.

Pass policies with `-p, --policy <FILE>`. The option may be repeated; objects
merge recursively, later scalar values replace earlier ones, and arrays combine.
JSON is the default. Use `--policy-format yaml` for YAML and always specify the
format with `-p -`.

`run` also merges policy attached to the program executable. `policy validate`
checks parsing, resolution, and platform support. `policy resolve` prints the
normalized policy; add `--tool <PROGRAM>` to include executable policy.
`doctor` checks that the platform sandbox is usable.

Inspection and management commands print one JSON document. `run` returns the
program's exit status. Usage errors return 2; other Landstrip failures return 1.

### Agent extensions

Companion extensions integrate Landstrip with Pi and OpenCode. The Pi extension
also provides primary agents and process-backed subagents.

```sh
pi install npm:pi-landstrip
opencode plugin install opencode-landstrip
```

See [pi-landstrip](packages/pi-landstrip/README.md) and
[opencode-landstrip](packages/opencode-landstrip/README.md).

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
    "allowLocalBinding": false,
    "allowUnixSockets": []
  }
}
```

Paths may be absolute, relative to the starting directory, or prefixed with
`~`. Path lists also accept `*`, `**`, `?`, and character-class globs.

Writes are denied by default. `allowWrite` grants writable roots; `denyWrite`
always takes precedence. Reads are unrestricted until `denyRead` is non-empty;
`allowRead` then adds exceptions, with the most specific read rule winning.

Concrete `denyWrite` paths work on every platform. Glob denies are evaluated at
access time on Linux and macOS, including for newly created files. Windows does
not enforce glob `denyWrite` entries.

Direct TCP and new Unix sockets are denied by default. Proxy ports allow
loopback connections only to those ports; Landstrip does not start a proxy or
filter domains. `allowLocalBinding` permits local TCP binding and loopback
connections. `allowUnixSockets` grants pathname sockets, and
`allowAllUnixSockets` allows all Unix sockets. Set `allowNetwork` to `true` to
disable network enforcement while keeping filesystem restrictions.

On Unix, supplementary executable policy is read from the
`user.landstrip.policy` extended attribute. On Windows it is read from the
`landstrip.policy` NTFS alternate data stream. Executable policy is merged
after `--policy` files.

## Platforms

| Platform | Filesystem | Network |
| --- | --- | --- |
| Linux | Landlock and seccomp | TCP and Unix socket rules |
| macOS | Seatbelt | TCP and Unix socket rules |
| Windows | AppContainer or restricted user | AppContainer capabilities or account-scoped WFP |

Windows requires an explicit read allowlist. AppContainer is used without
installation; core Landstrip defaults to LPAC. `windows.appContainerMode` may
select `standard`, which is weaker because it can see resources granted to
`ALL APPLICATION PACKAGES`. In AppContainer, `windows.allowLoopback` exposes
every local loopback service; without it, proxy ports are blocked.

Use `landstrip windows install` when software such as Git Bash cannot start in
AppContainer. It provisions restricted local users and activates that mode.
`windows uninstall` removes it and returns to AppContainer. An unhealthy
installation fails closed; inspect it with `windows status`.

Windows does not support `allowLocalBinding` or Unix socket policy.
Restricted-user mode permits proxy ports only from the range chosen at install
time and does not support `windows.allowLoopback`.

## Traps

Landstrip failures and broker-reported denials are JSON objects with a stable
`kind` and `code`. Failures and completed denials go to standard error. The
sandboxed program may also write to standard error.

On Unix, `--trap-fd FD` sends structured events to an already-open descriptor
numbered 3 or higher. On Linux, a socket trap descriptor can carry a
`state: "query"` filesystem or network event that pauses an operation for the
integrating host to answer. Query events go only to that socket. Kernel-only
and static-profile denials do not always produce a per-access event.

Trap kinds are `filesystem`, `network`, `launch`, `usage`, and `internal`.
Filesystem and network records describe denied operations; the other kinds
report failures in Landstrip itself.

## Licensing

The JavaScript npm wrapper is licensed under `Apache-2.0`. The Rust source and
native binaries are licensed under `LGPL-2.1-or-later`. Corresponding source for
each native package is available from the matching repository tag.
