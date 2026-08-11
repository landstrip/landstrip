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

Windows ACL allow roots must exist when the policy is resolved. Missing
`allowRead` and `allowWrite` targets are omitted and remain inaccessible.

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

## Development

### Check

```sh
make ci
CI_MSRV=1 make ci  # optional MSRV check
```

`scripts/ci.sh` runs the Rust build, tests, clippy, and fmt, stages the host
binary into `npm/<host>/bin`, smoke-tests the npm wrapper, and runs every
agent-extension workspace's `ci:fmt`/`ci:lint`/`ci:check`/`ci:test` scripts
via `scripts/test-extensions.sh --local-root`.

### Package

All cross targets use [`cross`](https://github.com/cross-rs/cross) and Docker.
Linux x64/arm64 (musl) and Windows x64 (GNU) use official cross images.

```sh
make package
make package PLATFORMS='linux-x64 win32-x64'
PACKAGE_STRICT=1 make package
```

On a macOS host both `darwin-*` targets build natively with `cargo`; the
`osxcross` images are only required when packaging from Linux. The
`win32-arm64` target uses a local MSVC image because cross-rs cannot ship it:

```sh
git clone https://github.com/cross-rs/cross-toolchains.git
cd cross-toolchains/docker
cp /path/to/MacOSX*.sdk.tar.xz .  # only for darwin-* from Linux
docker build -f Dockerfile.aarch64-pc-windows-msvc-cross \
  -t ghcr.io/cross-rs/aarch64-pc-windows-msvc-cross:local .
```

`darwin-arm64`/`darwin-x64` osxcross images follow the same `docker build` step
from `Dockerfile.aarch64-apple-darwin-cross` / `Dockerfile.x86_64-apple-darwin-cross`
(supplying a macOS SDK archive) when packaging from Linux.

`ls` the `artifacts/` directory after a run; `make publish` requires every
platform binary staged in `npm/*/bin`.

### Release

After `scripts/release.sh <version>` and pushing the tag:

```sh
make ci
PACKAGE_STRICT=1 make package
make publish
```

`make publish` publishes crates.io and npm packages from the locally packaged
binaries, then uploads GitHub release tarballs with `gh`.


## Development

### Check

```sh
make ci
CI_MSRV=1 make ci  # optional MSRV check
```

`scripts/ci.sh` runs the Rust build, tests, clippy, and fmt, stages the host
binary into `npm/<host>/bin`, smoke-tests the npm wrapper, and runs every
agent-extension workspace's `ci:fmt`/`ci:lint`/`ci:check`/`ci:test` scripts
via `scripts/test-extensions.sh --local-root`.


### Package

All cross targets use [`cross`](https://github.com/cross-rs/cross) and Docker.
Linux x64/arm64 (musl) and Windows x64 (GNU) use official cross images.

```sh
make package
make package PLATFORMS='linux-x64 win32-x64'
PACKAGE_STRICT=1 make package
```

On a macOS host both `darwin-*` targets build natively with `cargo`; the
`osxcross` images are only required when packaging from Linux. The
`win32-arm64` target uses a local MSVC image because cross-rs cannot ship it:

```sh
git clone https://github.com/cross-rs/cross-toolchains.git
cd cross-toolchains/docker
cp /path/to/MacOSX*.sdk.tar.xz .  # only for darwin-* from Linux
docker build -f Dockerfile.aarch64-pc-windows-msvc-cross \
  -t ghcr.io/cross-rs/aarch64-pc-windows-msvc-cross:local .
```

`darwin-arm64`/`darwin-x64` osxcross images follow the same `docker build` step
from `Dockerfile.aarch64-apple-darwin-cross` / `Dockerfile.x86_64-apple-darwin-cross`
(supplying a macOS SDK archive) when packaging from Linux.

`ls` the `artifacts/` directory after a run; `make publish` requires every
platform binary staged in `npm/*/bin`.


### Release

After `scripts/release.sh <version>` and pushing the tag:

```sh
make ci
PACKAGE_STRICT=1 make package
make publish
```

`make publish` publishes crates.io and npm packages from the locally packaged
binaries, then uploads GitHub release tarballs with `gh`.

### Package

All cross targets use [`cross`](https://github.com/cross-rs/cross) and Docker.
Linux x64/arm64 (musl) and Windows x64 (GNU) use official cross images.

```sh
make package
make package PLATFORMS='linux-x64 win32-x64'
PACKAGE_STRICT=1 make package
```

On a macOS host both `darwin-*` targets build natively with `cargo`; the
`osxcross` images are only required when packaging from Linux. The
`win32-arm64` target uses a local MSVC image because cross-rs cannot ship it:

```sh
git clone https://github.com/cross-rs/cross-toolchains.git
cd cross-toolchains/docker
cp /path/to/MacOSX*.sdk.tar.xz .  # only for darwin-* from Linux
docker build -f Dockerfile.aarch64-pc-windows-msvc-cross \
  -t ghcr.io/cross-rs/aarch64-pc-windows-msvc-cross:local .
```

`darwin-arm64`/`darwin-x64` osxcross images follow the same `docker build` step
from `Dockerfile.aarch64-apple-darwin-cross` / `Dockerfile.x86_64-apple-darwin-cross`
(supplying a macOS SDK archive) when packaging from Linux.

`ls` the `artifacts/` directory after a run; `make publish` requires every
platform binary staged in `npm/*/bin`.

## Licensing

The JavaScript npm wrapper is licensed under `Apache-2.0`. The Rust source and
native binaries are licensed under `LGPL-2.1-or-later`. Corresponding source for
each native package is available from the matching repository tag.
