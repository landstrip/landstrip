<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
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

## Quick start

```sh
landstrip run -p policy.json -- cargo test
landstrip policy validate -p policy.json
landstrip policy resolve -p policy.json
landstrip doctor
```

Windows builds also provide `windows install`, `windows status`, and
`windows uninstall`. Full command reference: `landstrip --help` and the
[manual page](man/man1/landstrip.1).

### Agent extensions

```sh
pi install npm:pi-landstrip
opencode plugin install opencode-landstrip
```

See [pi-landstrip](packages/pi-landstrip/README.md) and
[opencode-landstrip](packages/opencode-landstrip/README.md).

## Policy sketch

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

Pass policies with `-p, --policy <FILE>` (repeatable). Semantics, platform
limits, traps, and exit status are in the manual page.

## Development

### Package

Artifacts land in `npm/*/bin` and `artifacts/`. Staging writes platform tarballs
and matching `<file>.sha256` sidecars under `artifacts/`.

Non-host targets use [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild)
(Zig as linker). Requires `cargo-zigbuild`, `zig`, and the matching `rustup`
targets (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
`x86_64-pc-windows-gnu`, `aarch64-pc-windows-gnullvm`, `aarch64-apple-darwin`,
`x86_64-apple-darwin`). Host-native triples use plain `cargo`. Darwin links
`libsandbox`; from Linux set `SDKROOT` to a macOS SDK (Apple SDK; not
redistributed).

```sh
make package
make package PLATFORMS='linux-x64 win32-x64'
PACKAGE_STRICT=1 make package
```

`make publish` uploads each GitHub release tarball with its `<file>.sha256`
sidecar. Verify a download with:

```sh
sha256sum -c landstrip-<version>-<platform>.tar.gz.sha256
```

## License

`landstrip` is free software under the GNU Lesser General Public License
version 2.1 or later (LGPL-2.1+). See [LICENSE-LGPL-2.1](LICENSE-LGPL-2.1).

The JavaScript npm wrapper is under the Apache License 2.0. See
[LICENSE-APACHE-2.0](LICENSE-APACHE-2.0). Corresponding source for each native
package is available from the matching repository tag.
