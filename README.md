# landstrip

`landstrip` runs a command in a Linux sandbox built from Landlock access control
rules and seccomp.

`landstrip` accepts JSON policy files that are compatible with the
[Anthropic Sandbox Runtime](https://github.com/anthropic-experimental/sandbox-runtime)
JSON format i.e., matching subset with the macOS Seatbelt backend.

## Sealtbelt and Landstrip comparison

| Area      | Seatbelt backend         | Landstrip backend          |
| --------- | ------------------------ | -------------------------- |
| Kernel    | sandbox-exec / Seatbelt  | Landlock + seccomp         |
| FS view   | host view + path rules   | host view + object rules   |
| Timing    | dynamic path checks      | launch-time snapshot       |
| Globs     | profile regex/path match | expanded at launch         |
| TCP net   | localhost proxy ports    | loopback proxy ports       |
| Proxies   | supplied by runtime      | supplied by caller/runtime |
| Unix sock | path allowlist           | path allowlist via broker  |
| Runtime   | unknown settings ignored | unknown settings ignored   |

## Sandbox model

### Files

`landstrip` lowers filesystem policy to Landlock allowlists.

Write access is denied by default. `allowWrite` grants roots, and `denyWrite`
subtracts from them.

Read access stays unrestricted unless `denyRead` is set. `allowRead` then adds
paths back.

Landlock rules are tied to opened filesystem objects, not path strings. If an
allowed directory is removed and recreated, the new directory is not
automatically allowed unless an allowed ancestor covers it.

Globs use the macOS sandbox syntax: absolute paths, relative paths from the
current directory, `~`, `*`, `**`, `?`, and character classes. Globs are expanded
when the sandbox is created.

### Network

Direct TCP is denied by default. `httpProxyPort` and `socksProxyPort` allow only
loopback connections to local proxy ports. `landstrip` does not start proxies or
set proxy environment variables.

Non-TCP INET sockets, packet sockets, and netlink sockets are blocked.

Unix sockets are denied by default. `allowUnixSockets` permits pathname
`connect` and `bind` under listed paths. Relative paths are resolved against the
sandboxed process current directory. Abstract sockets, unnamed sockets, and
`socketpair` are not path-mediated. `allowAllUnixSockets` permits new Unix
sockets without path checks.

Inherited descriptors above stdio are closed before `exec`.

## Licensing

`landstrip` is licensed under `LGPL-2.1-or-later`.
