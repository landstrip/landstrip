# @landstrip/landstrip-api

TypeScript APIs for Landstrip. Requires Node.js ≥18 and depends on
`@landstrip/landstrip` to install the executable for Linux, macOS, and Windows on
x64/arm64. This API package does not own the CLI or platform binary packages.

## Install

```sh
npm install --save-dev @landstrip/landstrip-api
```

## Usage

```sh
npx landstrip run -p policy.json -- cargo test
npx landstrip check -p policy.json
npx landstrip doctor
```

See the [quick start](../../README.md#quick-start) for a policy example;
[landstrip(1)](../landstrip/man/man1/landstrip.1) covers policy and platform
limits.

## Node.js API

```js
const { execFileSync } = require("node:child_process");
const { binaryPath } = require("@landstrip/landstrip-api");

execFileSync(binaryPath(), ["run", "-p", "policy.json", "--", "cargo", "test"], {
  stdio: "inherit",
});
```

`binaryPath()` resolves an official installed binary or throws; `packageName()`
returns its package name. Both accept `platform` and `arch`, defaulting to the
current process.

[`lib/index.d.ts`](lib/index.d.ts) exports `LandstripTrap` and
`LandstripControlResponse`, and [`/proxy`](lib/proxy.d.ts) exports the proxy
helpers. [`/shared`](lib/shared.d.ts) provides:

- `decodeLandstripTrap(value)` / `parseTrapStanza(stanza)`: validated trap or `null`.
  Extra fields survive; missing/unknown denial states become `info`, never queries.
- `serializeTrapStanza(trap)`: formats a validated `LandstripTrap` as a blank-line-terminated `key=value` stanza.
- `isQueryTrap(trap)`: narrows validated events to `LandstripQueryTrap`.
  Query IDs are nonzero decimal `u64` strings, present only on queries.
- `writeLandstripPolicyFile(policy, prefix = 'landstrip-')`: returns `{ dir, path }`.
  Remove `dir` with `rmSync(dir, { recursive: true, force: true })` after use.
  Failed writes clean up; failed cleanup reports both errors and the directory
  path in an `AggregateError`.

## macOS log correlation

Both `LandstripDarwinPolicy` and `SandboxDarwinConfig` accept optional
`logTag?: string`, under the JSON key `macos` (not `darwin`):

```js
const { buildLandstripPolicy } = require("@landstrip/landstrip-api/shared");
const policy = buildLandstripPolicy({ macos: { logTag: "agent-session-42" } });
```

`macos.logTag` tags Seatbelt denial logs for correlation. It must be nonempty
and contain no double quote, backslash, ASCII control character (0x00–0x1f),
or DEL (0x7f). `null` is invalid. `buildLandstripPolicy` and `parseSandboxConfig`
validate and forward it; `deepMergeSandboxConfig` uses the override tag when
provided, otherwise preserving the base tag.

## Trap transport and reporting

On Unix, `--trap FD|PATH` accepts either an inherited open FD ≥3 or an absolute
Unix domain stream socket path. Start the socket listener before launching
Landstrip: the host Landstrip process connects before sandbox setup, and the
sandboxed child never inherits the trap transport.

On Linux, the stream is bidirectional and uses blank-line-terminated `key=value`
stanzas. For `state: "query"` events, reply on the same socket with
`controlResponseStanza(trap.query_id, "allow")` (or `"deny"`); the syscall waits
for an answer, and responder decisions are cached per `(operation, target)` for
the run. Terminal denials are always reported as `state: "info"` stanzas (deferred
until non-zero exit for unlisted reads; immediate for writes, explicit
`DenyMatch` reads, and network denials). When `--trap` is provided, non-usage
stanzas are written only to `--trap`, leaving child `stderr` untouched unless
writing to `--trap` fails. macOS reports setup/launch failures on the trap
transport and closes it on successful exec; use Seatbelt logs for runtime
denials.

## Development

Run `make ci` from the repository root.

## License

[Apache-2.0](LICENSE); native binaries installed through `@landstrip/landstrip`
are [LGPL-2.1-or-later](../landstrip/LICENSE).
