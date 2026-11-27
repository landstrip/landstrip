# @landstrip/landstrip-api

TypeScript APIs for Landstrip. Requires Node.js ≥18 and depends on
[`@landstrip/landstrip`](../landstrip-cli/README.md) to install the executable
for Linux, macOS, and Windows (x64/arm64).

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

See [usage](../../README.md#usage) for a policy example and
[landstrip(1)](../landstrip/man/man1/landstrip.1) for policy rules and platform
limits.

## Node.js API

```js
const { execFileSync } = require('node:child_process');
const { binaryPath } = require('@landstrip/landstrip-api');

execFileSync(
  binaryPath(),
  ['run', '-p', 'policy.json', '--', 'cargo', 'test'],
  { stdio: 'inherit' },
);
```

| Subpath    | Declarations                         | Highlights                                                                                  |
| ---------- | ------------------------------------ | ------------------------------------------------------------------------------------------- |
| `.`        | [`lib/index.d.ts`](lib/index.d.ts)   | `binaryPath`, `packageName`, `LandstripPolicy`, `LandstripTrap`, `LandstripControlResponse` |
| `./proxy`  | [`lib/proxy.d.ts`](lib/proxy.d.ts)   | `startFilterProxy`, `createProxyCredentials`, `createProxyUrl`, `createProxyEnvironment`    |
| `./shared` | [`lib/shared.d.ts`](lib/shared.d.ts) | Policy builders, config parser/merger, path/domain evaluators, trap and Seatbelt codecs     |

- `binaryPath(platform?, arch?)` resolves an official installed binary or
  throws; `packageName(platform?, arch?)` returns its package name.
- `startFilterProxy` gates proxied domains and supports `allowedMethods`,
  host-scoped `headerRules` (`replaceTokens`, `upgradeHttps`), and loopback
  `upstreams` gateways so guests never need raw upstream credentials.
- `writeLandstripPolicyFile(policy, prefix?)` writes a temporary policy file and
  returns `{ dir, path }`. Remove `dir` with
  `rmSync(dir, { recursive: true, force: true })` after use; failed cleanup
  reports both errors and `dir` in an `AggregateError`.
- `parseSandboxConfig` and `deepMergeSandboxConfig` validate and merge
  `SandboxConfigFile` layers, including `macos.logTag` (forwarded by
  `buildLandstripPolicy`) and `linux.backend`
  (`'auto' | 'container' | 'machine'`, passed as `--backend` to
  `landstrip run`).
- `decodeLandstripTrap`, `parseTrapStanza`, `serializeTrapStanza`,
  `isQueryTrap`, and `controlResponseStanza(queryId, action)` handle `--trap`
  stanzas; missing or unknown denial states normalize to `'info'`.

See [landstrip(1)](../landstrip/man/man1/landstrip.1) for `--trap` transport,
`macos.logTag` constraints, and platform enforcement details.

## Development

Run `make ci` from the repository root.

## License

[Apache-2.0](LICENSE); native binaries installed through `@landstrip/landstrip`
are [LGPL-2.1-or-later](../landstrip/LICENSE).
