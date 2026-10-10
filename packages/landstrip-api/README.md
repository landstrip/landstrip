# @landstrip/landstrip-api

Node.js wrapper, native binaries, and TypeScript types for the Landstrip sandbox.
Requires Node.js 18 or newer; binaries are provided for Linux, macOS, and Windows
on x64 and arm64.

## Install and run

```sh
npm install --save-dev @landstrip/landstrip-api
npx landstrip run -p policy.json -- cargo test
```

See the [quick start](../../README.md#quick-start) for an example policy and
[landstrip(1)](../landstrip/man/man1/landstrip.1) for CLI options, policy rules,
and platform limits.

## Node.js API

```js
const { execFileSync } = require('node:child_process');
const { binaryPath } = require('@landstrip/landstrip-api');

execFileSync(binaryPath(), ['run', '-p', 'policy.json', '--', 'cargo', 'test'], {
  stdio: 'inherit',
});
```

`binaryPath()` returns the installed native binary's canonical path and checks
that it belongs to an official Landstrip package. It throws if the platform is
unsupported, the binary is missing, or package ownership cannot be verified.
`packageName()` returns the platform's binary package name. Both accept optional
`platform` and `arch` arguments, defaulting to the current process.

The package exports [`LandstripTrap` and `LandstripControlResponse`](lib/index.d.ts)
for structured events and Linux broker replies. Runtime traps and approval
queries are Linux-only; macOS's `--trap` reports setup and launch failures.
Descriptor lifetimes and the reply protocol are covered in the manual.

Integration helpers are exported through [`/shared`](lib/shared.d.ts) and
[`/proxy`](lib/proxy.d.ts).

`writeLandstripPolicyFile(policy, prefix = 'landstrip-')` from `/shared` writes
`policy.json` and returns `{ dir, path }`. The caller owns `dir` and must remove it
with `rmSync(dir, { recursive: true, force: true })` after use. Serialization
happens before directory creation; failed writes remove partial files and their
directory. If cleanup also fails, an `AggregateError` reports both errors and the
directory path.

## Development

Run `make ci` from the repository root.

## License

[Apache-2.0](LICENSE). The bundled native binary is
[LGPL-3.0-or-later](../landstrip/LICENSE).
