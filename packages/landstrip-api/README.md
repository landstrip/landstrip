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

`binaryPath()` returns the installed native binary's path and throws if the
platform is unsupported or its binary package is missing. `packageName()` returns
the platform's binary package name. Both accept optional `platform` and `arch`
arguments, defaulting to the current process.

The package exports [`LandstripTrap` and `LandstripControlResponse`](lib/index.d.ts)
for structured events and Linux broker replies. Runtime traps and approval
queries are Linux-only; macOS's `--trap` reports setup and launch failures.
Descriptor lifetimes and the reply protocol are covered in the manual.

Integration helpers are exported through [`/shared`](lib/shared.d.ts) and
[`/proxy`](lib/proxy.d.ts).

## Development

Run `make ci` from the repository root.

## License

[Apache-2.0](LICENSE). The bundled native binary is
[LGPL-3.0-or-later](../landstrip/LICENSE).
