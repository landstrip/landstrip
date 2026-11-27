# @landstrip/landstrip

Command-line executable for Landstrip on Linux, macOS, and Windows (x64/arm64).
Requires Node.js ≥18 and installs the matching native platform package
automatically.

## Install

```sh
npm install --save-dev @landstrip/landstrip
```

## Usage

```sh
npx landstrip run -p policy.json -- cargo test
npx landstrip check -p policy.json
npx landstrip doctor
```

See [usage](../../README.md#usage) for a policy example and
[landstrip(1)](../landstrip/man/man1/landstrip.1) for CLI options and platform
limits. For TypeScript APIs, install
[`@landstrip/landstrip-api`](../landstrip-api/README.md), which depends on this
package.

## License

[Apache-2.0](LICENSE); native binaries are
[LGPL-2.1-or-later](../landstrip/LICENSE).
