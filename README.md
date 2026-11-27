# landstrip

Landstrip runs commands in an OS-level sandbox using KVM or Landlock/seccomp on
Linux, Seatbelt on macOS, and AppContainer on Windows.

## Install

```sh
npm install --save-dev @landstrip/landstrip
```

## Usage

Save this as `policy.json`. Windows also needs explicit read grants for the
executable and its dependencies.

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
    "allowLocalBinding": false
  }
}
```

```sh
npx landstrip run -p policy.json -- cargo test
npx landstrip check -p policy.json
npx landstrip doctor
```

See [landstrip(1)](packages/landstrip/man/man1/landstrip.1) for CLI options,
policy rules, platform limits, denial reporting, and the trap transport. For
TypeScript APIs, install
[`@landstrip/landstrip-api`](packages/landstrip-api/README.md).

## Packages

| Directory                                                    | Contents        | License           |
| ------------------------------------------------------------ | --------------- | ----------------- |
| [`packages/landstrip`](packages/landstrip)                   | binary          | LGPL-2.1-or-later |
| [`packages/landstrip-api`](packages/landstrip-api)           | Node.js API     | Apache-2.0        |
| [`packages/opencode-landstrip`](packages/opencode-landstrip) | OpenCode plugin | Apache-2.0        |
| [`packages/pi-landstrip`](packages/pi-landstrip)             | Pi extension    | Apache-2.0        |
