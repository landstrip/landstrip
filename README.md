# landstrip

`landstrip` runs commands in an OS-level sandbox using Landlock on Linux,
Seatbelt on macOS, and AppContainer or restricted users on Windows.

## Quick start

Install the CLI and native binary for your platform:

```sh
npm install --save-dev @landstrip/landstrip-api
```

For Linux or macOS, save this as `policy.json`. Windows requires explicit read
grants for the program and its dependencies; see the manual below.

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
npx landstrip policy validate -p policy.json
npx landstrip doctor
```

See [landstrip(1)](packages/landstrip/man/man1/landstrip.1) for policy rules,
merged-policy inspection, CLI options, and platform limits.

## Integrations

- [Node.js API](packages/landstrip-api/README.md): native binary access and trap types.
- [OpenCode](packages/opencode-landstrip/README.md): `opencode-landstrip` plugin.
- [Pi](packages/pi-landstrip/README.md): `pi-landstrip` extension and subagents.

## Development

Run `make ci` from the repository root.

## License

- Native sandbox: [LGPL-3.0-or-later](packages/landstrip/LICENSE).
- Node.js API and agent extensions: Apache-2.0; see each package's `LICENSE`.
