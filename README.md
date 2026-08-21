# landstrip

`landstrip` runs commands in an OS-level sandbox using Landlock on Linux,
Seatbelt on macOS, and AppContainer or restricted users on Windows.

## Install

```sh
npm install --save-dev @landstrip/landstrip
npx landstrip run -p policy.json -- cargo test
```

The npm package installs a Node.js wrapper and a native binary for the current
platform.

## Usage

```sh
landstrip run -p policy.json -- cargo test
landstrip policy validate -p policy.json
landstrip policy resolve -p policy.json
landstrip doctor
```

Run `landstrip --help` or see [landstrip(1)](man/man1/landstrip.1) for the full
command reference.

## Agent extensions

| Integration | Package                | Documentation                                                        |
| ----------- | ---------------------- | -------------------------------------------------------------------- |
| OpenCode    | `opencode-landstrip`   | [OpenCode](packages/opencode-landstrip/README.md)                    |
| Pi          | `pi-landstrip`         | [Pi](packages/pi-landstrip/README.md)                                |

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
    "allowLocalBinding": false
  }
}
```

Pass policies with `-p, --policy <FILE>`. Later policies merge over earlier
ones. Platform behavior and limits are documented in the manual.

## Development

```sh
make ci
```

## Licensing

`landstrip` uses [LGPL-2.1+](LICENSE-LGPL-2.1).

The JavaScript wrapper and agent extensions use
[Apache 2.0](LICENSE-APACHE-2.0).
