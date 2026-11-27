# opencode-landstrip

OS-level sandboxing for AI commands in OpenCode ≥2.0.18.

## Install

```sh
opencode plugin install opencode-landstrip          # project
opencode plugin install opencode-landstrip --global # global
```

Installation registers both the server and TUI plugins. Unusable sandboxing
fails closed; `enabled: false` permits unsandboxed Bash.

## Usage

| Command / Key | Action                                            |
| ------------- | ------------------------------------------------- |
| `/landstrip`  | Open the sandbox inspector pane                   |
| `Enter`       | Toggle sandbox isolation in the inspector pane    |
| `Esc`         | Close the inspector pane or cancel a confirmation |

## Permissions and configuration

Only AI `bash` is OS-isolated; the OpenCode plugin API cannot replace user shell
commands. Tool approval never overrides hard sandbox denials, and interactive
requests without a live presenter remain denied.

Configuration loads in order, appending to list fields and overriding scalar
fields:

1. Bundled [`sandbox.json`](sandbox.json)
2. `$XDG_CONFIG_HOME/opencode/sandbox.json` (or
   `~/.config/opencode/sandbox.json` when `XDG_CONFIG_HOME` is unset, empty, or
   relative)
3. `.opencode/sandbox.json`
4. Plugin options

Persistent approvals write to the active global or project file. Defaults allow
project writes, deny sensitive-file writes, and block direct networking. On
Linux, `linux.backend` selects `"auto"` (default; uses `"machine"` when
`/dev/kvm` is accessible, otherwise `"container"`), `"container"`, or
`"machine"`.

See [landstrip(1)](../landstrip/man/man1/landstrip.1) for policy rules, native
traps, and platform limits.

## Development

```sh
npm ci && npm run all
npm run ci:fmt
```

## License

[Apache-2.0](LICENSE).
