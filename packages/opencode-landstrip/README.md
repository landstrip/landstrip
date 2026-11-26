# opencode-landstrip

Landstrip sandboxing for AI commands in OpenCode ≥2.0.18.

## Install and use

```sh
opencode plugin install opencode-landstrip          # project
opencode plugin install opencode-landstrip --global # global
```

Installation configures server/TUI plugins; `/landstrip` opens the management pane.

## Permissions and configuration

Only AI `bash` is OS-isolated; the plugin API cannot replace user shell commands.
Tool approval never overrides hard sandbox denials. Interactive requests without
a live presenter remain denied.

Configuration is loaded in order from the bundled [`sandbox.json`](sandbox.json),
the global config at `$XDG_CONFIG_HOME/opencode/sandbox.json` (or
`~/.config/opencode/sandbox.json` when `XDG_CONFIG_HOME` is unset, empty, or
relative), `.opencode/sandbox.json`, and plugin options. Later sources append to
list settings and override non-list settings. Persistent approvals are written to
the selected global or project file.

Defaults allow project writes, deny sensitive-file writes, and block networking.
Unusable sandboxing fails closed; `enabled: false` permits unsandboxed Bash.
On Linux, `linux.backend` selects `"auto"` (default; uses `"machine"` when
`/dev/kvm` is accessible and falls back to `"container"`), `"container"`, or
`"machine"`.

See [landstrip(1)](../landstrip/man/man1/landstrip.1) for hard-denial rules,
native traps, and platform limits.

## Development

From this package: `npm ci && npm run all`; `npm run ci:fmt` checks formatting
without edits.

## License

[Apache-2.0](LICENSE).
