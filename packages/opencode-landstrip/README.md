# opencode-landstrip

`opencode-landstrip` is an [OpenCode](https://opencode.ai/) plugin that sandboxes
commands using an Anthropic-compatible policy. It delegates OS-level enforcement
to [`landstrip`](https://github.com/landstrip/landstrip).

The plugin includes a default [sandbox policy](./sandbox.json). Global and
project-specific policies can override it.

## Installation

### Automatic install

Install for the current project:

```sh
opencode plugin install opencode-landstrip
```

Install globally:

```sh
opencode plugin install opencode-landstrip --global
```

### Manual install

For a manual installation, update OpenCode's configuration files.

Add the plugin to `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-landstrip"]
}
```

Add TUI entry point to `tui.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-landstrip/tui"]
}
```

To disable the plugin later:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [["opencode-landstrip", { "enabled": false }]]
}
```

The `/sandbox` command shows the current configuration and toggles the sandbox
on or off. The toggle persists `enabled` to the project config when it already
sets it, otherwise to the global config.

## Behavior

When OpenCode requests a sandboxed permission, the plugin sends a host
notification and opens a dialog. The user can allow once, allow for the session,
persist for the project or globally, or reject. The dialog shows the exact path
or domain being approved.

Project approvals are written to `.opencode/sandbox.json`; global approvals go
to `~/.config/opencode/sandbox.json`. A newly created global file starts with the
default sandbox policy.

OpenCode's plugin API can wrap AI `bash` tool calls, but cannot replace manually
typed shell-mode commands with a Landstrip wrapper. Those commands can inherit
OpenCode's proxy environment, but this plugin does not process-sandbox them.

## License

`opencode-landstrip` is licensed under `Apache-2.0`. See [LICENSE](LICENSE).

The bundled `@landstrip/landstrip` package is licensed separately as
`Apache-2.0 AND LGPL-2.1-or-later`.
