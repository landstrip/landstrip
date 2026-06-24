# opencode-landstrip

`opencode-landstrip` is a plugin for [OpenCode](https://opencode.ai/) providing
a sandbox defined with a policy compatible with Anthropic's JSON format. It uses
[`landstrip`](https://github.com/landstrip/landstrip) to implement the sandbox.

`opencode-landstrip` has a default policy [sandbox.json](./sandbox.json), and
allows the define either or both global or project specific policies.

## Installing the plugin

### Automatic install

Project specific install:

```
opencode plugin install opencode-landstrip
```

Global install:

```
opencode plugin install opencode-landstrip --global
```

### Manual install

These changes are applied to OpenCode's configuration directories

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

The plugin can be later on disabled as follows:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [["opencode-landstrip", { "enabled": false }]]
}
```

## Behavior

When OpenCode asks for a sandboxed permission, the plugin emits a host
notification. After that the plugin opens a dialog with the choices to allow
once, allow for the session, persist for the project, persist globally, or
reject. The dialog shows the exact path or domain being approved.

Project approvals are written to `.opencode/sandbox.json`; global approvals are
written to `~/.config/opencode/sandbox.json`. When the global configuration is
initially written it acquires the copy of the default sandbox configuration.

OpenCode's current plugin API allows wrapping AI `bash` tool calls, but does not
allow a plugin to replace manually typed shell-mode commands with a landstrip
wrapper. Those commands can still receive the proxy environment from OpenCode,
but they are not process-sandboxed by this plugin.

## License

`opencode-landstrip` is licensed under `MIT`. See [LICENSE](LICENSE) for more
information.

The bundled `@landstrip/landstrip` package is licensed separately as
`Apache-2.0 AND LGPL-2.1-or-later`.
