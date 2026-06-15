# opencode-landstrip

Landlock-based sandboxing for [opencode](https://opencode.ai/) using
[`landstrip`](https://github.com/jarkkojs/landstrip).

## Install

Add the plugin to `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-landstrip"]
}
```

Add the TUI entrypoint to `tui.json` if you install or configure the plugin
manually:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-landstrip/tui"]
}
```

`opencode plugin install opencode-landstrip` configures both entrypoints.

This installs `opencode-landstrip` and its `@jarkkojs/landstrip` dependency, which
includes platform-specific native binaries for Linux, macOS, and Windows.

Requires OpenCode `1.17.7` or newer.

On unsupported platforms the plugin loads but leaves sandboxing disabled.

## Configure

Create `.opencode/sandbox.json` in a project or
`~/.config/opencode/sandbox.json` globally. Project config takes precedence and
array fields are merged with global/default values.

See [`sandbox.json`](./sandbox.json) for a starter config.

## Behavior

The plugin wraps opencode's AI `bash` tool in `landstrip`, routes proxy-aware
network traffic through an allowlist proxy, and blocks read/write tool access
outside configured filesystem allowlists. The default policy is strict: network
access is off unless domains are allowed, reads are limited to the project,
`~/.gitconfig`, and `/dev/null`, and writes are limited to the project and
`/dev/null`.

Run `/sandbox` in the TUI to inspect the active sandbox configuration. A compact
status badge in the prompt area shows whether the sandbox is active and whether
network is proxied or open.

When OpenCode asks for a sandboxed permission, the TUI plugin plays the host's
permission sound and desktop notification, then opens a single dialog with
choices to allow once, allow for the session, persist for the project, persist
globally, or reject. The dialog shows the exact path or domain being approved.
Project approvals are written to `.opencode/sandbox.json`; global approvals are
written to `~/.config/opencode/sandbox.json`.

OpenCode's current plugin API allows wrapping AI `bash` tool calls, but does not
allow a plugin to replace manually typed shell-mode commands with a landstrip
wrapper. Those commands can still receive the proxy environment from OpenCode,
but they are not process-sandboxed by this plugin.

## Disable

Set `enabled` to `false` in `sandbox.json`, or pass plugin options:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [["opencode-landstrip", { "enabled": false }]]
}
```

## License

`opencode-landstrip` is licensed under `MIT`. See [LICENSE](LICENSE) for more
information.

The bundled `@jarkkojs/landstrip` package is licensed separately as
`Apache-2.0 AND LGPL-2.1-or-later`.
