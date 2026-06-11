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
  "plugin": ["opencode-landstrip"]
}
```

`opencode plugin install opencode-landstrip` configures both entrypoints.

This installs `opencode-landstrip` and its `@jarkkojs/landstrip` dependency, which
includes platform-specific native binaries for Linux, macOS, and Windows.

On unsupported platforms the plugin loads but leaves sandboxing disabled.

## Configure

Create `.opencode/sandbox.json` in a project or
`~/.config/opencode/sandbox.json` globally. Project config takes precedence.

See [`sandbox.json`](./sandbox.json) for a starter config.

## Behavior

The plugin wraps opencode's AI `bash` tool in `landstrip`, routes proxy-aware
network traffic through an allowlist proxy, and blocks read/write tool access
outside configured filesystem allowlists.

Run `/sandbox` in the TUI to inspect the active sandbox configuration.

opencode's current server plugin API does not expose Pi-style custom permission
dialogs or a way to rewrite manually typed shell-mode commands. The `/sandbox`
status view is provided by the TUI plugin entrypoint. Blocked access fails with
an error that points at the sandbox config files.

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
