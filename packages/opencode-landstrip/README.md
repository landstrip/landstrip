# opencode-landstrip

`opencode-landstrip` sandboxes OpenCode AI `bash` calls with
[`landstrip`](https://github.com/landstrip/landstrip) and the supported Anthropic
Sandbox Runtime policy fields.

The bundled [policy](./sandbox.json) is merged with global, project, and plugin
options in that order.

## Installation

```sh
# Current project
opencode plugin install opencode-landstrip

# Global
opencode plugin install opencode-landstrip --global
```

For a manual install, add the server plugin to `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-landstrip"]
}
```

Add the TUI plugin to `tui.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-landstrip/tui"]
}
```

Run `/sandbox` to inspect or toggle the sandbox. The toggle writes to the
project config if it already defines `enabled`; otherwise it writes to the
global config.

## Behavior

AI `bash` calls run through Landstrip. Direct network access is blocked by
default; the plugin's local HTTP and HTTPS proxy enforces `allowedDomains` and
`deniedDomains`.
The domain lists are plugin policy fields, not core Landstrip fields.

OpenCode agent permissions authorize a tool before dispatch. Landstrip sandbox
permissions authorize a blocked filesystem or network operation during the
command. The TUI shows one permission at a time, with OpenCode's prompt first;
subagent sandbox prompts are routed to the root session. Filesystem approvals
may be saved to `.opencode/sandbox.json` or
`~/.config/opencode/sandbox.json`.
Without a live TUI presenter, blocked operations are denied.

Shell-mode commands typed by the user are not process-sandboxed because
OpenCode's plugin API cannot replace their execution. They may inherit proxy
settings and receive policy checks, but they do not have an OS sandbox.

See the main [Landstrip documentation](https://github.com/landstrip/landstrip#readme)
for policy semantics and platform limits.

## License

`opencode-landstrip` is licensed under `Apache-2.0`. See [LICENSE](LICENSE).
The bundled `@landstrip/landstrip` package is licensed separately as
`Apache-2.0 AND LGPL-2.1-or-later`.
