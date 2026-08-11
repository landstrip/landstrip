# opencode-landstrip

`opencode-landstrip` runs OpenCode AI `bash` calls through
[`landstrip`](https://github.com/landstrip/landstrip).

## Install

```sh
# Current project
opencode plugin install opencode-landstrip

# Global
opencode plugin install opencode-landstrip --global
```

A manual installation needs both plugins. Add the server plugin to
`opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-landstrip"]
}
```

Add the presenter to `tui.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-landstrip/tui"]
}
```

## Permissions

OpenCode agent permissions authorize tool dispatch. Landstrip sandbox
permissions authorize filesystem and network access before a tool or while its
process runs. Agent approval never bypasses a sandbox hard denial.

The TUI presents one request at a time. OpenCode's native agent prompt has
priority; Landstrip requests retain FIFO order and are routed to the originating
root session. Without a live presenter, blocked sandbox requests are denied.

Filesystem approvals may be stored in `.opencode/sandbox.json` for the project
or `~/.config/opencode/sandbox.json` globally. `/sandbox` displays or toggles the
policy. It updates the project file when that file defines `enabled`, otherwise
the global file.

## Configuration

Policy merges in this order:

1. bundled [`sandbox.json`](./sandbox.json);
2. `~/.config/opencode/sandbox.json`;
3. `.opencode/sandbox.json`;
4. plugin options.

Objects merge recursively, arrays combine, and later scalar values replace
earlier values. The global file is initialized from the bundled policy when it
does not exist. Programmatic plugin options may be the policy object directly or
`{ "config": { ... } }`.

| Field                         | Bundled default                                                                                                 |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `enabled`                     | `true`                                                                                                          |
| `filesystem.denyRead`         | `["/Users", "/home"]`                                                                                           |
| `filesystem.allowRead`        | `[".", "~/.gitconfig", "~/.config/git/config", "/dev/null"]`                                                    |
| `filesystem.allowWrite`       | `[".", "/dev/null"]`                                                                                            |
| `filesystem.denyWrite`        | `["**/.env", "**/.env.*", "**/*.pem", "**/*.key", ".opencode/sandbox.json", "~/.config/opencode/sandbox.json"]` |
| `network.allowNetwork`        | `false`                                                                                                         |
| `network.allowLocalBinding`   | `false`                                                                                                         |
| `network.allowAllUnixSockets` | `false`                                                                                                         |
| `network.allowUnixSockets`    | `[]`                                                                                                            |
| `network.allowedDomains`      | `[]`                                                                                                            |
| `network.deniedDomains`       | `[]`                                                                                                            |

Filesystem and core network semantics follow the main
[Landstrip policy](https://github.com/landstrip/landstrip#policy). `allowedDomains`
and `deniedDomains` are plugin-only fields enforced by its local HTTP/HTTPS proxy.

If `enabled` is true but the Landstrip binary, version, or platform is unusable,
AI Bash fails closed rather than running without isolation. Set `enabled` to
false explicitly to allow unsandboxed AI Bash.

## Limits

Only AI `bash` calls are process-sandboxed. Shell-mode commands entered directly
by the user cannot be replaced through OpenCode's plugin API. They may inherit
proxy settings and receive policy checks, but they do not have OS isolation.

See the main [Landstrip documentation](https://github.com/landstrip/landstrip#readme) for platform limits.

## License

`opencode-landstrip` is licensed under `Apache-2.0`. The bundled Landstrip
package is licensed separately as `Apache-2.0 AND LGPL-2.1-or-later`.
