# pi-landstrip

Pi extension for sandboxed Bash, primary agents, and process-backed subagents.
Pi 0.82.0 and Node.js 22.19.0 or newer are required.

## Install

```sh
pi install npm:pi-landstrip
```

The package includes Landstrip binaries for Linux, macOS, and Windows on x64
and Arm64. When sandboxing is enabled, an unusable binary or platform fails
closed. Use `--no-sandbox` or set `enabled` to `false` for unsandboxed execution.

## Permissions

Agent permissions control tool dispatch. Sandbox permissions control filesystem
and network access. Agent approval never bypasses a sandbox hard denial.

AI Bash, `!`, `!!`, and subagents use OS isolation. Primary file tools use the
trusted Pi process unless `toolFilesystemPolicy` is `"sandbox"`. Persistent
sandbox approvals update `.pi/sandbox.json` or `~/.pi/agent/sandbox.json`.

## Sandbox settings

Policy merges from bundled `sandbox.json`, global
`~/.pi/agent/sandbox.json`, then trusted-project `.pi/sandbox.json`.
`/settings` displays or toggles the effective policy.

```json
{
  "enabled": true,
  "shell": { "readAccess": "host" },
  "filesystem": {
    "allowWrite": ["."],
    "denyWrite": ["**/.env", "**/*.pem"]
  },
  "network": { "allowNetwork": false }
}
```

See [`sandbox.json`](sandbox.json) for exact defaults. Workers always use policy
reads. Windows requires an explicit read allowlist.

## Agents

Configure agents in `~/.pi/agent/landstrip.json`, `.pi/landstrip.json`, or a
`landstrip` object in the matching Pi settings file:

```json
{
  "maxSubagents": 2,
  "toolFilesystemPolicy": "sandbox",
  "permission": {
    "task": { "*": "deny", "review": "allow" }
  }
}
```

`maxSubagents` accepts 0 through 16. Agent definitions can override model,
prompt, mode, options, and permissions. Global definitions load before trusted
project definitions.

## Commands and tasks

- `/settings` opens a screen-wide pane with sandbox and agent settings.
- `/sandbox` opens the same pane on its sandbox section.
- `/agents` selects agents and lists task sessions.
- `Ctrl+Shift+A` cycles primary agents while Pi is idle.

The `task` tool starts isolated workers. Set `background: true` to return
immediately and use `task_id` to continue a saved task.

## Licensing

[Apache 2.0](../../LICENSE-APACHE-2.0).
