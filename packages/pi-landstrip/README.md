# pi-landstrip

`pi-landstrip` adds sandboxed Bash, primary agents, and process-backed subagents
to [Pi](https://pi.dev/). OS isolation is provided by
[`landstrip`](https://github.com/landstrip/landstrip).

Requires Pi 0.82.0 or later and Node.js 22.19.0 or later.

## Installation

```sh
pi install npm:pi-landstrip
```

For a manual install, add the package to global or trusted project
`settings.json`:

```json
{
  "packages": ["npm:pi-landstrip"]
}
```

The package includes native Linux, macOS, and Windows binaries for x64 and
Arm64. On unsupported platforms, the extension loads with sandboxing disabled.

## Behavior

AI Bash calls and shell commands entered with `!` or `!!` run through
Landstrip. Subagents run as separate Pi RPC processes and are sandboxed unless
the sandbox is explicitly disabled.

The root Pi process is trusted. Pi filesystem tools and plugin callbacks run
outside the OS sandbox. By default, agent permissions alone control filesystem
tool dispatch. Set `toolFilesystemPolicy` to `"sandbox"` to preflight primary
`read`, `write`, `edit`, and `apply_patch` calls against the sandbox filesystem
rules. This path check is not an OS isolation boundary. On Linux and macOS,
primary Bash reads use the same host view by default; writes remain sandboxed.
Subagent processes retain the configured read and write policy.

The default [sandbox policy](./sandbox.json) limits writes to the project and
restricts worker reads within the user's home to the project and a few bootstrap
files. Direct network access is blocked. When the platform permits loopback, the
extension's proxy filters allowed HTTP and HTTPS domains.

When a command needs more access, Pi can allow it once, for the session, or in
the project or global policy. Project approvals go to `.pi/sandbox.json` and
global approvals to `~/.pi/agent/sandbox.json`.

- `/sandbox` inspects and toggles the sandbox.
- `/agents` selects agents, edits agent settings, and shows task sessions.
- `Ctrl+Shift+A` cycles visible primary agents while Pi is idle.

### Disabling the sandbox

Use `--no-sandbox` or set `enabled` to `false` in `sandbox.json`:

```json
{
  "enabled": false
}
```

Subagents remain separate processes but lose Landstrip OS isolation. Pi warns
once per session. Trusted project config overrides global config; `/sandbox`
updates a project sandbox file when present, otherwise the global file.

### Shell read access

`"shell": { "readAccess": "host" }` keeps primary Bash and `!`/`!!` reads
consistent with trusted Pi filesystem tools. Set `readAccess` to `"policy"` to
apply `filesystem.denyRead` and `filesystem.allowRead` to shell commands as an
intentional stricter boundary. Worker processes always use the filesystem read
policy. Windows always uses policy reads because its sandbox requires an explicit
read allowlist.

### Permission layers

| Layer                  | Checked            | Controls                              |
| ---------------------- | ------------------ | ------------------------------------- |
| Agent permission       | Before a tool runs | Which tools the agent may call        |
| Filesystem tool policy | Before a file tool | Paths primary file tools may access   |
| OS sandbox policy      | During a process   | Process filesystem and network access |

When a file-tool path requires sandbox approval and agent permission also asks,
Pi composes both decisions into one prompt. The existing once, session, project,
and global sandbox approval scopes apply. Subagents continue to rely on OS
sandbox enforcement.

## Agents

The built-in primary agents are `build` and `plan`. The built-in subagents are
`explore`, `general`, and `scout`. `/agents` can activate, edit, or disable
configured agents.

The `task` tool starts a subagent. It accepts:

```json
{
  "description": "Review sandbox boundary",
  "prompt": "Review the sandbox implementation and report concrete issues.",
  "subagent_type": "explore",
  "task_id": "optional-session-id",
  "command": "optional-originating-command",
  "background": false
}
```

`description`, `prompt`, and `subagent_type` are required. Foreground tasks
return their result directly. Background tasks return immediately and report
completion later. Continue a saved task with `task_id`; inspect it with
`/agents <id>`.

Workers use normal Pi resource discovery and plugin loading. Each task starts a
fresh process; continuing a task restores its saved session in a new process.
Agent `deny`, `ask`, and `allow` rules are checked before tool dispatch.

Model requests originate inside each worker. Workers can read Pi authentication
and inherited credential environment variables. Loaded worker plugins share
that access, so install only trusted plugins and use suitable credentials.

## Configuration

Landstrip settings are read from `~/.pi/agent/landstrip.json` and, for trusted
projects, `.pi/landstrip.json`. The same object may instead be placed under
`landstrip` in the matching `settings.json`. Use only one form at each scope.
Sandbox settings remain in `~/.pi/agent/sandbox.json` and `.pi/sandbox.json`.

```json
{
  "maxSubagents": 2,
  "toolFilesystemPolicy": "sandbox",
  "agent": {
    "review": {
      "description": "Review code without modifying it",
      "mode": "subagent",
      "prompt": "Report concrete findings.",
      "permission": {
        "edit": "deny",
        "bash": "ask"
      }
    }
  },
  "permission": {
    "task": {
      "*": "deny",
      "review": "allow"
    }
  }
}
```

`maxSubagents` is the concurrency limit, from 0 to 16. Zero disables
the `task` tool. Agent definitions support `mode`, `prompt`, `model`, `variant`,
`steps`, `color`, `hidden`, `disable`, `options`, and permission rules. Modes
are `primary`, `subagent`, or `all`.

`toolFilesystemPolicy` defaults to "host", preserving Pi's normal filesystem
tool behavior. Set it to "sandbox" to apply `sandbox.json` path rules before
primary file tools run. `denyWrite` is a hard denial; other blocked paths use the
standard sandbox approval scopes.

Pi Markdown agents are loaded from `~/.pi/agent/agents/` and `.pi/agents/`.
Configured `agent` entries override Markdown agents with the same name.
Project definitions override global definitions.

For example, save this advisor subagent as `~/.pi/agent/agents/advisor.md`:
