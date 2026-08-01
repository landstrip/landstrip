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
outside the OS sandbox. Agent permissions still control tool dispatch, but they
are not an OS isolation boundary.

The default [sandbox policy](./sandbox.json) limits reads and writes to the
project and a few bootstrap files. Direct network access is blocked. When the
platform permits loopback, the extension's proxy filters allowed HTTP and HTTPS
domains.

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

### Permission layers

| Layer            | Checked            | Controls                       |
| ---------------- | ------------------ | ------------------------------ |
| Agent permission | Before a tool runs | Which tools the agent may call |
| Sandbox policy   | During a command   | Filesystem and network access  |

An agent approval allows tool dispatch; the sandbox still applies to the
resulting process.

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

Agent settings are read from `~/.pi/agent/settings.json` and, for trusted
projects, `.pi/settings.json`. Sandbox settings are read from
`~/.pi/agent/sandbox.json` and `.pi/sandbox.json`.

```json
{
  "landstrip": {
    "maxSubagents": 2,
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
}
```

`landstrip.maxSubagents` is the concurrency limit, from 0 to 16. Zero disables
the `task` tool. Agent definitions support `mode`, `prompt`, `model`, `variant`,
`steps`, `color`, `hidden`, `disable`, `options`, and permission rules. Modes
are `primary`, `subagent`, or `all`.

Pi Markdown agents are loaded from `~/.pi/agent/agents/` and `.pi/agents/`.
`landstrip.agent` settings override Markdown agents with the same name.
Project definitions override global definitions.

For example, save this advisor subagent as `~/.pi/agent/agents/advisor.md`:

```markdown
---
description: Escalate to a stronger reviewer for a plan, correction, or stop signal
mode: subagent
hidden: false
variant: high
permission:
  '*': deny
  read: allow
  grep: allow
  glob: allow
  list: allow
---

You are an advisor model in an advisor-strategy pattern. An executor model is running a task end-to-end — calling tools, reading results, iterating toward a solution. When the executor hits a decision it cannot reasonably solve alone, it consults you for guidance via the `task` tool with `subagent_type: "advisor"`.

The executor should put the full situation in the task prompt: the goal, what it has tried, tool results that matter, current hypothesis, and the decision it needs. You may use read-only tools to verify claims against the repository when file paths are given; do not modify anything.

Return ONE of:

- a **plan** (concrete next steps the executor should take),
- a **correction** (the executor is going down a wrong path — redirect it),
- a **stop signal** (the executor should halt and escalate to the user).

Be concise, directive, and grounded in the shared context. Name files, functions, and line numbers where possible. No preamble, no apologies, no meta-commentary about being an advisor — just the guidance the executor needs.

Give advice serious weight for the executor: prefer primary-source evidence and root causes over temporary fixes. If requirements are ambiguous or contradictory, stop and say what the user must decide.
```

See the main [Landstrip documentation](https://github.com/landstrip/landstrip#readme)
for `sandbox.json` fields and platform policy semantics.

### Platform notes

- **Linux:** blocked operations can be approved while the command is running.
- **macOS:** a worker's Seatbelt policy is fixed at startup; restart the task to
  apply new filesystem access.
- **Windows:** the bundled policy uses standard AppContainer because Pi's Git
  Bash cannot start in LPAC. Standard mode is weaker than LPAC.
  `windows.allowLoopback` enables the domain proxy but exposes every local
  loopback service. Restricted-user mode avoids that broad exemption.

Install restricted-user mode from the intended Windows host account, then
restart Pi:

```powershell
npx @landstrip/landstrip windows install
npx @landstrip/landstrip windows status
```

Remove it with `npx @landstrip/landstrip windows uninstall`.

## Plugin API

Other Pi extensions can discover the v2 runtime with `useLandstrip` from
`pi-landstrip/api`. The runtime provides:

- `getContext()` for sandbox and task context.
- `registerShellProvider()` for replacing POSIX shell invocation preparation.
- `prepareProcess()` for one policy-aware process launch.
- `registerWorkerExtension()` for trusted worker extensions.
- `on()` for sandbox and subagent lifecycle events.

A shell provider receives the command, working directory, composed command
environment, and abort signal. It returns an executable, arguments, minimal
launcher environment, required read paths, and optional cleanup. Landstrip adds
platform variables required by its launcher, such as Windows `ProgramData`.
Providers should pass the composed environment through a private temporary file,
include that file in `readPaths`, and remove it in `dispose()`; do not copy secrets
into `launcherEnv`. Landstrip remains responsible for starting the process, applying
policy, proxying network access, handling traps, and prompting for additional
access. Only one external provider can be active; disposing it restores the
built-in POSIX provider.

Use `provideLandstripShell()` to register a provider independently of extension
load order. Shell providers and worker extensions are trusted code. Workers also
receive an informational `LANDSTRIP_CONTEXT` environment value; it is not proof
of authorization.

## Limits

At most `maxSubagents` tasks run concurrently. Nested task depth is capped at
3, and a nested `task` tool is available only when the parent agent has explicit
permission. Session switching and shutdown stop live workers.

## License

`pi-landstrip` is licensed under `Apache-2.0`. See [LICENSE](LICENSE). The
bundled `@landstrip/landstrip` package is licensed separately as
`Apache-2.0 AND LGPL-2.1-or-later`.
