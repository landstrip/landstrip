# pi-landstrip

```
Subagents  3 active
├─ ● running  @explore  Design Pi entry parsing
├─ ● running  @general  Design trigger serialization
└─ ● running  @general  Design bounded summaries
```

`pi-landstrip` is a [Pi](https://pi.dev/) extension that provides sandboxed Bash
execution, OpenCode-compatible primary agents, and sandbox-aware subagents. It
uses an Anthropic-compatible policy and delegates OS-level enforcement to
[`landstrip`](https://github.com/landstrip/landstrip).

The extension includes a shared [sandbox policy](./sandbox.json) and separate
[agent configuration](./subagents.json). Global and trusted-project files can
override both.

Process-backed subagents require Pi >= 0.80.6 and < 0.81.0, and Node.js >= 22.19.0.

## Installation

### Automatic install

```sh
pi install npm:pi-landstrip
```

This installs `pi-landstrip` and its `@landstrip/landstrip` dependency. Native
binaries are published for Linux, macOS, and Windows on x64 and Arm64.

### Manual install

Add the extension to `~/.pi/agent/settings.json` (global) or
`.pi/settings.json` (project):

```json
{
  "packages": ["npm:pi-landstrip"]
}
```

Alternatively, place the extension under `~/.pi/agent/extensions/` (global) or
`.pi/extensions/` (project). See Pi's
[extension documentation](https://pi.dev/docs/latest/extensions) for details.

On unsupported platforms the extension loads but leaves sandboxing disabled.

## Disabling

Use the `--no-sandbox` flag, or set `enabled` to `false` in `sandbox.json`:

```json
{
  "enabled": false
}
```

When sandboxing is explicitly disabled, subagents still run as separate Pi RPC
processes, but without the outer Landstrip OS sandbox. The extension warns once
per session. Agent tool permissions still apply, but they are not an OS isolation
boundary.

Trusted project config overrides global config. `/sandbox` updates a trusted
project sandbox file when present, otherwise the global file. Pi versions
without a project-trust API use only global configuration.

## Behavior

When Pi requests a sandboxed permission, the extension sends a host notification
and opens a dialog. The user can allow once, allow for the session, persist for
the project or globally, or reject. The dialog shows the exact path or domain
being approved.

Project approvals are written to `.pi/sandbox.json`; global approvals are
written to `~/.pi/agent/sandbox.json`.

The main agent remains a normal Pi process. `pi-landstrip` replaces Bash
execution, including AI `bash` calls and manually typed shell commands (`!` and
`!!`), with a Landstrip-wrapped implementation. Network traffic uses an
allowlist proxy when direct access is disabled. Pi's filesystem tools and plugin
callbacks remain trusted code outside the Landstrip sandbox.

By default, Bash and subagent processes have no direct network access. Reads are
limited to the project, Git configuration, and `/dev/null`; writes are limited
to the project and `/dev/null`.

Subagent startup adds read-only bootstrap access to the selected Pi runtime,
global settings, model/auth configuration, installed plugins, skills, and the
task's dedicated session directory. These paths are required to construct a
normal Pi worker and are not persisted into `sandbox.json`. The worker receives
write access only to its own session and temporary directories.

Use `/sandbox` to inspect the active policy and toggle sandboxing. Use `/agents`
to select the primary role, inspect worker configuration and status, and set the
global or trusted-project concurrency limit.

## Primary agents

The `/agents` selector provides OpenCode-compatible `build` and `plan` roles by
default. Build has normal development access; plan asks before shell commands
and file changes. The selection controls the root system prompt and permissions
and is restored with the session.

## Subagents

Landstrip provides an OpenCode-compatible `task` tool. Each active task runs as a
full `pi --mode rpc` process inside an outer Landstrip sandbox. The sandbox
covers Pi, its plugins and tools, model requests, and descendant processes. The
root Pi process supervises RPC, permissions, nesting, persistence, and result
delivery.

Workers use normal Pi resource discovery and plugin loading, plus the
`pi-landstrip` worker extension. Requested tools are composed inside the worker,
so plugins can add or replace implementations. Each task starts a fresh Pi
process and plugin instances; continuing a `task_id` restores its persisted Pi
session in a new process.

The tool accepts the OpenCode task fields:

```json
{
  "description": "Review sandbox boundary",
  "prompt": "Review the sandbox implementation and report concrete issues.",
  "subagent_type": "review",
  "task_id": "optional-session-id",
  "command": "optional-originating-command",
  "background": false
}
```

Foreground tasks return the child result directly. Background tasks return a
queued result and deliver completion automatically. Task rows show lifecycle
state, current activity, tool-call count, elapsed time, and expandable output.
Use `/subagents` or the task row's `/subagents <id>` command to inspect a child
transcript. Completed and failed task metadata remains available after reload,
and persisted sessions can be continued with `task_id`.

Session switching or shutdown stops live workers. After an unclean restart,
unfinished work is marked interrupted; completed but undelivered background
results are delivered when the root session resumes.

OpenCode-style permissions wrap each worker's composed tools: `deny` blocks,
`ask` prompts in the root UI, and `allow` runs the tool. Other workers may
continue while a prompt is open. Forwarded worker dialogs identify the agent,
task summary, and task ID. An "Allow for this session" decision applies to the
root session and its descendants.

Tool permissions cannot widen the outer Landstrip policy. Sandbox approvals
continue to use `.pi/sandbox.json` and `~/.pi/agent/sandbox.json`.

Subagents fail closed when sandboxing is expected but unavailable, unsupported,
or missing. An explicit `--no-sandbox` flag or `enabled: false` configuration is
treated as an intentional opt-out and uses the warned unsandboxed process path.
Unsupported Pi versions still fail task startup.

### Platform behavior

- **Linux**: seccomp query traps can grant a blocked filesystem or network
  operation dynamically, so an approved worker can continue without restart.
- **macOS**: Seatbelt policy is fixed when the worker starts. Update
  `sandbox.json`, then restart or continue the task in a fresh worker to apply
  additional filesystem access. Main-agent Bash can retry a command, but there
  is no live worker-policy update.
- **Windows**: AppContainer cannot permit only the loopback proxy port, so
  domain-proxied worker networking is unavailable and the worker has no network.
  Setting `network.allowNetwork` to `true` is a degraded mode that permits model
  access but gives the entire worker unrestricted network access; domain lists
  are then not a boundary.

### Credentials

Model requests originate inside each worker. Pi's `auth.json` is readable but
not writable by workers. Inherited credential environment variables also cross
the sandbox boundary, and plugins loaded in that worker share access to these
credentials. Landstrip does not provide a credential broker: load only trusted
plugins and use credentials appropriate for the sandboxed process. An OAuth
refresh that needs to rewrite `auth.json` must be completed in the root Pi
first.

## Configuration

Subagent configuration is read from `~/.pi/agent/subagents.json` and, for trusted
projects, `.pi/subagents.json`. Project values override global values; both are
merged over the packaged [defaults](./subagents.json). Sandbox policy remains in
`~/.pi/agent/sandbox.json` and `.pi/sandbox.json`. Pi's `settings.json` contains
only normal Pi settings, such as the `pi-landstrip` package entry.

`subagents.json` accepts only top-level `maxSubagents` and `subagents`; sandbox
fields belong in `sandbox.json`.

```json
{
  "maxSubagents": 2,
  "subagents": {
    "agent": {
      "review": {
        "description": "Review code without modifying it",
        "mode": "subagent",
        "prompt": "Review the requested code and report concrete findings.",
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

`maxSubagents` is an integer from 0 through 16 controlling concurrent workers.
The packaged default is 0, which removes the `task` tool while retaining primary
roles. There is no separate subagent enable switch. The Settings tab in
`/agents` edits this limit for global and trusted-project configuration.

Agent modes, hidden/disabled agents, prompts, and ordered `allow`/`ask`/`deny`
permissions apply to primary agents and subagents. Subagent workers also honor
model selection, supported Pi thinking-level variants, and step limits. Primary
agent activation currently changes the prompt and permissions only. Later
matching permission rules win. Put provider-specific values under `options`;
unknown agent fields are rejected. Agent permissions cannot weaken an enabled
OS sandbox, grant filesystem access, or grant network access.

## Configuration migration

There is no compatibility loader for previous subagent configuration sources.
Legacy keys in `settings.json` produce a migration warning. Move configuration as
follows, then remove the old fields:

- Move `agent` and `permission` from Pi `settings.json` or OpenCode JSON under
  `subagents.agent` and `subagents.permission`.
- Convert legacy `tools` booleans to explicit `permission` rules.
- Move Markdown agent prompts into each `subagents.agent.<name>.prompt` string.
- Put the worker limit in top-level `maxSubagents`; zero disables delegation.
- Use `~/.pi/agent/subagents.json` for global configuration and
  `.pi/subagents.json` for trusted project configuration.
- Leave sandbox policy in `~/.pi/agent/sandbox.json` and `.pi/sandbox.json`;
  those files are unchanged.

Do not put these fields in Pi's `settings.json`; `pi-landstrip` does not read
them there.

## Limits

`pi-landstrip` grants at most `maxSubagents` scheduler permits to active
subagent work and allows nesting to three levels. A foreground parent returns
its permit while waiting for a child and reacquires it before resuming,
preventing nested-task deadlocks. A worker receives a nested `task` tool only
when its agent has an explicit `task` permission. Nested tasks are separate Pi
processes supervised by the root and Landstrip-wrapped unless sandboxing is
explicitly disabled, so an inactive parent process can remain alive during the
handoff. Persisted sessions remain resumable by `task_id`.

## License

`pi-landstrip` is licensed under `Apache-2.0`. See [LICENSE](LICENSE).

The bundled `@landstrip/landstrip` package is licensed separately as
`Apache-2.0 AND LGPL-2.1-or-later`.
