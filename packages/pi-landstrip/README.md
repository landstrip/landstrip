# pi-landstrip

`pi-landstrip` is an extension for [pi](https://pi.dev/) providing sandbox-aware
subagents and a sandbox defined with a policy compatible with Anthropic's JSON
format. It uses [`landstrip`](https://github.com/landstrip/landstrip) to
implement the sandbox.

`pi-landstrip` has a shared sandbox policy [sandbox.json](./sandbox.json) and a
separate [subagents.json](./subagents.json) for primary-agent and subagent
configuration. Global and trusted project files can override both.

Pi >=0.80.6 <0.81.0 and Node.js >=22.19.0 are required for process-backed subagents.

## Installing the extension

### Automatic install

```
pi install npm:pi-landstrip
```

This installs `pi-landstrip` and its `@landstrip/landstrip` dependency. Native
binaries are currently published for Linux x64, Windows x64, and macOS x64/arm64.

### Manual install

Add the extension to `~/.pi/agent/settings.json` (global) or
`.pi/settings.json` (project):

```json
{
  "packages": ["npm:pi-landstrip"]
}
```

Alternatively, drop the extension under `~/.pi/agent/extensions/` (global) or
`.pi/extensions/` (project). See the pi
[extensions](https://pi.dev/docs/latest/extensions) documentation for details.

On unsupported platforms the extension loads but leaves sandboxing disabled.

## Disable

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

When pi asks for a sandboxed permission, the extension emits a host
notification. After that the extension opens a dialog with the choices to allow
once, allow for the session, persist for the project, persist globally, or
reject. The dialog shows the exact path or domain being approved.

Project approvals are written to `.pi/sandbox.json`; global approvals are
written to `~/.pi/agent/sandbox.json`.

The main agent remains a normal Pi process. Pi performs its usual filesystem
tool and plugin composition; `pi-landstrip` replaces Bash execution, including
AI `bash` calls and manually typed shell-mode commands (`!` and `!!`), with a
Landstrip-wrapped implementation. Network traffic is routed through an
allowlist proxy when network access is off. Main-agent filesystem tools and
plugin callbacks remain trusted Pi code and are not confined by Landstrip. The
default policy for Bash and subagent processes is strict: network access is off
unless domains are allowed, reads are limited to the project, `~/.gitconfig`,
and `/dev/null`, and writes are limited to the project and `/dev/null`.

Subagent startup adds read-only bootstrap access to the selected Pi runtime,
global settings, model/auth configuration, installed plugins, skills, and the
task's dedicated session directory. These paths are required to construct a
normal Pi worker and are not persisted into `sandbox.json`. The worker receives
write access only to its own session and temporary directories.

Use `/sandbox` inside Pi to inspect the active policy and toggle sandboxing. Use
`/agents` to select the primary role; its Settings tab controls the global and
trusted-project maximum number of concurrent subagents.

## Primary agents

The `/agents` selector provides OpenCode-compatible `build` and `plan` roles by default.
Build has normal development access; plan asks before shell commands and file
changes. The selection controls the root system prompt and permissions and is
restored with the session.

## Subagents

Landstrip provides an OpenCode-compatible `task` tool. Each active task is a
full `pi --mode rpc` process under one outer Landstrip instance. The sandbox
covers Pi itself, its plugins and tools, model requests, and every descendant
process. The root Pi supervises RPC, permissions, nesting, persistence, and
completion delivery.

The worker uses normal Pi resource discovery and plugin loading from the Pi
filesystem, plus the pi-landstrip worker extension. Its requested active tool
names come from the parent, but their implementations are composed normally in
the worker: plugins can add or replace tools, including replacements such as
`pi-readseek`. Every task run starts a fresh Pi process and fresh plugin
instances. Continuing a `task_id` restores its persisted Pi session in a new
worker process.

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
running result while the worker continues, then deliver completion to the
parent automatically. The process exits when the run settles; its Pi session
remains on disk and can be continued with `task_id`. While tasks are active, Pi
shows their parent-child tree automatically above the editor.
Session switching or shutdown stops live workers. After an unclean restart,
unfinished work is marked interrupted rather than silently rerun; a completed
but undelivered background result is delivered when the root session resumes.

OpenCode-style worker permissions are enforced around the worker's composed
tools: `deny` blocks a call, `ask` suspends that worker and asks in the root UI,
and `allow` lets the tool run. Other workers may continue while a prompt is
open. An "Allow for this session" worker-permission decision applies to the
root session and its descendants. These permissions are separate from the
outer Landstrip policy and cannot widen it. Sandbox approvals continue to use
`.pi/sandbox.json` and `~/.pi/agent/sandbox.json`.

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

Subagent configuration is read from `~/.pi/agent/subagents.json` and, for
trusted projects, `.pi/subagents.json`. Project values override global values;
both are merged over the packaged [default](./subagents.json). Sandbox policy
continues to use `~/.pi/agent/sandbox.json` and `.pi/sandbox.json`. Pi's
`settings.json` contains only normal Pi settings such as the `pi-landstrip`
package entry. `subagents.json` accepts only top-level `maxSubagents` and
`subagents`; sandbox fields belong only in `sandbox.json`.

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

`maxSubagents` is an integer from 0 through 16 controlling concurrent worker
processes. Setting it to zero removes the `task` tool while retaining the primary
roles. There is no separate subagent enable switch. The Settings tab in `/agents`
edits this limit separately for global and trusted-project configuration.

Agent modes, hidden/disabled agents, prompts, and ordered `allow`/`ask`/`deny`
permissions apply to primary agents and subagents. Subagent workers also honor
model selection, supported Pi thinking-level variants, and step limits. Primary
agent activation currently changes the prompt and permissions only. Later
matching permission rules win. Put provider-specific values under `options`;
unknown agent fields are rejected. Agent permissions cannot weaken an enabled
OS sandbox, grant filesystem access, or grant network access.

## Migrating configuration

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

Do not put `subagents`, `agent`, `permission`, or `maxSubagents` in Pi's
`settings.json`; Pi-Landstrip does not read them there.

## Limits

Pi-Landstrip runs at most `maxSubagents` worker processes concurrently and
allows nesting to three levels. A foreground parent hands its scheduler permit to a child
while waiting, preventing nested-task deadlocks. A worker receives a nested
`task` tool only when its agent has an explicit `task` permission. Nested tasks
are separate Pi processes supervised by the root and Landstrip-wrapped unless
sandboxing is explicitly disabled. Persisted sessions remain resumable by `task_id`.

## License

`pi-landstrip` is licensed under `Apache-2.0`. See [LICENSE](LICENSE) for more
information.

The bundled `@landstrip/landstrip` package is licensed separately as
`Apache-2.0 AND LGPL-2.1-or-later`.
