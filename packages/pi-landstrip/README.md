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
override both. OpenCode integration flags live under `landstrip.opencode` in Pi
`settings.json`.

Process-backed subagents require Pi >= 0.82.0, and Node.js >= 22.19.0.

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

On Windows, Pi's Git Bash/MSYS shell cannot run under LPAC. The packaged policy
therefore selects standard AppContainer explicitly. This is weaker than LPAC because
resources granted to `ALL APPLICATION PACKAGES` remain visible; `/sandbox` and the
status line report the active backend and mode. There is no silent
LPAC-to-standard fallback.

An optional restricted-user backend supports Git Bash without AppContainer. It
requires one-time elevated host setup and persistent local accounts and WFP rules;
see [Windows restricted-user setup](#windows-restricted-user-setup).

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

Trusted project config overrides global config except for the Windows backend,
which can be selected only in the trusted global file. `/sandbox` updates a trusted
project sandbox file when present, otherwise the global file. Pi versions without a
project-trust API use only global configuration.

## Behavior

When Pi requests a sandboxed permission, the extension sends a host notification
and opens a dialog. The user can allow once, allow for the session, persist for
the project or globally, or reject. The dialog shows the exact path or domain
being approved.

Project approvals are written to `.pi/sandbox.json`; global approvals are
written to `~/.pi/agent/sandbox.json`.

The main agent remains a normal Pi process. `pi-landstrip` replaces Bash execution,
including AI `bash` calls and manually typed shell commands (`!` and `!!`), with a
Landstrip-wrapped implementation. Network traffic uses an allowlist proxy when
direct access is disabled and the platform policy permits loopback; otherwise it is
blocked. Pi's filesystem tools and plugin callbacks remain trusted code outside the
Landstrip sandbox.

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
and file changes. Built-in colors match OpenCode's default theme roles
(`success`/green for build, `warning`/orange for plan) and appear in the status
line and agent selectors.
The selection controls the root system prompt and permissions and is restored
with the session. Press `Ctrl+Shift+A` while Pi is idle to cycle through enabled
primary agents; switching is blocked while an agent run is active.

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
Use `/subagents` to open an inspector with **Agents** and **Sessions** tabs. The
Agents tab lists every available subagent type and its `built-in`, `global`, or
`local` source. The Sessions tab inspects child transcripts; task rows can open a
specific one with `/subagents <id>`. Completed and failed task metadata remains
available after reload, and persisted sessions can be continued with `task_id`.

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
- **Windows AppContainer**: the packaged policy selects standard AppContainer for
  Pi's Git Bash/MSYS runtime. With `windows.allowLoopback: false` (the default), the
  extension does not start an unreachable proxy and the worker has no network.
  Setting `windows.allowLoopback` to `true` enables the domain proxy, but also gives
  the AppContainer access to every local loopback service, not only the proxy port.
  Setting `network.allowNetwork` to `true` instead gives the entire worker
  unrestricted network access; domain lists are then not a boundary. Both opt-ins
  are explicit security downgrades and produce warnings.
- **Windows restricted user**: WFP blocks restricted accounts except for the
  installed proxy port range, so domain-filtered proxying works without a broad
  loopback exemption. `network.allowNetwork: true` leases a separately provisioned
  unrestricted account. Filesystem grants are journaled and revoked after every
  process tree exits.

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
merged over the packaged [defaults](./subagents.json). The packaged subagent types
are `code-reviewer`, `explore`, `general`, and the OpenCode-compatible `scout`
reconnaissance agent.

The read-only `code-reviewer` is available without additional configuration: delegate
with `task` using `subagent_type: "code-reviewer"`. It can read and search files and
run a fixed set of non-mutating Git inspection commands; all other tools are denied.

Sandbox policy remains in `~/.pi/agent/sandbox.json` and `.pi/sandbox.json`. OpenCode
integration flags live under `landstrip.opencode` in global or trusted-project Pi
`settings.json`; both default to `true`:

```json
{
  "packages": ["npm:pi-landstrip"],
  "landstrip": {
    "opencode": {
      "showGlobalAgents": true,
      "showLocalAgents": true
    }
  }
}
```

- `showGlobalAgents` imports `agent` definitions from `opencode.json` and
  `opencode.jsonc`, plus Markdown agents under `agent/` and `agents/`, in the
  OpenCode global config directory (`$OPENCODE_CONFIG_DIR`,
  `$XDG_CONFIG_HOME/opencode`, or `~/.config/opencode`).
- `showLocalAgents` imports `agent` definitions from project `opencode.json` and
  `opencode.jsonc`, `.opencode/opencode.json` and `.opencode/opencode.jsonc`, and
  Markdown agents under `.opencode/agent/` and `.opencode/agents/`.

Project settings override global settings. Set a flag to `false` to disable that
source. OpenCode project agents override global OpenCode agents. Pi definitions from
`subagents.json` (built-in, global, and project) take precedence over OpenCode imports
with the same name; conflicts are silent. Project Pi settings and project OpenCode
agents are skipped when the project is untrusted; global OpenCode agents still load
when `showGlobalAgents` is enabled.

OpenCode JSONC comments and trailing commas are supported. `{file:path}` prompt tokens
resolve relative to the OpenCode config file. `subagents.json` accepts only top-level
`maxSubagents` and `subagents`; sandbox fields belong in `sandbox.json`.

The Windows sandbox fields are:

```json
{
  "windows": {
    "backend": "appContainer",
    "appContainerMode": "standard",
    "allowLoopback": false
  }
}
```

`backend` is `"appContainer"` or `"restrictedUser"`. It is a trusted host setting:
only `~/.pi/agent/sandbox.json` can change it, and project configuration cannot
override it. `appContainerMode` is `"lpac"` or `"standard"`; core Landstrip defaults
to LPAC, while the Pi package defaults to standard mode for Git Bash compatibility.
`allowLoopback` is independently opt-in and applies only to AppContainer.

### Windows restricted-user setup

Provision the backend once before selecting it in global configuration:

```powershell
npx @landstrip/landstrip windows setup
npx @landstrip/landstrip windows status
```

Setup requests UAC elevation and defaults to eight restricted-network accounts, two
unrestricted-network accounts, and proxy ports 60080-60111. Run
`npx @landstrip/landstrip windows setup --help` for pool and port options. Then set
`"backend": "restrictedUser"` in `~/.pi/agent/sandbox.json` and restart Pi.

The extension checks installation health and reads the configured proxy range before
launching a restricted worker. Restricted-user mode does not support
`windows.allowLoopback` or `network.allowLocalBinding`. Remove the persistent
accounts, WFP rules, runner, and recovered per-run ACL grants with:

```powershell
npx @landstrip/landstrip windows uninstall
```

A subagent configuration example follows:

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
The packaged default is 1, making `task` and `code-reviewer` available immediately.
Set it to 0 to remove the `task` tool while retaining primary roles. There is no
separate subagent enable switch. The Settings tab in `/agents` edits this limit for
global and trusted-project configuration.

Agent modes, hidden/disabled agents, prompts, colors, and ordered
`allow`/`ask`/`deny` permissions apply to primary agents and subagents. Prompt
strings may include OpenCode-style `{file:path}` tokens; relative paths resolve
against the `subagents.json` file that defines them. `color` accepts `#RRGGBB`
or OpenCode theme names (`primary`, `secondary`, `accent`, `success`, `warning`,
`error`, `info`). `hidden` only hides an agent from user-facing primary pickers;
the model can still invoke a hidden subagent via `task`.

Primary agents honor configured models and supported Pi thinking-level variants;
omitting either preserves the current session setting. A model may use the full
`provider/model` name or a bare model ID when that ID is unique. Selection fails
without changing the active primary agent when the model is missing, ambiguous,
or unavailable for authentication. Subagent workers also honor model selection,
supported Pi thinking-level variants, and step limits. Later matching permission
rules win. Put provider-specific values under `options`; unknown agent fields are
rejected. Agent permissions cannot weaken an enabled OS sandbox, grant filesystem
access, or grant network access.

## Configuration migration

There is no compatibility loader for previous Pi agent configuration fields. Legacy
keys in `settings.json` produce a migration warning. Move configuration as follows,
then remove the old fields:

- Move `agent` and `permission` from Pi `settings.json` under `subagents.agent` and
  `subagents.permission` in `subagents.json`.
- Convert legacy `tools` booleans to explicit `permission` rules.
- Put the worker limit in top-level `maxSubagents` in `subagents.json`; zero disables
  delegation.
- Move top-level `opencode` from `subagents.json` to `landstrip.opencode` in the
  corresponding global or project Pi `settings.json`.
- Use `~/.pi/agent/subagents.json` for global Pi agent configuration and
  `.pi/subagents.json` for trusted project Pi agent configuration.
- Leave sandbox policy in `~/.pi/agent/sandbox.json` and `.pi/sandbox.json`; those
  files are unchanged.

## Plugin API

Pi extensions can discover the active Landstrip runtime through the versioned
API exported by `pi-landstrip/api`:

```ts
import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import { useLandstrip } from 'pi-landstrip/api';

export default function (pi: ExtensionAPI) {
  const dispose = useLandstrip(pi, (landstrip) => {
    const context = landstrip.getContext();
    // Register Landstrip-aware behavior here.
  });
  pi.on('session_shutdown', dispose);
}
```

Discovery is callback-based so it works regardless of extension load order.
Do not wait for discovery from an extension factory: Pi initializes extension
factories sequentially. The returned function stops future notifications.

The runtime exposes:

- `getContext()` for the host, role, sandbox state, task identity, agent and
  nesting depth.
- `createBashTool()` for extensions that need Landstrip execution with their
  own tool presentation.
- `prepareProcess()` for single-use process launches under the effective
  sandbox policy.
- `registerWorkerExtension()` to load an absolute extension entry in Landstrip
  subagents. The returned function removes the registration.
- `on()` for typed `sandbox.changed`, `subagent.start` and `subagent.end`
  lifecycle events.

Registered worker extensions are trusted code. Landstrip adds their canonical
directories and dependency roots to worker read access, loads them with Pi's
`--extension` option, and propagates them to nested tasks.

Workers receive a base64url JSON `LANDSTRIP_CONTEXT` environment variable.
Extensions can read it without runtime discovery:

```ts
import { contextFromEnvironment } from 'pi-landstrip/api';

const context = contextFromEnvironment();
```

This public context is informational and contains no permission rules, policy,
credentials or proxy secrets. Environment values can be spoofed outside a
Landstrip worker and must not be treated as authorization.

Generic process preparation fails closed on Windows when sandboxing is disabled.
Windows cannot reliably reclaim an unsandboxed descendant tree after its leader
has exited; enabled Landstrip launches use an AppContainer job object instead.

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
