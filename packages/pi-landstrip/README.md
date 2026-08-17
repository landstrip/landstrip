# pi-landstrip

`pi-landstrip` adds sandboxed Bash, primary agents, and process-backed subagents
to [Pi](https://pi.dev/). It requires Pi 0.82.0 or later and Node.js 22.19.0 or
later.

## Install

```sh
pi install npm:pi-landstrip
```

For a manual global or trusted-project install, add the package to Pi's
`settings.json`:

```json
{
  "packages": ["npm:pi-landstrip"]
}
```

The package includes Landstrip binaries for Linux, macOS, and Windows on x64 and
Arm64. If sandboxing is enabled but the binary or platform is unusable, Bash,
shell commands, and sandboxed workers fail closed. Only `--no-sandbox` or
`"enabled": false` permits execution without OS isolation.

## Permissions

Pi evaluates two permission categories:

| Category | Checked                                 | Controls                         |
| -------- | --------------------------------------- | -------------------------------- |
| Agent    | Before dispatch                         | Whether an agent may call a tool |
| Sandbox  | Before file access and during processes | Filesystem and network resources |

Agent rules return `deny`, `ask`, or `allow`. An agent approval authorizes only
tool dispatch and cannot bypass a sandbox hard denial.

By default, primary `read`, `write`, `edit`, and `apply_patch` tools run in the
trusted Pi process and only agent permissions apply. Set
`toolFilesystemPolicy` to `"sandbox"` to preflight their paths against
`sandbox.json`. `denyWrite` remains a hard denial. If both agent and sandbox
approval are needed, Pi presents one prompt for the call.

AI Bash, `!`, `!!`, and subagent processes use OS isolation. Subagents rely on
that isolation instead of repeating file-tool preflight. Pi presents all agent
and sandbox requests through one FIFO prompt queue.

Sandbox approvals may apply once, for the session, to the project, or globally.
Persistent approvals update `.pi/sandbox.json` or
`~/.pi/agent/sandbox.json`. Headless requests that require approval are denied.

## Sandbox configuration

Sandbox policy merges in this order:

1. bundled [`sandbox.json`](./sandbox.json);
2. `~/.pi/agent/sandbox.json`;
3. `.pi/sandbox.json` for a trusted project.

Objects merge recursively, arrays combine, and later scalar values replace
earlier values. `/sandbox` displays or toggles the policy. It writes the project
policy in a trusted project and the global policy otherwise.

| Field                         | Bundled default                                                                                    |
| ----------------------------- | -------------------------------------------------------------------------------------------------- |
| `enabled`                     | `true`                                                                                             |
| `shell.readAccess`            | `"host"`                                                                                           |
| `filesystem.denyRead`         | `["/Users", "/home"]`                                                                              |
| `filesystem.allowRead`        | `[".", "~/.gitconfig", "~/.config/git/config", "/dev/null"]`                                       |
| `filesystem.allowWrite`       | `[".", "/dev/null"]`                                                                               |
| `filesystem.denyWrite`        | `["**/.env", "**/.env.*", "**/*.pem", "**/*.key", ".pi/sandbox.json", "~/.pi/agent/sandbox.json"]` |
| `network.allowNetwork`        | `false`                                                                                            |
| `network.allowLocalBinding`   | `false`                                                                                            |
| `network.allowAllUnixSockets` | `false`                                                                                            |
| `network.allowUnixSockets`    | `[]`                                                                                               |
| `network.allowedDomains`      | `[]`                                                                                               |
| `network.deniedDomains`       | `[]`                                                                                               |
| `windows.appContainerMode`    | `"standard"`                                                                                       |
| `windows.allowLoopback`       | `false`                                                                                            |

Filesystem and core network semantics follow the main
[Landstrip policy](https://github.com/landstrip/landstrip#policy). `allowedDomains`
and `deniedDomains` are plugin fields enforced by the local HTTP/HTTPS proxy.

`shell.readAccess: "host"` gives primary Bash and `!`/`!!` the trusted host read
view on Linux and macOS while retaining sandboxed writes. `"policy"` applies
`denyRead` and `allowRead`. Workers always use policy reads. Windows always uses
policy reads because it requires an explicit read allowlist.

With `enabled: false`, subagents remain separate processes but lose Landstrip OS
isolation; Pi warns once per session.

## Agent configuration

Agent configuration merges built-ins, global configuration, then trusted-project
configuration. Use either dedicated files:

- `~/.pi/agent/landstrip.json`
- `.pi/landstrip.json`

or a top-level `landstrip` object in the matching `settings.json`. Using both
forms at one scope is an error.

```json
{
  "maxSubagents": 2,
  "toolFilesystemPolicy": "sandbox",
  "agent": {
    "review": {
      "description": "Review without modifying files",
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

| Field                  | Default         | Values                                       |
| ---------------------- | --------------- | -------------------------------------------- |
| `maxSubagents`         | `1`             | integer from 0 through 16; 0 disables `task` |
| `toolFilesystemPolicy` | `"host"`        | `"host"` or `"sandbox"`                      |
| `agent`                | built-in agents | named agent definitions                      |
| `permission`           | built-in rules  | global tool/resource rules                   |

Agent definitions accept `name`, `description`, `prompt`, `mode`, `model`,
`variant`, `temperature`, `top_p`, `steps`, `color`, `hidden`, `disable`,
`options`, and `permission`. `mode` is `primary`, `subagent`, or `all` and
defaults to `all`. `/agents` Primary lists only `mode: primary` agents. The
Subagent tab lists `mode: subagent` and `mode: all` agents, including JSON and
Markdown definitions.

The built-in primary agents are `build` and `plan`; built-in subagents are
`general`, `scout`, and `explore`. Pi also loads Markdown agents from
`~/.pi/agent/agents/` and `.pi/agents/`. Project definitions overlay global
definitions. Configured fields overlay Markdown agents with the same name, so a
model-only `landstrip.json` entry keeps the Markdown agent's mode, prompt, and
permissions.

## Commands and tasks

- `/sandbox` inspects and toggles sandboxing.
- `/agents` selects or edits agents and lists task sessions.
- `Ctrl+Shift+A` cycles visible primary agents while Pi is idle.

The `task` tool requires `description`, `prompt`, and `subagent_type`. Optional
`task_id` continues a saved task, `command` records the originating command, and
`background: true` returns immediately. `/agents <task-id>` inspects a task.
Each invocation starts a fresh Pi RPC process; continuation restores its saved
session in a new process.

Workers use normal Pi resource and plugin discovery. Their model requests can
read Pi authentication and inherited credential environment variables. Install
only trusted worker plugins and use credentials appropriate for the sandboxed
task.

## Permission ask providers

A separate Pi extension can resolve agent permission rules that return `ask` by
registering one `LandstripPermissionAskProvider`:

```ts
import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import { provideLandstripPermissionAsk } from 'pi-landstrip/api';

export default function permissionReviewer(pi: ExtensionAPI): void {
  provideLandstripPermissionAsk(pi, {
    id: 'example-reviewer',
    async decide(request) {
      if (request.toolName === 'bash' && request.input.command === 'git status') {
        return { decision: 'allow' };
      }
      return { decision: 'abstain' };
    },
  });
}
```

The provider receives the tool name and input, pending permission/resource pairs,
the primary or subagent context, and an abort signal. `allow` approves that call,
`deny` blocks it, and `abstain` uses the normal UI prompt or headless denial.
Provider errors also fall back safely. Only one provider may be registered at a
time; the helper works regardless of extension load order and returns a disposer.

## License

`pi-landstrip` is licensed under `Apache-2.0`. The bundled Landstrip package is
licensed separately as `Apache-2.0 AND LGPL-2.1-or-later`.
