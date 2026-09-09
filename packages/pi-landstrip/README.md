# pi-landstrip

Sandboxed Bash, primary agents, and process-backed subagents for Pi.
Requires Pi ≥0.82.0 and Node.js ≥22.19.0.

## Install

```sh
pi install npm:pi-landstrip
```

Includes native binaries for Linux, macOS, and Windows on x64 and Arm64.
Enabled sandboxing fails closed if the binary or platform is unusable;
`--no-sandbox` or `enabled: false` explicitly permits unsandboxed execution.

## Permissions and configuration

Agent permissions govern tool dispatch, not sandbox access: approval never
bypasses a sandbox hard denial. With sandboxing enabled, AI Bash, `!`, `!!`, and
subagents use OS isolation. Primary file tools run in trusted Pi; setting
`toolFilesystemPolicy: "sandbox"` applies filesystem policy checks, not OS isolation.

Policy merges from bundled [`sandbox.json`](sandbox.json), then
`~/.pi/agent/sandbox.json`, then trusted-project `.pi/sandbox.json`.
Arrays combine; later scalar values win. Persistent sandbox approvals update
the global or project file. Store only overrides:

```json
{
  "shell": { "readAccess": "policy" },
  "filesystem": { "allowWrite": ["."] },
  "network": { "allowNetwork": false }
}
```

The bundled shell default is `readAccess: "host"`; workers always use policy
reads. Windows requires an explicit read allowlist. Native policy and CLI
semantics are in [landstrip(1)](../landstrip/man/man1/landstrip.1).
Runtime seccomp traps and query approval are Linux-only. On macOS, `--trap`
reports setup/launch errors only and closes on successful exec.

Worker read boundaries:

- Bootstrap grants can override bundled `denyRead` defaults, never persisted
  global or trusted-project denies. Denied startup resources prevent launch.
  Legacy copies of `/home` or `/Users` count as explicit denies: remove them only
  if unintended; bundled defaults remain. New global files start as `{}`.
- `filesystem.denyReadAlways` cannot be overridden by equal/nested read grants
  or shell host reads. Private workers protect parent auth-file and lock roots
  with this policy and `denyWrite`. Non-empty `denyReadAlways` and private worker
  auth are unsupported on Windows.
- External skill, prompt, and theme directories may need explicit discovery
  access. Prefer resource file paths: resolved-file grants do not cover enclosing
  directories.

## Agents and tasks

Configure `~/.pi/agent/landstrip.json`, trusted-project `.pi/landstrip.json`, or
`landstrip` in the corresponding Pi settings file. Global definitions load first.

```json
{
  "maxSubagents": 2,
  "toolFilesystemPolicy": "sandbox",
  "permission": { "task": { "*": "deny", "review": "allow" } }
}
```

`maxSubagents` accepts 0–16. Agent definitions can override model, prompt, mode,
options, and permissions.

`/landstrip` opens the management pane; `/landstrip help` lists commands and
shortcuts. Common commands:

| Command                           | Action                          |
| --------------------------------- | ------------------------------- |
| `/landstrip status`               | Inspect sandbox, agents, tasks. |
| `/landstrip settings`             | Set concurrency/file policy.    |
| `/landstrip sandbox [on\|off]`    | Inspect/toggle OS isolation.    |
| `/landstrip agents [@name]`       | List/select primary agents.     |
| `/landstrip subagents`            | List process subagents.         |
| `/landstrip tasks [list]`         | List task sessions.             |
| `/landstrip tasks kill <task-id>` | Terminate a task.               |
| `/landstrip logs [task-id]`       | Open task logs.                 |

Task IDs accept unique prefixes; bare IDs open logs in the pane.
`Ctrl+Shift+A` cycles primary agents while Pi is idle. The `task` tool accepts
`background: true` for immediate return and `task_id` to continue a saved task.
Press `Enter` in running/queued task logs to steer the worker.

### Worker environment and authentication

Workers start `--offline`: install resources and refresh model catalogs in the
parent first. Model/auth requests still need permitted endpoints.

Workers inherit only runtime paths, locale, certificate paths, and supported Pi
configuration—not parent API keys, tool tokens, proxy URLs, or arbitrary variables.
The parent refreshes selected-provider auth and sends it through a private Unix
pipe, never arguments or worker environment. Environment-based tool logins need
separate configuration; authenticated workers fail before spawning on Windows.

Selected Bedrock, Vertex, and Azure settings also travel privately. Ambient AWS
profiles need an explicit region for non-ARN models; custom credential-chain
environment paths are unsupported (use scoped keys or a Bedrock bearer token).
Provider credential files still need filesystem permission.

## Development

From this package: `npm ci`, then `npm run all` (format, lint, typecheck, build,
and tests; building requires Bun). For a read-only formatting check: `npm run ci:fmt`.

## License

Apache-2.0; see [LICENSE](LICENSE).
