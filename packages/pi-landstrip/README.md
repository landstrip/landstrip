# pi-landstrip

Sandboxed Bash, primary agents, and process-backed subagents for Pi.
Requires Pi ≥0.82.0 and Node.js ≥22.19.0.

## Install

```sh
pi install npm:pi-landstrip
```

Unusable sandboxing fails closed; `--no-sandbox` or `enabled: false` permits
unsandboxed execution.

## Permissions and configuration

With sandboxing enabled, Bash (`bash`, `!`, `!!`) and workers are OS-isolated.
Primary file tools run in trusted Pi and preflight paths against the sandbox
filesystem policy. Tool approval never bypasses hard denials.

Configuration is loaded in order from the bundled [`sandbox.json`](sandbox.json),
`~/.pi/agent/sandbox.json`, and `.pi/sandbox.json` in a trusted project. Later
files append to list settings and override non-list settings. Persistent
approvals are written to the global or project file. For policy-only shell reads:

```json
{ "shell": { "readAccess": "policy" } }
```

Shell reads default to `"host"`; workers always use policy reads. See
[landstrip(1)](../landstrip/man/man1/landstrip.1) for native policy, traps,
and platform limits, including Windows read grants and hard-denial restrictions.

Worker boundaries:

- Workers can read their startup files despite the bundled `denyRead` defaults.
  If your own sandbox settings block a needed path with `denyRead`, Pi asks for
  approval before starting the worker. Declining prevents startup. Existing
  `allowRead` grants and session approvals are reused. `denyReadAlways` blocks
  startup without asking.
- Hard read denials also apply to shell host reads. Private workers protect
  parent auth-file/lock roots with `denyReadAlways` and `denyWrite`;
  private worker authentication is unsupported on Windows.
- `filesystem.denyWriteAlways` rejects write attempts without prompting.
- External skills/prompts/themes may need directory discovery grants;
  resolved-file grants do not include parent directories.

## Agents and tasks

Configure `~/.pi/agent/landstrip.json`, trusted-project `.pi/landstrip.json`, or
`landstrip` in the corresponding Pi settings file. Global definitions load first.

```json
{
  "maxSubagents": 2,
  "permission": { "task": { "*": "deny", "review": "allow" } }
}
```

`maxSubagents` accepts values from 0 to 16. Agent definitions can override
model, prompt, mode, options, and permissions.

Use `/landstrip-sandbox` for sandbox overview/policy (`Overview`, `Policy`, `Help`)
and `/landstrip-subagents` for subagent/task management (`Tasks`, `Log`, `Subagent`,
`Primary`, `Settings`, `Help`). Task IDs accept unique prefixes; bare IDs open logs.
`/landstrip-subagents tasks cancel <id>` terminates a task. `Ctrl+Shift+A` cycles
primary agents while idle. The `task` tool accepts `background: true`, `include_context: true`,
and `task_id` to continue a saved task; the `tasks` tool supports `list`, `inspect`,
`steer`, and `cancel`. Press `S` in `Tasks` or `Enter` in running/queued logs to steer workers.

### Worker environment and authentication

Workers start `--offline`; install resources and refresh model catalogs in the
parent first. Provider endpoints still need network permission.

Only runtime paths, locale, certificate paths, and supported Pi config are
inherited—not parent API keys, tool tokens, proxy URLs, or arbitrary variables.
The parent refreshes selected-provider auth and sends it, along with selected
Bedrock/Vertex/Azure settings, over a private Unix pipe, not arguments or
environment. Configure tool logins separately; authenticated workers cannot
launch on Windows.

Ambient AWS profiles need an explicit region for non-ARN Bedrock models.
Custom credential-chain environment paths are unsupported; use scoped keys or
a Bedrock bearer token. Provider credential files need filesystem grants.

## Extension API

[`pi-landstrip/api`](api.ts) exports `createLandstrip`. `prepareProcess()` returns
`undefined` without a runtime. Dispose prepared processes separately from the
discovery handle; generic `spawn()` returns `ChildProcess`, RPC workers use
piped streams.

## Development

From this package: `npm ci && npm run all` (Bun required).
`npm run ci:fmt` checks formatting without edits.

## License

[Apache-2.0](LICENSE).
