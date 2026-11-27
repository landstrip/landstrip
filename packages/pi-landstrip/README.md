# pi-landstrip

OS-level sandboxing for Bash and process-backed agents in Pi ≥0.82.0 (Node.js
≥22.19.0).

## Install

```sh
pi install npm:pi-landstrip
```

Unusable sandboxing fails closed; `--no-sandbox` or `enabled: false` permits
unsandboxed execution.

## Usage

| Command / Key                            | Action                                                                       |
| ---------------------------------------- | ---------------------------------------------------------------------------- |
| `/landstrip-sandbox`                     | Open sandbox panes (`Overview`, `Policy`, `Help`)                            |
| `/landstrip-sandbox on\|off`             | Enable or disable OS sandbox isolation                                       |
| `/landstrip-subagents`                   | Open agent panes (`Tasks`, `Log`, `Subagent`, `Primary`, `Settings`, `Help`) |
| `/landstrip-subagents tasks <id>`        | Open logs for a task ID or unique prefix                                     |
| `/landstrip-subagents tasks cancel <id>` | Cancel a running or queued task                                              |
| `/landstrip-subagents agents [@name]`    | List agents or switch the active primary agent                               |
| `Ctrl+Shift+A`                           | Cycle primary agents while idle                                              |
| `S` / `Enter`                            | Steer a worker from `Tasks` (`S`) or active task logs (`Enter`)              |

## Permissions and configuration

With sandboxing enabled, Bash (`bash`, `!`, `!!`) and worker processes are
OS-isolated. Primary file tools run in trusted Pi and preflight paths against
the sandbox filesystem policy. Tool approval never overrides hard sandbox
denials.

Configuration loads in order, appending to list fields and overriding scalar
fields:

1. Bundled [`sandbox.json`](sandbox.json)
2. `~/.pi/agent/sandbox.json`
3. `.pi/sandbox.json` (in trusted projects)

Persistent approvals write to the global or project file. Shell reads default to
`"host"`, while workers always use `"policy"` reads. Set `"policy"` to restrict
shell reads to `allowRead`:

```json
{ "shell": { "readAccess": "policy" } }
```

On Linux, `linux.backend` selects `"auto"` (default; uses `"machine"` when
`/dev/kvm` is accessible, otherwise `"container"`), `"container"`, or
`"machine"`.

Worker boundaries:

- Startup files remain readable despite bundled `denyRead` defaults. User
  `denyRead` rules matching startup files prompt before launch (reusing
  `allowRead` and session grants); declining or matching `denyReadAlways` aborts
  startup.
- `denyReadAlways` also applies to `"host"` shell reads, and `denyWriteAlways`
  rejects writes without prompting.
- Private workers protect parent auth and lock roots with `denyReadAlways` and
  `denyWrite` (unsupported on Windows).
- External skills, prompts, and themes may need directory grants; resolved-file
  grants do not cover parent directories.

See [landstrip(1)](../landstrip/man/man1/landstrip.1) for policy rules, native
traps, and platform limits.

## Subagents

Configure `~/.pi/agent/landstrip.json` (loaded first) and `.pi/landstrip.json`
in trusted projects:

```json
{
  "maxSubagents": 2,
  "permission": { "task": { "*": "deny", "review": "allow" } }
}
```

`maxSubagents` accepts `0`–`16`. Agent definitions can override model, prompt,
mode, options, and permissions.

| Tool    | Option / Action                         | Description                                                                         |
| ------- | --------------------------------------- | ----------------------------------------------------------------------------------- |
| `task`  | `model`                                 | Override `provider/model[:level]` for the run (must exist and have auth configured) |
| `task`  | `background: true`                      | Run asynchronously without blocking the turn                                        |
| `task`  | `include_context: true`                 | Forward parent conversation context                                                 |
| `task`  | `worktree: true`                        | Run in an isolated detached Git worktree                                            |
| `task`  | `task_id`                               | Resume a saved task (keeps stored `model` and rechecks auth; rejects a new `model`) |
| `tasks` | `list` / `inspect` / `steer` / `cancel` | Inspect or control active and saved tasks                                           |

Valid thinking levels for `model` are `off`, `minimal`, `low`, `medium`, `high`,
`xhigh`, and `max`. When omitted, resolution checks
`modelThinkingLevels[provider/model]` and `defaultThinkingLevel` in
`~/.pi/agent/settings.json`, falling back to `medium`.

### Worker environment and authentication

Workers start `--offline`; install resources and refresh model catalogs in the
parent first. Provider endpoints still require network permission.

Workers inherit only runtime paths, locale, certificate paths, and supported Pi
settings. The parent refreshes selected-provider credentials and sends them—with
selected Bedrock, Vertex, or Azure settings—over a private Unix pipe rather than
arguments or environment variables (unsupported on Windows; configure tool
logins separately). Ambient AWS profiles need an explicit region for non-ARN
Bedrock models; custom credential-chain environment paths are unsupported, and
provider credential files require filesystem grants.

## Extension API

[`pi-landstrip/api`](api.ts) exports `createLandstrip`. `prepareProcess()`
returns `undefined` when no runtime is active; dispose prepared processes
separately from the discovery handle. Generic `spawn()` returns a
`ChildProcess`, while RPC workers use piped streams.

## Development

Requires Bun:

```sh
npm ci && npm run all
npm run ci:fmt
```

## License

[Apache-2.0](LICENSE).
