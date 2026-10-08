# opencode-landstrip

Landstrip sandboxing for AI commands in OpenCode ≥2.0.18.

## Install and use

```sh
opencode plugin install opencode-landstrip          # project
opencode plugin install opencode-landstrip --global # global
```

Installation configures server and TUI plugins. `/landstrip` opens the management
pane; Pi's agent/task subcommands are unavailable.

## Permissions and configuration

OpenCode authorizes tool dispatch; Landstrip enforces filesystem/network access.
Approval never bypasses hard denials. Interactive requests without a live
presenter remain denied. Only AI `bash` receives OS isolation: OpenCode's plugin
API cannot replace direct user shell commands.

Policy precedence: bundled [`sandbox.json`](sandbox.json) → global →
`.opencode/sandbox.json` → plugin options. The global file is
`$XDG_CONFIG_HOME/opencode/sandbox.json` (`~/.config` when unset, empty, or relative).
Persistent approvals update the chosen project/global file.

Arrays combine; later scalar values win. Defaults allow project writes, deny
sensitive-file writes, and block network access. Enabled sandboxing fails closed
on unusable binaries/platforms; `enabled: false` explicitly permits unsandboxed Bash.

`filesystem.denyReadAlways` and `filesystem.denyWriteAlways` block approvals and
equal/nested grants. Non-empty hard-denial lists are unsupported on Windows.

See [landstrip(1)](../landstrip/man/man1/landstrip.1) for native CLI/policy semantics.
Runtime seccomp traps/query approval are Linux-only. Native macOS `--trap` reports
setup/launch errors only and closes on successful exec—not runtime violations.

## Development

From this package: `npm ci`, then `npm run all` (format, lint, typecheck, tests).
Read-only formatting check: `npm run ci:fmt`.

## License

Apache-2.0; see [LICENSE](LICENSE).
