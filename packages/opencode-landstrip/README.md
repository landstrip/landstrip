# opencode-landstrip

Landstrip sandboxing for AI `bash` calls in OpenCode ≥1.17.7.

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

Policy precedence (persistent approvals update the project/global files):

1. Bundled [`sandbox.json`](sandbox.json).
2. `~/.config/opencode/sandbox.json`.
3. `.opencode/sandbox.json`.
4. Plugin options.

Arrays combine; later scalar values win. Defaults allow project writes, deny
sensitive-file writes, and block network access. Enabled sandboxing fails closed
on unusable binaries/platforms; `enabled: false` explicitly permits unsandboxed Bash.

See [landstrip(1)](../landstrip/man/man1/landstrip.1) for native CLI/policy semantics.
Runtime seccomp traps/query approval are Linux-only. Native macOS `--trap` reports
setup/launch errors only and closes on successful exec—not runtime violations.

## Development

From this package: `npm ci`, then `npm run all` (format, lint, typecheck, tests).
Read-only formatting check: `npm run ci:fmt`.

## License

Apache-2.0; see [LICENSE](LICENSE).
