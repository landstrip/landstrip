# opencode-landstrip

OpenCode plugin that runs AI `bash` calls through Landstrip.

## Install

```sh
# Current project
opencode plugin install opencode-landstrip

# Global
opencode plugin install opencode-landstrip --global
```

The installer configures both the server plugin and TUI presenter.

## Permissions

OpenCode permissions authorize tool dispatch. Landstrip permissions authorize
filesystem and network access. Agent approval never bypasses a sandbox hard
denial, and requests without a live presenter are denied.

`/sandbox` displays or toggles the policy. Persistent approvals update
`.opencode/sandbox.json` or `~/.config/opencode/sandbox.json`.

## Configuration

Policy merges in this order:

1. bundled `sandbox.json`;
2. `~/.config/opencode/sandbox.json`;
3. `.opencode/sandbox.json`;
4. plugin options.

Objects merge recursively, arrays combine, and later scalar values replace
earlier values. The bundled policy denies sensitive files and network access
while allowing project writes. See [`sandbox.json`](sandbox.json) for its exact
defaults.

If sandboxing is enabled but the binary or platform is unusable, AI Bash fails
closed. Set `enabled` to `false` explicitly to allow unsandboxed AI Bash.

Only AI `bash` calls receive OS isolation; direct user shell commands cannot be
replaced through OpenCode's plugin API.

## Licensing

[Apache 2.0](../../LICENSE-APACHE-2.0).
