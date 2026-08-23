import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { binaryPath as installedLandstripBinaryPath } from '@landstrip/landstrip';

import { installLandstripMock, packageRoot, transpile } from './helper.mjs';

const execFileAsync = promisify(execFile);

async function withPlugin(options, run, mock = {}) {
  const tempDir = await mkdtemp(join(tmpdir(), 'opencode-landstrip-test-'));
  const modulePath = join(tempDir, 'plugin.mjs');
  const home = join(tempDir, 'home');
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;

  try {
    const compiled = transpile(await readFile(join(packageRoot, 'index.ts'), 'utf8'));
    const sharedCompiled = transpile(await readFile(join(packageRoot, 'shared.ts'), 'utf8'));

    await mkdir(home, { recursive: true });
    await writeFile(join(tempDir, 'shared.js'), sharedCompiled);
    await writeFile(
      join(tempDir, 'sandbox.json'),
      await readFile(join(packageRoot, 'sandbox.json'), 'utf8'),
    );
    await writeFile(modulePath, compiled);
    process.env.HOME = home;
    process.env.USERPROFILE = home;

    const landstrip = mock.externalBinary ? modulePath : installedLandstripBinaryPath();
    await installLandstripMock(
      tempDir,
      `export function binaryPath() { return ${JSON.stringify(landstrip)}; }`,
    );

    const {
      default: { server: plugin },
    } = await import(pathToFileURL(modulePath).href);
    const messages = [];
    const hooks = await plugin(
      {
        client: {
          app: {
            log: async (entry) => {
              messages.push(entry.body.message);
            },
          },
          tui: { showToast: async () => undefined },
        },
        directory: tempDir,
      },
      options,
    );

    await run({ hooks, messages, tempDir });
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    await rm(tempDir, { force: true, recursive: true });
  }
}

test('bash wrapping is idempotent for repeated before hooks', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: {
        allowRead: ['.'],
        allowWrite: ['.'],
        denyRead: [],
        denyWrite: [],
      },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, messages }) => {
      const input = { callID: 'bash-call', tool: 'bash' };
      try {
        const output = {
          args: {
            command: 'git status --short',
            description: 'Shows concise git status',
          },
        };

        await hooks['tool.execute.before'](input, output);
        const wrapped = output.args.command;

        assert.notEqual(wrapped, 'git status --short', messages.join('\n'));

        await hooks['tool.execute.before'](input, output);

        assert.equal(output.args.command, wrapped);
        assert.equal(output.args.description, 'Shows concise git status (landstrip)');
        // A wrapped command contains one landstrip invocation. Idempotency is
        // primarily guarded by equality above, with this count catching nesting.
        assert.equal(wrapped.match(/'-p'/g)?.length, 1);
      } finally {
        await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
      }
    },
  );
});

test('disabled sandbox reports its configuration state', async () => {
  await withPlugin({ enabled: false }, async ({ hooks, messages }) => {
    const output = { args: { command: 'git status --short', description: 'Shows git status' } };
    await hooks['tool.execute.before']({ callID: 'disabled', tool: 'bash' }, output);

    assert.equal(output.args.command, 'git status --short');
    assert.ok(messages.includes('Sandbox is disabled by configuration'));
  });
});

test('disabled sandbox preserves OpenCode permission prompts', async () => {
  await withPlugin({ enabled: false }, async ({ hooks }) => {
    const output = { status: 'ask' };
    await hooks['permission.ask'](
      {
        id: 'permission-disabled',
        type: 'edit',
        callID: 'edit-call',
        sessionID: 'session',
        messageID: 'message',
        title: 'Edit file',
        metadata: { filepath: '/tmp/test.txt' },
        time: { created: 0 },
      },
      output,
    );

    assert.equal(output.status, 'ask');
  });
});

test('option-managed sandbox state cannot be overwritten', async () => {
  await withPlugin({ enabled: false }, async ({ tempDir }) => {
    const shared = await import(pathToFileURL(join(tempDir, 'shared.js')).href);
    shared.loadConfig(tempDir, { enabled: false });
    const configPath = shared.getConfigPaths(tempDir).globalPath;
    const before = await readFile(configPath, 'utf8');

    assert.throws(
      () => shared.setSandboxConfigEnabled(tempDir, true, { enabled: false }),
      /Sandbox state is managed by plugin options/,
    );
    assert.equal(await readFile(configPath, 'utf8'), before);
  });
});

test('setSandboxConfigEnabled toggles persisted enabled and the server honors it', async () => {
  await withPlugin(
    {
      // No `enabled` here: the persisted sandbox.json drives it.
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      const shared = await import(pathToFileURL(join(tempDir, 'shared.js')).href);
      const wrap = async (callID) => {
        const output = { args: { command: 'git status --short', description: 'd' } };
        await hooks['tool.execute.before']({ callID, tool: 'bash' }, output);
        await hooks['tool.execute.after'](
          { callID, tool: 'bash', args: output.args },
          { title: '', output: '', metadata: {} },
        );
        return output.args.command;
      };

      // The template defaults enabled: true, so wrapping is active.
      assert.notEqual(await wrap('on'), 'git status --short');

      // /sandbox toggle off: persists enabled:false (no project config -> global).
      assert.equal(shared.setSandboxConfigEnabled(tempDir, false), 'global');
      assert.equal(await wrap('off'), 'git status --short', 'disabled config skips wrapping');

      // /sandbox toggle back on.
      assert.equal(shared.setSandboxConfigEnabled(tempDir, true), 'global');
      assert.notEqual(await wrap('on-again'), 'git status --short');
    },
  );
});

test('external landstrip binary is refused', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: {
        allowRead: ['.'],
        allowWrite: ['.'],
        denyRead: [],
        denyWrite: [],
      },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, messages }) => {
      const output = {
        args: {
          command: 'git status --short',
          description: 'Shows concise git status',
        },
      };

      await assert.rejects(
        hooks['tool.execute.before']({ callID: 'external-binary-call', tool: 'bash' }, output),
        /Broken @landstrip\/landstrip installation: Refusing to use landstrip binary/,
      );

      assert.equal(output.args.command, 'git status --short');
      assert.match(
        messages.join('\n'),
        /Refusing to use landstrip binary outside official @landstrip\/landstrip packages/,
      );
    },
    { externalBinary: true },
  );
});

test('headless filesystem denials do not become session allowances', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, messages, tempDir }) => {
      const blockedPath = `${tempDir}-blocked`;
      const shared = await import(pathToFileURL(join(tempDir, 'shared.js')).href);
      const leakedScope = shared.sessionScopeFor(blockedPath, tempDir);
      const firstInput = { callID: 'headless-first', tool: 'bash' };
      const firstOutput = { args: { command: `cat ${blockedPath}`, description: 'read blocked' } };

      await hooks['tool.execute.before'](firstInput, firstOutput);
      await hooks['tool.execute.after'](firstInput, {
        title: '',
        output:
          JSON.stringify({
            kind: 'filesystem',
            operation: 'read',
            path: blockedPath,
            state: 'query',
            query_id: 'headless-query',
          }) + `\ncat: ${blockedPath}: Permission denied`,
        metadata: {},
      });

      assert.match(
        messages.join('\n'),
        /No live TUI presenter was available, so access remains denied/,
      );

      const retryInput = { callID: 'headless-retry', tool: 'bash' };
      const retryOutput = { args: { command: `cat ${blockedPath}`, description: 'retry blocked' } };
      try {
        await hooks['tool.execute.before'](retryInput, retryOutput);
        const policyMatch = retryOutput.args.command.match(/\s'-p'\s+'([^']+)'/);
        assert.ok(policyMatch, 'wrapped command includes a policy path');
        const policy = JSON.parse(await readFile(policyMatch[1], 'utf8'));
        assert.ok(!policy.filesystem.allowRead.includes(leakedScope));
      } finally {
        await hooks['tool.execute.after'](retryInput, { title: '', output: '', metadata: {} });
      }
    },
  );
});

test('permission.ask approves every apply_patch path for one call and then expires them', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: {
        allowRead: ['.'],
        allowWrite: ['.'],
        denyRead: [],
        denyWrite: [],
      },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks }) => {
      const paths = ['../outside-a.txt', '../outside-b.txt'];
      const patchText = `*** Begin Patch
*** Add File: ${paths[0]}
+one
*** Add File: ${paths[1]}
+two
*** End Patch`;
      const input = { callID: 'apply-patch-call', tool: 'apply_patch' };
      const output = { args: { patchText } };
      const permissionOutput = { status: 'allow' };

      await hooks['permission.ask'](
        {
          id: 'permission-apply-patch',
          type: 'edit',
          patterns: paths,
          callID: input.callID,
          sessionID: 'session',
          messageID: 'message',
          title: 'Apply patch',
          metadata: { filepath: paths.join(', ') },
          time: { created: 0 },
        },
        permissionOutput,
      );

      assert.equal(permissionOutput.status, 'ask');
      await hooks['tool.execute.before'](input, output);
      await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
      await assert.rejects(hooks['tool.execute.before'](input, output), /requires approval/);
    },
  );
});

test('a denyRead read asks for approval instead of hard-denying', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: {
        allowRead: [],
        allowWrite: ['.'],
        denyRead: ['/tmp/opencode-landstrip-denied'],
        denyWrite: [],
      },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks }) => {
      const filepath = '/tmp/opencode-landstrip-denied/secret.txt';
      const permissionOutput = { status: 'allow' };

      await hooks['permission.ask'](
        {
          id: 'permission-read',
          type: 'read',
          pattern: filepath,
          callID: 'read-ask',
          sessionID: 'session',
          messageID: 'message',
          title: 'Read file',
          metadata: {},
          time: { created: 0 },
        },
        permissionOutput,
      );

      // A read under denyRead prompts (allow once/session/persist or reject)
      // rather than being denied outright.
      assert.equal(permissionOutput.status, 'ask');

      // Until it is approved, the read tool still blocks the access.
      await assert.rejects(
        hooks['tool.execute.before'](
          { callID: 'read-unapproved', tool: 'read' },
          { args: { path: filepath } },
        ),
        /requires approval/,
      );
    },
  );
});

test('permission.ask can approve one bash domain for wrapping policy', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: {
        allowRead: ['.'],
        allowWrite: ['.'],
        denyRead: [],
        denyWrite: [],
      },
      network: { allowedDomains: [], deniedDomains: [] },
    },
    async ({ hooks }) => {
      const input = { callID: 'bash-domain-call', tool: 'bash' };
      const permissionOutput = { status: 'allow' };

      await hooks['permission.ask'](
        {
          id: 'permission-bash',
          type: 'bash',
          callID: input.callID,
          sessionID: 'session',
          messageID: 'message',
          title: 'Run shell command',
          metadata: { command: 'curl https://example.com' },
          time: { created: 0 },
        },
        permissionOutput,
      );

      assert.equal(permissionOutput.status, 'ask');

      try {
        const output = {
          args: {
            command: 'curl https://example.com',
            description: 'Fetch example',
          },
        };

        await hooks['tool.execute.before'](input, output);

        assert.notEqual(output.args.command, 'curl https://example.com');
        assert.equal(output.args.description, 'Fetch example (landstrip)');
      } finally {
        await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
      }
    },
  );
});

test('proxy refuses private destinations without connecting', async () => {
  let connections = 0;
  const upstream = createServer(() => {
    connections += 1;
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const address = upstream.address();
  assert.ok(address && typeof address !== 'string');

  try {
    await withPlugin(
      {
        enabled: true,
        filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
        network: { allowNetwork: false, allowedDomains: ['*'], deniedDomains: [] },
      },
      async ({ hooks }) => {
        const input = { callID: 'proxy-call', tool: 'bash' };
        const args = { command: 'curl https://example.com' };
        await hooks['tool.execute.before'](input, { args });

        const env = {};
        await hooks['shell.env'](input, { env });
        const proxyUrl = new URL(env.HTTP_PROXY);
        const port = Number(proxyUrl.port);
        const authorization = `Basic ${Buffer.from(
          `${proxyUrl.username}:${proxyUrl.password}`,
        ).toString('base64')}`;

        try {
          const unauthenticated = await new Promise((resolveResponse, rejectResponse) => {
            const socket = connect(port, '127.0.0.1', () => {
              socket.write(
                `CONNECT 127.0.0.1:${address.port} HTTP/1.1\r\nHost: 127.0.0.1:${address.port}\r\n\r\n`,
              );
            });
            let data = '';
            socket.setEncoding('utf-8');
            socket.on('data', (chunk) => {
              data += chunk;
            });
            socket.on('close', () => resolveResponse(data));
            socket.on('error', rejectResponse);
          });
          assert.match(unauthenticated, /^HTTP\/1\.1 407 Proxy Authentication Required/);

          const response = await new Promise((resolveResponse, rejectResponse) => {
            const socket = connect(port, '127.0.0.1', () => {
              socket.write(
                `CONNECT 127.0.0.1:${address.port} HTTP/1.1\r\nHost: 127.0.0.1:${address.port}\r\nProxy-Authorization: ${authorization}\r\n\r\n`,
              );
            });
            let data = '';
            socket.setEncoding('utf-8');
            socket.on('data', (chunk) => {
              data += chunk;
            });
            socket.on('close', () => resolveResponse(data));
            socket.on('error', rejectResponse);
          });

          assert.match(response, /^HTTP\/1\.1 502 Bad Gateway/);
          assert.equal(connections, 0);
        } finally {
          await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
        }
      },
    );
  } finally {
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test('deniedDomains override allowedDomains for bash permission', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
      network: {
        allowNetwork: false,
        allowedDomains: ['evil.example'],
        deniedDomains: ['evil.example'],
      },
    },
    async ({ hooks }) => {
      const permissionOutput = { status: 'allow' };
      await hooks['permission.ask'](
        {
          id: 'permission-bash',
          type: 'bash',
          callID: 'bash-call',
          sessionID: 'session',
          messageID: 'message',
          title: 'Run shell command',
          metadata: { command: 'curl https://evil.example' },
          time: { created: 0 },
        },
        permissionOutput,
      );
      assert.equal(permissionOutput.status, 'deny');
    },
  );
});

test('glob deny matches root and nested, single * stays in one segment', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: {
        allowRead: ['.'],
        allowWrite: ['.'],
        denyRead: [],
        denyWrite: ['**/.env', '*.kee'],
      },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      const denied = [
        join(tempDir, '.env'),
        join(tempDir, 'config', '.env'),
        join(tempDir, 'a.kee'),
      ];
      for (const path of denied) {
        await assert.rejects(
          hooks['tool.execute.before'](
            { callID: `write-${path}`, tool: 'write' },
            { args: { path } },
          ),
          /write access denied/,
          path,
        );
      }

      await assert.doesNotReject(
        hooks['tool.execute.before'](
          { callID: 'write-nested-kee', tool: 'write' },
          { args: { path: join(tempDir, 'sub', 'a.kee') } },
        ),
      );
    },
  );
});

test('deny overrides allow when a path matches both lists', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: {
        allowRead: ['.'],
        allowWrite: ['.'],
        denyRead: ['**/.env'],
        denyWrite: ['**/.env'],
      },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      const filepath = join(tempDir, 'config', '.env');

      const readOutput = { status: 'allow' };
      await hooks['permission.ask'](
        {
          id: 'permission-read',
          type: 'read',
          pattern: filepath,
          callID: 'read-ask',
          sessionID: 'session',
          messageID: 'message',
          title: 'Read file',
          metadata: {},
          time: { created: 0 },
        },
        readOutput,
      );
      // A read shadowed by a more specific denyRead prompts rather than being
      // silently allowed by the broader allowRead — and writes still hard-deny.
      assert.equal(readOutput.status, 'ask');
      await assert.rejects(
        hooks['tool.execute.before'](
          { callID: 'read-unapproved', tool: 'read' },
          { args: { path: filepath } },
        ),
        /requires approval/,
      );

      await assert.rejects(
        hooks['tool.execute.before'](
          { callID: 'write-call', tool: 'write' },
          { args: { path: filepath } },
        ),
        /write access denied/,
      );
    },
  );
});

test('sandbox config files are write-protected by default', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      const home = join(tempDir, 'home');
      const projectConfig = join(tempDir, '.opencode', 'sandbox.json');
      const globalConfig = join(home, '.config', 'opencode', 'sandbox.json');

      // The default denyWrite (merged in even with an empty override) keeps the
      // model from rewriting its own sandbox config through the write tool.
      for (const path of [projectConfig, globalConfig]) {
        await assert.rejects(
          hooks['tool.execute.before'](
            { callID: `write-${path}`, tool: 'write' },
            { args: { path } },
          ),
          /write access denied/,
          path,
        );
      }

      // Ordinary project files remain writable.
      await assert.doesNotReject(
        hooks['tool.execute.before'](
          { callID: 'write-notes', tool: 'write' },
          { args: { path: join(tempDir, 'notes.txt') } },
        ),
      );
    },
  );
});

test('a broad denyRead does not block reads inside an allowed project', async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [tmpdir()], denyWrite: [] },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      // tempDir lives under tmpdir(); the more specific allowRead '.' wins over
      // the broader denyRead, so project files stay readable.
      await assert.doesNotReject(
        hooks['tool.execute.before'](
          { callID: 'read-inside', tool: 'read' },
          { args: { path: join(tempDir, 'main.ts') } },
        ),
      );

      // A path outside the project but under the same denyRead needs approval:
      // an unapproved read is blocked rather than hard-denied.
      await assert.rejects(
        hooks['tool.execute.before'](
          { callID: 'read-outside', tool: 'read' },
          { args: { path: join(tmpdir(), 'opencode-landstrip-elsewhere', 'secret') } },
        ),
        /requires approval/,
      );
    },
  );
});

const linuxOnly = { skip: process.platform !== 'linux' };

async function withQueryServer(tempDir, run) {
  const shared = await import(pathToFileURL(join(tempDir, 'shared.js')).href);
  const server = createServer();
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const port = server.address().port;
  shared.writeDiscoveryPort(tempDir, port);
  try {
    await run({ shared, port });
  } finally {
    shared.removeDiscoveryFile(tempDir);
    server.close();
  }
}

test('query-response: bash wrapping injects fd 3 and stays idempotent', linuxOnly, async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      await withQueryServer(tempDir, async ({ port }) => {
        const input = { callID: 'query-a', sessionID: 'session-query-a', tool: 'bash' };
        const output = { args: { command: 'git status --short', description: 'status' } };
        try {
          await hooks['tool.execute.before'](input, output);
          const wrapped = output.args.command;

          // The server plugin must route query traps to the TUI's discovered
          // endpoint so held filesystem operations can be approved interactively.
          assert.match(wrapped, new RegExp(`/dev/tcp/127\\.0\\.0\\.1/${port}\\b`));
          assert.match(wrapped, /'--trap-fd' '3'/);
          assert.match(wrapped, /opencode-landstrip-session/);
          assert.match(wrapped, /session-query-a/);
          assert.equal(wrapped.includes(' || '), false, 'has no command retry branch');
          assert.equal(wrapped.match(/'--trap-fd'/g)?.length, 1);
          assert.equal(wrapped.match(/'-p'/g)?.length, 1);
          // The original command roundtrips cleanly into the socket branch.
          assert.ok(wrapped.includes("'-lc' 'git status --short'"));

          // Re-running the before hook must not double-wrap.
          await hooks['tool.execute.before'](input, output);
          assert.equal(output.args.command, wrapped);
          assert.equal(wrapped.match(/\/dev\/tcp/g)?.length, 1);

          // A fresh call rewraps the original command with its own session identity.
          const reuseInput = {
            callID: 'query-b',
            sessionID: 'session-query-b',
            tool: 'bash',
          };
          const reuse = {
            args: { command: wrapped, description: 'status again' },
          };
          try {
            await hooks['tool.execute.before'](reuseInput, reuse);
            assert.notEqual(reuse.args.command, wrapped);
            assert.match(reuse.args.command, /session-query-b/);
            assert.doesNotMatch(reuse.args.command, /session-query-a/);
            assert.equal(reuse.args.command.match(/\/dev\/tcp/g)?.length, 1);
            assert.equal(reuse.args.description, 'status again (landstrip)');
          } finally {
            await hooks['tool.execute.after'](reuseInput, { title: '', output: '', metadata: {} });
          }
        } finally {
          await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
        }
      });
    },
  );
});

test('query-response: missing session identity ignores the TUI endpoint', linuxOnly, async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      await withQueryServer(tempDir, async ({ port }) => {
        const input = { callID: 'query-headless', tool: 'bash' };
        const output = { args: { command: 'git status --short', description: 'status' } };
        try {
          await hooks['tool.execute.before'](input, output);
          assert.doesNotMatch(
            output.args.command,
            new RegExp(`/dev/tcp/127\\.0\\.0\\.1/${port}\\b`),
          );
          assert.doesNotMatch(output.args.command, /opencode-landstrip-session/);
        } finally {
          await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
        }
      });
    },
  );
});

test(
  'query-response: stale discovery port falls back to local trap server',
  linuxOnly,
  async () => {
    await withPlugin(
      {
        enabled: true,
        filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
        network: { allowedDomains: ['*'], deniedDomains: [] },
      },
      async ({ hooks, tempDir }) => {
        const shared = await import(pathToFileURL(join(tempDir, 'shared.js')).href);
        const staleServer = createServer();
        await new Promise((res) => staleServer.listen(0, '127.0.0.1', res));
        const stalePort = staleServer.address().port;
        shared.writeDiscoveryPort(tempDir, stalePort);
        await new Promise((res) => staleServer.close(res));

        const input = {
          callID: 'stale-discovery',
          sessionID: 'session-stale-discovery',
          tool: 'bash',
        };
        const output = { args: { command: 'git status --short', description: 'status' } };
        try {
          await hooks['tool.execute.before'](input, output);
          const wrapped = output.args.command;

          assert.match(wrapped, /'--trap-fd' '3'/);
          assert.doesNotMatch(wrapped, new RegExp(`/dev/tcp/127\\.0\\.0\\.1/${stalePort}\\b`));
          assert.match(wrapped, /\/dev\/tcp\/127\.0\.0\.1\/\d+\b/);
        } finally {
          shared.removeDiscoveryFile(tempDir);
          await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
        }
      },
    );
  },
);
test('query-response: a failing command executes only once', linuxOnly, async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      await withQueryServer(tempDir, async () => {
        await hooks.config({ shell: '/bin/sh' });
        const counter = join(tempDir, 'attempts');
        const command = `printf 'attempt\\n' >> ${JSON.stringify(counter)}; exit 17`;
        const input = {
          callID: 'single-execution',
          sessionID: 'session-single-execution',
          tool: 'bash',
        };
        const output = { args: { command, description: 'write once before failure' } };

        try {
          await hooks['tool.execute.before'](input, output);
          const { stdout: setup } = await execFileAsync(
            '/bin/bash',
            ['-c', 'eval "set -- $1"; printf %s "$3"', 'bash', output.args.command],
            { cwd: tempDir },
          );
          assert.ok(setup, 'uses a single fd-setup wrapper');
          const offlineSetup = setup.replace(/\/dev\/tcp\/127\.0\.0\.1\/\d+/, '/dev/null');
          await assert.rejects(
            execFileAsync('/bin/bash', ['-c', offlineSetup, 'bash', '/bin/sh', '-c', command], {
              cwd: tempDir,
            }),
            (error) => error?.code === 17,
          );
          assert.equal(await readFile(counter, 'utf8'), 'attempt\n');
        } finally {
          await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
        }
      });
    },
  );
});

test('query-response: recovery re-extracts the original command', linuxOnly, async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      await withQueryServer(tempDir, async () => {
        const inputA = { callID: 'recover-a', sessionID: 'session-recover', tool: 'bash' };
        const outputA = { args: { command: 'git status --short', description: 'status' } };
        await hooks['tool.execute.before'](inputA, outputA);
        const wrapped = outputA.args.command;
        // Drop the policy dir so the next pass must re-extract and re-wrap.
        await hooks['tool.execute.after'](inputA, { title: '', output: '', metadata: {} });

        const inputB = { callID: 'recover-b', sessionID: 'session-recover', tool: 'bash' };
        const outputB = { args: { command: wrapped, description: 'status' } };
        try {
          await hooks['tool.execute.before'](inputB, outputB);
          const rewrapped = outputB.args.command;

          assert.notEqual(rewrapped, wrapped, 'a fresh policy dir is generated');
          // The original command is recovered whole from the expired wrapper.
          assert.equal(rewrapped.match(/'--trap-fd'/g)?.length, 1);
          assert.ok(rewrapped.includes("'-lc' 'git status --short'"));
        } finally {
          await hooks['tool.execute.after'](inputB, { title: '', output: '', metadata: {} });
        }
      });
    },
  );
});

function readLine(socket) {
  return new Promise((resolvePromise, reject) => {
    let buffer = '';
    const onData = (chunk) => {
      buffer += chunk.toString('utf8');
      const newline = buffer.indexOf('\n');
      if (newline !== -1) {
        socket.off('data', onData);
        socket.off('error', onError);
        resolvePromise(buffer.slice(0, newline));
      }
    };
    const onError = (error) => {
      socket.off('data', onData);
      reject(error);
    };
    socket.on('data', onData);
    socket.on('error', onError);
  });
}

test('query-response: headless trap handling fails closed without hanging', linuxOnly, async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
      network: { allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks }) => {
      const input = { callID: 'trap-server', tool: 'bash' };
      const output = { args: { command: 'git status --short', description: 'status' } };
      try {
        await hooks['tool.execute.before'](input, output);
        const portMatch = output.args.command.match(/\/dev\/tcp\/127\.0\.0\.1\/(\d+)\b/);
        assert.ok(portMatch, 'wrapped command carries the trap-server port');
        const port = Number(portMatch[1]);

        const socket = connect(port, '127.0.0.1');
        await new Promise((res, rej) => {
          socket.once('connect', res);
          socket.once('error', rej);
        });
        try {
          // A path outside allowRead/allowWrite is denied. The query_id must
          // round-trip unchanged so landstrip can release the held syscall.
          socket.write(
            JSON.stringify({
              kind: 'filesystem',
              operation: 'read',
              path: '/etc/hostname',
              state: 'query',
              query_id: '42',
            }) + '\n',
          );
          assert.deepEqual(JSON.parse(await readLine(socket)), {
            query_id: '42',
            action: 'deny',
          });

          // Network queries are denied rather than left suspended.
          socket.write(
            JSON.stringify({
              kind: 'network',
              operation: 'connect',
              target: '93.184.216.34:443',
              state: 'query',
              query_id: '43',
            }) + '\n',
          );
          assert.deepEqual(JSON.parse(await readLine(socket)), {
            query_id: '43',
            action: 'deny',
          });
        } finally {
          socket.destroy();
        }
      } finally {
        await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
      }
    },
  );
});
