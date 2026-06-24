import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import ts from 'typescript';

async function withPlugin(options, run, mock = {}) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const tempDir = await mkdtemp(join(tmpdir(), 'opencode-landstrip-test-'));
  const modulePath = join(tempDir, 'plugin.mjs');
  const home = join(tempDir, 'home');
  const originalHome = process.env.HOME;

  const transpile = (text) =>
    ts.transpileModule(text, {
      compilerOptions: {
        module: ts.ModuleKind.ES2022,
        target: ts.ScriptTarget.ES2022,
        verbatimModuleSyntax: false,
      },
    }).outputText;

  try {
    const compiled = transpile(await readFile(join(root, 'index.ts'), 'utf8'));
    const sharedCompiled = transpile(await readFile(join(root, 'shared.ts'), 'utf8'));

    await mkdir(home, { recursive: true });
    await writeFile(join(tempDir, 'shared.js'), sharedCompiled);
    await writeFile(modulePath, compiled);
    process.env.HOME = home;

    const landstripMockDir = join(tempDir, 'node_modules', '@landstrip', 'landstrip');
    await mkdir(landstripMockDir, { recursive: true });
    const fakeLandstrip = join(
      mock.externalBinary ? tempDir : landstripMockDir,
      process.platform === 'win32' ? 'landstrip.cmd' : 'landstrip',
    );
    await writeFile(
      fakeLandstrip,
      process.platform === 'win32'
        ? '@echo landstrip 0.16.4\r\n'
        : '#!/bin/sh\nprintf "landstrip 0.16.4\\n"\n',
    );
    if (process.platform !== 'win32') await chmod(fakeLandstrip, 0o755);

    await writeFile(
      join(landstripMockDir, 'package.json'),
      JSON.stringify({ name: '@landstrip/landstrip', type: 'module', main: './index.mjs' }),
    );
    await writeFile(
      join(landstripMockDir, 'index.mjs'),
      `export function binaryPath() { return ${JSON.stringify(fakeLandstrip)}; }`,
    );

    const { default: plugin } = await import(pathToFileURL(modulePath).href);
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
        assert.equal(wrapped.match(/'-p'/g)?.length, 1);
      } finally {
        await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
      }
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

      await hooks['tool.execute.before']({ callID: 'external-binary-call', tool: 'bash' }, output);

      assert.equal(output.args.command, 'git status --short');
      assert.match(
        messages.join('\n'),
        /Refusing to use landstrip binary outside official @landstrip\/landstrip packages/,
      );
    },
    { externalBinary: true },
  );
});

test('permission.ask can approve one edit call outside allowWrite', async () => {
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
    async ({ hooks, tempDir }) => {
      const filepath = resolve(tempDir, '..', 'outside.txt');
      const permissionOutput = { status: 'allow' };

      await hooks['permission.ask'](
        {
          id: 'permission-edit',
          type: 'edit',
          callID: 'edit-call',
          sessionID: 'session',
          messageID: 'message',
          title: 'Edit file',
          metadata: { filepath },
          time: { created: 0 },
        },
        permissionOutput,
      );

      assert.equal(permissionOutput.status, 'ask');
      await hooks['tool.execute.before'](
        { callID: 'edit-call', tool: 'edit' },
        { args: { path: filepath } },
      );
    },
  );
});

test('permission.ask deny is not remembered as a read allowance', async () => {
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
          callID: 'read-call',
          sessionID: 'session',
          messageID: 'message',
          title: 'Read file',
          metadata: {},
          time: { created: 0 },
        },
        permissionOutput,
      );

      assert.equal(permissionOutput.status, 'deny');
      await assert.rejects(
        hooks['tool.execute.before'](
          { callID: 'read-call', tool: 'read' },
          { args: { path: filepath } },
        ),
        /read access denied/,
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

test('proxy answers 502 instead of crashing when upstream is unreachable', async () => {
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
      const port = Number(new URL(env.HTTP_PROXY).port);

      try {
        const response = await new Promise((resolveResponse, rejectResponse) => {
          const socket = connect(port, '127.0.0.1', () => {
            socket.write('CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n');
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
      } finally {
        await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
      }
    },
  );
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
          callID: 'read-call',
          sessionID: 'session',
          messageID: 'message',
          title: 'Read file',
          metadata: {},
          time: { created: 0 },
        },
        readOutput,
      );
      assert.equal(readOutput.status, 'deny');
      await assert.rejects(
        hooks['tool.execute.before'](
          { callID: 'read-call', tool: 'read' },
          { args: { path: filepath } },
        ),
        /read access denied/,
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

      // A path outside the project but under the same denyRead stays blocked.
      await assert.rejects(
        hooks['tool.execute.before'](
          { callID: 'read-outside', tool: 'read' },
          { args: { path: join(tmpdir(), 'opencode-landstrip-elsewhere', 'secret') } },
        ),
        /read access denied/,
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
        const input = { callID: 'query-a', tool: 'bash' };
        const output = { args: { command: 'git status --short', description: 'status' } };
        try {
          await hooks['tool.execute.before'](input, output);
          const wrapped = output.args.command;

          assert.match(wrapped, new RegExp(`/dev/tcp/127\\.0\\.0\\.1/${port}\\b`));
          assert.match(wrapped, /'--trap-fd' '3'/);
          assert.ok(wrapped.includes(' || '), 'has the plain fallback branch');
          // Two --trap-fd (native /dev/tcp + bash -c fallback), three -p (both
          // trapped branches + plain fallback).
          assert.equal(wrapped.match(/'--trap-fd'/g)?.length, 2);
          assert.equal(wrapped.match(/'-p'/g)?.length, 3);
          // The original command roundtrips cleanly into the socket branch.
          assert.ok(wrapped.includes("'-lc' 'git status --short'"));

          // Re-running the before hook must not double-wrap.
          await hooks['tool.execute.before'](input, output);
          assert.equal(output.args.command, wrapped);
          assert.equal(wrapped.match(/\/dev\/tcp/g)?.length, 2);

          // A fresh call receiving the wrapped command (policy dir still present)
          // is recognized as already-generated and left intact.
          const reuse = {
            args: { command: wrapped, description: 'status again' },
          };
          await hooks['tool.execute.before']({ callID: 'query-b', tool: 'bash' }, reuse);
          assert.equal(reuse.args.command, wrapped);
          assert.equal(reuse.args.description, 'status again (landstrip)');
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
        const inputA = { callID: 'recover-a', tool: 'bash' };
        const outputA = { args: { command: 'git status --short', description: 'status' } };
        await hooks['tool.execute.before'](inputA, outputA);
        const wrapped = outputA.args.command;
        // Drop the policy dir so the next pass must re-extract and re-wrap.
        await hooks['tool.execute.after'](inputA, { title: '', output: '', metadata: {} });

        const inputB = { callID: 'recover-b', tool: 'bash' };
        const outputB = { args: { command: wrapped, description: 'status' } };
        try {
          await hooks['tool.execute.before'](inputB, outputB);
          const rewrapped = outputB.args.command;

          assert.notEqual(rewrapped, wrapped, 'a fresh policy dir is generated');
          // Extraction stopped at `||`: the original command is recovered whole,
          // not folded together with the old plain fallback branch.
          assert.equal(rewrapped.match(/'--trap-fd'/g)?.length, 2);
          assert.ok(rewrapped.includes("'-lc' 'git status --short'"));
        } finally {
          await hooks['tool.execute.after'](inputB, { title: '', output: '', metadata: {} });
        }
      });
    },
  );
});
