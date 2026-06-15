import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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

    const landstripMockDir = join(tempDir, 'node_modules', '@jarkkojs', 'landstrip');
    await mkdir(landstripMockDir, { recursive: true });
    const fakeLandstrip = join(
      mock.externalBinary ? tempDir : landstripMockDir,
      process.platform === 'win32' ? 'landstrip.cmd' : 'landstrip',
    );
    await writeFile(
      fakeLandstrip,
      process.platform === 'win32'
        ? '@echo landstrip 0.11.9\r\n'
        : '#!/bin/sh\nprintf "landstrip 0.11.9\\n"\n',
    );
    if (process.platform !== 'win32') await chmod(fakeLandstrip, 0o755);

    await writeFile(
      join(landstripMockDir, 'package.json'),
      JSON.stringify({ name: '@jarkkojs/landstrip', type: 'module', main: './index.mjs' }),
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
        /Refusing to use landstrip binary outside official @jarkkojs\/landstrip packages/,
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
