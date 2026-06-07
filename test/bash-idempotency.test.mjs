import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import ts from 'typescript';

test('bash wrapping is idempotent for repeated before hooks', async () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const tempDir = await mkdtemp(join(tmpdir(), 'opencode-landstrip-test-'));
  const modulePath = join(tempDir, 'plugin.mjs');
  const home = join(tempDir, 'home');
  const originalHome = process.env.HOME;

  try {
    const source = await readFile(join(root, 'index.ts'), 'utf8');
    const compiled = ts.transpileModule(source, {
      compilerOptions: {
        module: ts.ModuleKind.ES2022,
        target: ts.ScriptTarget.ES2022,
        verbatimModuleSyntax: false,
      },
    }).outputText;

    await mkdir(home, { recursive: true });
    await writeFile(modulePath, compiled);
    process.env.HOME = home;

    const fakeLandstrip = join(
      tempDir,
      process.platform === 'win32' ? 'landstrip.cmd' : 'landstrip',
    );
    await writeFile(
      fakeLandstrip,
      process.platform === 'win32'
        ? '@echo landstrip 0.8.3\r\n'
        : '#!/bin/sh\nprintf "landstrip 0.8.3\\n"\n',
    );
    if (process.platform !== 'win32') await chmod(fakeLandstrip, 0o755);

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
      {
        enabled: true,
        filesystem: {
          allowRead: [tempDir],
          allowWrite: [tempDir],
          denyRead: [],
          denyWrite: [],
        },
        landstrip: { command: fakeLandstrip },
        network: { allowedDomains: ['*'], deniedDomains: [] },
      },
    );

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
      await hooks['tool.execute.after'](input);
    }
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    await rm(tempDir, { force: true, recursive: true });
  }
});
