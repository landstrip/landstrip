import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import ts from 'typescript';

async function loadShared() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const tempDir = await mkdtemp(join(tmpdir(), 'opencode-landstrip-shared-'));
  const compiled = ts.transpileModule(await readFile(join(root, 'shared.ts'), 'utf8'), {
    compilerOptions: {
      module: ts.ModuleKind.ES2022,
      target: ts.ScriptTarget.ES2022,
      verbatimModuleSyntax: false,
    },
  }).outputText;

  const landstripDir = join(tempDir, 'node_modules', '@jarkkojs', 'landstrip');
  await mkdir(landstripDir, { recursive: true });
  await writeFile(
    join(landstripDir, 'package.json'),
    JSON.stringify({ name: '@jarkkojs/landstrip', type: 'module', main: './index.mjs' }),
  );
  await writeFile(join(landstripDir, 'index.mjs'), 'export function binaryPath() { return ""; }');

  const modulePath = join(tempDir, 'shared.js');
  await writeFile(modulePath, compiled);

  const mod = await import(pathToFileURL(modulePath).href);
  return { mod, cleanup: () => rm(tempDir, { force: true, recursive: true }) };
}

// The server hook receives `{ type, pattern }` while the TUI receives
// `{ permission, patterns }`; both must parse identically through shared.ts.
test('shared parser agrees across server and TUI permission shapes', async () => {
  const { mod, cleanup } = await loadShared();
  try {
    const { permissionType, permissionResource, updateForPermission } = mod;

    const serverEdit = { type: 'edit', pattern: '/abs/file.txt', metadata: {} };
    const tuiEdit = { permission: 'edit', patterns: ['/abs/file.txt'], metadata: {} };
    assert.equal(permissionType(serverEdit), 'edit');
    assert.equal(permissionType(tuiEdit), 'edit');
    assert.deepEqual(updateForPermission(serverEdit), {
      filesystem: { allowWrite: ['/abs/file.txt'] },
    });
    assert.deepEqual(updateForPermission(tuiEdit), updateForPermission(serverEdit));

    const serverRead = { type: 'read', pattern: '/abs/read.txt', metadata: {} };
    const tuiRead = { permission: 'read', patterns: ['/abs/read.txt'], metadata: {} };
    assert.deepEqual(updateForPermission(serverRead), {
      filesystem: { allowRead: ['/abs/read.txt'] },
    });
    assert.deepEqual(updateForPermission(tuiRead), updateForPermission(serverRead));

    const serverBash = { type: 'bash', metadata: { command: 'curl https://example.com/x' } };
    const tuiBash = { permission: 'bash', patterns: ['curl https://example.com/x'], metadata: {} };
    assert.deepEqual(updateForPermission(serverBash), {
      network: { allowedDomains: ['example.com'] },
    });
    assert.deepEqual(updateForPermission(tuiBash), updateForPermission(serverBash));
    assert.equal(permissionResource(serverBash), 'example.com');
    assert.equal(permissionResource(tuiBash), 'example.com');

    // A bash command without a URL has nothing to persist.
    assert.equal(updateForPermission({ type: 'bash', metadata: { command: 'ls -la' } }), null);
  } finally {
    await cleanup();
  }
});
