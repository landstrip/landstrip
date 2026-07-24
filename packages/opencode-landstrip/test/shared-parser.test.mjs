import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

import { installLandstripMock, packageRoot, transpile } from './helper.mjs';

async function loadShared() {
  const tempDir = await mkdtemp(join(tmpdir(), 'opencode-landstrip-shared-'));
  const compiled = transpile(await readFile(join(packageRoot, 'shared.ts'), 'utf8'));

  await installLandstripMock(tempDir, 'export function binaryPath() { return ""; }');

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

test('path scopes use platform-native containment semantics', async () => {
  const { mod, cleanup } = await loadShared();
  try {
    const project = join(tmpdir(), 'opencode-landstrip-project');
    const filePath = join(project, 'src', 'file.txt');

    assert.equal(mod.pathUnderDirectory(filePath, project), true);
    assert.equal(mod.pathUnderDirectory(`${project}-other`, project), false);
    assert.equal(mod.sessionAllows(new Set([project]), filePath), true);
    assert.equal(mod.sessionScopeFor(filePath, project), project);

    if (process.platform === 'win32') {
      assert.equal(mod.pathUnderDirectory(filePath.toUpperCase(), project.toLowerCase()), true);
    }
  } finally {
    await cleanup();
  }
});

test('sandbox summary reports an unavailable landstrip binary', async () => {
  const { mod, cleanup } = await loadShared();
  try {
    const summary = mod.sandboxSummary(
      {
        enabled: true,
        network: {
          allowNetwork: false,
          allowLocalBinding: false,
          allowAllUnixSockets: false,
          allowUnixSockets: [],
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: { denyRead: [], allowRead: [], allowWrite: [], denyWrite: [] },
      },
      '/global/sandbox.json',
      '/project/sandbox.json',
    );

    assert.match(summary, /landstrip package binary: \(unavailable\)/);
  } finally {
    await cleanup();
  }
});

// Landstrip 0.17 tags filesystem/network traps with `state` ("query" vs
// "info") and a decimal-string `query_id` ("0" marks a terminal event); the
// static-profile platforms omit both. Before 0.17 `query_id` was a JSON
// number — landstrip's own deserializer rejects a numeric id when it is
// echoed back, so a stale/mismatched shape must fail to decode rather than
// be silently accepted, or an answered query would still leave the child's
// syscall suspended.
test('landstrip trap parser decodes state/query_id and the server filter', async () => {
  const { mod, cleanup } = await loadShared();
  try {
    const { decodeLandstripTrap, parseLandstripTraps } = mod;

    const query = decodeLandstripTrap({
      kind: 'filesystem',
      operation: 'write',
      path: '/a',
      state: 'query',
      query_id: '7',
    });
    assert.equal(query.state, 'query');
    assert.equal(query.query_id, '7');

    // Regression guard: a numeric query_id (the pre-0.17 shape) must fail to
    // decode rather than be accepted and later echoed back as a number.
    assert.equal(
      decodeLandstripTrap({
        kind: 'filesystem',
        operation: 'write',
        path: '/a',
        state: 'query',
        query_id: 7,
      }),
      null,
    );

    // A trap missing query_id entirely (e.g. a malformed line) also fails to
    // decode rather than being treated as a valid terminal event.
    assert.equal(decodeLandstripTrap({ kind: 'filesystem', operation: 'write', path: '/a' }), null);

    // A missing/unknown `state` degrades to "informational" rather than
    // failing to decode — the safe direction, since it is never treated as a
    // pending query that needs answering.
    const noState = decodeLandstripTrap({
      kind: 'filesystem',
      operation: 'write',
      path: '/a',
      query_id: '0',
    });
    assert.equal(noState.state, undefined);

    const info = decodeLandstripTrap({
      kind: 'filesystem',
      operation: 'read',
      path: '/b',
      state: 'info',
      query_id: '0',
    });
    assert.equal(info.state, 'info');

    const lines = [
      JSON.stringify({
        kind: 'filesystem',
        operation: 'write',
        path: '/a',
        state: 'query',
        query_id: '1',
      }),
      JSON.stringify({
        kind: 'filesystem',
        operation: 'write',
        path: '/b',
        state: 'info',
        query_id: '0',
      }),
      'not json',
    ].join('\n');
    const traps = parseLandstripTraps(lines);
    assert.equal(traps.length, 2);

    // The server toasts only terminal traps; query traps are answered live.
    const terminalOnly = traps.filter((t) => !(t.kind === 'filesystem' && t.state === 'query'));
    assert.equal(terminalOnly.length, 1);
    assert.equal(terminalOnly[0].path, '/b');
  } finally {
    await cleanup();
  }
});

// Before 0.17, landstrip's launch/usage/internal failures were plain text, so
// these decode arms never ran against real output. `internal` in particular
// changed shape (flat code/mechanism/message, not a nested `detail` bag) —
// pin the fix so a POLICY_PARSE_FAILED renders its real code instead of a
// blank "internal error".
test('formatLandstripTrap renders the new trap shapes', async () => {
  const { mod, cleanup } = await loadShared();
  try {
    const { formatLandstripTrap } = mod;

    assert.equal(
      formatLandstripTrap({
        kind: 'internal',
        code: 'POLICY_PARSE_FAILED',
        message: 'invalid policy JSON',
      }),
      'landstrip: POLICY_PARSE_FAILED: invalid policy JSON',
    );

    assert.equal(
      formatLandstripTrap({
        kind: 'internal',
        code: 'SANDBOX_SETUP_FAILED',
        mechanism: 'landlock',
        message: 'ruleset creation failed',
      }),
      'landstrip: SANDBOX_SETUP_FAILED [landlock]: ruleset creation failed',
    );

    assert.equal(
      formatLandstripTrap({
        kind: 'filesystem',
        operation: 'read',
        path: '/etc/shadow',
        mechanism: 'seccomp',
        state: 'info',
        query_id: '0',
      }),
      'landstrip: filesystem read denied (/etc/shadow) [seccomp]',
    );
  } finally {
    await cleanup();
  }
});
