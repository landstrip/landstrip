import assert from 'node:assert/strict';
import { copyFile, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { join } from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

import { packageRoot, readLine, transpile } from './helper.mjs';

const linuxOnly = { skip: process.platform !== 'linux' };

function restoreEnv(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

async function withTui(run) {
  const directory = await mkdtemp(join(packageRoot, '.tui-query-test-'));
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  const originalRuntimeDir = process.env.XDG_RUNTIME_DIR;
  const disposers = [];

  try {
    process.env.HOME = directory;
    process.env.USERPROFILE = directory;
    process.env.XDG_RUNTIME_DIR = directory;

    await writeFile(
      join(directory, 'tui.js'),
      transpile(await readFile(join(packageRoot, 'tui.ts'), 'utf8')),
    );
    await writeFile(
      join(directory, 'shared.js'),
      transpile(await readFile(join(packageRoot, 'shared.ts'), 'utf8')),
    );
    await copyFile(join(packageRoot, 'sandbox.json'), join(directory, 'sandbox.json'));

    const [{ tui }, shared] = await Promise.all([
      import(pathToFileURL(join(directory, 'tui.js')).href),
      import(pathToFileURL(join(directory, 'shared.js')).href),
    ]);
    const session = { id: 'root', directory };
    const api = {
      attention: { notify: async () => undefined },
      event: { on: () => () => undefined },
      keymap: { registerLayer: () => () => undefined },
      kv: { get: () => true, set: () => undefined },
      lifecycle: { onDispose: (dispose) => disposers.push(dispose) },
      mode: { push: () => () => undefined },
      route: { current: { name: 'session', params: { sessionID: session.id } } },
      slots: { register: () => undefined },
      state: {
        path: { directory },
        session: {
          get: (sessionID) => (sessionID === session.id ? session : undefined),
          permission: () => [],
        },
      },
      ui: { toast: () => undefined },
    };

    await tui(
      api,
      {
        enabled: true,
        filesystem: { allowWrite: ['**'], denyWrite: ['protected'] },
      },
      { state: 'loaded' },
    );

    let port = null;
    for (let attempt = 0; attempt < 100 && port === null; attempt += 1) {
      port = shared.readDiscoveryPort(directory);
      if (port === null) await delay(10);
    }
    assert.notEqual(port, null, 'TUI trap server did not publish its port');
    await run({ directory, port });
  } finally {
    for (const dispose of disposers.reverse()) dispose();
    restoreEnv('HOME', originalHome);
    restoreEnv('USERPROFILE', originalUserProfile);
    restoreEnv('XDG_RUNTIME_DIR', originalRuntimeDir);
    await delay(10);
    await rm(directory, { force: true, recursive: true });
  }
}

test('TUI denies an explicit denyWrite match without prompting', linuxOnly, async () => {
  await withTui(async ({ directory, port }) => {
    const socket = connect(port, '127.0.0.1');
    await new Promise((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });

    try {
      socket.write(
        JSON.stringify({ kind: 'opencode-landstrip-session', sessionID: 'root' }) + '\n',
      );
      const deniedPath = join(directory, 'protected', 'secret.txt');
      socket.write(
        JSON.stringify({
          kind: 'filesystem',
          code: 'FILESYSTEM_DENIED',
          state: 'query',
          query_id: 'hard-deny',
          operation: 'write',
          path: deniedPath,
          requested_path: deniedPath,
          syscall: 'openat',
          errno: 'EACCES',
          flags: ['O_WRONLY'],
          reason: 'deny_match',
          suggested_grant: { allowWrite: deniedPath },
          process: { pid: process.pid, exe: null, cwd: directory },
          mechanism: 'seccomp',
        }) + '\n',
      );

      assert.deepEqual(JSON.parse(await readLine(socket)), {
        query_id: 'hard-deny',
        action: 'deny',
      });
    } finally {
      socket.destroy();
    }
  });
});
