import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { packageRoot, transpile } from './helper.mjs';

const execFileAsync = promisify(execFile);
const linuxOnly = { skip: process.platform !== 'linux' };

async function withPlugin(options, run) {
  const tempDir = await mkdtemp(join(tmpdir(), 'opencode-landstrip-test-'));
  const modulePath = join(tempDir, 'plugin.mjs');
  const home = join(tempDir, 'home');
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;

  try {
    await mkdir(home, { recursive: true });
    await mkdir(join(tempDir, 'node_modules', '@landstrip'), { recursive: true });
    await symlink(
      fileURLToPath(new URL('../', import.meta.resolve('@landstrip/landstrip-api'))),
      join(tempDir, 'node_modules', '@landstrip', 'landstrip-api'),
      'junction',
    );
    await writeFile(
      join(tempDir, 'shared.js'),
      transpile(await readFile(join(packageRoot, 'shared.ts'), 'utf8')),
    );
    await writeFile(
      join(tempDir, 'sandbox.json'),
      await readFile(join(packageRoot, 'sandbox.json'), 'utf8'),
    );
    await writeFile(modulePath, transpile(await readFile(join(packageRoot, 'index.ts'), 'utf8')));
    process.env.HOME = home;
    process.env.USERPROFILE = home;

    const {
      default: { server: plugin },
    } = await import(pathToFileURL(modulePath).href);
    const messages = [];
    const hooks = await plugin(
      {
        client: {
          app: { log: async (entry) => messages.push(entry.body.message) },
          tui: { showToast: async () => undefined },
        },
        directory: tempDir,
      },
      options,
    );
    await hooks.config({ shell: '/bin/sh' });
    await run({ hooks, messages, tempDir });
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    await rm(tempDir, { force: true, recursive: true });
  }
}

test('proxy authenticates requests and connects to allowed private destinations', async () => {
  let connections = 0;
  const upstreamSockets = new Set();
  const upstream = createServer((socket) => {
    connections += 1;
    upstreamSockets.add(socket);
    socket.once('close', () => upstreamSockets.delete(socket));
    socket.on('data', (chunk) => socket.write(chunk));
  });

  try {
    await new Promise((resolve, reject) => {
      upstream.once('error', reject);
      upstream.listen(0, '127.0.0.1', resolve);
    });
    const address = upstream.address();
    assert.ok(address && typeof address !== 'string');
    await withPlugin(
      {
        enabled: true,
        filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
        network: { allowNetwork: false, allowedDomains: ['*'], deniedDomains: [] },
      },
      async ({ hooks }) => {
        const input = { callID: 'proxy-call', tool: 'bash' };
        try {
          const args = { command: 'curl https://example.com' };
          await hooks['tool.execute.before'](input, { args });
          const env = {};
          await hooks['shell.env'](input, { env });
          const proxyUrl = new URL(env.HTTP_PROXY);
          const authorization = `Basic ${Buffer.from(
            `${proxyUrl.username}:${proxyUrl.password}`,
          ).toString('base64')}`;

          const unauthenticated = await new Promise((resolve, reject) => {
            const socket = connect(Number(proxyUrl.port), '127.0.0.1', () => {
              socket.write(
                `CONNECT 127.0.0.1:${address.port} HTTP/1.1\r\nHost: 127.0.0.1:${address.port}\r\n\r\n`,
              );
            });
            let data = '';
            socket.setEncoding('utf8');
            socket.setTimeout(2_000, () => socket.destroy(new Error('Proxy response timed out')));
            socket.on('data', (chunk) => {
              data += chunk;
            });
            socket.once('close', () => resolve(data));
            socket.once('error', reject);
          });
          assert.match(unauthenticated, /^HTTP\/1\.1 407 Proxy Authentication Required/);
          assert.equal(connections, 0);

          const response = await new Promise((resolve, reject) => {
            const socket = connect(Number(proxyUrl.port), '127.0.0.1', () => {
              socket.write(
                `CONNECT 127.0.0.1:${address.port} HTTP/1.1\r\nHost: 127.0.0.1:${address.port}\r\nProxy-Authorization: ${authorization}\r\n\r\n`,
              );
            });
            let data = '';
            let sent = false;
            socket.setEncoding('utf8');
            socket.setTimeout(2_000, () => socket.destroy(new Error('Proxy tunnel timed out')));
            socket.on('data', (chunk) => {
              data += chunk;
              if (!sent && data.includes('\r\n\r\n')) {
                sent = true;
                socket.write('smoke-payload');
              }
              if (data.endsWith('smoke-payload')) socket.destroy();
            });
            socket.once('close', () => resolve(data));
            socket.once('error', reject);
          });
          assert.match(response, /^HTTP\/1\.1 200 Connection Established/);
          assert.ok(response.endsWith('smoke-payload'));
          assert.equal(connections, 1);
        } finally {
          await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
        }
      },
    );
  } finally {
    for (const socket of upstreamSockets) socket.destroy();
    await new Promise((resolve, reject) =>
      upstream.close((error) => (error ? reject(error) : resolve())),
    );
  }
});

test(
  'sandbox wrapping is idempotent and a failing command executes only once',
  linuxOnly,
  async () => {
    await withPlugin(
      {
        enabled: true,
        filesystem: { allowRead: ['.'], allowWrite: ['.'], denyRead: [], denyWrite: [] },
        network: { allowNetwork: true, allowedDomains: ['*'], deniedDomains: [] },
      },
      async ({ hooks, messages, tempDir }) => {
        const counter = join(tempDir, 'attempts');
        const command = `printf 'attempt\\n' >> ${JSON.stringify(counter)}; exit 17`;
        const input = { callID: 'single-execution', tool: 'bash' };
        const output = { args: { command, description: 'write once before failure' } };

        try {
          await hooks['tool.execute.before'](input, output);
          const wrapped = output.args.command;
          assert.notEqual(wrapped, command, messages.join('\n'));
          assert.match(wrapped, /'--trap-fd' '3'/);
          await hooks['tool.execute.before'](input, output);
          assert.equal(output.args.command, wrapped);
          assert.equal(output.args.description, 'write once before failure (landstrip)');
          await assert.rejects(
            execFileAsync('/bin/bash', ['-c', wrapped], { cwd: tempDir, timeout: 10_000 }),
            (error) => error.code === 17,
          );
          assert.equal(await readFile(counter, 'utf8'), 'attempt\n');
        } finally {
          await hooks['tool.execute.after'](input, { title: '', output: '', metadata: {} });
        }
      },
    );
  },
);

test('headless sandbox denies protected file access without hanging', linuxOnly, async () => {
  await withPlugin(
    {
      enabled: true,
      filesystem: {
        allowRead: ['.'],
        allowWrite: ['.'],
        denyRead: ['protected'],
        denyWrite: ['protected'],
      },
      network: { allowNetwork: true, allowedDomains: ['*'], deniedDomains: [] },
    },
    async ({ hooks, tempDir }) => {
      await mkdir(join(tempDir, 'protected'));
      const secret = join(tempDir, 'protected', 'secret.txt');
      await writeFile(secret, 'secret stays private\n');
      const input = { callID: 'headless-denial', tool: 'bash' };
      const output = {
        args: { command: 'cat protected/secret.txt; printf changed > protected/secret.txt' },
      };
      const result = { title: '', output: '', metadata: {} };

      try {
        await hooks['tool.execute.before'](input, output);
        assert.match(output.args.command, /'--trap-fd' '3'/);
        await assert.rejects(
          execFileAsync('/bin/bash', ['-c', output.args.command], {
            cwd: tempDir,
            timeout: 10_000,
          }),
          (error) => {
            assert.equal(error.killed, false);
            assert.equal(typeof error.code, 'number');
            assert.ok(error.code > 0);
            assert.match(error.stderr, /Permission denied/);
            assert.equal(error.stdout, '');
            result.output = error.stderr;
            return true;
          },
        );
        assert.equal(await readFile(secret, 'utf8'), 'secret stays private\n');
      } finally {
        await hooks['tool.execute.after'](input, result);
      }
    },
  );
});
