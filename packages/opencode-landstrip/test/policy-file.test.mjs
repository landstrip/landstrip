import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';

const require = createRequire(import.meta.url);
const sharedPath = require.resolve('@landstrip/landstrip-api/shared');
const { buildLandstripPolicy, serializeLandstripPolicy, writeLandstripPolicyFile } = require(
  sharedPath,
);

function freshShared(t) {
  const cached = require.cache[sharedPath];
  delete require.cache[sharedPath];
  t.after(() => {
    delete require.cache[sharedPath];
    if (cached) require.cache[sharedPath] = cached;
  });
  return require(sharedPath);
}

for (const prefix of [undefined, 'opencode-landstrip-', 'pi-landstrip-']) {
  test(`policy file preserves serialization and caller ownership (${prefix ?? 'default'})`, () => {
    const policy = buildLandstripPolicy({
      baseDirectory: '/workspace',
      filesystem: { allowRead: ['.'], denyWriteAlways: ['secrets'] },
      network: { allowNetwork: false },
      windows: { appContainerMode: 'standard', allowLoopback: true },
      httpProxyPort: 8080,
    });
    const original = structuredClone(policy);
    const file = writeLandstripPolicyFile(policy, prefix);
    try {
      assert.ok(basename(file.dir).startsWith(prefix ?? 'landstrip-'));
      assert.equal(dirname(file.dir), tmpdir());
      assert.equal(file.path, join(file.dir, 'policy.json'));
      assert.equal(fs.readFileSync(file.path, 'utf8'), serializeLandstripPolicy(policy));
      assert.deepEqual(JSON.parse(fs.readFileSync(file.path, 'utf8')), policy);
      assert.deepEqual(policy, original);
      assert.equal(fs.existsSync(file.dir), true);
    } finally {
      fs.rmSync(file.dir, { recursive: true, force: true });
    }
    assert.equal(fs.existsSync(file.dir), false);
  });
}

for (const prefix of ['opencode-landstrip-', 'pi-landstrip-']) {
  for (const partial of [false, true]) {
    test(`policy file removes directory after ${partial ? 'partial' : 'failed'} write (${prefix})`, (t) => {
      const failure = Object.assign(new Error('disk full'), { code: 'ENOSPC' });
      const realMkdtemp = fs.mkdtempSync;
      const realWrite = fs.writeFileSync;
      const realRemove = fs.rmSync;
      let dir;
      let partialFileExisted = false;
      t.after(() => {
        if (dir) realRemove(dir, { recursive: true, force: true });
      });
      t.mock.method(fs, 'mkdtempSync', (path) => {
        dir = realMkdtemp(path);
        return dir;
      });
      t.mock.method(fs, 'writeFileSync', (path, contents, encoding) => {
        if (partial) {
          realWrite(path, contents.slice(0, 10), encoding);
          partialFileExisted = fs.existsSync(path);
        }
        throw failure;
      });
      const shared = freshShared(t);
      assert.throws(
        () => shared.writeLandstripPolicyFile(buildLandstripPolicy({}), prefix),
        (error) => error === failure,
      );
      assert.ok(dir);
      assert.equal(partialFileExisted, partial);
      assert.equal(fs.existsSync(dir), false);
    });
  }
}

test('policy file propagates directory allocation failure without writing or cleanup', (t) => {
  const failure = Object.assign(new Error('permission denied'), { code: 'EACCES' });
  t.mock.method(fs, 'mkdtempSync', () => {
    throw failure;
  });
  const write = t.mock.method(fs, 'writeFileSync');
  const remove = t.mock.method(fs, 'rmSync');
  const shared = freshShared(t);
  assert.throws(
    () => shared.writeLandstripPolicyFile(buildLandstripPolicy({})),
    (error) => error === failure,
  );
  assert.equal(write.mock.calls.length, 0);
  assert.equal(remove.mock.calls.length, 0);
});

test('policy file serializes before allocating a directory', (t) => {
  const failure = new Error('serialization failed');
  const allocate = t.mock.method(fs, 'mkdtempSync');
  const shared = freshShared(t);
  const policy = {
    toJSON() {
      throw failure;
    },
  };
  assert.throws(
    () => shared.writeLandstripPolicyFile(policy),
    (error) => error === failure,
  );
  assert.equal(allocate.mock.calls.length, 0);
});

test('policy file reports both write and cleanup failures with the directory path', (t) => {
  const writeFailure = Object.assign(new Error('disk full'), { code: 'ENOSPC' });
  const cleanupFailure = Object.assign(new Error('permission denied'), { code: 'EACCES' });
  const realMkdtemp = fs.mkdtempSync;
  const realRemove = fs.rmSync;
  let dir;
  t.after(() => {
    if (dir) realRemove(dir, { recursive: true, force: true });
  });
  t.mock.method(fs, 'mkdtempSync', (path) => {
    dir = realMkdtemp(path);
    return dir;
  });
  t.mock.method(fs, 'writeFileSync', () => {
    throw writeFailure;
  });
  t.mock.method(fs, 'rmSync', () => {
    throw cleanupFailure;
  });
  const shared = freshShared(t);
  assert.throws(
    () => shared.writeLandstripPolicyFile(buildLandstripPolicy({})),
    (error) => {
      assert.ok(error instanceof AggregateError);
      assert.deepEqual(error.errors, [writeFailure, cleanupFailure]);
      assert.ok(error.message.includes(dir));
      return true;
    },
  );
});
