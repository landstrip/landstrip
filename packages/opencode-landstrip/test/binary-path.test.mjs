import assert from 'node:assert/strict';
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

import { packageRoot, transpile } from './helper.mjs';

const require = createRequire(import.meta.url);
const apiSource = new URL('../../landstrip-api/', import.meta.url);
const apiManifest = JSON.parse(readFileSync(new URL('package.json', apiSource), 'utf8'));

function apiFixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'landstrip-binary-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const apiDir = join(root, 'node_modules', '@landstrip', 'landstrip-api');
  mkdirSync(apiDir, { recursive: true });
  writeFileSync(join(apiDir, 'package.json'), JSON.stringify(apiManifest));
  cpSync(new URL('lib/', apiSource), join(apiDir, 'lib'), { recursive: true });
  const api = require(join(apiDir, 'lib', 'index.js'));
  return { root, apiDir, api };
}

function binaryPackage(directory, name, platform = process.platform) {
  mkdirSync(join(directory, 'bin'), { recursive: true });
  writeFileSync(join(directory, 'package.json'), JSON.stringify({ name }));
  const binary = join(directory, 'bin', platform === 'win32' ? 'landstrip.exe' : 'landstrip');
  writeFileSync(binary, 'fixture binary');
  return binary;
}

function installBinary(fixture, platform = process.platform, arch = process.arch) {
  const name = fixture.api.packageName(platform, arch);
  const directory = join(fixture.apiDir, 'node_modules', name);
  return binaryPackage(directory, name, platform);
}

function linkPackage(fixture, directory) {
  const link = join(fixture.apiDir, 'node_modules', fixture.api.packageName());
  mkdirSync(dirname(link), { recursive: true });
  symlinkSync(directory, link, 'junction');
}

for (const name of Object.keys(apiManifest.optionalDependencies)) {
  const [platform, arch] = name.slice('@landstrip/landstrip-'.length).split('-');
  test(`binaryPath resolves the official ${platform}-${arch} package`, (t) => {
    const fixture = apiFixture(t);
    assert.equal(fixture.api.packageName(platform, arch), name);
    const binary = installBinary(fixture, platform, arch);
    assert.equal(fixture.api.binaryPath(platform, arch), realpathSync.native(binary));
  });
}

test('binaryPath resolves a symlinked official package', (t) => {
  const fixture = apiFixture(t);
  const directory = join(fixture.root, 'store', 'platform');
  const binary = binaryPackage(directory, fixture.api.packageName());
  linkPackage(fixture, directory);
  assert.equal(fixture.api.binaryPath(), realpathSync.native(binary));
});

test('binaryPath resolves a binary symlink to another official package', (t) => {
  const fixture = apiFixture(t);
  const binary = installBinary(fixture);
  const target = binaryPackage(join(fixture.root, 'store', 'api'), apiManifest.name);
  rmSync(binary);
  symlinkSync(target, binary, 'file');
  assert.equal(fixture.api.binaryPath(), realpathSync.native(target));
});

for (const manifest of [{ name: 'foreign-binary' }, null, '{invalid JSON']) {
  test(`binaryPath rejects foreign ownership with manifest ${JSON.stringify(manifest)}`, (t) => {
    const fixture = apiFixture(t);
    const binary = installBinary(fixture);
    const directory = join(fixture.root, 'foreign');
    const target = binaryPackage(directory, 'foreign-binary');
    writeFileSync(
      join(directory, 'package.json'),
      typeof manifest === 'string' ? manifest : JSON.stringify(manifest),
    );
    rmSync(binary);
    symlinkSync(target, binary, 'file');
    assert.throws(
      () => fixture.api.binaryPath(),
      /Refusing to use landstrip binary outside official @landstrip\/landstrip-api packages/,
    );
  });
}

test('binaryPath skips a malformed nested manifest before the official owner', (t) => {
  const fixture = apiFixture(t);
  const binary = installBinary(fixture);
  writeFileSync(join(dirname(binary), 'package.json'), '{invalid JSON');
  assert.equal(fixture.api.binaryPath(), realpathSync.native(binary));
});

test('binaryPath preserves ownership read errors', (t) => {
  const fixture = apiFixture(t);
  const binary = installBinary(fixture);
  const manifest = join(dirname(realpathSync.native(binary)), 'package.json');
  const error = Object.assign(new Error('ownership read denied'), { code: 'EACCES' });
  const fs = require('node:fs');
  const read = fs.readFileSync;
  t.mock.method(fs, 'readFileSync', (path, ...args) => {
    if (path === manifest) throw error;
    return read(path, ...args);
  });
  assert.throws(
    () => fixture.api.binaryPath(),
    (failure) => failure === error,
  );
});

test('binaryPath rejects a missing platform package', (t) => {
  const fixture = apiFixture(t);
  assert.throws(() => fixture.api.binaryPath(), /binary package .* is not installed/);
});

test('binaryPath rejects a missing binary', (t) => {
  const fixture = apiFixture(t);
  rmSync(installBinary(fixture));
  assert.throws(() => fixture.api.binaryPath(), { code: 'ENOENT' });
});

test('binaryPath rejects a directory in place of the binary', (t) => {
  const fixture = apiFixture(t);
  const binary = installBinary(fixture);
  rmSync(binary);
  mkdirSync(binary);
  assert.throws(() => fixture.api.binaryPath(), /landstrip binary not found/);
});

test('binaryPath rejects unsupported targets', (t) => {
  const fixture = apiFixture(t);
  assert.throws(
    () => fixture.api.binaryPath('unsupported', 'x64'),
    /Unsupported landstrip platform/,
  );
});

async function importShared(fixture) {
  symlinkSync(
    dirname(require.resolve('ipaddr.js/package.json')),
    join(fixture.root, 'node_modules', 'ipaddr.js'),
    'junction',
  );
  const modulePath = join(fixture.root, 'shared.mjs');
  writeFileSync(modulePath, transpile(readFileSync(join(packageRoot, 'shared.ts'), 'utf8')));
  return import(pathToFileURL(modulePath).href);
}

test('OpenCode caches the shared binary resolver result', async (t) => {
  const fixture = apiFixture(t);
  const binary = installBinary(fixture);
  const resolve = fixture.api.binaryPath;
  const resolver = t.mock.method(fixture.api, 'binaryPath', resolve);
  const shared = await importShared(fixture);
  assert.equal(shared.landstripBinaryPath(), realpathSync.native(binary));
  assert.equal(shared.landstripBinaryPath(), realpathSync.native(binary));
  assert.equal(resolver.mock.callCount(), 1);
});

test('OpenCode caches the shared binary resolver error', async (t) => {
  const fixture = apiFixture(t);
  const error = new Error('broken binary installation');
  const resolver = t.mock.method(fixture.api, 'binaryPath', () => {
    throw error;
  });
  const shared = await importShared(fixture);
  assert.throws(
    () => shared.landstripBinaryPath(),
    (failure) => failure === error,
  );
  assert.throws(
    () => shared.landstripBinaryPath(),
    (failure) => failure === error,
  );
  assert.equal(resolver.mock.callCount(), 1);
});
