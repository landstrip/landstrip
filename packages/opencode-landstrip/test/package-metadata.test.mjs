import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

function readJson(url) {
  return JSON.parse(readFileSync(url, 'utf8'));
}

function assertLockedPackage(lock, packageName, version) {
  const lockedPackage = lock.packages[`node_modules/${packageName}`];
  assert.equal(lockedPackage?.version, version);
  assert.equal(lockedPackage?.resolved?.endsWith(`-${version}.tgz`), true);
}

test('package metadata matches the Landstrip release', () => {
  const extensionPackage = readJson(new URL('../package.json', import.meta.url));
  const extensionLock = readJson(new URL('../package-lock.json', import.meta.url));
  const landstripPackage = readJson(new URL('../../../package.json', import.meta.url));
  const version = landstripPackage.version;
  const platformDependencies = Object.keys(landstripPackage.optionalDependencies ?? {});

  assert.equal(extensionPackage.version, version);
  assert.equal(extensionLock.version, version);
  assert.equal(extensionLock.packages[''].version, version);
  assert.equal(extensionPackage.dependencies?.['@landstrip/landstrip'], `^${version}`);
  assert.equal(extensionLock.packages[''].dependencies?.['@landstrip/landstrip'], `^${version}`);

  for (const packageName of ['@landstrip/landstrip', ...platformDependencies]) {
    assertLockedPackage(extensionLock, packageName, version);
  }
  assert.deepEqual(
    extensionLock.packages['node_modules/@landstrip/landstrip'].optionalDependencies,
    landstripPackage.optionalDependencies,
  );
});
