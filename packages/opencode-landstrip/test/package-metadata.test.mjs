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
  const landstripPackage = readJson(new URL('../../landstrip/package.json', import.meta.url));
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

test('registers the Landstrip pane without intercepting commands', () => {
  const tuiSource = readFileSync(new URL('../tui.ts', import.meta.url), 'utf8');
  const serverSource = readFileSync(new URL('../index.ts', import.meta.url), 'utf8');

  assert.match(tuiSource, /slash: \{ name: 'landstrip' \}/);
  assert.doesNotMatch(tuiSource, /slash: \{ name: 'sandbox' \}/);
  assert.doesNotMatch(tuiSource, /DialogConfirm|ui\.dialog/);
  assert.match(tuiSource, /app: \(\) => jsx\(LandstripPane/);
  assert.match(tuiSource, /position: 'absolute',[\s\S]*bottom: 0,[\s\S]*left: 0,[\s\S]*right: 0/);
  assert.match(tuiSource, /width: 22, children: label/);
  assert.match(tuiSource, /Disable the sandbox\? Commands will run without OS isolation\./);
  assert.doesNotMatch(serverSource, /'command\.execute\.before'/);
});
