import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

interface PackageJson {
  version: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  resolved?: string;
}

interface PackageLock extends PackageJson {
  packages: Record<string, PackageJson>;
}

function readJson<T>(url: URL): T {
  return JSON.parse(readFileSync(url, 'utf8')) as T;
}

function expectLockedPackage(lock: PackageLock, packageName: string, version: string): void {
  const lockedPackage = lock.packages[`node_modules/${packageName}`];
  expect(lockedPackage?.version).toBe(version);
  expect(lockedPackage?.resolved?.endsWith(`-${version}.tgz`)).toBe(true);
}

describe('package metadata', () => {
  it('matches the Landstrip release', () => {
    const extensionPackage = readJson<PackageJson>(new URL('./package.json', import.meta.url));
    const extensionLock = readJson<PackageLock>(new URL('./package-lock.json', import.meta.url));
    const landstripPackage = readJson<PackageJson>(new URL('../../package.json', import.meta.url));
    const version = landstripPackage.version;
    const platformDependencies = Object.keys(landstripPackage.optionalDependencies ?? {});

    expect(extensionPackage.version).toBe(version);
    expect(extensionLock.version).toBe(version);
    expect(extensionLock.packages[''].version).toBe(version);
    expect(extensionPackage.dependencies?.['@landstrip/landstrip']).toBe(`^${version}`);
    expect(extensionLock.packages[''].dependencies?.['@landstrip/landstrip']).toBe(`^${version}`);

    for (const packageName of ['@landstrip/landstrip', ...platformDependencies]) {
      expectLockedPackage(extensionLock, packageName, version);
    }
    expect(
      extensionLock.packages['node_modules/@landstrip/landstrip'].optionalDependencies,
    ).toEqual(landstripPackage.optionalDependencies);
  });
});
