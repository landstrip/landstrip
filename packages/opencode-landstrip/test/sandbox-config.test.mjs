import assert from 'node:assert/strict';
import test from 'node:test';
import {
  deepMergeSandboxConfig,
  mergeArray,
  parseSandboxConfig,
} from '@landstrip/landstrip-api/shared';

test('mergeArray returns base when override is undefined or empty', () => {
  assert.deepEqual(mergeArray(['a', 'b'], undefined), ['a', 'b']);
  assert.deepEqual(mergeArray(['a', 'b'], []), ['a', 'b']);
});

test('mergeArray merges and deduplicates string arrays', () => {
  assert.deepEqual(mergeArray(['a', 'b'], ['b', 'c', 'd']), ['a', 'b', 'c', 'd']);
  assert.deepEqual(mergeArray([], ['x', 'y']), ['x', 'y']);
  assert.deepEqual(mergeArray([{ literal: '/a' }], [{ literal: '/a' }, { glob: '/b/*' }]), [
    { literal: '/a' },
    { glob: '/b/*' },
  ]);
});

test('parseSandboxConfig parses valid config and partial config', () => {
  const full = {
    enabled: true,
    shell: { readAccess: 'policy' },
    network: {
      allowNetwork: false,
      allowLocalBinding: true,
      allowAllUnixSockets: false,
      allowUnixSockets: ['/var/run/docker.sock'],
      allowedDomains: ['example.com'],
      deniedDomains: ['bad.com'],
    },
    filesystem: {
      denyRead: ['/secrets'],
      denyReadAlways: ['/etc/shadow'],
      allowRead: ['/workspace'],
      allowWrite: ['/workspace/dist'],
      denyWrite: ['/workspace/src'],
      denyWriteAlways: ['/workspace/.git'],
    },
    linux: {
      backend: 'container',
    },
    macos: {
      allowTrustd: true,
      allowMachLookup: ['com.example.service'],
      allowAppleEvents: false,
      allowPty: true,
    },
    windows: {
      appContainerMode: 'lpac',
      allowLoopback: false,
    },
  };

  const parsed = parseSandboxConfig(full);
  assert.deepEqual(parsed, full);

  const partial = {
    enabled: false,
    network: { allowNetwork: true },
  };
  assert.deepEqual(parseSandboxConfig(partial), partial);
});

test('parseSandboxConfig rejects non-objects', () => {
  assert.throws(() => parseSandboxConfig(null), /must be an object/);
  assert.throws(() => parseSandboxConfig('string'), /must be an object/);
  assert.throws(() => parseSandboxConfig(42), /must be an object/);
});

test('parseSandboxConfig rejects unknown fields', () => {
  assert.throws(
    () => parseSandboxConfig({ unknownField: true }),
    /unknown sandbox field unknownField/,
  );
  assert.throws(
    () => parseSandboxConfig({ shell: { unknown: true } }),
    /unknown sandbox field shell\.unknown/,
  );
  assert.throws(
    () => parseSandboxConfig({ network: { unknown: true } }),
    /unknown sandbox field network\.unknown/,
  );
  assert.throws(
    () => parseSandboxConfig({ filesystem: { unknown: true } }),
    /unknown sandbox field filesystem\.unknown/,
  );
  assert.throws(
    () => parseSandboxConfig({ linux: { unknown: true } }),
    /unknown sandbox field linux\.unknown/,
  );
  assert.throws(
    () => parseSandboxConfig({ macos: { unknown: true } }),
    /unknown sandbox field macos\.unknown/,
  );
  assert.throws(
    () => parseSandboxConfig({ windows: { unknown: true } }),
    /unknown sandbox field windows\.unknown/,
  );
});

test('parseSandboxConfig rejects invalid types and enums', () => {
  assert.throws(() => parseSandboxConfig({ enabled: 'true' }), /enabled must be a boolean/);
  assert.throws(
    () => parseSandboxConfig({ network: { allowNetwork: 'yes' } }),
    /network\.allowNetwork must be a boolean/,
  );
  assert.throws(
    () => parseSandboxConfig({ filesystem: { denyRead: 'not-array' } }),
    /filesystem\.denyRead must be an array of strings/,
  );
  assert.throws(
    () => parseSandboxConfig({ filesystem: { denyRead: [123] } }),
    /filesystem\.denyRead must be an array of strings/,
  );
  assert.throws(
    () => parseSandboxConfig({ shell: { readAccess: 'invalid' } }),
    /shell\.readAccess must be host or policy/,
  );
  assert.throws(
    () => parseSandboxConfig({ linux: { backend: 'invalid' } }),
    /linux\.backend must be auto, container, or machine/,
  );
  assert.throws(
    () => parseSandboxConfig({ windows: { appContainerMode: 'invalid' } }),
    /windows\.appContainerMode must be lpac or standard/,
  );
});

test('deepMergeSandboxConfig deep merges partial config into base config', () => {
  const base = {
    enabled: true,
    shell: { readAccess: 'host' },
    network: {
      allowNetwork: false,
      allowLocalBinding: true,
      allowAllUnixSockets: false,
      allowUnixSockets: ['/tmp/sock1'],
      allowedDomains: ['domain1.com'],
      deniedDomains: ['bad1.com'],
    },
    filesystem: {
      denyRead: ['/base/denyRead'],
      denyReadAlways: ['/base/denyReadAlways'],
      allowRead: ['/base/allowRead'],
      allowWrite: ['/base/allowWrite'],
      denyWrite: ['/base/denyWrite'],
      denyWriteAlways: ['/base/denyWriteAlways'],
    },
    linux: {
      backend: 'auto',
    },
    macos: {
      allowTrustd: false,
      allowMachLookup: ['com.example.one'],
      allowAppleEvents: false,
      allowPty: false,
    },
    windows: {
      appContainerMode: 'standard',
      allowLoopback: false,
    },
  };

  const overrides = {
    enabled: false,
    shell: { readAccess: 'policy' },
    network: {
      allowNetwork: true,
      allowedDomains: ['domain2.com'],
    },
    filesystem: {
      allowWrite: ['/base/overrideWrite'],
      denyWriteAlways: ['/base/overrideDenyWriteAlways'],
    },
    linux: {
      backend: 'container',
    },
    macos: {
      allowTrustd: true,
      allowMachLookup: ['com.example.two'],
    },
    windows: {
      allowLoopback: true,
    },
  };

  const merged = deepMergeSandboxConfig(base, overrides);

  assert.equal(merged.enabled, false);
  assert.equal(merged.shell?.readAccess, 'policy');
  assert.equal(merged.network.allowNetwork, true);
  assert.equal(merged.network.allowLocalBinding, true); // preserved
  assert.deepEqual(merged.network.allowedDomains, ['domain1.com', 'domain2.com']); // merged
  assert.deepEqual(merged.filesystem.allowWrite, ['/base/allowWrite', '/base/overrideWrite']); // merged
  assert.deepEqual(merged.filesystem.denyWriteAlways, [
    '/base/denyWriteAlways',
    '/base/overrideDenyWriteAlways',
  ]); // merged
  assert.deepEqual(merged.filesystem.denyRead, ['/base/denyRead']); // preserved
  assert.equal(merged.linux?.backend, 'container'); // overridden
  assert.deepEqual(merged.macos, {
    allowTrustd: true,
    allowMachLookup: ['com.example.one', 'com.example.two'],
    allowAppleEvents: false,
    allowPty: false,
  });
  assert.equal(merged.windows?.appContainerMode, 'standard'); // preserved
  assert.equal(merged.windows?.allowLoopback, true); // overridden
});
