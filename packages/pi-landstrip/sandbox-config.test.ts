import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import {
  deepMergeSandboxConfig,
  parseSandboxConfig,
  type SandboxConfig as BaseSandboxConfig,
  type SandboxConfigFile,
} from '@landstrip/landstrip-api/shared';
import {
  buildLandstripRunArgs,
  formatSandboxPromptGuidelines,
  type SandboxConfig,
} from './index.ts';

describe('sandbox config in pi-landstrip', () => {
  it('parses bundled sandbox.json correctly', () => {
    const raw = JSON.parse(
      readFileSync(new URL('./sandbox.json', import.meta.url), 'utf8'),
    ) as unknown;
    const parsed = parseSandboxConfig(raw);

    expect(parsed.enabled).toBe(true);
    expect(parsed.shell?.readAccess).toBe('host');
    expect(parsed.network?.allowNetwork).toBe(false);
    expect(parsed.filesystem?.allowRead).toContain('.');
    expect(parsed.filesystem?.denyWrite).toContain('**/.env');
    expect(parsed.linux?.backend).toBe('auto');
    expect(parsed.windows?.appContainerMode).toBe('standard');
  });

  it('deep merges configuration overrides', () => {
    const base: BaseSandboxConfig = {
      enabled: true,
      shell: { readAccess: 'host' },
      network: {
        allowNetwork: false,
        allowLocalBinding: false,
        allowAllUnixSockets: false,
        allowUnixSockets: ['/tmp/sock1'],
        allowedDomains: ['example.com'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: ['/Users'],
        denyReadAlways: [],
        allowRead: ['.'],
        allowWrite: ['.'],
        denyWrite: ['**/.env'],
        denyWriteAlways: [],
      },
      linux: {
        backend: 'auto',
      },
      windows: {
        appContainerMode: 'standard',
        allowLoopback: false,
      },
    };

    const overrides: SandboxConfigFile = {
      network: {
        allowedDomains: ['api.example.com'],
      },
      filesystem: {
        denyWriteAlways: ['/etc/passwd'],
      },
      shell: {
        readAccess: 'policy',
      },
      linux: {
        backend: 'container',
      },
    };

    const merged = deepMergeSandboxConfig(base, overrides);
    expect(merged.enabled).toBe(true);
    expect(merged.shell?.readAccess).toBe('policy');
    expect(merged.network.allowedDomains).toEqual(['example.com', 'api.example.com']);
    expect(merged.filesystem.denyWriteAlways).toEqual(['/etc/passwd']);
    expect(merged.linux?.backend).toBe('container');
  });

  it('formats 3-line sandbox boundary prompt guidelines', () => {
    const baseConfig: SandboxConfig = {
      enabled: true,
      shell: { readAccess: 'host' },
      network: {
        allowNetwork: false,
        allowLocalBinding: false,
        allowAllUnixSockets: false,
        allowUnixSockets: [],
        allowedDomains: ['api.github.com'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: ['/home'],
        denyReadAlways: ['~/.ssh/id_ed25519'],
        allowRead: ['.'],
        allowWrite: ['.', '/dev/null'],
        denyWrite: ['**/.env'],
        denyWriteAlways: ['**/*.pem'],
      },
      linux: {
        backend: 'auto',
      },
      windows: {
        appContainerMode: 'standard',
        allowLoopback: false,
      },
    };

    const lines = formatSandboxPromptGuidelines(baseConfig, {
      allowWrite: ['/tmp/stage'],
      domains: ['registry.npmjs.org'],
    });
    expect(lines).toHaveLength(3);
    expect(lines[0]).toContain('allowed only in ., /dev/null, /tmp/stage');
    expect(lines[0]).toContain('denied for **/.env, **/*.pem');
    expect(lines[1]).toContain('except ~/.ssh/id_ed25519');
    expect(lines[2]).toContain('api.github.com, registry.npmjs.org');

    expect(formatSandboxPromptGuidelines({ ...baseConfig, enabled: false })).toEqual([]);
  });

  it('builds landstrip run arguments with Linux backend overrides', () => {
    expect(
      buildLandstripRunArgs('/tmp/policy.json', '/bin/sh', ['-c', 'true'], {
        linuxBackend: 'auto',
        trapFd: 3,
        platform: 'linux',
      }),
    ).toEqual(['run', '-p', '/tmp/policy.json', '--trap', '3', '--', '/bin/sh', '-c', 'true']);

    expect(
      buildLandstripRunArgs('/tmp/policy.json', '/bin/sh', ['-c', 'true'], {
        linuxBackend: 'container',
        inheritFd: 4,
        trapFd: 3,
        platform: 'linux',
      }),
    ).toEqual([
      'run',
      '-p',
      '/tmp/policy.json',
      '--backend',
      'container',
      '--inherit',
      '4',
      '--trap',
      '3',
      '--',
      '/bin/sh',
      '-c',
      'true',
    ]);

    expect(
      buildLandstripRunArgs('/tmp/policy.json', '/bin/sh', ['-c', 'true'], {
        linuxBackend: 'machine',
        trapFd: 3,
        platform: 'darwin',
      }),
    ).toEqual(['run', '-p', '/tmp/policy.json', '--trap', '3', '--', '/bin/sh', '-c', 'true']);
  });
});
