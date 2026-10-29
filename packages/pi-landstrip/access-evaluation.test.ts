import { describe, expect, it } from 'vitest';
import {
  matchPathSpecificity,
  matchesPathPattern,
  evaluateReadAccess,
  evaluateWriteAccess,
  evaluateDomainAccess,
  isDomainAllowed,
  isPathReadAllowed,
  shouldPromptForWrite,
} from '@landstrip/landstrip-api/shared';

describe('access evaluation helpers in pi-landstrip', () => {
  const cwd = '/workspace/project';

  it('evaluates read access tiers and specificity', () => {
    expect(
      evaluateReadAccess(
        '/workspace/project/secrets/key.pem',
        {
          allowRead: ['/workspace/project'],
          denyRead: [],
          denyReadAlways: ['/workspace/project/secrets'],
        },
        { baseDirectory: cwd },
      ),
    ).toBe('deny');

    expect(
      evaluateReadAccess(
        '/home/user/.cache/app/data',
        {
          allowRead: ['/home/user/.cache'],
          denyRead: ['/home/user'],
          denyReadAlways: [],
        },
        { baseDirectory: cwd },
      ),
    ).toBe('allow');

    expect(
      evaluateReadAccess(
        '/home/user/.cache/secret',
        {
          allowRead: ['/home/user'],
          denyRead: ['/home/user/.cache/secret'],
          denyReadAlways: [],
        },
        { baseDirectory: cwd },
      ),
    ).toBe('ask');
  });

  it('evaluates write access tiers', () => {
    const fs = {
      allowWrite: ['/workspace/project'],
      denyWrite: ['/workspace/project/node_modules', '**/*.pem'],
      denyWriteAlways: ['/workspace/project/.git'],
    };

    expect(evaluateWriteAccess('/workspace/project/.git/config', fs, { baseDirectory: cwd })).toBe(
      'deny',
    );
    expect(
      evaluateWriteAccess('/workspace/project/node_modules/pkg', fs, { baseDirectory: cwd }),
    ).toBe('ask');
    expect(
      evaluateWriteAccess('/workspace/project/node_modules/pkg', fs, {
        baseDirectory: cwd,
        allowWriteOverrides: ['/workspace/project/node_modules/pkg'],
      }),
    ).toBe('allow');
    expect(evaluateWriteAccess('/workspace/project/a.pem', fs, { baseDirectory: cwd })).toBe('ask');
    expect(
      evaluateWriteAccess('/workspace/project/a.pem', fs, {
        baseDirectory: cwd,
        allowWriteOverrides: ['/workspace/project/a.pem'],
      }),
    ).toBe('allow');
    expect(evaluateWriteAccess('/workspace/project/src/index.ts', fs, { baseDirectory: cwd })).toBe(
      'allow',
    );
    expect(evaluateWriteAccess('/etc/passwd', fs, { baseDirectory: cwd })).toBe('ask');
  });

  it('evaluates network access', () => {
    const net = {
      allowNetwork: false,
      allowedDomains: ['*.github.com', 'api.npmjs.org'],
      deniedDomains: ['secret.github.com'],
    };

    expect(evaluateDomainAccess('github.com', net)).toBe('allow');
    expect(evaluateDomainAccess('gist.github.com', net)).toBe('allow');
    expect(evaluateDomainAccess('secret.github.com', net)).toBe('deny');
    expect(evaluateDomainAccess('malicious.com', net)).toBe('ask');

    expect(isDomainAllowed('gist.github.com', net)).toBe(true);
    expect(isDomainAllowed('secret.github.com', net)).toBe(false);
  });

  it('evaluates path pattern matching and write prompt requirements', () => {
    expect(matchesPathPattern('/workspace/project/foo.ts', ['*.ts'], cwd)).toBe(true);
    expect(matchesPathPattern('/workspace/project/foo.py', ['*.ts'], cwd)).toBe(false);

    expect(
      matchPathSpecificity('/workspace/project/sub/file', ['/workspace/project/sub'], cwd),
    ).toBeGreaterThan(0);
    expect(matchPathSpecificity('/other/file', ['/workspace/project'], cwd)).toBe(-1);

    expect(isPathReadAllowed('/workspace/project/file', ['/workspace'], [], cwd)).toBe(true);
    expect(isPathReadAllowed('/workspace/project/file', [], ['/workspace'], cwd)).toBe(false);

    expect(shouldPromptForWrite('/workspace/project/file', [], [], cwd)).toBe(true);
    expect(shouldPromptForWrite('/workspace/project/file', ['/workspace'], [], cwd)).toBe(false);
    expect(
      shouldPromptForWrite('/workspace/project/a.pem', ['/workspace/project'], ['**/*.pem'], cwd),
    ).toBe(true);
    expect(
      shouldPromptForWrite(
        '/workspace/project/a.pem',
        ['/workspace/project', '/workspace/project/a.pem'],
        ['**/*.pem'],
        cwd,
      ),
    ).toBe(false);
  });
});
