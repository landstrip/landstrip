import test from 'node:test';
import assert from 'node:assert/strict';
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

test('matchPathSpecificity ranks matching patterns by specificity', () => {
  const cwd = '/workspace/project';
  assert.equal(matchPathSpecificity('/workspace/project/src/index.ts', [], cwd), -1);
  assert.equal(matchPathSpecificity('/workspace/project/src/index.ts', ['/other'], cwd), -1);

  const broadMatch = matchPathSpecificity('/workspace/project/src/index.ts', ['/workspace'], cwd);
  const narrowMatch = matchPathSpecificity(
    '/workspace/project/src/index.ts',
    ['/workspace/project/src'],
    cwd,
  );
  assert.ok(narrowMatch > broadMatch);

  const globMatch = matchPathSpecificity('/workspace/project/.env', ['**/.env'], cwd);
  assert.ok(globMatch > 0);
});

test('matchesPathPattern checks path patterns with and without globs', () => {
  const cwd = '/workspace/project';
  assert.equal(matchesPathPattern('/workspace/project/foo.ts', ['*.ts', '*.js'], cwd), true);
  assert.equal(matchesPathPattern('/workspace/project/foo.py', ['*.ts', '*.js'], cwd), false);
  assert.equal(
    matchesPathPattern('/workspace/project/sub/test.txt', ['/workspace/project/sub'], cwd),
    true,
  );
  assert.equal(
    matchesPathPattern('/workspace/project/other/test.txt', ['/workspace/project/sub'], cwd),
    false,
  );
  assert.equal(
    matchesPathPattern('/workspace/project/[bracket]/file.txt', [{ literal: '[bracket]' }], cwd),
    true,
  );
  assert.equal(
    matchesPathPattern('/workspace/project/b/file.txt', [{ literal: '[bracket]' }], cwd),
    false,
  );
  assert.equal(
    matchesPathPattern('/workspace/project/src/index.ts', [{ glob: 'src/*.ts' }], cwd),
    true,
  );
});

test('evaluateReadAccess handles allow, deny, denyAlways, and specificity overrides', () => {
  const cwd = '/workspace/project';

  // denyReadAlways hard-denies
  const resDenyAlways = evaluateReadAccess(
    '/workspace/project/secrets/key.pem',
    {
      allowRead: ['/workspace/project'],
      denyRead: [],
      denyReadAlways: ['/workspace/project/secrets'],
    },
    { baseDirectory: cwd },
  );
  assert.equal(resDenyAlways, 'deny');

  // allowRead more specific than denyRead
  const resAllowSpecific = evaluateReadAccess(
    '/home/user/.cache/app/data',
    {
      allowRead: ['/home/user/.cache'],
      denyRead: ['/home/user'],
      denyReadAlways: [],
    },
    { baseDirectory: cwd },
  );
  assert.equal(resAllowSpecific, 'allow');

  // denyRead more specific than allowRead requires user approval (ask)
  const resDenySpecific = evaluateReadAccess(
    '/home/user/.cache/secret',
    {
      allowRead: ['/home/user'],
      denyRead: ['/home/user/.cache/secret'],
      denyReadAlways: [],
    },
    { baseDirectory: cwd },
  );
  assert.equal(resDenySpecific, 'ask');

  // requireAllowMatch returns ask if no allow pattern matches
  const resUnlisted = evaluateReadAccess(
    '/opt/other/file',
    {
      allowRead: ['/workspace/project'],
      denyRead: [],
      denyReadAlways: [],
    },
    { baseDirectory: cwd, requireAllowMatch: true },
  );
  assert.equal(resUnlisted, 'ask');
});

test('evaluateWriteAccess evaluates allow, ask, deny, and carveout tiers', () => {
  const cwd = '/workspace/project';
  const fs = {
    allowWrite: ['/workspace/project'],
    denyWrite: ['/workspace/project/node_modules', '**/*.pem'],
    denyWriteAlways: ['/workspace/project/.git'],
  };

  assert.equal(
    evaluateWriteAccess('/workspace/project/.git/config', fs, { baseDirectory: cwd }),
    'deny',
  );
  assert.equal(
    evaluateWriteAccess('/workspace/project/node_modules/pkg', fs, { baseDirectory: cwd }),
    'ask',
  );
  assert.equal(
    evaluateWriteAccess('/workspace/project/node_modules/pkg', fs, {
      baseDirectory: cwd,
      allowWriteOverrides: ['/workspace/project/node_modules/pkg'],
    }),
    'allow',
  );
  assert.equal(evaluateWriteAccess('/workspace/project/a.pem', fs, { baseDirectory: cwd }), 'ask');
  assert.equal(
    evaluateWriteAccess('/workspace/project/a.pem', fs, {
      baseDirectory: cwd,
      allowWriteOverrides: ['/workspace/project/a.pem'],
    }),
    'allow',
  );
  assert.equal(
    evaluateWriteAccess('/workspace/project/src/index.ts', fs, { baseDirectory: cwd }),
    'allow',
  );
  assert.equal(evaluateWriteAccess('/etc/passwd', fs, { baseDirectory: cwd }), 'ask');
});

test('evaluateDomainAccess and isDomainAllowed evaluate network rules correctly', () => {
  const net = {
    allowNetwork: false,
    allowedDomains: ['*.github.com', 'api.npmjs.org'],
    deniedDomains: ['secret.github.com'],
  };

  assert.equal(evaluateDomainAccess('github.com', net), 'allow');
  assert.equal(evaluateDomainAccess('gist.github.com', net), 'allow');
  assert.equal(evaluateDomainAccess('secret.github.com', net), 'deny');
  assert.equal(evaluateDomainAccess('malicious.com', net), 'ask');

  assert.equal(isDomainAllowed('gist.github.com', net), true);
  assert.equal(isDomainAllowed('secret.github.com', net), false);
  assert.equal(isDomainAllowed('malicious.com', net), false);

  const openNet = { allowNetwork: true, allowedDomains: [], deniedDomains: [] };
  assert.equal(evaluateDomainAccess('anywhere.com', openNet), 'allow');
  assert.equal(isDomainAllowed('anywhere.com', openNet), true);
});

test('isPathReadAllowed and shouldPromptForWrite work as expected', () => {
  const cwd = '/workspace/project';

  // isPathReadAllowed
  assert.equal(isPathReadAllowed('/workspace/project/file', ['/workspace'], [], cwd), true);
  assert.equal(isPathReadAllowed('/workspace/project/file', [], ['/workspace'], cwd), false);
  assert.equal(
    isPathReadAllowed('/workspace/project/file', ['/workspace/project'], ['/workspace'], cwd),
    true,
  );

  // shouldPromptForWrite
  assert.equal(shouldPromptForWrite('/workspace/project/file', [], [], cwd), true);
  assert.equal(shouldPromptForWrite('/workspace/project/file', ['/workspace'], [], cwd), false);
  assert.equal(
    shouldPromptForWrite('/workspace/project/a.pem', ['/workspace/project'], ['**/*.pem'], cwd),
    true,
  );
  assert.equal(
    shouldPromptForWrite(
      '/workspace/project/a.pem',
      ['/workspace/project', '/workspace/project/a.pem'],
      ['**/*.pem'],
      cwd,
    ),
    false,
  );
  assert.equal(shouldPromptForWrite('/other/file', ['/workspace'], [], cwd), true);
});
