import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PROXY_ENVIRONMENT_VARIABLES,
  createProxyCredentials,
  createProxyUrl,
  createProxyEnvironment,
} from '@landstrip/landstrip-api/proxy';

test('PROXY_ENVIRONMENT_VARIABLES contains all standard proxy environment variables', () => {
  assert.deepEqual(
    [...PROXY_ENVIRONMENT_VARIABLES],
    ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'],
  );
});

test('createProxyCredentials generates random credentials or uses custom token', () => {
  const randomCreds = createProxyCredentials();
  assert.ok(typeof randomCreds.token === 'string' && randomCreds.token.length > 0);
  assert.ok(randomCreds.authorization.startsWith('Basic '));
  const decodedRandom = Buffer.from(
    randomCreds.authorization.slice('Basic '.length),
    'base64',
  ).toString();
  assert.equal(decodedRandom, `landstrip:${randomCreds.token}`);

  const fixedCreds = createProxyCredentials('custom-secret-token');
  assert.equal(fixedCreds.token, 'custom-secret-token');
  const decodedFixed = Buffer.from(
    fixedCreds.authorization.slice('Basic '.length),
    'base64',
  ).toString();
  assert.equal(decodedFixed, 'landstrip:custom-secret-token');
});

test('createProxyUrl builds http proxy URLs with credentials and host', () => {
  assert.equal(createProxyUrl(8080, 'my-token'), 'http://landstrip:my-token@127.0.0.1:8080');
  assert.equal(createProxyUrl(9090, null), 'http://127.0.0.1:9090');
  assert.equal(createProxyUrl(9090, undefined), 'http://127.0.0.1:9090');
  assert.equal(
    createProxyUrl(8080, 'my-token', 'localhost'),
    'http://landstrip:my-token@localhost:8080',
  );
});

test('createProxyEnvironment configures environment dictionary with proxy settings', () => {
  const baseEnv = { PATH: '/bin:/usr/bin', OTHER: 'value' };
  const env = createProxyEnvironment(12345, { token: 'secret-tok', baseEnv });

  assert.equal(env.PATH, '/bin:/usr/bin');
  assert.equal(env.OTHER, 'value');
  assert.equal(env.HTTP_PROXY, 'http://landstrip:secret-tok@127.0.0.1:12345');
  assert.equal(env.HTTPS_PROXY, 'http://landstrip:secret-tok@127.0.0.1:12345');
  assert.equal(env.ALL_PROXY, 'http://landstrip:secret-tok@127.0.0.1:12345');
  assert.equal(env.http_proxy, 'http://landstrip:secret-tok@127.0.0.1:12345');
  assert.equal(env.https_proxy, 'http://landstrip:secret-tok@127.0.0.1:12345');
  assert.equal(env.all_proxy, 'http://landstrip:secret-tok@127.0.0.1:12345');
  assert.equal(env.NO_PROXY, '');
  assert.equal(env.no_proxy, '');

  // Does not mutate baseEnv
  assert.equal(baseEnv.HTTP_PROXY, undefined);

  // Inactive port returns copy of baseEnv
  const inactiveEnv = createProxyEnvironment(null, { token: 'secret-tok', baseEnv });
  assert.deepEqual(inactiveEnv, baseEnv);
  assert.notEqual(inactiveEnv, baseEnv);

  const optionsEnv = createProxyEnvironment(54321, {
    token: 'opt-token',
    host: '127.0.0.2',
    baseEnv: { USER: 'test' },
  });
  assert.equal(optionsEnv.USER, 'test');
  assert.equal(optionsEnv.HTTP_PROXY, 'http://landstrip:opt-token@127.0.0.2:54321');
  assert.equal(optionsEnv.NO_PROXY, '');
});
