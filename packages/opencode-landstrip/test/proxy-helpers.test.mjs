import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer, request as requestHttp } from 'node:http';
import {
  PROXY_ENVIRONMENT_VARIABLES,
  createProxyCredentials,
  createProxyUrl,
  createProxyEnvironment,
  startFilterProxy,
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

test('startFilterProxy enforces method allowlists, substitutes tokens per host, and serves gateway routes', async () => {
  const seen = [];
  const upstream = createHttpServer((req, res) => {
    seen.push({ url: req.url, method: req.method, auth: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = upstream.address().port;

  const proxy = await startFilterProxy({
    isDomainAllowed: (domain) => domain === 'localhost' || domain === '127.0.0.1',
    allowedMethods: ['GET'],
    headerRules: [
      {
        host: 'localhost',
        replaceTokens: { 'phantom-tok': 'real-secret' },
      },
    ],
    upstreams: {
      '/svc': {
        target: `http://localhost:${upstreamPort}/api`,
        headers: { Authorization: 'Bearer injected-gw' },
      },
    },
  });

  const callProxy = (method, path, headers = {}) =>
    new Promise((resolve, reject) => {
      const req = requestHttp(
        { host: '127.0.0.1', port: proxy.port, method, path, headers },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode));
        },
      );
      req.on('error', reject);
      req.end();
    });

  try {
    assert.equal(
      await callProxy('GET', `http://localhost:${upstreamPort}/v1`, {
        Authorization: 'Bearer phantom-tok',
      }),
      200,
    );
    assert.equal(seen[0].auth, 'Bearer real-secret');

    // Cross-host phantom token leak blocked
    assert.equal(
      await callProxy('GET', `http://127.0.0.1:${upstreamPort}/v1`, {
        Authorization: 'Bearer phantom-tok',
      }),
      403,
    );

    // Disallowed method blocked
    assert.equal(await callProxy('DELETE', `http://localhost:${upstreamPort}/v1`), 405);

    // Gateway route rewrites prefix and injects header
    assert.equal(await callProxy('GET', '/svc/items'), 200);
    assert.equal(seen[1].url, '/api/items');
    assert.equal(seen[1].auth, 'Bearer injected-gw');
  } finally {
    await proxy.stop();
    await new Promise((resolve) => upstream.close(resolve));
  }
});
