import { execFileSync } from 'node:child_process';
import { createServer as createHttpServer, request as requestHttp } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { connect as connectNet, type AddressInfo } from 'node:net';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import {
  PROXY_ENVIRONMENT_VARIABLES,
  createProxyCredentials,
  createProxyUrl,
  createProxyEnvironment,
  startFilterProxy,
} from '@landstrip/landstrip-api/proxy';
import { temporaryDirectory } from './test-util.ts';

describe('proxy helpers in pi-landstrip', () => {
  it('exposes standard proxy environment variables', () => {
    expect(PROXY_ENVIRONMENT_VARIABLES).toEqual([
      'HTTP_PROXY',
      'HTTPS_PROXY',
      'ALL_PROXY',
      'http_proxy',
      'https_proxy',
      'all_proxy',
    ]);
  });

  it('generates random credentials and supports custom tokens', () => {
    const creds = createProxyCredentials();
    expect(creds.token.length).toBeGreaterThan(0);
    expect(creds.authorization.startsWith('Basic ')).toBe(true);

    const explicit = createProxyCredentials('custom-pass');
    expect(explicit.token).toBe('custom-pass');
    expect(Buffer.from(explicit.authorization.slice('Basic '.length), 'base64').toString()).toBe(
      'landstrip:custom-pass',
    );
  });

  it('formats proxy urls', () => {
    expect(createProxyUrl(8080, 'auth-token')).toBe('http://landstrip:auth-token@127.0.0.1:8080');
    expect(createProxyUrl(8080, null)).toBe('http://127.0.0.1:8080');
    expect(createProxyUrl(8080, undefined, 'localhost')).toBe('http://localhost:8080');
  });

  it('populates environment variables when proxy is active', () => {
    const base = { FOO: 'bar' };
    const populated = createProxyEnvironment(8080, { token: 'test-tok', baseEnv: base });
    expect(populated.FOO).toBe('bar');
    expect(populated.HTTP_PROXY).toBe('http://landstrip:test-tok@127.0.0.1:8080');
    expect(populated.HTTPS_PROXY).toBe('http://landstrip:test-tok@127.0.0.1:8080');
    expect(populated.ALL_PROXY).toBe('http://landstrip:test-tok@127.0.0.1:8080');
    expect(populated.http_proxy).toBe('http://landstrip:test-tok@127.0.0.1:8080');
    expect(populated.https_proxy).toBe('http://landstrip:test-tok@127.0.0.1:8080');
    expect(populated.all_proxy).toBe('http://landstrip:test-tok@127.0.0.1:8080');
    expect(populated.NO_PROXY).toBe('');
    expect(populated.no_proxy).toBe('');

    // Returns unpolluted copy when port is inactive
    const inactive = createProxyEnvironment(null, { token: 'test-tok', baseEnv: base });
    expect(inactive).toEqual(base);
    expect(inactive).not.toBe(base);
  });

  it('enforces allowedMethods on HTTP requests and CONNECT tunnels', async () => {
    const upstream = createHttpServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`ok:${req.method}`);
    });
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
    const upstreamPort = (upstream.address() as AddressInfo).port;
    const proxy = await startFilterProxy({
      isDomainAllowed: () => true,
      allowedMethods: ['get', 'HEAD'],
    });

    try {
      const sendProxyHttp = (method: string) =>
        new Promise<{ status: number; allow?: string; body: string }>((resolve, reject) => {
          const req = requestHttp(
            {
              host: '127.0.0.1',
              port: proxy.port,
              method,
              path: `http://127.0.0.1:${upstreamPort}/items`,
            },
            (res) => {
              let body = '';
              res.setEncoding('utf8');
              res.on('data', (chunk) => {
                body += chunk;
              });
              res.on('end', () => {
                resolve({
                  status: res.statusCode ?? 0,
                  allow: typeof res.headers.allow === 'string' ? res.headers.allow : undefined,
                  body,
                });
              });
            },
          );
          req.on('error', reject);
          req.end();
        });

      const getRes = await sendProxyHttp('GET');
      expect(getRes.status).toBe(200);
      expect(getRes.body).toBe('ok:GET');

      const postRes = await sendProxyHttp('POST');
      expect(postRes.status).toBe(405);
      expect(postRes.allow).toBe('GET, HEAD');

      const connectStatus = await new Promise<string>((resolve, reject) => {
        const socket = connectNet(proxy.port, '127.0.0.1', () => {
          socket.write(
            `CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`,
          );
        });
        let raw = '';
        socket.setEncoding('utf8');
        socket.on('data', (chunk) => {
          raw += chunk;
        });
        socket.on('end', () => resolve(raw.split('\r\n')[0] ?? ''));
        socket.on('error', reject);
      });
      expect(connectStatus).toContain('405 Method Not Allowed');
    } finally {
      await proxy.stop();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  });

  it('injects host-scoped headers, substitutes phantom tokens, blocks cross-host leaks, and routes loopback gateways over HTTPS', async () => {
    const dir = temporaryDirectory('landstrip-proxy-tls-');
    const keyPath = join(dir, 'key.pem');
    const certPath = join(dir, 'cert.pem');
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        keyPath,
        '-out',
        certPath,
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
      ],
      { stdio: 'ignore' },
    );
    const key = readFileSync(keyPath);
    const cert = readFileSync(certPath);

    const seenRequests: Array<{ url?: string; auth?: string; custom?: string }> = [];
    const tlsUpstream = createHttpsServer({ key, cert }, (req, res) => {
      seenRequests.push({
        url: req.url,
        auth: req.headers.authorization,
        custom:
          typeof req.headers['x-injected'] === 'string' ? req.headers['x-injected'] : undefined,
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    await new Promise<void>((resolve) => tlsUpstream.listen(0, '127.0.0.1', resolve));
    const tlsPort = (tlsUpstream.address() as AddressInfo).port;

    const creds = createProxyCredentials('proxy-pass');
    const proxy = await startFilterProxy({
      isDomainAllowed: (domain) => domain === 'localhost' || domain === '127.0.0.1',
      authorization: creds.authorization,
      headerRules: [
        {
          host: 'localhost',
          headers: { 'X-Injected': 'host-secret' },
          replaceTokens: { 'phantom-gh-token': 'ghp_real_secret_value' },
          upgradeHttps: true,
          allowedMethods: ['GET'],
          ca: cert,
        },
      ],
      upstreams: {
        '/openai': {
          target: `https://localhost:${tlsPort}/v1`,
          replaceTokens: { 'phantom-openai-key': 'sk-real-openai-key' },
          ca: cert,
        },
      },
    });

    const rawHttp = (options: {
      path: string;
      method?: string;
      headers?: Record<string, string>;
    }) =>
      new Promise<{ status: number; body: string }>((resolve, reject) => {
        const req = requestHttp(
          {
            host: '127.0.0.1',
            port: proxy.port,
            method: options.method ?? 'GET',
            path: options.path,
            headers: options.headers,
          },
          (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => {
              body += chunk;
            });
            res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
          },
        );
        req.on('error', reject);
        req.end();
      });

    try {
      // 1. Plain http://localhost:<tlsPort> upgraded to TLS with substituted token & injected header
      const upgraded = await rawHttp({
        path: `http://localhost:${tlsPort}/repos`,
        headers: {
          'Proxy-Authorization': creds.authorization,
          Authorization: 'Bearer phantom-gh-token',
        },
      });
      expect(upgraded.status).toBe(200);
      expect(seenRequests[0]).toEqual({
        url: '/repos',
        auth: 'Bearer ghp_real_secret_value',
        custom: 'host-secret',
      });

      // 2. Sending localhost's phantom token to a different host (127.0.0.1) is rejected with 403
      const leaked = await rawHttp({
        path: `http://127.0.0.1:${tlsPort}/exfil`,
        headers: {
          'Proxy-Authorization': creds.authorization,
          Authorization: 'Bearer phantom-gh-token',
        },
      });
      expect(leaked.status).toBe(403);

      // 3. Loopback gateway route (/openai/models -> https://localhost:<tlsPort>/v1/models)
      //    authorized by the route's phantom bearer token without Proxy-Authorization
      const gateway = await rawHttp({
        path: '/openai/models?limit=1',
        headers: {
          Authorization: 'Bearer phantom-openai-key',
        },
      });
      expect(gateway.status).toBe(200);
      expect(seenRequests[1]).toEqual({
        url: '/v1/models?limit=1',
        auth: 'Bearer sk-real-openai-key',
        custom: 'host-secret',
      });

      // 4. Loopback gateway without Proxy-Authorization AND without valid phantom token returns 407
      const unauthGateway = await rawHttp({
        path: '/openai/models',
      });
      expect(unauthGateway.status).toBe(407);
    } finally {
      await proxy.stop();
      await new Promise<void>((resolve) => tlsUpstream.close(() => resolve()));
    }
  });
});
