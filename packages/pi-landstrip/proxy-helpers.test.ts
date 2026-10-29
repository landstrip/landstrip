import { describe, expect, it } from 'vitest';
import {
  PROXY_ENVIRONMENT_VARIABLES,
  createProxyCredentials,
  createProxyUrl,
  createProxyEnvironment,
} from '@landstrip/landstrip-api/proxy';

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
});
