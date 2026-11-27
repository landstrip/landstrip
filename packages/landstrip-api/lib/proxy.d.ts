// SPDX-License-Identifier: Apache-2.0

export interface ProxyPortRange {
  low: number;
  high: number;
}

export interface ProxyHeaderInjectionRule {
  /**
   * Destination host pattern (exact host or `*.example.com`, never `'*'`).
   * Matched against the canonicalized upstream host.
   */
  host: string;
  /** Headers set or overwritten on matching upstream requests. */
  headers?: Readonly<Record<string, string>> | undefined;
  /**
   * Placeholder-to-secret substitutions applied only when targeting `host`.
   * Requests carrying a configured placeholder to any non-matching host or
   * `CONNECT` tunnel are rejected with `403 Forbidden`.
   */
  replaceTokens?: Readonly<Record<string, string>> | undefined;
  /**
   * Upgrade matching plain `http://<host>` proxy requests to upstream
   * `https://`.
   */
  upgradeHttps?: boolean | undefined;
  /** Optional HTTP method allowlist for this rule (case-insensitive). */
  allowedMethods?: readonly string[] | undefined;
  /** Optional custom CA bundle when upgrading or connecting over TLS. */
  ca?: string | Buffer | ReadonlyArray<string | Buffer> | undefined;
}

export interface ProxyUpstreamGateway {
  /**
   * Upstream base URL (`http://...` or `https://...`), e.g.
   * `'https://api.openai.com/v1'`. Requests to
   * `http://127.0.0.1:<proxyPort>/<prefix>/...` map to `<target>/...`.
   */
  target: string;
  /**
   * Headers set or overwritten on requests routed through this gateway prefix.
   */
  headers?: Readonly<Record<string, string>> | undefined;
  /**
   * Placeholder-to-secret substitutions scoped to this gateway route.
   * When proxy `authorization` is enabled, presenting one of a route's
   * placeholders in request headers also authorizes that loopback route.
   */
  replaceTokens?: Readonly<Record<string, string>> | undefined;
  /**
   * Optional HTTP method allowlist for this gateway route (case-insensitive).
   */
  allowedMethods?: readonly string[] | undefined;
  /** Optional custom CA bundle when `target` uses `https:`. */
  ca?: string | Buffer | ReadonlyArray<string | Buffer> | undefined;
}

export interface FilterProxyOptions {
  /** Gate for every proxied domain; may prompt interactively. */
  isDomainAllowed(domain: string): boolean | Promise<boolean>;
  /** Exact `Proxy-Authorization` header value required from clients. */
  authorization?: string | undefined;
  /** Inclusive listen port range; defaults to an ephemeral port. */
  portRange?: ProxyPortRange | undefined;
  /**
   * Global HTTP method allowlist (case-insensitive, e.g. `['GET', 'HEAD']`).
   * Rejects `CONNECT` with `405 Method Not Allowed` unless `'CONNECT'` is
   * listed.
   */
  allowedMethods?: readonly string[] | undefined;
  /** Host-scoped header/token injection and HTTPS-upgrade rules. */
  headerRules?: readonly ProxyHeaderInjectionRule[] | undefined;
  /**
   * Loopback path-prefix gateway routes
   * (`{ '/openai': { target: 'https://api.openai.com' } }`).
   */
  upstreams?: Readonly<Record<string, ProxyUpstreamGateway>> | undefined;
}

export interface FilterProxyHandle {
  port: number;
  stop(): Promise<void>;
}

export function startFilterProxy(
  options: FilterProxyOptions,
): Promise<FilterProxyHandle>;

export const PROXY_ENVIRONMENT_VARIABLES: readonly [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
];

export type ProxyEnvironmentVariable =
  (typeof PROXY_ENVIRONMENT_VARIABLES)[number];

export interface ProxyCredentials {
  token: string;
  authorization: string;
}

export function createProxyCredentials(token?: string): ProxyCredentials;

export function createProxyUrl(
  port: number,
  token?: string | null,
  host?: string,
): string;

export interface CreateProxyEnvironmentOptions {
  token?: string | null | undefined;
  host?: string | undefined;
  baseEnv?: NodeJS.ProcessEnv | undefined;
}

export function createProxyEnvironment(
  port?: number | null,
  options?: CreateProxyEnvironmentOptions,
): NodeJS.ProcessEnv;
