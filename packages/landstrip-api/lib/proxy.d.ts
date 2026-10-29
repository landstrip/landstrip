// SPDX-License-Identifier: Apache-2.0

export interface ProxyPortRange {
  low: number;
  high: number;
}

export interface FilterProxyOptions {
  /** Gate for every proxied domain; may prompt interactively. */
  isDomainAllowed(domain: string): boolean | Promise<boolean>;
  /** Exact `Proxy-Authorization` header value required from clients. */
  authorization?: string;
  /** Inclusive listen port range; defaults to an ephemeral port. */
  portRange?: ProxyPortRange;
}

export interface FilterProxyHandle {
  port: number;
  stop(): Promise<void>;
}

export function startFilterProxy(options: FilterProxyOptions): Promise<FilterProxyHandle>;

export const PROXY_ENVIRONMENT_VARIABLES: readonly [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
];

export type ProxyEnvironmentVariable = (typeof PROXY_ENVIRONMENT_VARIABLES)[number];

export interface ProxyCredentials {
  token: string;
  authorization: string;
}

export function createProxyCredentials(token?: string): ProxyCredentials;

export function createProxyUrl(port: number, token?: string | null, host?: string): string;

export interface CreateProxyEnvironmentOptions {
  token?: string | null | undefined;
  host?: string | undefined;
  baseEnv?: NodeJS.ProcessEnv | undefined;
}

export function createProxyEnvironment(
  port?: number | null,
  options?: CreateProxyEnvironmentOptions,
): NodeJS.ProcessEnv;
