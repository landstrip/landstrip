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
