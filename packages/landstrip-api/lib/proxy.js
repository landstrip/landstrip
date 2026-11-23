// SPDX-License-Identifier: Apache-2.0
'use strict';

const { randomBytes } = require('node:crypto');

const { lookup } = require('node:dns/promises');
const { Agent, createServer: createHttpServer, request: requestHttp } = require('node:http');
const { Agent: HttpsAgent, request: requestHttps } = require('node:https');
const { connect, isIP } = require('node:net');
const { pipeline } = require('node:stream');
const { connect: connectTls } = require('node:tls');

const { canonicalizeHost, domainMatchesPattern } = require('./shared');

function parseProxyPort(value, defaultPort) {
  const rawPort = value ?? String(defaultPort);
  if (!/^\d+$/.test(rawPort)) return null;

  const port = Number(rawPort);
  return port >= 1 && port <= 65535 ? port : null;
}

function splitHostPort(target) {
  if (/\s|[\u0000-\u001f\u007f]/.test(target) || /[/?#\\]/.test(target)) return null;

  let url;
  try {
    url = new URL(`connect://${target}`);
  } catch {
    return null;
  }

  if (url.username || url.password || url.pathname || url.search || url.hash || !url.port) {
    return null;
  }

  const host = canonicalizeHost(url.hostname);
  const port = parseProxyPort(url.port, 0);
  if (!host || port === null) return null;
  return { host, port };
}

const proxyAuthenticateChallenge = 'Basic realm="landstrip"';
const httpTokenPattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const forbiddenInjectedHeaders = new Set([
  'connection',
  'content-length',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function normalizeMethodAllowlist(methods, label) {
  if (methods === undefined) return null;
  if (!Array.isArray(methods) || methods.length === 0) {
    throw new TypeError(`${label} must be a non-empty array of HTTP methods`);
  }
  const normalized = new Set();
  for (const method of methods) {
    if (typeof method !== 'string' || !httpTokenPattern.test(method)) {
      throw new TypeError(`${label} contains an invalid HTTP method`);
    }
    normalized.add(method.toUpperCase());
  }
  return {
    set: normalized,
    allowHeader: [...normalized].join(', '),
  };
}

function normalizeInjectedHeaders(headers, label) {
  if (headers === undefined) return [];
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new TypeError(`${label} must be an object`);
  }
  const entries = [];
  for (const [name, value] of Object.entries(headers)) {
    if (!httpTokenPattern.test(name)) {
      throw new TypeError(`${label} contains an invalid header name: ${name}`);
    }
    const lower = name.toLowerCase();
    if (forbiddenInjectedHeaders.has(lower)) {
      throw new TypeError(`${label} cannot override hop-by-hop or host header: ${name}`);
    }
    if (typeof value !== 'string' || /[\r\n\u0000]/.test(value)) {
      throw new TypeError(`${label} header "${name}" must be a single-line string`);
    }
    entries.push([lower, value]);
  }
  return entries;
}

function normalizeTokenReplacements(replaceTokens, label) {
  if (replaceTokens === undefined) return new Map();
  if (!replaceTokens || typeof replaceTokens !== 'object' || Array.isArray(replaceTokens)) {
    throw new TypeError(`${label} must be an object`);
  }
  const map = new Map();
  for (const [placeholder, secret] of Object.entries(replaceTokens)) {
    if (typeof placeholder !== 'string' || placeholder.length === 0 || /[\r\n\u0000]/.test(placeholder)) {
      throw new TypeError(`${label} placeholder must be a non-empty single-line string`);
    }
    if (typeof secret !== 'string' || /[\r\n\u0000]/.test(secret)) {
      throw new TypeError(`${label} replacement must be a single-line string`);
    }
    map.set(placeholder, secret);
  }
  return map;
}

function validateHostRulePattern(pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern === '*') {
    throw new TypeError('headerRules[].host must be a specific host or *.domain pattern');
  }
  if (pattern.startsWith('*.')) {
    if (!canonicalizeHost(pattern.slice(2))) {
      throw new TypeError(`Invalid headerRules host pattern: ${pattern}`);
    }
    return pattern;
  }
  const canonical = canonicalizeHost(pattern);
  if (!canonical) {
    throw new TypeError(`Invalid headerRules host: ${pattern}`);
  }
  return canonical;
}

function normalizeHeaderRules(headerRules) {
  if (headerRules === undefined) return [];
  if (!Array.isArray(headerRules)) {
    throw new TypeError('headerRules must be an array');
  }
  return headerRules.map((rule, index) => {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      throw new TypeError(`headerRules[${index}] must be an object`);
    }
    return {
      host: validateHostRulePattern(rule.host),
      headers: normalizeInjectedHeaders(rule.headers, `headerRules[${index}].headers`),
      replaceTokens: normalizeTokenReplacements(
        rule.replaceTokens,
        `headerRules[${index}].replaceTokens`,
      ),
      upgradeHttps: Boolean(rule.upgradeHttps),
      allowedMethods: normalizeMethodAllowlist(
        rule.allowedMethods,
        `headerRules[${index}].allowedMethods`,
      ),
      ca: rule.ca,
    };
  });
}

function normalizeGatewayPrefix(rawPrefix) {
  if (typeof rawPrefix !== 'string' || !rawPrefix.startsWith('/') || /[\s?#\\]/.test(rawPrefix)) {
    throw new TypeError(`Invalid upstream gateway prefix: ${rawPrefix}`);
  }
  if (rawPrefix === '/') return '/';
  const trimmed = rawPrefix.replace(/\/+$/, '');
  return trimmed || '/';
}

function normalizeUpstreams(upstreams) {
  if (upstreams === undefined) return [];
  if (!upstreams || typeof upstreams !== 'object' || Array.isArray(upstreams)) {
    throw new TypeError('upstreams must be an object');
  }
  const routes = [];
  const seenPrefixes = new Set();
  for (const [rawPrefix, config] of Object.entries(upstreams)) {
    const prefix = normalizeGatewayPrefix(rawPrefix);
    if (seenPrefixes.has(prefix)) {
      throw new TypeError(`Duplicate upstream gateway prefix: ${prefix}`);
    }
    seenPrefixes.add(prefix);
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new TypeError(`upstreams["${rawPrefix}"] must be an object`);
    }
    if (typeof config.target !== 'string') {
      throw new TypeError(`upstreams["${rawPrefix}"].target must be a URL string`);
    }
    let targetUrl;
    try {
      targetUrl = new URL(config.target);
    } catch {
      throw new TypeError(`Invalid upstream target URL: ${config.target}`);
    }
    if (
      (targetUrl.protocol !== 'http:' && targetUrl.protocol !== 'https:') ||
      targetUrl.username ||
      targetUrl.password ||
      targetUrl.search ||
      targetUrl.hash
    ) {
      throw new TypeError(
        `Invalid upstream target URL (must be http/https without credentials, query, or hash): ${config.target}`,
      );
    }
    const host = canonicalizeHost(targetUrl.hostname);
    if (!host) {
      throw new TypeError(`Invalid upstream target host: ${targetUrl.hostname}`);
    }
    const defaultPort = targetUrl.protocol === 'https:' ? 443 : 80;
    const port = parseProxyPort(targetUrl.port || undefined, defaultPort);
    if (port === null) {
      throw new RangeError(`Invalid upstream target port: ${targetUrl.port}`);
    }
    const basePath = targetUrl.pathname === '/' ? '' : targetUrl.pathname.replace(/\/+$/, '');
    routes.push({
      prefix,
      protocol: targetUrl.protocol,
      host,
      port,
      basePath,
      headers: normalizeInjectedHeaders(config.headers, `upstreams["${rawPrefix}"].headers`),
      replaceTokens: normalizeTokenReplacements(
        config.replaceTokens,
        `upstreams["${rawPrefix}"].replaceTokens`,
      ),
      allowedMethods: normalizeMethodAllowlist(
        config.allowedMethods,
        `upstreams["${rawPrefix}"].allowedMethods`,
      ),
      ca: config.ca,
    });
  }
  routes.sort((left, right) => right.prefix.length - left.prefix.length);
  return routes;
}

function joinGatewayPath(basePath, suffix) {
  const normalizedSuffix = suffix ? (suffix.startsWith('/') ? suffix : `/${suffix}`) : '';
  const joined = `${basePath}${normalizedSuffix}`;
  return joined || '/';
}

function formatHostHeader(host, port, protocol) {
  const defaultPort = protocol === 'https:' ? 443 : 80;
  const hostLiteral = isIP(host) === 6 ? `[${host}]` : host;
  return port === defaultPort ? hostLiteral : `${hostLiteral}:${port}`;
}

function headersContainToken(headers, token) {
  for (const value of Object.values(headers)) {
    if (typeof value === 'string' && value.includes(token)) return true;
    if (Array.isArray(value) && value.some((item) => typeof item === 'string' && item.includes(token))) {
      return true;
    }
  }
  return false;
}

function applyTokenReplacements(value, replacements) {
  let updated = value;
  for (const [placeholder, secret] of replacements) {
    if (updated.includes(placeholder)) {
      updated = updated.replaceAll(placeholder, secret);
    }
  }
  return updated;
}

function denyProxyRequest(client, status = '403 Forbidden', headers = {}) {
  let response = `HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n`;
  for (const [name, value] of Object.entries(headers)) response += `${name}: ${value}\r\n`;
  client.write(`${response}\r\n`);
  client.end();
}

async function resolveProxyEndpoints(host) {
  const canonicalHost = canonicalizeHost(host);
  if (!canonicalHost) throw new Error('Proxy destination has an invalid host');

  const literalFamily = isIP(canonicalHost);
  if (literalFamily === 4 || literalFamily === 6) {
    return [{ address: canonicalHost, family: literalFamily }];
  }

  const addresses = await lookup(canonicalHost, { all: true, verbatim: true });
  const endpoints = [];
  const seen = new Set();
  for (const { address } of addresses) {
    const canonicalAddress = canonicalizeHost(address);
    const family = canonicalAddress ? isIP(canonicalAddress) : 0;
    if ((family !== 4 && family !== 6) || seen.has(canonicalAddress)) continue;
    seen.add(canonicalAddress);
    endpoints.push({ address: canonicalAddress, family });
  }
  if (endpoints.length === 0) {
    throw new Error(`Proxy could not resolve destination: ${canonicalHost}`);
  }
  return endpoints;
}

function pipeSockets(client, upstream, initialData) {
  upstream.on('error', () => client.destroy());
  client.on('error', () => upstream.destroy());

  if (initialData?.length) upstream.write(initialData);

  client.pipe(upstream);
  upstream.pipe(client);
}

function startFilterProxy(options) {
  const { isDomainAllowed, authorization, portRange } = options;
  const globalAllowedMethods = normalizeMethodAllowlist(options.allowedMethods, 'allowedMethods');
  const headerRules = normalizeHeaderRules(options.headerRules);
  const upstreamRoutes = normalizeUpstreams(options.upstreams);
  const allPlaceholders = new Set();
  for (const rule of headerRules) {
    for (const placeholder of rule.replaceTokens.keys()) allPlaceholders.add(placeholder);
  }
  for (const route of upstreamRoutes) {
    for (const placeholder of route.replaceTokens.keys()) allPlaceholders.add(placeholder);
  }
  let boundPort = null;
  const sockets = new Set();
  const hopByHopHeaders = [
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'proxy-connection',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
  ];

  function trackSocket(socket) {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  }

  async function connectProxyEndpoints(endpoints, port, client) {
    let lastError;
    for (const endpoint of endpoints) {
      if (stopped || client.destroyed) throw new Error('Proxy connection was cancelled');

      try {
        return await new Promise((resolve, reject) => {
          const upstream = connect({ host: endpoint.address, port, family: endpoint.family });
          let connected = false;
          const destroyUpstream = () => upstream.destroy();
          trackSocket(upstream);
          client.once('close', destroyUpstream);
          upstream.once('connect', () => {
            connected = true;
            resolve(upstream);
          });
          upstream.once('error', reject);
          upstream.once('close', () => {
            client.off('close', destroyUpstream);
            if (!connected) reject(new Error('Proxy connection closed'));
          });
        });
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError ?? new Error('Proxy could not connect to destination');
  }

  async function connectTlsEndpoints(endpoints, port, serverHost, ca, client) {
    const rawSocket = await connectProxyEndpoints(endpoints, port, client);
    if (stopped || client.destroyed) {
      rawSocket.destroy();
      throw new Error('Proxy connection was cancelled');
    }
    return new Promise((resolve, reject) => {
      let secured = false;
      const tlsSocket = connectTls({
        socket: rawSocket,
        servername: isIP(serverHost) ? undefined : serverHost,
        ...(ca !== undefined ? { ca } : {}),
      });
      const destroyTls = () => tlsSocket.destroy();
      trackSocket(tlsSocket);
      client.once('close', destroyTls);
      tlsSocket.once('secureConnect', () => {
        secured = true;
        resolve(tlsSocket);
      });
      tlsSocket.once('error', (error) => {
        rawSocket.destroy();
        reject(error);
      });
      tlsSocket.once('close', () => {
        client.off('close', destroyTls);
        if (!secured) reject(new Error('TLS connection closed'));
      });
    });
  }

  function isAuthorized(headers) {
    return !authorization || headers['proxy-authorization'] === authorization;
  }

  function matchGatewayRoute(pathname) {
    for (const route of upstreamRoutes) {
      if (route.prefix === '/') {
        return { route, suffix: pathname };
      }
      if (pathname === route.prefix) {
        return { route, suffix: '' };
      }
      if (pathname.startsWith(`${route.prefix}/`)) {
        return { route, suffix: pathname.slice(route.prefix.length) };
      }
    }
    return null;
  }

  function isLoopbackGatewayTarget(url) {
    if (boundPort === null || upstreamRoutes.length === 0) return false;
    const targetPort = parseProxyPort(url.port || undefined, 80);
    if (targetPort !== boundPort) return false;
    const host = canonicalizeHost(url.hostname);
    return host === '127.0.0.1' || host === '::1' || host === 'localhost';
  }

  function stripHopByHopHeaders(headers) {
    const forwarded = { ...headers };
    const connection = forwarded.connection;
    const connectionValue = Array.isArray(connection) ? connection.join(',') : connection;
    for (const name of connectionValue?.split(',') ?? []) {
      delete forwarded[name.trim().toLowerCase()];
    }
    for (const name of hopByHopHeaders) delete forwarded[name];
    return forwarded;
  }

  function denyHttpRequest(response, statusCode, statusMessage, headers = {}) {
    if (!response.headersSent) {
      response.writeHead(statusCode, statusMessage, {
        Connection: 'close',
        'Content-Length': '0',
        ...headers,
      });
    }
    response.end();
  }

  async function handleConnect(client, target, rest) {
    const endpoint = splitHostPort(target);
    if (!endpoint) {
      denyProxyRequest(client, '400 Bad Request');
      return;
    }

    if (!(await isDomainAllowed(endpoint.host))) {
      if (!client.destroyed) denyProxyRequest(client);
      return;
    }
    if (stopped || client.destroyed) return;

    const endpoints = await resolveProxyEndpoints(endpoint.host);
    if (stopped || client.destroyed) return;

    let upstreamSocket;
    try {
      upstreamSocket = await connectProxyEndpoints(endpoints, endpoint.port, client);
    } catch {
      if (!stopped && !client.destroyed) denyProxyRequest(client, '502 Bad Gateway');
      return;
    }
    if (stopped || client.destroyed) {
      upstreamSocket.destroy();
      return;
    }

    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    pipeSockets(client, upstreamSocket, rest);
  }

  async function handleHttp(clientRequest, clientResponse) {
    const rawUrl = clientRequest.url ?? '';
    let gatewayMatch = null;
    let url = null;

    if (rawUrl.startsWith('/')) {
      try {
        url = new URL(`http://127.0.0.1${rawUrl}`);
      } catch {
        denyHttpRequest(clientResponse, 400, 'Bad Request');
        return;
      }
      gatewayMatch = matchGatewayRoute(url.pathname);
      if (!gatewayMatch) {
        // Non-gateway origin-form request (transparent HTTP proxy with Host header).
        if (!isAuthorized(clientRequest.headers)) {
          denyHttpRequest(clientResponse, 407, 'Proxy Authentication Required', {
            'Proxy-Authenticate': proxyAuthenticateChallenge,
          });
          return;
        }
        const authority = clientRequest.headers.host;
        if (!authority) {
          denyHttpRequest(clientResponse, 400, 'Bad Request');
          return;
        }
        try {
          url = new URL(`http://${authority}${rawUrl}`);
        } catch {
          denyHttpRequest(clientResponse, 400, 'Bad Request');
          return;
        }
      }
    } else {
      try {
        url = new URL(rawUrl);
      } catch {
        denyHttpRequest(clientResponse, 400, 'Bad Request');
        return;
      }
      if (url.protocol === 'http:' && !url.username && !url.password && isLoopbackGatewayTarget(url)) {
        gatewayMatch = matchGatewayRoute(url.pathname);
      }
    }

    if (gatewayMatch) {
      const { route } = gatewayMatch;
      const authorizedByPlaceholder =
        route.replaceTokens.size > 0 &&
        [...route.replaceTokens.keys()].some((token) =>
          headersContainToken(clientRequest.headers, token),
        );
      if (!isAuthorized(clientRequest.headers) && !authorizedByPlaceholder) {
        denyHttpRequest(clientResponse, 407, 'Proxy Authentication Required', {
          'Proxy-Authenticate': proxyAuthenticateChallenge,
        });
        return;
      }
    } else if (!isAuthorized(clientRequest.headers)) {
      denyHttpRequest(clientResponse, 407, 'Proxy Authentication Required', {
        'Proxy-Authenticate': proxyAuthenticateChallenge,
      });
      return;
    }

    if (!gatewayMatch && (url.protocol !== 'http:' || url.username || url.password)) {
      denyHttpRequest(clientResponse, 400, 'Bad Request');
      return;
    }

    const host = gatewayMatch ? gatewayMatch.route.host : canonicalizeHost(url.hostname);
    if (!host) {
      denyHttpRequest(clientResponse, 400, 'Bad Request');
      return;
    }

    const matchingRules = headerRules.filter((rule) => domainMatchesPattern(host, rule.host));
    const method = (clientRequest.method ?? 'GET').toUpperCase();
    const methodGates = [
      globalAllowedMethods,
      gatewayMatch?.route.allowedMethods ?? null,
      ...matchingRules.map((rule) => rule.allowedMethods),
    ].filter(Boolean);
    for (const gate of methodGates) {
      if (!gate.set.has(method)) {
        denyHttpRequest(clientResponse, 405, 'Method Not Allowed', {
          Allow: gate.allowHeader,
        });
        return;
      }
    }

    const allowedTokens = new Map();
    if (gatewayMatch) {
      for (const [placeholder, secret] of gatewayMatch.route.replaceTokens) {
        allowedTokens.set(placeholder, secret);
      }
    }
    for (const rule of matchingRules) {
      for (const [placeholder, secret] of rule.replaceTokens) {
        allowedTokens.set(placeholder, secret);
      }
    }
    for (const placeholder of allPlaceholders) {
      if (!allowedTokens.has(placeholder) && headersContainToken(clientRequest.headers, placeholder)) {
        denyHttpRequest(clientResponse, 403, 'Forbidden');
        return;
      }
    }

    if (!(await isDomainAllowed(host))) {
      if (!clientResponse.destroyed) denyHttpRequest(clientResponse, 403, 'Forbidden');
      return;
    }
    const clientSocket = clientRequest.socket;
    if (stopped || clientSocket.destroyed || clientResponse.destroyed) return;

    const upgradeHttps = !gatewayMatch && matchingRules.some((rule) => rule.upgradeHttps);
    const protocol = gatewayMatch ? gatewayMatch.route.protocol : upgradeHttps ? 'https:' : 'http:';
    const port = gatewayMatch
      ? gatewayMatch.route.port
      : parseProxyPort(url.port || undefined, protocol === 'https:' ? 443 : 80);
    if (port === null) {
      denyHttpRequest(clientResponse, 400, 'Bad Request');
      return;
    }

    const endpoints = await resolveProxyEndpoints(host);
    if (stopped || clientSocket.destroyed || clientResponse.destroyed) return;

    const forwardedHeaders = stripHopByHopHeaders(clientRequest.headers);
    if (allowedTokens.size > 0) {
      for (const [headerName, headerValue] of Object.entries(forwardedHeaders)) {
        if (typeof headerValue === 'string') {
          forwardedHeaders[headerName] = applyTokenReplacements(headerValue, allowedTokens);
        } else if (Array.isArray(headerValue)) {
          forwardedHeaders[headerName] = headerValue.map((item) =>
            typeof item === 'string' ? applyTokenReplacements(item, allowedTokens) : item,
          );
        }
      }
    }
    const injectedEntries = [
      ...(gatewayMatch ? gatewayMatch.route.headers : []),
      ...matchingRules.flatMap((rule) => rule.headers),
    ];
    if (injectedEntries.length > 0) {
      const existingByLower = new Map();
      for (const key of Object.keys(forwardedHeaders)) {
        existingByLower.set(key.toLowerCase(), key);
      }
      for (const [lowerName, value] of injectedEntries) {
        const prevKey = existingByLower.get(lowerName);
        if (prevKey && prevKey !== lowerName) delete forwardedHeaders[prevKey];
        forwardedHeaders[lowerName] = value;
        existingByLower.set(lowerName, lowerName);
      }
    }
    forwardedHeaders.host = formatHostHeader(host, port, protocol);

    let customCa = gatewayMatch?.route.ca;
    for (const rule of matchingRules) {
      if (rule.ca !== undefined) customCa = rule.ca;
    }
    const upstreamPath = gatewayMatch
      ? `${joinGatewayPath(gatewayMatch.route.basePath, gatewayMatch.suffix)}${url.search}`
      : `${url.pathname}${url.search}` || '/';

    const agent = protocol === 'https:' ? new HttpsAgent() : new Agent();
    agent.createConnection = (_options, callback) => {
      const pending =
        protocol === 'https:'
          ? connectTlsEndpoints(endpoints, port, host, customCa, clientSocket)
          : connectProxyEndpoints(endpoints, port, clientSocket);
      pending.then(
        (socket) => callback(null, socket),
        (error) => callback(error),
      );
    };
    const sendUpstream = protocol === 'https:' ? requestHttps : requestHttp;
    const upstreamRequest = sendUpstream({
      host,
      port,
      method,
      path: upstreamPath,
      headers: forwardedHeaders,
      agent,
    });
    upstreamRequest.once('response', (upstreamResponse) => {
      clientResponse.writeHead(
        upstreamResponse.statusCode ?? 502,
        upstreamResponse.statusMessage,
        stripHopByHopHeaders(upstreamResponse.headers),
      );
      pipeline(upstreamResponse, clientResponse, (error) => {
        if (error) upstreamRequest.destroy();
      });
    });
    upstreamRequest.once('error', () => {
      if (!clientResponse.headersSent) {
        denyHttpRequest(clientResponse, 502, 'Bad Gateway');
      } else {
        clientResponse.destroy();
      }
    });
    clientRequest.once('aborted', () => upstreamRequest.destroy());
    clientRequest.once('error', () => upstreamRequest.destroy());
    clientResponse.once('error', () => upstreamRequest.destroy());
    clientResponse.once('close', () => {
      clientRequest.unpipe(upstreamRequest);
      upstreamRequest.destroy();
      agent.destroy();
    });
    clientRequest.pipe(upstreamRequest);
  }

  const server = createHttpServer({ maxHeaderSize: 65536 }, (request, response) => {
    handleHttp(request, response).catch(() => denyHttpRequest(response, 502, 'Bad Gateway'));
  });
  server.on('connection', trackSocket);
  server.on('connect', (request, client, head) => {
    if (!isAuthorized(request.headers)) {
      denyProxyRequest(client, '407 Proxy Authentication Required', {
        'Proxy-Authenticate': proxyAuthenticateChallenge,
      });
      return;
    }
    for (const placeholder of allPlaceholders) {
      if (headersContainToken(request.headers, placeholder)) {
        denyProxyRequest(client, '403 Forbidden');
        return;
      }
    }
    if (globalAllowedMethods && !globalAllowedMethods.set.has('CONNECT')) {
      denyProxyRequest(client, '405 Method Not Allowed', {
        Allow: globalAllowedMethods.allowHeader,
      });
      return;
    }
    handleConnect(client, request.url, head).catch(() =>
      denyProxyRequest(client, '502 Bad Gateway'),
    );
  });
  server.on('clientError', (error, client) => {
    const status =
      error.code === 'HPE_HEADER_OVERFLOW'
        ? '431 Request Header Fields Too Large'
        : '400 Bad Request';
    denyProxyRequest(client, status);
  });

  let stopped = false;

  return new Promise((resolve, reject) => {
    const listen = (port) => {
      server.once('error', (error) => {
        if (error.code === 'EADDRINUSE' && portRange && port < portRange.high) {
          listen(port + 1);
          return;
        }
        reject(error);
      });
      server.listen(port, '127.0.0.1', () => {
        server.removeAllListeners('error');
        const address = server.address();
        boundPort = address.port;

        resolve({
          port: address.port,
          stop: () =>
            new Promise((done) => {
              if (stopped) {
                done();
                return;
              }
              stopped = true;
              for (const socket of sockets) socket.destroy();
              server.close(() => done());
            }),
        });
      });
    };
    listen(portRange ? portRange.low : 0);
  });
}

const PROXY_ENVIRONMENT_VARIABLES = [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
];

function createProxyCredentials(tokenArg) {
  const token =
    typeof tokenArg === 'string' && tokenArg.length > 0
      ? tokenArg
      : randomBytes(32).toString('base64url');
  const authorization = `Basic ${Buffer.from(`landstrip:${token}`).toString('base64')}`;
  return { token, authorization };
}

function createProxyUrl(port, token, host = '127.0.0.1') {
  const hostname = canonicalizeHost(host);
  if (!hostname) throw new TypeError('Invalid proxy hostname');
  if (parseProxyPort(String(port), 0) === null) throw new RangeError('Invalid proxy port');
  const url = new URL('http://127.0.0.1');
  url.hostname = isIP(hostname) === 6 ? `[${hostname}]` : hostname;
  if (canonicalizeHost(url.hostname) !== hostname) throw new TypeError('Invalid proxy hostname');
  url.port = String(port);
  if (typeof token === 'string' && token.length > 0) {
    url.username = 'landstrip';
    url.password = encodeURIComponent(token);
  }
  return url.href.slice(0, -1);
}

function createProxyEnvironment(port, options) {
  const token = typeof options?.token === 'string' ? options.token : null;
  const host = typeof options?.host === 'string' ? options.host : '127.0.0.1';
  const baseEnv = options?.baseEnv && typeof options.baseEnv === 'object' ? options.baseEnv : undefined;

  const result = baseEnv ? { ...baseEnv } : {};
  if (!port || typeof port !== 'number' || port <= 0) {
    return result;
  }

  const url = createProxyUrl(port, token, host);
  for (const name of PROXY_ENVIRONMENT_VARIABLES) {
    result[name] = url;
  }
  result.NO_PROXY = '';
  result.no_proxy = '';
  return result;
}

module.exports = {
  startFilterProxy,
  PROXY_ENVIRONMENT_VARIABLES,
  createProxyCredentials,
  createProxyUrl,
  createProxyEnvironment,
};
