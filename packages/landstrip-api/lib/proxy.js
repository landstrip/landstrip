// SPDX-License-Identifier: Apache-2.0
'use strict';

const { lookup } = require('node:dns/promises');
const { Agent, createServer: createHttpServer, request: requestHttp } = require('node:http');
const { BlockList, connect, isIP } = require('node:net');

const { canonicalizeHost } = require('./shared');

const prohibitedProxyAddresses = new BlockList();

for (const [network, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]) {
  prohibitedProxyAddresses.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
]) {
  prohibitedProxyAddresses.addSubnet(network, prefix, 'ipv6');
}

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

function denyProxyRequest(client, status = '403 Forbidden', headers = {}) {
  let response = `HTTP/1.1 ${status}\r\nContent-Length: 0\r\n`;
  for (const [name, value] of Object.entries(headers)) response += `${name}: ${value}\r\n`;
  client.write(`${response}\r\n`);
  client.end();
}

function isPublicProxyAddress(address) {
  const canonicalAddress = canonicalizeHost(address);
  if (!canonicalAddress) return false;

  const family = isIP(canonicalAddress);
  if (family === 4) return !prohibitedProxyAddresses.check(canonicalAddress, 'ipv4');
  if (family === 6) return !prohibitedProxyAddresses.check(canonicalAddress, 'ipv6');
  return false;
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

  function isAuthorized(headers) {
    return !authorization || headers['proxy-authorization'] === authorization;
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
    if (!isAuthorized(clientRequest.headers)) {
      denyHttpRequest(clientResponse, 407, 'Proxy Authentication Required', {
        'Proxy-Authenticate': proxyAuthenticateChallenge,
      });
      return;
    }

    let url;
    try {
      url = new URL(clientRequest.url);
    } catch {
      const authority = clientRequest.headers.host;
      if (!authority) {
        denyHttpRequest(clientResponse, 400, 'Bad Request');
        return;
      }

      try {
        url = new URL(`http://${authority}${clientRequest.url}`);
      } catch {
        denyHttpRequest(clientResponse, 400, 'Bad Request');
        return;
      }
    }

    if (url.protocol !== 'http:' || url.username || url.password) {
      denyHttpRequest(clientResponse, 400, 'Bad Request');
      return;
    }

    const host = canonicalizeHost(url.hostname);
    if (!host) {
      denyHttpRequest(clientResponse, 400, 'Bad Request');
      return;
    }
    if (!(await isDomainAllowed(host))) {
      if (!clientResponse.destroyed) denyHttpRequest(clientResponse, 403, 'Forbidden');
      return;
    }
    const clientSocket = clientRequest.socket;
    if (stopped || clientSocket.destroyed || clientResponse.destroyed) return;

    const port = parseProxyPort(url.port || undefined, 80);
    if (port === null) {
      denyHttpRequest(clientResponse, 400, 'Bad Request');
      return;
    }

    const endpoints = await resolveProxyEndpoints(host);
    if (stopped || clientSocket.destroyed || clientResponse.destroyed) return;

    const forwardedHeaders = stripHopByHopHeaders(clientRequest.headers);
    forwardedHeaders.host = url.host;

    const agent = new Agent();
    agent.createConnection = (_options, callback) => {
      connectProxyEndpoints(endpoints, port, clientSocket).then(
        (socket) => callback(null, socket),
        (error) => callback(error),
      );
    };
    const upstreamRequest = requestHttp({
      host,
      port,
      method: clientRequest.method,
      path: `${url.pathname}${url.search}` || '/',
      headers: forwardedHeaders,
      agent,
    });
    upstreamRequest.once('response', (upstreamResponse) => {
      clientResponse.writeHead(
        upstreamResponse.statusCode ?? 502,
        upstreamResponse.statusMessage,
        stripHopByHopHeaders(upstreamResponse.headers),
      );
      upstreamResponse.pipe(clientResponse);
    });
    upstreamRequest.once('error', () => {
      if (!clientResponse.headersSent) {
        denyHttpRequest(clientResponse, 502, 'Bad Gateway');
      } else {
        clientResponse.destroy();
      }
    });
    clientRequest.once('aborted', () => upstreamRequest.destroy());
    clientResponse.once('close', () => {
      if (!clientResponse.writableEnded) upstreamRequest.destroy();
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

module.exports = {
  isPublicProxyAddress,
  startFilterProxy,
};
