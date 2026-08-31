// SPDX-License-Identifier: Apache-2.0
'use strict';

const { lookup } = require('node:dns/promises');
const { BlockList, connect, createServer, isIP } = require('node:net');

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

function splitHostPort(target, defaultPort) {
  const bracketMatch = target.match(/^\[([^\]]+)\](?::(.*))?$/);
  const host = bracketMatch?.[1];
  if (host) {
    const port = parseProxyPort(bracketMatch[2], defaultPort);
    return port === null ? null : { host, port };
  }

  const lastColon = target.lastIndexOf(':');
  if (lastColon > -1 && target.indexOf(':') === lastColon) {
    const port = parseProxyPort(target.slice(lastColon + 1), defaultPort);
    return port === null ? null : { host: target.slice(0, lastColon), port };
  }

  return { host: target, port: defaultPort };
}

function denyProxyRequest(client, status = '403 Forbidden', body) {
  const bodyStr = body ? String(body) : '';
  const bodyBuf = Buffer.from(bodyStr);
  client.write(`HTTP/1.1 ${status}\r\nContent-Length: ${bodyBuf.length}\r\n\r\n${bodyBuf}`);
  client.end();
}

function isPublicProxyAddress(address, family = isIP(address)) {
  if (family === 4) return !prohibitedProxyAddresses.check(address, 'ipv4');
  if (family === 6) return !prohibitedProxyAddresses.check(address, 'ipv6');
  return false;
}

async function resolveProxyEndpoint(host) {
  const literalFamily = isIP(host);
  if (literalFamily === 4 || literalFamily === 6) {
    if (!isPublicProxyAddress(host, literalFamily)) {
      throw new Error(`Proxy destination is not public: ${host}`);
    }
    return { address: host, family: literalFamily };
  }

  const addresses = await lookup(host, { all: true, verbatim: true });
  if (
    addresses.length === 0 ||
    addresses.some(({ address, family }) => !isPublicProxyAddress(address, family))
  ) {
    throw new Error(`Proxy destination resolves to a non-public address: ${host}`);
  }

  const endpoint = addresses[0];
  if (endpoint.family !== 4 && endpoint.family !== 6) {
    throw new Error(`Proxy could not resolve destination: ${host}`);
  }
  return { address: endpoint.address, family: endpoint.family };
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

  // Track the upstream socket so stop() tears it down, and abandon a still-
  // connecting upstream when its client goes away — otherwise a connect to a
  // black-holed host lingers in SYN-retry (~2 min), leaking an fd per request.
  function trackUpstream(upstream, client, settled) {
    sockets.add(upstream);
    upstream.once('close', () => sockets.delete(upstream));
    client.once('close', () => {
      if (!settled()) upstream.destroy();
    });
  }

  async function handleConnect(client, target, rest) {
    const endpoint = splitHostPort(target, 443);
    if (!endpoint) {
      denyProxyRequest(client, '400 Bad Request');
      return;
    }

    if (!(await isDomainAllowed(endpoint.host))) {
      denyProxyRequest(client);
      return;
    }

    const resolved = await resolveProxyEndpoint(endpoint.host);
    let settled = false;
    const upstream = connect(
      { host: resolved.address, port: endpoint.port, family: resolved.family },
      () => {
        settled = true;
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        pipeSockets(client, upstream, rest);
      },
    );
    trackUpstream(upstream, client, () => settled);
    upstream.once('error', (err) => {
      if (settled) return;
      settled = true;
      denyProxyRequest(client, '502 Bad Gateway', err?.message || 'Bad Gateway');
    });
  }

  async function handleHttp(client, headerText, rest) {
    const lines = headerText.split(/\r?\n/);
    const requestLine = lines[0];
    if (!requestLine) {
      denyProxyRequest(client, '400 Bad Request');
      return;
    }

    const [method, rawTarget, version] = requestLine.split(' ');
    if (!method || !rawTarget || !version) {
      denyProxyRequest(client, '400 Bad Request');
      return;
    }

    let url;
    try {
      url = new URL(rawTarget);
    } catch {
      const host = lines
        .find((line) => line.toLowerCase().startsWith('host:'))
        ?.slice(5)
        .trim();
      if (!host) {
        denyProxyRequest(client, '400 Bad Request');
        return;
      }

      try {
        url = new URL(`http://${host}${rawTarget}`);
      } catch {
        denyProxyRequest(client, '400 Bad Request');
        return;
      }
    }

    if (!(await isDomainAllowed(url.hostname))) {
      denyProxyRequest(client);
      return;
    }

    const port = parseProxyPort(url.port || undefined, url.protocol === 'https:' ? 443 : 80);
    if (port === null) {
      denyProxyRequest(client, '400 Bad Request');
      return;
    }

    const path = `${url.pathname}${url.search}` || '/';
    lines[0] = `${method} ${path} ${version}`;

    const rewrittenHeader = lines
      .filter(
        (line) =>
          !line.toLowerCase().startsWith('proxy-connection:') &&
          !line.toLowerCase().startsWith('proxy-authorization:'),
      )
      .map((line) => (line.toLowerCase().startsWith('host:') ? `Host: ${url.host}` : line))
      .join('\r\n');
    const resolved = await resolveProxyEndpoint(url.hostname);
    let settled = false;
    const upstream = connect({ host: resolved.address, port, family: resolved.family }, () => {
      settled = true;
      upstream.write(`${rewrittenHeader}\r\n\r\n`);
      pipeSockets(client, upstream, rest);
    });
    trackUpstream(upstream, client, () => settled);
    upstream.once('error', (err) => {
      if (settled) return;
      settled = true;
      denyProxyRequest(client, '502 Bad Gateway', err?.message || 'Bad Gateway');
    });
  }

  function handleClient(client) {
    sockets.add(client);
    client.on('close', () => sockets.delete(client));
    client.on('error', () => sockets.delete(client));

    let buffered = Buffer.alloc(0);

    client.on('data', (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      const headerEnd = buffered.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (buffered.length > 65536) {
          client.removeAllListeners('data');
          client.pause();
          denyProxyRequest(client, '431 Request Header Fields Too Large');
        }
        return;
      }

      client.pause();
      client.removeAllListeners('data');

      const header = buffered.subarray(0, headerEnd).toString('utf-8');
      const rest = buffered.subarray(headerEnd + 4);
      if (authorization) {
        const supplied = header
          .split(/\r?\n/)
          .find((line) => line.toLowerCase().startsWith('proxy-authorization:'))
          ?.slice('proxy-authorization:'.length)
          .trim();
        if (supplied !== authorization) {
          denyProxyRequest(client, '407 Proxy Authentication Required');
          return;
        }
      }
      const [method, target] = header.split(/\r?\n/, 1)[0].split(' ');

      const task =
        method?.toUpperCase() === 'CONNECT' && target
          ? handleConnect(client, target, rest)
          : handleHttp(client, header, rest);
      task.catch((err) => denyProxyRequest(client, '502 Bad Gateway', err?.message || 'Bad Gateway'));
    });
  }

  const server = createServer(handleClient);
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
