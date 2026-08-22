// SPDX-License-Identifier: Apache-2.0
'use strict';

const { realpathSync } = require('node:fs');
const { homedir } = require('node:os');
const { dirname, isAbsolute, join, relative, sep } = require('node:path');

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function expandHomePath(value) {
  if (value === '~' || value === '$HOME') return homedir();
  if (value.startsWith('~/')) return join(homedir(), value.slice(2));
  if (value.startsWith('$HOME/')) return join(homedir(), value.slice(6));
  return value;
}

function pathUnderDirectory(filePath, dir) {
  const child = relative(dir, filePath);
  return child === '' || (!isAbsolute(child) && child !== '..' && !child.startsWith(`..${sep}`));
}

function sessionAllows(prefixes, filePath) {
  for (const prefix of prefixes) {
    if (pathUnderDirectory(filePath, prefix)) return true;
  }
  return false;
}

// The broadest ancestor worth approving in one action: the immediate child of
// `$HOME` (e.g. `~/.cargo`) for paths under the user's home, the project root
// for paths under it, otherwise the containing directory. A file sitting
// directly on a boundary falls back to the exact file so nothing widens
// silently.
function sessionScopeFor(filePath, baseDirectory) {
  const dir = dirname(filePath);
  const homeBoundaries = new Set([homedir()]);
  try {
    homeBoundaries.add(realpathSync.native(homedir()));
  } catch {
    // $HOME not resolvable — fall back to the raw value only.
  }

  for (const boundary of homeBoundaries) {
    if (pathUnderDirectory(dir, boundary)) {
      const first = relative(boundary, dir).split(sep)[0];
      if (!first) return filePath;
      return join(boundary, first);
    }
  }

  const projectBoundaries = new Set([baseDirectory]);
  try {
    projectBoundaries.add(realpathSync.native(baseDirectory));
  } catch {
    // Project directory not resolvable — fall back to the raw value only.
  }

  for (const boundary of projectBoundaries) {
    if (pathUnderDirectory(dir, boundary)) return boundary;
  }

  return dir;
}

function domainMatchesPattern(domain, pattern) {
  // A trailing dot ("pastebin.com.") is the same host to DNS but would slip
  // past a literal deny entry; strip it from both sides before matching.
  const normalizedDomain = domain.toLowerCase().replace(/\.+$/, '');
  const normalizedPattern = pattern.toLowerCase().replace(/\.+$/, '');

  if (normalizedPattern === '*') return true;
  if (normalizedPattern.startsWith('*.')) {
    const base = normalizedPattern.slice(2);
    return normalizedDomain === base || normalizedDomain.endsWith(`.${base}`);
  }

  return normalizedDomain === normalizedPattern;
}

function domainMatchesAny(domain, patterns) {
  return patterns.some((pattern) => domainMatchesPattern(domain, pattern));
}

function allowsAllDomains(allowedDomains) {
  return allowedDomains.includes('*');
}

// landstrip emits each trap as a flat JSON record tagged by a `kind`
// discriminant (`filesystem`, `network`, `launch`, `usage`, `internal`)
// alongside a stable `code` and variant-specific fields. The declarations it
// ships are erased at compile time, so validate the fields callers read
// before trusting a decoded line. `state` is deliberately not validated: a
// missing or unknown state degrades to "informational", the safe direction.
// `query_id` must be a string — landstrip < 0.17 sent a number, and a
// numeric id fails its own deserializer when echoed back.
const LANDSTRIP_OPERATIONS = new Set(['read', 'write']);

function isLandstripTrap(value) {
  if (!isRecord(value)) return false;

  switch (value.kind) {
    case 'filesystem':
      return (
        LANDSTRIP_OPERATIONS.has(value.operation) &&
        typeof value.path === 'string' &&
        typeof value.query_id === 'string'
      );
    case 'network':
      return (
        typeof value.operation === 'string' &&
        typeof value.target === 'string' &&
        typeof value.query_id === 'string'
      );
    case 'launch':
      return typeof value.program === 'string' && typeof value.message === 'string';
    case 'usage':
      return typeof value.message === 'string';
    case 'internal':
      return typeof value.code === 'string' && typeof value.message === 'string';
    default:
      return false;
  }
}

function decodeLandstripTrap(value) {
  return isLandstripTrap(value) ? value : null;
}

function parseTrapLine(line) {
  try {
    const parsed = JSON.parse(line);
    return isLandstripTrap(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function parseLandstripTraps(output) {
  const traps = [];

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed[0] !== '{') continue;
    const trap = parseTrapLine(trimmed);
    if (trap) traps.push(trap);
  }

  return traps;
}

function isFilesystemTrap(trap) {
  return trap.kind === 'filesystem';
}

// filesystem and network traps report an access the policy denied; launch,
// usage and internal traps report that landstrip itself failed.
function isDenialTrap(trap) {
  return trap.kind === 'filesystem' || trap.kind === 'network';
}

// A `state: "query"` trap suspends the child's syscall until the host answers
// it on the trap socket. An `info` trap is terminal.
function isQueryTrap(trap) {
  return isDenialTrap(trap) && trap.state === 'query';
}

function formatLandstripTrap(trap) {
  switch (trap.kind) {
    case 'filesystem':
      return `landstrip: filesystem ${trap.operation} denied (${trap.path})${
        trap.mechanism ? ` [${trap.mechanism}]` : ''
      }`;
    case 'network':
      return `landstrip: network ${trap.operation} denied (${trap.target})${
        trap.mechanism ? ` [${trap.mechanism}]` : ''
      }`;
    case 'launch':
      return `landstrip: launch failed (${trap.program})${trap.message ? `: ${trap.message}` : ''}`;
    case 'usage':
      return `landstrip: usage error: ${trap.message}`;
    case 'internal': {
      const mechanism = trap.mechanism ? ` [${trap.mechanism}]` : '';
      return `landstrip: ${trap.code}${mechanism}: ${trap.message}`;
    }
  }
}

function formatLandstripTraps(traps) {
  return traps.map(formatLandstripTrap).join('\n');
}

// The broker matches an answer to its query by the exact decimal `query_id`
// string the trap carried. A numeric id fails its deserializer, the line is
// dropped, and the child's syscall stays suspended.
function controlResponseLine(queryId, action) {
  return JSON.stringify({ query_id: queryId, action }) + '\n';
}

module.exports = {
  isRecord,
  expandHomePath,
  pathUnderDirectory,
  sessionAllows,
  sessionScopeFor,
  domainMatchesPattern,
  domainMatchesAny,
  allowsAllDomains,
  decodeLandstripTrap,
  parseTrapLine,
  parseLandstripTraps,
  isFilesystemTrap,
  isDenialTrap,
  isQueryTrap,
  formatLandstripTrap,
  formatLandstripTraps,
  controlResponseLine,
};
