// SPDX-License-Identifier: Apache-2.0
'use strict';

const { lstatSync, readlinkSync, realpathSync } = require('node:fs');
const { homedir } = require('node:os');
const { basename, dirname, isAbsolute, join, relative, resolve, sep } = require('node:path');
const { domainToASCII } = require('node:url');

const ipaddr = require('ipaddr.js');

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

function canonicalizeHost(host) {
  const bracketed = host.startsWith('[');
  if (bracketed !== host.endsWith(']')) return null;

  // A trailing dot ("pastebin.com.") is the same host to DNS but would slip
  // past a literal deny entry; strip a single trailing dot and reject the rest.
  const value = bracketed ? host.slice(1, -1) : host.replace(/\.$/, '');
  if (!value || value.endsWith('.')) return null;

  if (ipaddr.isValid(value)) {
    if (bracketed && ipaddr.parse(value).kind() !== 'ipv6') return null;
    return ipaddr.process(value).toString();
  }
  if (bracketed) return null;

  const ascii = domainToASCII(value);
  if (!ascii) return null;

  try {
    const parsed = new URL(`http://${ascii}/`);
    return parsed.hostname === ascii.toLowerCase() ? parsed.hostname : null;
  } catch {
    return null;
  }
}

function domainMatchesPattern(domain, pattern) {
  const normalizedDomain = canonicalizeHost(domain);
  if (!normalizedDomain) return false;
  if (pattern === '*') return true;

  if (pattern.startsWith('*.')) {
    const base = canonicalizeHost(pattern.slice(2));
    return base !== null && (normalizedDomain === base || normalizedDomain.endsWith(`.${base}`));
  }

  const normalizedPattern = canonicalizeHost(pattern);
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

// Relative entries (notably ".") resolve against the caller-supplied base
// directory — the command's working directory that landstrip itself uses as
// its policy base — never the host process's own cwd.
function expandPath(filePath, baseDirectory) {
  return resolve(baseDirectory, expandHomePath(filePath));
}

function canonicalizePath(filePath, baseDirectory, seen = new Set()) {
  const abs = expandPath(filePath, baseDirectory);
  const missing = [];
  let existing = abs;

  for (;;) {
    try {
      const stat = lstatSync(existing);
      if (stat.isSymbolicLink()) {
        if (seen.has(existing)) return abs;
        seen.add(existing);
        const target = resolve(dirname(existing), readlinkSync(existing), ...missing);
        return canonicalizePath(target, baseDirectory, seen);
      }
      break;
    } catch {
      const parent = dirname(existing);
      if (parent === existing) return abs;
      missing.unshift(basename(existing));
      existing = parent;
    }
  }

  try {
    return resolve(realpathSync.native(existing), ...missing);
  } catch {
    return abs;
  }
}

function canonicalizeGlobPattern(pattern, baseDirectory) {
  const expanded = expandPath(pattern, baseDirectory);
  const wildcard = expanded.search(/[*?[\]]/);
  if (wildcard < 0) return canonicalizePath(expanded, baseDirectory);

  const prefix = expanded.slice(0, wildcard);
  const base = prefix.endsWith(sep) ? prefix : dirname(prefix);
  const suffixOffset = base.endsWith(sep) ? base.length - 1 : base.length;
  const canonicalBase = canonicalizePath(base, baseDirectory);
  const suffix = expanded.slice(suffixOffset);
  return canonicalBase.endsWith(sep) && suffix.startsWith(sep)
    ? `${canonicalBase}${suffix.slice(1)}`
    : `${canonicalBase}${suffix}`;
}

function normalizePathSeparators(path) {
  return process.platform === 'win32' ? path.replaceAll('\\', '/') : path;
}

const globRegExpCache = new Map();

class ByteGlobRegExp extends RegExp {
  exec(value) {
    return super.exec(Buffer.from(String(value)).toString('latin1'));
  }
}

// Translates an absolute glob pattern using the same UTF-8 byte semantics as
// the Rust policy matcher: `**` crosses directories, `*` stays within one
// segment, `?` matches one non-separator byte, and classes support byte ranges.
function globToRegExp(globPattern) {
  const cached = globRegExpCache.get(globPattern);
  if (cached) return cached;

  const pattern = Buffer.from(globPattern).toString('latin1');
  let escaped = '';
  for (let at = 0; at < pattern.length;) {
    if (pattern.startsWith('**/', at)) {
      escaped += '(?:[\\s\\S]*/)?';
      at += 3;
    } else if (pattern.startsWith('**', at)) {
      escaped += '[\\s\\S]*';
      at += 2;
    } else if (pattern[at] === '*') {
      escaped += '[^/]*';
      at += 1;
    } else if (pattern[at] === '?') {
      escaped += '[^/]';
      at += 1;
    } else if (pattern[at] === '[') {
      const end = pattern.indexOf(']', at + 1);
      if (end < 0) {
        escaped += '\\[';
        at += 1;
        continue;
      }

      const content = pattern.slice(at + 1, end);
      const hex = (code) => `\\x${code.toString(16).padStart(2, '0')}`;
      let characterClass = '';
      for (let offset = 0; offset < content.length;) {
        if (offset + 2 < content.length && content[offset + 1] === '-') {
          const start = content.charCodeAt(offset);
          const finish = content.charCodeAt(offset + 2);
          if (start <= finish) characterClass += `${hex(start)}-${hex(finish)}`;
          offset += 3;
        } else {
          characterClass += hex(content.charCodeAt(offset));
          offset += 1;
        }
      }
      escaped += characterClass ? `(?=[^/])[${characterClass}]` : '(?!)';
      at = end + 1;
    } else {
      escaped += pattern[at].replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
      at += 1;
    }
  }

  const result = new ByteGlobRegExp(`^${escaped}(?![\\s\\S])`);
  globRegExpCache.set(globPattern, result);
  return result;
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
  expandPath,
  canonicalizePath,
  canonicalizeGlobPattern,
  normalizePathSeparators,
  globToRegExp,
  pathUnderDirectory,
  sessionAllows,
  sessionScopeFor,
  canonicalizeHost,
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
