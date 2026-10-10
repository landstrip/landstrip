// SPDX-License-Identifier: Apache-2.0
'use strict';

const {
  lstatSync,
  mkdtempSync,
  readlinkSync,
  realpathSync,
  rmSync,
  writeFileSync,
} = require('node:fs');
const { homedir, tmpdir } = require('node:os');
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
  if (/[\s\p{Cc}/\\@?#]/u.test(host)) return null;

  const bracketed = host.startsWith('[');
  if (bracketed !== host.endsWith(']')) return null;
  const value = bracketed ? host.slice(1, -1) : host;

  if (ipaddr.isValid(value)) {
    if (bracketed && ipaddr.parse(value).kind() !== 'ipv6') return null;
    return ipaddr.process(value).toString();
  }
  if (bracketed || /[:%]/.test(value)) return null;

  // A trailing dot ("pastebin.com.") is the same host to DNS but would slip
  // past a literal deny entry; strip a single trailing dot and reject the rest.
  const ascii = domainToASCII(value).replace(/\.$/, '');
  if (!ascii || ascii.endsWith('.')) return null;

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

function resolveFilesystemPatterns(patterns, baseDirectory) {
  if (!patterns || !Array.isArray(patterns)) return [];
  if (!baseDirectory) return [...patterns];
  return patterns.map((pattern) =>
    /[*?[\]]/.test(pattern)
      ? canonicalizeGlobPattern(pattern, baseDirectory)
      : canonicalizePath(pattern, baseDirectory),
  );
}

function resolveFilesystemPolicy(filesystem, baseDirectory) {
  if (!filesystem) return {};
  const resolved = {};
  if (filesystem.denyRead !== undefined) {
    resolved.denyRead = resolveFilesystemPatterns(filesystem.denyRead, baseDirectory);
  }
  if (filesystem.denyReadAlways !== undefined) {
    resolved.denyReadAlways = resolveFilesystemPatterns(filesystem.denyReadAlways, baseDirectory);
  }
  if (filesystem.allowRead !== undefined) {
    resolved.allowRead = resolveFilesystemPatterns(filesystem.allowRead, baseDirectory);
  }
  if (filesystem.allowWrite !== undefined) {
    resolved.allowWrite = resolveFilesystemPatterns(filesystem.allowWrite, baseDirectory);
  }
  if (filesystem.denyWrite !== undefined) {
    resolved.denyWrite = resolveFilesystemPatterns(filesystem.denyWrite, baseDirectory);
  }
  if (filesystem.denyWriteAlways !== undefined) {
    resolved.denyWriteAlways = resolveFilesystemPatterns(filesystem.denyWriteAlways, baseDirectory);
  }
  return resolved;
}

function buildLandstripPolicy(options) {
  const policy = {};
  if (options.network) {
    const net = {
      allowNetwork: Boolean(options.network.allowNetwork),
      allowLocalBinding: Boolean(options.network.allowLocalBinding),
      allowAllUnixSockets: Boolean(options.network.allowAllUnixSockets),
      allowUnixSockets: Array.isArray(options.network.allowUnixSockets)
        ? [...options.network.allowUnixSockets]
        : [],
    };
    const httpProxyPort =
      options.httpProxyPort !== undefined
        ? options.httpProxyPort
        : options.network.httpProxyPort;
    if (httpProxyPort !== null && httpProxyPort !== undefined) {
      net.httpProxyPort = httpProxyPort;
    }
    const socksProxyPort =
      options.socksProxyPort !== undefined
        ? options.socksProxyPort
        : options.network.socksProxyPort;
    if (socksProxyPort !== null && socksProxyPort !== undefined) {
      net.socksProxyPort = socksProxyPort;
    }
    policy.network = net;
  }
  if (options.filesystem) {
    policy.filesystem = resolveFilesystemPolicy(
      options.filesystem,
      options.baseDirectory,
    );
  }
  if (options.windows) {
    policy.windows = {
      appContainerMode: options.windows.appContainerMode ?? 'lpac',
      allowLoopback: Boolean(options.windows.allowLoopback),
    };
  }
  return policy;
}

function serializeLandstripPolicy(policy) {
  return JSON.stringify(policy, null, 2) + '\n';
}

function writeLandstripPolicyFile(policy, prefix = 'landstrip-') {
  const contents = serializeLandstripPolicy(policy);
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const path = join(dir, 'policy.json');
  try {
    writeFileSync(path, contents, 'utf8');
  } catch (error) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        `Failed to remove partial Landstrip policy directory "${dir}"`,
      );
    }
    throw error;
  }
  return { dir, path };
}

function requireSandboxObject(value, label) {
  if (!isRecord(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function rejectUnknownSandboxFields(value, allowed, prefix = '') {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw new Error(`unknown sandbox field ${prefix}${key}`);
    }
  }
}

function validateBooleanFields(value, fields, prefix = '') {
  for (const field of fields) {
    if (value[field] !== undefined && typeof value[field] !== 'boolean') {
      throw new Error(`${prefix}${field} must be a boolean`);
    }
  }
}

function validateStringArrayFields(value, fields, prefix = '') {
  for (const field of fields) {
    const entry = value[field];
    if (entry === undefined) continue;
    if (!Array.isArray(entry) || entry.some((item) => typeof item !== 'string')) {
      throw new Error(`${prefix}${field} must be an array of strings`);
    }
  }
}

function mergeArray(base, override) {
  if (!override) return base;
  return [...new Set([...(base ?? []), ...override])];
}

function parseSandboxConfig(value) {
  requireSandboxObject(value, 'sandbox config');
  rejectUnknownSandboxFields(value, ['enabled', 'shell', 'network', 'filesystem', 'windows']);
  validateBooleanFields(value, ['enabled']);

  const config = {};
  if (value.enabled !== undefined) {
    config.enabled = value.enabled;
  }

  if (value.shell !== undefined) {
    requireSandboxObject(value.shell, 'shell');
    rejectUnknownSandboxFields(value.shell, ['readAccess'], 'shell.');
    if (
      value.shell.readAccess !== undefined &&
      value.shell.readAccess !== 'host' &&
      value.shell.readAccess !== 'policy'
    ) {
      throw new Error('shell.readAccess must be host or policy');
    }
    config.shell = { ...value.shell };
  }

  if (value.network !== undefined) {
    requireSandboxObject(value.network, 'network');
    rejectUnknownSandboxFields(
      value.network,
      [
        'allowNetwork',
        'allowLocalBinding',
        'allowAllUnixSockets',
        'allowUnixSockets',
        'allowedDomains',
        'deniedDomains',
      ],
      'network.',
    );
    validateBooleanFields(
      value.network,
      ['allowNetwork', 'allowLocalBinding', 'allowAllUnixSockets'],
      'network.',
    );
    validateStringArrayFields(
      value.network,
      ['allowUnixSockets', 'allowedDomains', 'deniedDomains'],
      'network.',
    );
    config.network = {};
    if (value.network.allowNetwork !== undefined) {
      config.network.allowNetwork = value.network.allowNetwork;
    }
    if (value.network.allowLocalBinding !== undefined) {
      config.network.allowLocalBinding = value.network.allowLocalBinding;
    }
    if (value.network.allowAllUnixSockets !== undefined) {
      config.network.allowAllUnixSockets = value.network.allowAllUnixSockets;
    }
    if (value.network.allowUnixSockets !== undefined) {
      config.network.allowUnixSockets = [...value.network.allowUnixSockets];
    }
    if (value.network.allowedDomains !== undefined) {
      config.network.allowedDomains = [...value.network.allowedDomains];
    }
    if (value.network.deniedDomains !== undefined) {
      config.network.deniedDomains = [...value.network.deniedDomains];
    }
  }

  if (value.filesystem !== undefined) {
    requireSandboxObject(value.filesystem, 'filesystem');
    rejectUnknownSandboxFields(
      value.filesystem,
      ['denyRead', 'denyReadAlways', 'allowRead', 'allowWrite', 'denyWrite', 'denyWriteAlways'],
      'filesystem.',
    );
    validateStringArrayFields(
      value.filesystem,
      ['denyRead', 'denyReadAlways', 'allowRead', 'allowWrite', 'denyWrite', 'denyWriteAlways'],
      'filesystem.',
    );
    config.filesystem = {};
    if (value.filesystem.denyRead !== undefined) {
      config.filesystem.denyRead = [...value.filesystem.denyRead];
    }
    if (value.filesystem.denyReadAlways !== undefined) {
      config.filesystem.denyReadAlways = [...value.filesystem.denyReadAlways];
    }
    if (value.filesystem.allowRead !== undefined) {
      config.filesystem.allowRead = [...value.filesystem.allowRead];
    }
    if (value.filesystem.allowWrite !== undefined) {
      config.filesystem.allowWrite = [...value.filesystem.allowWrite];
    }
    if (value.filesystem.denyWrite !== undefined) {
      config.filesystem.denyWrite = [...value.filesystem.denyWrite];
    }
    if (value.filesystem.denyWriteAlways !== undefined) {
      config.filesystem.denyWriteAlways = [...value.filesystem.denyWriteAlways];
    }
  }

  if (value.windows !== undefined) {
    requireSandboxObject(value.windows, 'windows');
    rejectUnknownSandboxFields(value.windows, ['appContainerMode', 'allowLoopback'], 'windows.');
    if (
      value.windows.appContainerMode !== undefined &&
      value.windows.appContainerMode !== 'standard' &&
      value.windows.appContainerMode !== 'lpac'
    ) {
      throw new Error('windows.appContainerMode must be lpac or standard');
    }
    validateBooleanFields(value.windows, ['allowLoopback'], 'windows.');
    config.windows = {};
    if (value.windows.appContainerMode !== undefined) {
      config.windows.appContainerMode = value.windows.appContainerMode;
    }
    if (value.windows.allowLoopback !== undefined) {
      config.windows.allowLoopback = value.windows.allowLoopback;
    }
  }

  return config;
}

function deepMergeSandboxConfig(base, overrides) {
  if (!overrides) return { ...base };

  const shell = overrides.shell;
  const network = overrides.network;
  const filesystem = overrides.filesystem;
  const windows = overrides.windows;

  const result = {
    enabled: overrides.enabled ?? base.enabled,
    network: {
      allowNetwork: network?.allowNetwork ?? base.network?.allowNetwork ?? false,
      allowLocalBinding: network?.allowLocalBinding ?? base.network?.allowLocalBinding ?? false,
      allowAllUnixSockets: network?.allowAllUnixSockets ?? base.network?.allowAllUnixSockets ?? false,
      allowUnixSockets: mergeArray(base.network?.allowUnixSockets, network?.allowUnixSockets),
      allowedDomains: mergeArray(base.network?.allowedDomains, network?.allowedDomains),
      deniedDomains: mergeArray(base.network?.deniedDomains, network?.deniedDomains),
    },
    filesystem: {
      denyRead: mergeArray(base.filesystem?.denyRead, filesystem?.denyRead),
      denyReadAlways: mergeArray(base.filesystem?.denyReadAlways, filesystem?.denyReadAlways),
      allowRead: mergeArray(base.filesystem?.allowRead, filesystem?.allowRead),
      allowWrite: mergeArray(base.filesystem?.allowWrite, filesystem?.allowWrite),
      denyWrite: mergeArray(base.filesystem?.denyWrite, filesystem?.denyWrite),
      denyWriteAlways: mergeArray(base.filesystem?.denyWriteAlways, filesystem?.denyWriteAlways),
    },
  };

  if (base.shell !== undefined || shell !== undefined) {
    result.shell = {
      readAccess: shell?.readAccess ?? base.shell?.readAccess ?? 'host',
    };
  }

  if (base.windows !== undefined || windows !== undefined) {
    result.windows = {
      appContainerMode: windows?.appContainerMode ?? base.windows?.appContainerMode ?? 'standard',
      allowLoopback: windows?.allowLoopback ?? base.windows?.allowLoopback ?? false,
    };
  }

  return result;
}


function normalizePathForComparison(filePath) {
  const normalized = normalizePathSeparators(filePath);
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function matchesPathPattern(filePath, patterns, baseDirectory = process.cwd()) {
  if (!Array.isArray(patterns) || patterns.length === 0) return false;
  const abs = normalizePathForComparison(canonicalizePath(filePath, baseDirectory));

  return patterns.some((pattern) => {
    const absPattern = normalizePathForComparison(canonicalizeGlobPattern(pattern, baseDirectory));

    if (/[*?[\]]/.test(pattern)) {
      const matcher = globToRegExp(absPattern);
      for (let candidate = abs; ;) {
        if (matcher.test(candidate)) return true;
        const parent = normalizePathSeparators(dirname(candidate));
        if (parent === candidate) break;
        candidate = process.platform === 'win32' ? parent.toLowerCase() : parent;
      }
      return false;
    }

    const sepChar = absPattern.endsWith('/') ? '' : '/';
    return abs === absPattern || abs.startsWith(absPattern + sepChar);
  });
}

function matchPathSpecificity(filePath, patterns, baseDirectory = process.cwd()) {
  if (!Array.isArray(patterns) || patterns.length === 0) return -1;
  let best = -1;
  for (const pattern of patterns) {
    if (!matchesPathPattern(filePath, [pattern], baseDirectory)) continue;
    const canonical = canonicalizeGlobPattern(pattern, baseDirectory);
    if (canonical.length > best) {
      best = canonical.length;
    }
  }
  return best;
}

function isPathReadAllowed(
  filePath,
  allowRead,
  denyRead,
  baseDirectory = process.cwd(),
  options,
) {
  const allowPatterns = Array.isArray(allowRead) ? allowRead : [];
  const denyPatterns = Array.isArray(denyRead) ? denyRead : [];
  const allow = matchPathSpecificity(filePath, allowPatterns, baseDirectory);
  const deny = matchPathSpecificity(filePath, denyPatterns, baseDirectory);

  if (options && options.requireAllowMatch) {
    return allow >= 0 && allow >= deny;
  }
  if (deny < 0) return true;
  return allow >= deny;
}

function isPathWriteAllowed(filePath, allowWrite, baseDirectory = process.cwd()) {
  const allowPatterns = Array.isArray(allowWrite) ? allowWrite : [];
  return allowPatterns.length > 0 && matchesPathPattern(filePath, allowPatterns, baseDirectory);
}

function shouldPromptForWrite(filePath, allowWrite, baseDirectory = process.cwd()) {
  return !isPathWriteAllowed(filePath, allowWrite, baseDirectory);
}

function normalizeReadOptions(options, allowReadOverrides) {
  if (typeof options === 'string') {
    return {
      baseDirectory: options,
      allowReadOverrides: Array.isArray(allowReadOverrides) ? allowReadOverrides : [],
      requireAllowMatch: false,
    };
  }
  return {
    baseDirectory: options?.baseDirectory,
    allowReadOverrides: options?.allowReadOverrides ?? (Array.isArray(allowReadOverrides) ? allowReadOverrides : []),
    requireAllowMatch: options?.requireAllowMatch ?? false,
  };
}

function evaluateReadAccess(filePath, filesystemOrConfig, options, allowReadOverrides) {
  const filesystem = filesystemOrConfig && 'filesystem' in filesystemOrConfig ? filesystemOrConfig.filesystem : (filesystemOrConfig ?? {});
  const opts = normalizeReadOptions(options, allowReadOverrides);
  const baseDirectory = opts.baseDirectory;

  if (filesystem.denyReadAlways && matchesPathPattern(filePath, filesystem.denyReadAlways, baseDirectory)) {
    return 'deny';
  }

  const effectiveAllowRead = opts.allowReadOverrides.length > 0
    ? mergeArray(filesystem.allowRead ?? [], opts.allowReadOverrides)
    : (filesystem.allowRead ?? []);

  if (isPathReadAllowed(filePath, effectiveAllowRead, filesystem.denyRead ?? [], baseDirectory, { requireAllowMatch: opts.requireAllowMatch })) {
    return 'allow';
  }

  return 'ask';
}

function normalizeWriteOptions(options, allowWriteOverrides) {
  if (typeof options === 'string') {
    return {
      baseDirectory: options,
      allowWriteOverrides: Array.isArray(allowWriteOverrides) ? allowWriteOverrides : [],
    };
  }
  return {
    baseDirectory: options?.baseDirectory,
    allowWriteOverrides: options?.allowWriteOverrides ?? (Array.isArray(allowWriteOverrides) ? allowWriteOverrides : []),
  };
}

function evaluateWriteAccess(filePath, filesystemOrConfig, options, allowWriteOverrides) {
  const filesystem = filesystemOrConfig && 'filesystem' in filesystemOrConfig ? filesystemOrConfig.filesystem : (filesystemOrConfig ?? {});
  const opts = normalizeWriteOptions(options, allowWriteOverrides);
  const baseDirectory = opts.baseDirectory;

  if (filesystem.denyWriteAlways && matchesPathPattern(filePath, filesystem.denyWriteAlways, baseDirectory)) {
    return 'denyAlways';
  }

  if (filesystem.denyWrite && matchesPathPattern(filePath, filesystem.denyWrite, baseDirectory)) {
    return 'deny';
  }

  const effectiveAllowWrite = opts.allowWriteOverrides.length > 0
    ? mergeArray(filesystem.allowWrite ?? [], opts.allowWriteOverrides)
    : (filesystem.allowWrite ?? []);

  if (effectiveAllowWrite.length > 0 && matchesPathPattern(filePath, effectiveAllowWrite, baseDirectory)) {
    return 'allow';
  }

  return 'ask';
}

function isDomainAllowed(domain, networkOrConfig, allowedDomainsOverrides) {
  const network = networkOrConfig && 'network' in networkOrConfig ? networkOrConfig.network : (networkOrConfig ?? {});
  if (network.allowNetwork) return true;
  const denied = network.deniedDomains ?? [];
  if (domainMatchesAny(domain, denied)) return false;
  const effectiveAllowed = Array.isArray(allowedDomainsOverrides) && allowedDomainsOverrides.length > 0
    ? mergeArray(network.allowedDomains ?? [], allowedDomainsOverrides)
    : (network.allowedDomains ?? []);
  return domainMatchesAny(domain, effectiveAllowed);
}

function evaluateDomainAccess(domain, networkOrConfig, options) {
  const network = networkOrConfig && 'network' in networkOrConfig ? networkOrConfig.network : (networkOrConfig ?? {});
  if (network.allowNetwork) return 'allow';
  const overrides = Array.isArray(options) ? options : options?.allowedDomainsOverrides;
  const denied = network.deniedDomains ?? [];
  if (domainMatchesAny(domain, denied)) return 'deny';
  const effectiveAllowed = Array.isArray(overrides) && overrides.length > 0
    ? mergeArray(network.allowedDomains ?? [], overrides)
    : (network.allowedDomains ?? []);
  if (domainMatchesAny(domain, effectiveAllowed)) return 'allow';
  return 'ask';
}


function isPathLike(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  return (
    trimmed === '~' ||
    trimmed.startsWith('/') ||
    trimmed.startsWith('\\\\') ||
    /^[a-zA-Z]:[\\/]/.test(trimmed) ||
    trimmed.startsWith('~/') ||
    trimmed.startsWith('~\\') ||
    trimmed.startsWith('./') ||
    trimmed.startsWith('.\\') ||
    trimmed.startsWith('../') ||
    trimmed.startsWith('..\\') ||
    trimmed.startsWith('.') ||
    trimmed.includes('/') ||
    trimmed.includes('\\')
  );
}

function normalizeBlockedPath(filePath, cwd = process.cwd()) {
  const nativePath =
    process.platform === 'win32' && /^\/[a-zA-Z](?:\/|$)/.test(filePath)
      ? `${filePath[1]}:${filePath.slice(2)}`
      : filePath;
  return canonicalizePath(isAbsolute(nativePath) ? nativePath : join(cwd, nativePath), cwd);
}

function normalizePathMatch(value, cwd) {
  return isPathLike(value) ? normalizeBlockedPath(value, cwd) : null;
}

function extractDomainsFromCommand(command) {
  if (typeof command !== 'string') return [];
  const domains = [];
  const urlRegex = /https?:\/\/([^\s/:?#'"]+)(?::\d+)?(?:[/?#]|\s|$)/g;
  let match;
  while ((match = urlRegex.exec(command)) !== null) {
    const domain = match[1].toLowerCase();
    if (!domains.includes(domain)) {
      domains.push(domain);
    }
  }
  return domains;
}

function extractCandidatePaths(command) {
  if (typeof command !== 'string') return [];
  const paths = [];
  const tokens = command.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
  for (const rawToken of tokens) {
    const token = rawToken.replace(/^["']|["']$/g, '');
    const clean = token.replace(/^[<>&|;]+|[<>&|;]+$/g, '');
    if (
      clean.length > 0 &&
      !clean.startsWith('-') &&
      (clean.startsWith('/') ||
        clean.startsWith('./') ||
        clean.startsWith('../') ||
        clean.startsWith('~/') ||
        clean.startsWith('\\\\') ||
        clean.startsWith('~\\') ||
        clean.startsWith('.\\') ||
        clean.startsWith('..\\') ||
        /^[a-zA-Z]:[\\/]/.test(clean))
    ) {
      if (!paths.includes(clean)) {
        paths.push(clean);
      }
    }
  }
  return paths;
}

function extractNativeDeniedPath(output, cwd = process.cwd()) {
  if (typeof output !== 'string') return null;
  const denial = String.raw`(?:Access is denied\.?|Operation not permitted|Permission denied)`;
  let match = output.match(new RegExp(String.raw`['"]([^'"\n]+)['"][^\r\n]{0,120}${denial}`, 'i'));
  if (match) return normalizePathMatch(match[1], cwd);

  // bash/sh and native Windows tools: line X: /path: Permission denied,
  // or cmd: C:\path: Access is denied.
  match = output.match(
    new RegExp(
      String.raw`(?:^|:\s+)((?:[a-zA-Z]:[\\/]|\\\\|/|\.{1,2}[\\/])[^:\r\n]*?):\s+${denial}$`,
      'im',
    ),
  );
  if (match) return normalizePathMatch(match[1], cwd);

  // ls/cat/cp: cannot open/access/stat '/path': Permission denied
  match = output.match(
    new RegExp(
      String.raw`^[a-zA-Z0-9_-]+: cannot (?:open|access|stat|create)(?: directory)? '?([^'\n]+?)'?(?: for (?:reading|writing))?: ${denial}$`,
      'im',
    ),
  );
  if (match) return normalizePathMatch(match[1], cwd);

  return null;
}

function extractNativeWriteDeniedPath(output, cwd = process.cwd()) {
  if (typeof output !== 'string') return null;
  const denial = String.raw`(?:Access is denied\.?|Operation not permitted|Permission denied)`;
  let match = output.match(
    new RegExp(
      String.raw`(?:[Uu]nable to create|failed to create(?: directory)?|cannot (?:create|touch|mkdir|remove|unlink|rename)|for writing)[^'"\x60\r\n]*['"\x60]([^'"\x60\r\n]+)['"\x60](?:[^\r\n]*\r?\n){0,3}[^\r\n]{0,120}${denial}`,
      'im',
    ),
  );
  if (match) return normalizePathMatch(match[1], cwd);

  match = output.match(
    new RegExp(
      String.raw`^[a-zA-Z0-9_-]+: cannot create(?: directory)? '?([^'\n]+?)'?(?: for writing)?: ${denial}$`,
      'im',
    ),
  );
  if (match) return normalizePathMatch(match[1], cwd);


  match = output.match(
    new RegExp(
      String.raw`^[a-zA-Z0-9_-]+: couldn't open temporary file ((?:[a-zA-Z]:[\\/]|\\\\|/)[^:\r\n]*?): ${denial}$`,
      'im',
    ),
  );
  if (match) return normalizePathMatch(match[1], cwd);

  return null;
}

function extractTrapBlockedPath(trapOutput, cwd = process.cwd(), operation) {
  if (typeof trapOutput !== 'string') return null;
  const traps = parseLandstripTraps(trapOutput);
  for (const trap of traps) {
    if (isFilesystemTrap(trap) && (!operation || trap.operation === operation)) {
      return normalizeBlockedPath(trap.path, cwd);
    }
  }
  return null;
}

function extractDeniedPath(output, options, commandArg) {
  if (typeof output !== 'string') return null;
  let cwd = process.cwd();
  let command = commandArg;
  if (typeof options === 'string') {
    cwd = options;
  } else if (options && typeof options === 'object') {
    if (typeof options.cwd === 'string') cwd = options.cwd;
    if (typeof options.command === 'string') command = options.command;
  }

  // 1. Structured traps
  const landstripTraps = parseLandstripTraps(output);
  const trapped = extractTrapBlockedPath(output, cwd);
  if (trapped) return trapped;

  // 2. Native shell/tool error messages
  const nativeMatch = extractNativeDeniedPath(output, cwd);
  if (nativeMatch) return nativeMatch;

  // 3. Fallback: if landstrip trapped but path wasn't specified, inspect command candidates
  if (
    command &&
    landstripTraps.some((trap) => trap.kind === 'filesystem' || trap.kind === 'internal')
  ) {
    for (const candidate of extractCandidatePaths(command)) {
      return normalizeBlockedPath(candidate, cwd);
    }
  }

  return null;
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
  resolveFilesystemPatterns,
  resolveFilesystemPolicy,
  buildLandstripPolicy,
  serializeLandstripPolicy,
  writeLandstripPolicyFile,
  mergeArray,
  parseSandboxConfig,
  deepMergeSandboxConfig,

  normalizePathForComparison,
  matchesPathPattern,
  matchPathSpecificity,
  isPathReadAllowed,
  isPathWriteAllowed,
  shouldPromptForWrite,
  evaluateReadAccess,
  evaluateWriteAccess,
  isDomainAllowed,
  evaluateDomainAccess,

  normalizeBlockedPath,
  extractTrapBlockedPath,
  extractDomainsFromCommand,
  extractCandidatePaths,
  extractNativeDeniedPath,
  extractNativeWriteDeniedPath,
  extractDeniedPath,
};
