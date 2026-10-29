// SPDX-License-Identifier: Apache-2.0
'use strict';

const {
  lstatSync,
  mkdtempSync,
  readlinkSync,
  readdirSync,
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

const LANDSTRIP_MECHANISMS = new Set([
  'landlock',
  'seccomp',
  'namespace',
  'seatbelt',
  'appcontainer',
  'windowsuser',
]);
const LANDSTRIP_INTERNAL_CODES = new Set([
  'POLICY_PARSE_FAILED',
  'POLICY_IO_FAILED',
  'POLICY_UNRESTRICTED_READ',
  'POLICY_DENY_READ_ALWAYS_UNSUPPORTED',
  'POLICY_DENY_WRITE_ALWAYS_UNSUPPORTED',
  'POLICY_LOCAL_BINDING_UNSUPPORTED',
  'POLICY_UNIX_SOCKET_UNSUPPORTED',
  'POLICY_UNIX_SOCKET_PATH',
  'POLICY_INVALID_PORT',
  'POLICY_EMPTY_PATH',
  'POLICY_INVALID_MACH_LOOKUP',
  'POLICY_INVALID_LOG_TAG',
  'POLICY_HOME_UNAVAILABLE',
  'POLICY_TRAVERSAL_DEPTH',
  'SUPERVISE_FAILED',
  'HOST_JOB_INCOMPATIBLE',
  'PLATFORM_UNSUPPORTED',
  'INTEGER_TOO_LARGE',
  'INTERNAL_ERROR',
]);

function isDenialRecord(value) {
  return (
    typeof value.query_id === 'string' &&
    /^(0|[1-9][0-9]{0,19})$/.test(value.query_id) &&
    BigInt(value.query_id) <= 18446744073709551615n &&
    (value.state !== 'query' || value.query_id !== '0') &&
    typeof value.syscall === 'string' &&
    typeof value.errno === 'string' &&
    value.mechanism === 'seccomp' &&
    isRecord(value.process) &&
    Number.isInteger(value.process.pid) &&
    value.process.pid >= 0 &&
    value.process.pid <= 4294967295 &&
    (value.process.exe === null || typeof value.process.exe === 'string') &&
    (value.process.cwd === null || typeof value.process.cwd === 'string')
  );
}

function isLandstripTrap(value) {
  if (!isRecord(value)) return false;

  switch (value.kind) {
    case 'filesystem': {
      if (!Array.isArray(value.flags)) return false;
      for (const flag of value.flags) {
        if (typeof flag !== 'string') return false;
      }
      const grant = value.operation === 'read' ? 'allowRead' : 'allowWrite';
      const otherGrant = value.operation === 'read' ? 'allowWrite' : 'allowRead';
      return (
        value.code === 'FILESYSTEM_DENIED' &&
        (value.operation === 'read' || value.operation === 'write') &&
        typeof value.path === 'string' &&
        typeof value.requested_path === 'string' &&
        (value.reason === 'allow_miss' || value.reason === 'deny_match') &&
        isRecord(value.suggested_grant) &&
        typeof value.suggested_grant[grant] === 'string' &&
        value.suggested_grant[otherGrant] === undefined &&
        isDenialRecord(value)
      );
    }
    case 'network':
      return (
        value.code === 'NETWORK_DENIED' &&
        (value.operation === 'connect' || value.operation === 'bind') &&
        typeof value.target === 'string' &&
        isDenialRecord(value)
      );
    case 'launch':
      return (
        value.code === 'LAUNCH_FAILED' &&
        typeof value.program === 'string' &&
        typeof value.message === 'string' &&
        (value.errno === undefined || typeof value.errno === 'string')
      );
    case 'usage':
      return value.code === 'USAGE_ERROR' && typeof value.message === 'string';
    case 'internal':
      return (
        typeof value.message === 'string' &&
        (value.code === 'SANDBOX_SETUP_FAILED'
          ? LANDSTRIP_MECHANISMS.has(value.mechanism)
          : LANDSTRIP_INTERNAL_CODES.has(value.code) && value.mechanism === undefined)
      );
    default:
      return false;
  }
}

function decodeLandstripTrap(value) {
  if (!isLandstripTrap(value)) return null;
  if (isDenialTrap(value) && value.state !== 'query' && value.state !== 'info') {
    return { ...value, state: 'info' };
  }
  return value;
}

function parseTrapLine(line) {
  try {
    return decodeLandstripTrap(JSON.parse(line));
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

function resolvePathSelector(entry, baseDirectory) {
  if (typeof entry === 'string') {
    return /[*?[\]]/.test(entry)
      ? canonicalizeGlobPattern(entry, baseDirectory)
      : canonicalizePath(entry, baseDirectory);
  }
  if (isRecord(entry)) {
    if (typeof entry.literal === 'string') {
      return { literal: canonicalizePath(entry.literal, baseDirectory) };
    }
    if (typeof entry.glob === 'string') {
      return { glob: canonicalizeGlobPattern(entry.glob, baseDirectory) };
    }
  }
  return entry;
}

function resolveFilesystemPatterns(patterns, baseDirectory) {
  if (!patterns || !Array.isArray(patterns)) return [];
  if (!baseDirectory) return [...patterns];
  return patterns.map((pattern) => resolvePathSelector(pattern, baseDirectory));
}

// Expand only glob roots; literal roots may not exist yet. Darwin also keeps lexical aliases.
function resolveWriteRoots(writeRoots, baseDirectory) {
  const roots = new Set();
  const opaqueErrors = new Set(['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM', 'EIO', 'ENOTCONN']);
  const addRoot = (root) => {
    if (process.platform === 'darwin') roots.add(root);
    roots.add(canonicalizePath(root, baseDirectory));
  };
  for (const selector of writeRoots) {
    const raw = isRecord(selector) ? selector.literal ?? selector.glob : selector;
    const lexical = expandPath(raw, baseDirectory);
    const { isGlob } = resolveSelectorForMatch(selector, baseDirectory);
    if (!isGlob) {
      addRoot(lexical);
      continue;
    }
    const wildcard = lexical.search(/[*?[\]]/);
    const prefix = lexical.slice(0, wildcard);
    const start = prefix.endsWith(sep) ? resolve(prefix) : dirname(prefix);
    const matcher = globToRegExp(normalizePathForComparison(lexical));
    const pending = [[start, 0]];
    let matched = false;
    while (pending.length > 0) {
      const [current, depth] = pending.pop();
      if (depth >= 40) throw new Error('Write-root glob traversal exceeds maximum depth (40)');
      try {
        const metadata = lstatSync(current);
        if (matcher.test(normalizePathForComparison(current))) {
          addRoot(current);
          matched = true;
        }
        if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
          for (const entry of readdirSync(current)) {
            pending.push([join(current, entry), depth + 1]);
          }
        }
      } catch (error) {
        if (!opaqueErrors.has(error.code)) throw error;
      }
    }
    if (!matched && typeof selector === 'string') {
      try {
        lstatSync(lexical);
        addRoot(lexical);
      } catch (error) {
        if (!opaqueErrors.has(error.code)) throw error;
      }
    }
  }
  return roots;
}

// Preserve write-root anchoring when lowering relative denies to absolute selectors.
function resolveWriteDenyPatterns(patterns, baseDirectory, writeRoots = [], options) {
  const anchorRootName = options?.anchorRootName ?? true;
  const resolved = resolveFilesystemPatterns(patterns, baseDirectory);
  if (!baseDirectory) return resolved;
  const lexicalBase = resolve(baseDirectory);
  const baseRoot = canonicalizePath(baseDirectory);
  let roots;
  for (const pattern of patterns ?? []) {
    const raw = isRecord(pattern) ? pattern.literal ?? pattern.glob : pattern;
    if (isAbsolute(expandHomePath(raw))) continue;
    roots ??= resolveWriteRoots(writeRoots, baseDirectory);
    const { isGlob } = resolveSelectorForMatch(pattern, baseDirectory);
    const relativePattern = normalizePathForComparison(relative(baseRoot, resolve(baseRoot, raw)));
    for (const root of roots) {
      if (anchorRootName) {
        const rootName = normalizePathForComparison(basename(root));
        if (rootName && (isGlob ? globToRegExp(relativePattern).test(rootName) : relativePattern === rootName)) {
          resolved.push({ literal: canonicalizePath(root, baseDirectory) });
        }
      }
      if (root !== baseRoot && root !== lexicalBase) resolved.push(resolvePathSelector(pattern, root));
    }
  }
  return resolved;
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
    resolved.denyWrite = resolveWriteDenyPatterns(filesystem.denyWrite, baseDirectory, filesystem.allowWrite, {
      anchorRootName: false,
    });
  }
  if (filesystem.denyWriteAlways !== undefined) {
    resolved.denyWriteAlways = resolveWriteDenyPatterns(filesystem.denyWriteAlways, baseDirectory, filesystem.allowWrite);
  }
  return resolved;
}

function validateDarwinLogTag(value) {
  if (typeof value !== 'string' || value.length === 0 || /["\\\x00-\x1f\x7f]/.test(value)) {
    throw new Error(
      'macos.logTag must be a nonempty string without double quotes, backslashes, ASCII control characters or DEL',
    );
  }
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
  if (options.macos) {
    policy.macos = {
      allowTrustd: Boolean(options.macos.allowTrustd),
      allowMachLookup: Array.isArray(options.macos.allowMachLookup)
        ? [...options.macos.allowMachLookup]
        : [],
      allowAppleEvents: Boolean(options.macos.allowAppleEvents),
      allowPty: Boolean(options.macos.allowPty),
    };
    if (options.macos.logTag !== undefined) {
      validateDarwinLogTag(options.macos.logTag);
      policy.macos.logTag = options.macos.logTag;
    }
  }
  if (options.windows) {
    policy.windows = {
      appContainerMode: options.windows.appContainerMode ?? 'lpac',
      allowLoopback: Boolean(options.windows.allowLoopback),
    };
    if (options.windows.allowAdditiveGrants) {
      policy.windows.allowAdditiveGrants = true;
    }
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
  const result = [];
  const seen = new Set();
  for (const item of [...(base ?? []), ...override]) {
    const key = typeof item === 'string' ? `s:${item}` : `o:${JSON.stringify(item)}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(item);
    }
  }
  return result;
}

function parseSandboxConfig(value) {
  requireSandboxObject(value, 'sandbox config');
  rejectUnknownSandboxFields(value, [
    'enabled',
    'shell',
    'network',
    'filesystem',
    'macos',
    'windows',
  ]);
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

  if (value.macos !== undefined) {
    requireSandboxObject(value.macos, 'macos');
    rejectUnknownSandboxFields(
      value.macos,
      ['allowTrustd', 'allowMachLookup', 'allowAppleEvents', 'allowPty', 'logTag'],
      'macos.',
    );
    validateBooleanFields(
      value.macos,
      ['allowTrustd', 'allowAppleEvents', 'allowPty'],
      'macos.',
    );
    validateStringArrayFields(value.macos, ['allowMachLookup'], 'macos.');
    config.macos = {};
    if (value.macos.allowTrustd !== undefined) {
      config.macos.allowTrustd = value.macos.allowTrustd;
    }
    if (value.macos.allowMachLookup !== undefined) {
      config.macos.allowMachLookup = [...value.macos.allowMachLookup];
    }
    if (value.macos.allowAppleEvents !== undefined) {
      config.macos.allowAppleEvents = value.macos.allowAppleEvents;
    }
    if (value.macos.allowPty !== undefined) {
      config.macos.allowPty = value.macos.allowPty;
    }
    if (value.macos.logTag !== undefined) {
      validateDarwinLogTag(value.macos.logTag);
      config.macos.logTag = value.macos.logTag;
    }
  }

  if (value.windows !== undefined) {
    requireSandboxObject(value.windows, 'windows');
    rejectUnknownSandboxFields(
      value.windows,
      ['appContainerMode', 'allowLoopback', 'allowAdditiveGrants'],
      'windows.',
    );
    if (
      value.windows.appContainerMode !== undefined &&
      value.windows.appContainerMode !== 'standard' &&
      value.windows.appContainerMode !== 'lpac'
    ) {
      throw new Error('windows.appContainerMode must be lpac or standard');
    }
    validateBooleanFields(value.windows, ['allowLoopback', 'allowAdditiveGrants'], 'windows.');
    config.windows = {};
    if (value.windows.appContainerMode !== undefined) {
      config.windows.appContainerMode = value.windows.appContainerMode;
    }
    if (value.windows.allowLoopback !== undefined) {
      config.windows.allowLoopback = value.windows.allowLoopback;
    }
    if (value.windows.allowAdditiveGrants !== undefined) {
      config.windows.allowAdditiveGrants = value.windows.allowAdditiveGrants;
    }
  }

  return config;
}

function deepMergeSandboxConfig(base, overrides) {
  if (!overrides) return { ...base };

  const shell = overrides.shell;
  const network = overrides.network;
  const filesystem = overrides.filesystem;
  const macos = overrides.macos;
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

  if (base.macos !== undefined || macos !== undefined) {
    result.macos = {
      allowTrustd: macos?.allowTrustd ?? base.macos?.allowTrustd ?? false,
      allowMachLookup: mergeArray(base.macos?.allowMachLookup ?? [], macos?.allowMachLookup),
      allowAppleEvents: macos?.allowAppleEvents ?? base.macos?.allowAppleEvents ?? false,
      allowPty: macos?.allowPty ?? base.macos?.allowPty ?? false,
    };
    const logTag = macos?.logTag ?? base.macos?.logTag;
    if (logTag !== undefined) {
      result.macos.logTag = logTag;
    }
  }

  if (base.windows !== undefined || windows !== undefined) {
    result.windows = {
      appContainerMode: windows?.appContainerMode ?? base.windows?.appContainerMode ?? 'standard',
      allowLoopback: windows?.allowLoopback ?? base.windows?.allowLoopback ?? false,
    };
    const allowAdditiveGrants =
      windows?.allowAdditiveGrants ?? base.windows?.allowAdditiveGrants;
    if (allowAdditiveGrants !== undefined) {
      result.windows.allowAdditiveGrants = allowAdditiveGrants;
    }
  }

  return result;
}


function normalizePathForComparison(filePath) {
  const normalized = normalizePathSeparators(filePath);
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function resolveSelectorForMatch(pattern, baseDirectory) {
  if (isRecord(pattern)) {
    if (typeof pattern.literal === 'string') {
      return {
        canonical: canonicalizePath(pattern.literal, baseDirectory),
        isGlob: false,
      };
    }
    if (typeof pattern.glob === 'string') {
      const isGlob = /[*?[\]]/.test(pattern.glob);
      return {
        canonical: isGlob
          ? canonicalizeGlobPattern(pattern.glob, baseDirectory)
          : canonicalizePath(pattern.glob, baseDirectory),
        isGlob,
      };
    }
  }
  const raw = String(pattern);
  const isGlob = /[*?[\]]/.test(raw);
  return {
    canonical: isGlob
      ? canonicalizeGlobPattern(raw, baseDirectory)
      : canonicalizePath(raw, baseDirectory),
    isGlob,
  };
}

function matchesPathPattern(filePath, patterns, baseDirectory = process.cwd()) {
  if (!Array.isArray(patterns) || patterns.length === 0) return false;
  const abs = normalizePathForComparison(canonicalizePath(filePath, baseDirectory));

  return patterns.some((pattern) => {
    const { canonical, isGlob } = resolveSelectorForMatch(pattern, baseDirectory);
    const absPattern = normalizePathForComparison(canonical);

    if (isGlob) {
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

// Relative write denies apply at the policy base and every effective write root.
function matchesWriteDenyPattern(filePath, patterns, baseDirectory = process.cwd(), writeRoots = []) {
  return matchesPathPattern(
    filePath,
    resolveWriteDenyPatterns(patterns, baseDirectory, writeRoots),
    baseDirectory,
  );
}

function matchPathSpecificity(filePath, patterns, baseDirectory = process.cwd()) {
  if (!Array.isArray(patterns) || patterns.length === 0) return -1;
  let best = -1;
  for (const pattern of patterns) {
    if (!matchesPathPattern(filePath, [pattern], baseDirectory)) continue;
    const { canonical } = resolveSelectorForMatch(pattern, baseDirectory);
    if (canonical.length > best) {
      best = canonical.length;
    }
  }
  return best;
}

function allowCarvesOutDeny(filePath, allowPatterns, denyPatterns, baseDirectory) {
  for (const denyPattern of denyPatterns) {
    if (!matchesPathPattern(filePath, [denyPattern], baseDirectory)) continue;
    const { canonical: denyCanonical } = resolveSelectorForMatch(denyPattern, baseDirectory);
    const carvedOut = allowPatterns.some((allowPattern) => {
      if (!matchesPathPattern(filePath, [allowPattern], baseDirectory)) return false;
      const { canonical: allowCanonical, isGlob: allowIsGlob } = resolveSelectorForMatch(
        allowPattern,
        baseDirectory,
      );
      if (!allowIsGlob) {
        return matchesPathPattern(allowCanonical, [denyPattern], baseDirectory);
      }
      return allowCanonical.length >= denyCanonical.length;
    });
    if (!carvedOut) return false;
  }
  return true;
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
  if (options && options.requireAllowMatch && !matchesPathPattern(filePath, allowPatterns, baseDirectory)) {
    return false;
  }
  return allowCarvesOutDeny(filePath, allowPatterns, denyPatterns, baseDirectory);
}

function isPathWriteAllowed(
  filePath,
  allowWrite,
  denyWrite,
  baseDirectory = process.cwd(),
) {
  const allowPatterns = Array.isArray(allowWrite) ? allowWrite : [];
  if (allowPatterns.length === 0 || !matchesPathPattern(filePath, allowPatterns, baseDirectory)) {
    return false;
  }
  const resolvedDeny = resolveWriteDenyPatterns(denyWrite, baseDirectory, allowPatterns, {
    anchorRootName: false,
  });
  return allowCarvesOutDeny(filePath, allowPatterns, resolvedDeny, baseDirectory);
}

function shouldPromptForWrite(
  filePath,
  allowWrite,
  denyWrite,
  baseDirectory = process.cwd(),
) {
  return !isPathWriteAllowed(filePath, allowWrite, denyWrite, baseDirectory);
}

function evaluateReadAccess(filePath, filesystem = {}, options) {
  const baseDirectory = options?.baseDirectory;
  const allowReadOverrides = Array.isArray(options?.allowReadOverrides)
    ? options.allowReadOverrides
    : [];
  const requireAllowMatch = options?.requireAllowMatch ?? false;

  if (filesystem.denyReadAlways && matchesPathPattern(filePath, filesystem.denyReadAlways, baseDirectory)) {
    return 'deny';
  }

  const effectiveAllowRead = allowReadOverrides.length > 0
    ? mergeArray(filesystem.allowRead ?? [], allowReadOverrides)
    : (filesystem.allowRead ?? []);

  if (isPathReadAllowed(filePath, effectiveAllowRead, filesystem.denyRead ?? [], baseDirectory, { requireAllowMatch })) {
    return 'allow';
  }

  return 'ask';
}

function evaluateWriteAccess(filePath, filesystem = {}, options) {
  const baseDirectory = options?.baseDirectory;
  const allowWriteOverrides = Array.isArray(options?.allowWriteOverrides)
    ? options.allowWriteOverrides
    : [];

  const effectiveAllowWrite = allowWriteOverrides.length > 0
    ? mergeArray(filesystem.allowWrite ?? [], allowWriteOverrides)
    : (filesystem.allowWrite ?? []);

  if (filesystem.denyWriteAlways && matchesWriteDenyPattern(filePath, filesystem.denyWriteAlways, baseDirectory, effectiveAllowWrite)) {
    return 'deny';
  }

  if (isPathWriteAllowed(filePath, effectiveAllowWrite, filesystem.denyWrite ?? [], baseDirectory)) {
    return 'allow';
  }

  return 'ask';
}

function isDomainAllowed(domain, network = {}, allowedDomainsOverrides) {
  if (network.allowNetwork) return true;
  const denied = network.deniedDomains ?? [];
  if (domainMatchesAny(domain, denied)) return false;
  const effectiveAllowed = Array.isArray(allowedDomainsOverrides) && allowedDomainsOverrides.length > 0
    ? mergeArray(network.allowedDomains ?? [], allowedDomainsOverrides)
    : (network.allowedDomains ?? []);
  return domainMatchesAny(domain, effectiveAllowed);
}

function evaluateDomainAccess(domain, network = {}, options) {
  if (network.allowNetwork) return 'allow';
  const overrides = options?.allowedDomainsOverrides;
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

const nativeWriteTools = new Set(['mkdir', 'rm', 'rmdir', 'tee', 'touch', 'truncate', 'unlink']);
const nativeShellTools = new Set(['bash', 'dash', 'fish', 'ksh', 'sh', 'zsh']);
const nativeWriteSyscalls = new Set([
  'chmod',
  'chown',
  'copyfile',
  'link',
  'mkdir',
  'mkdtemp',
  'rename',
  'rmdir',
  'symlink',
  'truncate',
  'unlink',
  'utimes',
  'write',
]);

function commandRedirectsToPath(command, path, cwd) {
  if (typeof command !== 'string') return false;
  const redirects = command.matchAll(
    /(?:[0-9]*>>?|&>>?|>\|)\s*(?:'([^'\r\n]+)'|"([^"\r\n]+)"|\x60([^\x60\r\n]+)\x60|([^\s'"\x60;&|<>]+))/g,
  );
  for (const redirect of redirects) {
    const target = redirect[1] ?? redirect[2] ?? redirect[3] ?? redirect[4];
    if (target !== undefined && normalizePathMatch(target, cwd) === path) return true;
  }
  return false;
}

function extractNativeWriteDeniedPath(output, cwd = process.cwd(), command) {
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

  match = output.match(
    new RegExp(
      String.raw`^([^\s:]+):\s+((?:[a-zA-Z]:[\\/]|\\\\|\/|\.{1,2}[\\/])[^:\r\n]*?):\s+${denial}$`,
      'im',
    ),
  );
  if (match) {
    const tool = basename(match[1]);
    const path = normalizePathMatch(match[2], cwd);
    if (path && nativeWriteTools.has(tool)) return path;
    if (path && nativeShellTools.has(tool) && commandRedirectsToPath(command, path, cwd)) return path;
  }

  match = output.match(
    new RegExp(
      String.raw`(?:EPERM|EACCES):\s*(?:operation not permitted|permission denied),\s*([a-z]+)\s+['"\x60]([^'"\x60\r\n]+)['"\x60]`,
      'i',
    ),
  );
  if (match && nativeWriteSyscalls.has(match[1].toLowerCase())) {
    return normalizePathMatch(match[2], cwd);
  }

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

function extractDeniedPath(output, options) {
  if (typeof output !== 'string') return null;
  const cwd = typeof options?.cwd === 'string' ? options.cwd : process.cwd();
  const command = typeof options?.command === 'string' ? options.command : undefined;
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
  matchesWriteDenyPattern,
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
