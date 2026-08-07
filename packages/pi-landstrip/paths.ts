// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { homedir } from 'node:os';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { realpathSync } from 'node:fs';

import { expandHomePath } from './util.ts';

const HOME = homedir();

const READ_ONLY_TOOLS = new Set(['read', 'grep', 'find', 'ls']);
const PATH_BEARING_TOOLS = new Set(['read', 'write', 'edit', 'grep', 'find', 'ls']);

const DEFAULT_PROTECTED_PATHS = [
  '.git',
  '.config/git',
  '.vscode',
  '.idea',
  '.husky',
  '.cargo',
  '.devcontainer',
  '.yarn',
  '.mvn',
  '.pi',
  '.gitconfig',
  '.gitmodules',
  '.gitignore',
  '.gitattributes',
  '.bashrc',
  '.bash_profile',
  '.bash_login',
  '.bash_aliases',
  '.bash_logout',
  '.zshrc',
  '.zprofile',
  '.zshenv',
  '.zlogin',
  '.zlogout',
  '.profile',
  '.envrc',
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
  '.pnp.cjs',
  '.pnp.loader.mjs',
  '.pnpmfile.cjs',
  'bunfig.toml',
  '.bunfig.toml',
  '.bazelrc',
  '.bazelversion',
  '.bazeliskrc',
  '.pre-commit-config.yaml',
  'lefthook.yml',
  'lefthook.yaml',
  '.lefthook.yml',
  '.lefthook.yaml',
  'gradle-wrapper.properties',
  'maven-wrapper.properties',
  '.devcontainer.json',
  '.ripgreprc',
  'pyrightconfig.json',
  '.mcp.json',
];

export function getDefaultProtectedPaths(): string[] {
  return [...DEFAULT_PROTECTED_PATHS];
}

export function isPathBearingTool(toolName: string): boolean {
  return PATH_BEARING_TOOLS.has(toolName);
}

export function isReadOnlyTool(toolName: string): boolean {
  return READ_ONLY_TOOLS.has(toolName);
}

export function expandHomePattern(pattern: string): string {
  return expandHomePath(pattern);
}

export function resolveInputPath(
  cwd: string,
  inputPath: unknown,
): string | undefined {
  if (typeof inputPath !== 'string') return undefined;
  const expanded = expandHomePath(inputPath);
  return isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded);
}

export function resolvePathForPolicy(path: string): string | undefined {
  try {
    return realpathSync(path);
  } catch {
    let dir = path;
    const segments: string[] = [];
    while (true) {
      try {
        const resolved = realpathSync(dir);
        return resolve(resolved, ...segments);
      } catch {
        const parent = resolve(dir, '..');
        if (parent === dir) break;
        segments.unshift(dir.slice(parent.length + 1));
        dir = parent;
      }
    }
    return undefined;
  }
}

export function isInside(path: string, cwd: string): boolean {
  const rel = relative(cwd, path);
  return rel !== '' && !rel.startsWith('..' + sep) && !isAbsolute(rel);
}

function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

export function matchesDeniedPath(path: string, patterns: readonly string[]): boolean {
  const normalized = path.replace(/\\/g, '/');
  return patterns.some((pattern) => {
    const expanded = expandHomePattern(pattern).replace(/\\/g, '/');
    return wildcardToRegExp(expanded).test(normalized);
  });
}

export function matchesProtectedPath(
  relativePath: string,
  protectedPaths: readonly string[],
): boolean {
  const normalizedPath = relativePath.replace(/\\/g, '/');
  return protectedPaths.some((pattern) => {
    const normalizedPattern = pattern.replace(/\\/g, '/');
    return (
      normalizedPath === normalizedPattern ||
      normalizedPath.startsWith(`${normalizedPattern}/`)
    );
  });
}

export function isProtectedPath(
  path: string,
  cwd: string,
  protectedPaths: readonly string[],
): boolean {
  const resolved = resolvePathForPolicy(path) ?? path;
  const resolvedCwd = resolvePathForPolicy(cwd) ?? cwd;

  if (isInside(resolved, resolvedCwd)) {
    const rel = relative(resolvedCwd, resolved).replace(/\\/g, '/');
    return matchesProtectedPath(rel, protectedPaths);
  }

  const normalizedResolved = resolved.replace(/\\/g, '/');
  const segments = normalizedResolved.split('/').filter(Boolean);
  for (let i = 0; i < segments.length; i++) {
    if (matchesProtectedPath(segments.slice(i).join('/'), protectedPaths)) {
      return true;
    }
  }
  return false;
}

const PROFILE_FILES = new Set([
  resolve(HOME, '.bashrc'),
  resolve(HOME, '.zshrc'),
  resolve(HOME, '.bash_profile'),
  resolve(HOME, '.profile'),
  resolve(HOME, '.bash_login'),
  resolve(HOME, '.bash_logout'),
  resolve(HOME, '.zprofile'),
  resolve(HOME, '.zshenv'),
  resolve(HOME, '.zlogin'),
  resolve(HOME, '.zlogout'),
  '/etc/profile',
  '/etc/environment',
  '/etc/bash.bashrc',
]);

const AUTHORIZED_KEYS_PATH = resolve(HOME, '.ssh/authorized_keys');

function resolveIfExists(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

const PROFILE_FILES_RESOLVED = new Set([...PROFILE_FILES].map(resolveIfExists));
const AUTHORIZED_KEYS_RESOLVED = resolveIfExists(AUTHORIZED_KEYS_PATH);

export function isProfileOrAuthorizedKeysPath(path: string): string | undefined {
  if (PROFILE_FILES.has(path) || PROFILE_FILES_RESOLVED.has(path)) {
    return 'shell profile modification is hard-denied';
  }
  if (path === AUTHORIZED_KEYS_PATH || path === AUTHORIZED_KEYS_RESOLVED) {
    return 'SSH authorized_keys modification is hard-denied';
  }
  return undefined;
}

export function isSafetyControlPath(path: string, cwd: string): boolean {
  const normalized = path.replace(/\\/g, '/');
  const file = normalized.split('/').pop() ?? '';
  if (
    normalized.endsWith('/.pi/sandbox.json') ||
    normalized.endsWith('/.pi/settings.json') ||
    normalized.endsWith('/sandbox.json')
  ) {
    return true;
  }
  if (normalized.includes('/.pi/extensions/') && file.includes('landstrip')) {
    return true;
  }
  if (normalized.includes('/.pi/') && file.startsWith('landstrip')) return true;
  if (
    normalized.includes('/pi-landstrip/') ||
    (isInside(path, cwd) && file.includes('landstrip'))
  ) {
    return true;
  }
  return false;
}

export function shellPathTokenToPath(
  token: string,
  cwd: string,
): string | undefined {
  let value = token.trim();
  if (!value || value === '-' || value.startsWith('&')) return undefined;
  value = value
    .replace(/^\$HOME(?=\/|$)/, HOME)
    .replace(/^\$\{HOME\}(?=\/|$)/, HOME);
  if (value.startsWith('~/')) value = resolve(HOME, value.slice(2));
  return isAbsolute(value) ? resolve(value) : resolve(cwd, value);
}