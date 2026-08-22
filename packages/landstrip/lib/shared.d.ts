// SPDX-License-Identifier: Apache-2.0

import type {
  LandstripControlResponse,
  LandstripFilesystemTrap,
  LandstripNetworkTrap,
  LandstripTrap,
} from './index.js';

export type LandstripDenialTrap = LandstripFilesystemTrap | LandstripNetworkTrap;

export function isRecord(value: unknown): value is Record<string, unknown>;

export function expandHomePath(path: string): string;

export function expandPath(filePath: string, baseDirectory: string): string;

export function canonicalizePath(filePath: string, baseDirectory: string): string;

export function canonicalizeGlobPattern(pattern: string, baseDirectory: string): string;

export function normalizePathSeparators(path: string): string;

export function globToRegExp(globPattern: string): RegExp;

export function pathUnderDirectory(filePath: string, dir: string): boolean;

export function sessionAllows(prefixes: Set<string>, filePath: string): boolean;

export function sessionScopeFor(filePath: string, baseDirectory: string): string;

export function domainMatchesPattern(domain: string, pattern: string): boolean;

export function domainMatchesAny(domain: string, patterns: string[]): boolean;

export function allowsAllDomains(allowedDomains: string[]): boolean;

export function decodeLandstripTrap(value: unknown): LandstripTrap | null;

export function parseTrapLine(line: string): LandstripTrap | null;

export function parseLandstripTraps(output: string): LandstripTrap[];

export function isFilesystemTrap(trap: LandstripTrap): trap is LandstripFilesystemTrap;

export function isDenialTrap(trap: LandstripTrap): trap is LandstripDenialTrap;

export function isQueryTrap(trap: LandstripTrap): trap is LandstripDenialTrap;

export function formatLandstripTrap(trap: LandstripTrap): string;

export function formatLandstripTraps(traps: LandstripTrap[]): string;

export function controlResponseLine(
  queryId: string,
  action: LandstripControlResponse['action'],
): string;
