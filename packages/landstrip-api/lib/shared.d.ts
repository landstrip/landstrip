// SPDX-License-Identifier: Apache-2.0

import type {
  DoctorReport,
  FeatureCapabilities,
  LandstripControlResponse,
  LandstripDarwinPolicy,
  LandstripFilesystemPolicy,
  LandstripFilesystemTrap,
  LandstripNetworkPolicy,
  LandstripNetworkTrap,
  LandstripPathSelector,
  LandstripPolicy,
  LandstripTrap,
  LandstripWindowsPolicy,
  SandboxConfig,
  SandboxConfigFile,
  SandboxConfigOverrides,
  SandboxDarwinConfig,
  SandboxDarwinConfigFile,
  SandboxFilesystemConfig,
  SandboxFilesystemConfigFile,
  SandboxImplementation,
  SandboxNetworkConfig,
  SandboxNetworkConfigFile,
  SandboxShellConfig,
  SandboxShellConfigFile,
  SandboxWindowsConfig,
  SandboxWindowsConfigFile,
  ShellReadAccess,
} from './index.js';

export type LandstripDenialTrap = LandstripFilesystemTrap | LandstripNetworkTrap;
export type LandstripQueryTrap = LandstripDenialTrap & { state: 'query' };

export type {
  DoctorReport,
  FeatureCapabilities,
  LandstripDarwinPolicy,
  LandstripPathSelector,
  SandboxConfig,
  SandboxConfigFile,
  SandboxConfigOverrides,
  SandboxDarwinConfig,
  SandboxDarwinConfigFile,
  SandboxFilesystemConfig,
  SandboxFilesystemConfigFile,
  SandboxImplementation,
  SandboxNetworkConfig,
  SandboxNetworkConfigFile,
  SandboxShellConfig,
  SandboxShellConfigFile,
  SandboxWindowsConfig,
  SandboxWindowsConfigFile,
  ShellReadAccess,
};

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

export function canonicalizeHost(host: string): string | null;

export function domainMatchesPattern(domain: string, pattern: string): boolean;

export function domainMatchesAny(domain: string, patterns: string[]): boolean;

export function allowsAllDomains(allowedDomains: string[]): boolean;

export function decodeLandstripTrap(value: unknown): LandstripTrap | null;

export function parseTrapLine(line: string): LandstripTrap | null;

export function parseLandstripTraps(output: string): LandstripTrap[];

export function isFilesystemTrap(trap: LandstripTrap): trap is LandstripFilesystemTrap;

export function isDenialTrap(trap: LandstripTrap): trap is LandstripDenialTrap;

export function isQueryTrap(trap: LandstripTrap): trap is LandstripQueryTrap;

export function formatLandstripTrap(trap: LandstripTrap): string;

export function formatLandstripTraps(traps: LandstripTrap[]): string;

export function controlResponseLine(
  queryId: string,
  action: LandstripControlResponse['action'],
): string;


export interface BuildLandstripPolicyOptions {
  filesystem?: LandstripFilesystemPolicy | undefined;
  network?: LandstripNetworkPolicy | undefined;
  macos?: LandstripDarwinPolicy | undefined;
  windows?: LandstripWindowsPolicy | undefined;
  baseDirectory?: string | undefined;
  httpProxyPort?: number | null | undefined;
  socksProxyPort?: number | null | undefined;
}

export function resolveFilesystemPatterns(
  patterns: LandstripPathSelector[] | undefined,
  baseDirectory?: string,
): LandstripPathSelector[];
export function resolveFilesystemPolicy(
  filesystem?: LandstripFilesystemPolicy,
  baseDirectory?: string,
): LandstripFilesystemPolicy;

/** Forwards macos.logTag; throws if it is empty, non-string, or contains a double quote, backslash, ASCII control or DEL. */
export function buildLandstripPolicy(
  options: BuildLandstripPolicyOptions,
): LandstripPolicy;

export function serializeLandstripPolicy(policy: LandstripPolicy): string;

export function writeLandstripPolicyFile(
  policy: LandstripPolicy,
  prefix?: string,
): { dir: string; path: string };


export function mergeArray<T = string>(base: T[], override?: T[]): T[];
/** Parses sandbox settings, validating macos.logTag with the same rules as buildLandstripPolicy (null is invalid). */
export function parseSandboxConfig(value: unknown): SandboxConfigFile;

/** Merges arrays and applies override scalar precedence, including macos.logTag. */
export function deepMergeSandboxConfig<T extends SandboxConfig = SandboxConfig>(
  base: T,
  overrides?: SandboxConfigFile,
): T;


export type PathAccessDecision = 'allow' | 'ask' | 'deny' | 'denyAlways';

export type DomainAccessDecision = 'allow' | 'ask' | 'deny';

export interface EvaluateReadOptions {
  baseDirectory?: string | undefined;
  allowReadOverrides?: string[] | undefined;
  requireAllowMatch?: boolean | undefined;
}

export interface EvaluateWriteOptions {
  baseDirectory?: string | undefined;
  allowWriteOverrides?: string[] | undefined;
}

export interface EvaluateDomainOptions {
  allowedDomainsOverrides?: string[] | undefined;
}

export function matchesPathPattern(
  filePath: string,
  patterns: LandstripPathSelector[],
  baseDirectory?: string,
): boolean;

// Relative write denies apply at the policy base and every effective write root.
export function matchesWriteDenyPattern(
  filePath: string,
  patterns: LandstripPathSelector[],
  baseDirectory?: string,
  writeRoots?: LandstripPathSelector[],
): boolean;

export function matchPathSpecificity(
  filePath: string,
  patterns: LandstripPathSelector[],
  baseDirectory?: string,
): number;

export function isPathReadAllowed(
  filePath: string,
  allowRead: LandstripPathSelector[],
  denyRead: LandstripPathSelector[],
  baseDirectory?: string,
  options?: { requireAllowMatch?: boolean },
): boolean;

export function isPathWriteAllowed(
  filePath: string,
  allowWrite: LandstripPathSelector[],
  baseDirectory?: string,
): boolean;

export function shouldPromptForWrite(
  filePath: string,
  allowWrite: LandstripPathSelector[],
  baseDirectory?: string,
): boolean;
export function evaluateReadAccess(
  filePath: string,
  filesystem: SandboxFilesystemConfig | SandboxFilesystemConfigFile,
  options?: EvaluateReadOptions,
): 'allow' | 'ask' | 'deny';

export function evaluateWriteAccess(
  filePath: string,
  filesystem: SandboxFilesystemConfig | SandboxFilesystemConfigFile,
  options?: EvaluateWriteOptions,
): PathAccessDecision;

export function isDomainAllowed(
  domain: string,
  network: SandboxNetworkConfig | SandboxNetworkConfigFile,
  allowedDomainsOverrides?: string[],
): boolean;

export function evaluateDomainAccess(
  domain: string,
  network: SandboxNetworkConfig | SandboxNetworkConfigFile,
  options?: EvaluateDomainOptions,
): DomainAccessDecision;


export function normalizeBlockedPath(filePath: string, cwd?: string): string;

export function extractTrapBlockedPath(
  trapOutput: string,
  cwd?: string,
  operation?: 'read' | 'write',
): string | null;
export function extractDomainsFromCommand(command: string): string[];

export function extractCandidatePaths(command: string): string[];

export function extractNativeDeniedPath(output: string, cwd?: string): string | null;

export function extractNativeWriteDeniedPath(
  output: string,
  cwd?: string,
  command?: string,
): string | null;

export interface ExtractDeniedPathOptions {
  cwd?: string | undefined;
  command?: string | undefined;
}

export function extractDeniedPath(output: string, options?: ExtractDeniedPathOptions): string | null;
