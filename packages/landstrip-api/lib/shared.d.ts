// SPDX-License-Identifier: Apache-2.0

import type {
  LandstripControlResponse,
  LandstripFilesystemPolicy,
  LandstripFilesystemTrap,
  LandstripNetworkPolicy,
  LandstripNetworkTrap,
  LandstripPolicy,
  LandstripTrap,
  LandstripWindowsPolicy,
  SandboxConfig,
  SandboxConfigFile,
  SandboxConfigOverrides,
  SandboxFilesystemConfig,
  SandboxFilesystemConfigFile,
  SandboxNetworkConfig,
  SandboxNetworkConfigFile,
  SandboxShellConfig,
  SandboxShellConfigFile,
  SandboxWindowsConfig,
  SandboxWindowsConfigFile,
  ShellReadAccess,
} from './index.js';

export type LandstripDenialTrap = LandstripFilesystemTrap | LandstripNetworkTrap;

export type {
  SandboxConfig,
  SandboxConfigFile,
  SandboxConfigOverrides,
  SandboxFilesystemConfig,
  SandboxFilesystemConfigFile,
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

export function isQueryTrap(trap: LandstripTrap): trap is LandstripDenialTrap;

export function formatLandstripTrap(trap: LandstripTrap): string;

export function formatLandstripTraps(traps: LandstripTrap[]): string;

export function controlResponseLine(
  queryId: string,
  action: LandstripControlResponse['action'],
): string;


export interface BuildLandstripPolicyOptions {
  filesystem?: LandstripFilesystemPolicy;
  network?: LandstripNetworkPolicy;
  windows?: LandstripWindowsPolicy;
  baseDirectory?: string;
  httpProxyPort?: number | null;
  socksProxyPort?: number | null;
}

export function resolveFilesystemPatterns(
  patterns: string[] | undefined,
  baseDirectory?: string,
): string[];

export function resolveFilesystemPolicy(
  filesystem?: LandstripFilesystemPolicy,
  baseDirectory?: string,
): LandstripFilesystemPolicy;

export function buildLandstripPolicy(
  options: BuildLandstripPolicyOptions,
): LandstripPolicy;

export function serializeLandstripPolicy(policy: LandstripPolicy): string;

export function writeLandstripPolicyFile(
  policy: LandstripPolicy,
  prefix?: string,
): { dir: string; path: string };


export function mergeArray(base: string[], override?: string[]): string[];

export function parseSandboxConfig(value: unknown): SandboxConfigFile;

export function deepMergeSandboxConfig<T extends SandboxConfig = SandboxConfig>(
  base: T,
  overrides?: SandboxConfigFile,
): T;


export type PathAccessDecision = 'allow' | 'ask' | 'deny' | 'denyAlways';

export type DomainAccessDecision = 'allow' | 'ask' | 'deny';

export interface EvaluateReadOptions {
  baseDirectory?: string;
  allowReadOverrides?: string[];
  requireAllowMatch?: boolean;
}

export interface EvaluateWriteOptions {
  baseDirectory?: string;
  allowWriteOverrides?: string[];
}

export interface EvaluateDomainOptions {
  allowedDomainsOverrides?: string[];
}

export function matchesPathPattern(
  filePath: string,
  patterns: string[],
  baseDirectory?: string,
): boolean;

export function matchPathSpecificity(
  filePath: string,
  patterns: string[],
  baseDirectory?: string,
): number;

export function isPathReadAllowed(
  filePath: string,
  allowRead: string[],
  denyRead: string[],
  baseDirectory?: string,
  options?: { requireAllowMatch?: boolean },
): boolean;

export function isPathWriteAllowed(
  filePath: string,
  allowWrite: string[],
  baseDirectory?: string,
): boolean;

export function shouldPromptForWrite(
  filePath: string,
  allowWrite: string[],
  baseDirectory?: string,
): boolean;

export function evaluateReadAccess(
  filePath: string,
  filesystem: SandboxFilesystemConfig | SandboxFilesystemConfigFile | SandboxConfig | SandboxConfigFile,
  options?: EvaluateReadOptions | string,
  allowReadOverrides?: string[],
): 'allow' | 'ask' | 'deny';

export function evaluateWriteAccess(
  filePath: string,
  filesystem: SandboxFilesystemConfig | SandboxFilesystemConfigFile | SandboxConfig | SandboxConfigFile,
  options?: EvaluateWriteOptions | string,
  allowWriteOverrides?: string[],
): PathAccessDecision;

export function isDomainAllowed(
  domain: string,
  network: SandboxNetworkConfig | SandboxNetworkConfigFile | SandboxConfig | SandboxConfigFile,
  allowedDomainsOverrides?: string[],
): boolean;

export function evaluateDomainAccess(
  domain: string,
  network: SandboxNetworkConfig | SandboxNetworkConfigFile | SandboxConfig | SandboxConfigFile,
  options?: EvaluateDomainOptions | string[],
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

export function extractNativeWriteDeniedPath(output: string, cwd?: string): string | null;

export interface ExtractDeniedPathOptions {
  cwd?: string;
  command?: string;
}

export function extractDeniedPath(
  output: string,
  options?: ExtractDeniedPathOptions | string,
  command?: string,
): string | null;
