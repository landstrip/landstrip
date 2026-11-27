// SPDX-License-Identifier: Apache-2.0

/** The kernel layer an event is attributed to. */
export type LandstripMechanism =
  | 'landlock'
  | 'seccomp'
  | 'kvm'
  | 'namespace'
  | 'seatbelt'
  | 'appcontainer'
  | 'windowsuser';

/**
 * `query` holds the syscall until the launcher answers with a
 * {@link LandstripControlResponse}; `info` is terminal. Queries need a socket on
 * `--trap`, and only the Linux broker raises them.
 */
export type LandstripTrapState = 'query' | 'info';

/** Why a filesystem access was mediated. */
export type LandstripTrapReason = 'allow_miss' | 'deny_match';

/** A filesystem access the policy denies. */
export interface LandstripFilesystemTrap {
  kind: 'filesystem';
  code: 'FILESYSTEM_DENIED';
  state: LandstripTrapState;
  /** Nonzero decimal `u64` present on `state: "query"` traps. */
  query_id?: string;
  operation: 'read' | 'write';
  /** The resolved path. */
  path: string;
  /** The path the tool asked for, when distinct from `path`. */
  requested_path?: string;
  syscall: string;
  errno: string;
  flags?: string[];
  reason: LandstripTrapReason;
  mechanism: 'kvm' | 'seccomp';
  pid: number;
  exe?: string;
  cwd?: string;
}

/** A network access the policy denies. */
export interface LandstripNetworkTrap {
  kind: 'network';
  code: 'NETWORK_DENIED';
  state: LandstripTrapState;
  /** Nonzero decimal `u64` present on `state: "query"` traps. */
  query_id?: string;
  operation: 'connect' | 'bind';
  /** `address:port` or Unix socket path. */
  target: string;
  syscall: string;
  errno: string;
  mechanism: 'kvm' | 'seccomp';
  pid: number;
  exe?: string;
  cwd?: string;
}

/** The sandbox was installed but the tool did not start. */
export interface LandstripLaunchTrap {
  kind: 'launch';
  code: 'LAUNCH_FAILED';
  program: string;
  /** Absent where the platform has no POSIX errno for the failure. */
  errno?: string;
  message: string;
}

/** The command line was rejected. Reaches stderr only; landstrip exits 2. */
export interface LandstripUsageTrap {
  kind: 'usage';
  code: 'USAGE_ERROR';
  message: string;
}

/** A policy the platform sandbox cannot enforce, rejected before launch. */
export type LandstripPolicyErrorCode =
  | 'POLICY_PARSE_FAILED'
  | 'POLICY_IO_FAILED'
  | 'POLICY_UNRESTRICTED_READ'
  | 'POLICY_DENY_READ_ALWAYS_UNSUPPORTED'
  | 'POLICY_DENY_WRITE_ALWAYS_UNSUPPORTED'
  | 'POLICY_LOCAL_BINDING_UNSUPPORTED'
  | 'POLICY_UNIX_SOCKET_UNSUPPORTED'
  | 'POLICY_UNIX_SOCKET_PATH'
  | 'POLICY_INVALID_PORT'
  | 'POLICY_EMPTY_PATH'
  | 'POLICY_INVALID_MACH_LOOKUP'
  | 'POLICY_INVALID_LOG_TAG'
  | 'POLICY_HOME_UNAVAILABLE'
  | 'POLICY_TRAVERSAL_DEPTH'
  | 'POLICY_GLOB_TOO_LONG'
  | 'POLICY_SELECTOR_LIMIT';
/** The stage that failed before the tool ran. */
export type LandstripInternalCode =
  | LandstripPolicyErrorCode
  | 'SANDBOX_SETUP_FAILED'
  | 'SUPERVISE_FAILED'
  | 'HOST_JOB_INCOMPATIBLE'
  | 'PLATFORM_UNSUPPORTED'
  | 'INTEGER_TOO_LARGE'
  | 'INTERNAL_ERROR';

/** Everything that fails before the tool runs. */
export type LandstripInternalTrap =
  | {
      kind: 'internal';
      code: 'SANDBOX_SETUP_FAILED';
      mechanism: LandstripMechanism;
      message: string;
    }
  | {
      kind: 'internal';
      code: Exclude<LandstripInternalCode, 'SANDBOX_SETUP_FAILED'>;
      mechanism?: never;
      message: string;
    };

/**
 * One landstrip event. Failure and completed-denial events are written to
 * stderr; pending Linux query events are written only to `--trap`.
 */
export type LandstripTrap =
  | LandstripFilesystemTrap
  | LandstripNetworkTrap
  | LandstripLaunchTrap
  | LandstripUsageTrap
  | LandstripInternalTrap;

/** Every code landstrip reports, across all trap kinds. */
export type LandstripCode = LandstripTrap['code'];

/**
 * The answer to a `state: "query"` trap, written back to the trap socket as a
 * blank-line-terminated `key=value` stanza. `query_id` is an opaque nonzero
 * decimal `u64` copied verbatim from the trap. An unanswered query holds the
 * sandboxed syscall.
 */
export interface LandstripControlResponse {
  query_id: string;
  action: 'allow' | 'deny';
}

export type LandstripPathSelector =
  | string
  | { literal: string }
  | { glob: string };

export interface LandstripFilesystemPolicy {
  denyRead?: LandstripPathSelector[];
  denyReadAlways?: LandstripPathSelector[];
  allowRead?: LandstripPathSelector[];
  allowWrite?: LandstripPathSelector[];
  denyWrite?: LandstripPathSelector[];
  denyWriteAlways?: LandstripPathSelector[];
}

export interface LandstripNetworkPolicy {
  allowNetwork?: boolean;
  allowLocalBinding?: boolean;
  allowAllUnixSockets?: boolean;
  allowUnixSockets?: LandstripPathSelector[];
  httpProxyPort?: number;
  socksProxyPort?: number;
}

export interface LandstripDarwinPolicy {
  /** Seatbelt log correlation tag: nonempty, without double quotes, backslashes, ASCII controls or DEL; not null. */
  logTag?: string;
  allowTrustd?: boolean;
  allowMachLookup?: string[];
  allowAppleEvents?: boolean;
  allowPty?: boolean;
}

export type LandstripWindowsAppContainerMode = 'lpac' | 'standard';

export interface LandstripWindowsPolicy {
  appContainerMode?: LandstripWindowsAppContainerMode;
  allowLoopback?: boolean;
  /** Accept the additive grants the restricted-user backend applies on top of the sandbox account's own rights. */
  allowAdditiveGrants?: boolean;
}

export interface LandstripPolicy {
  filesystem?: LandstripFilesystemPolicy;
  network?: LandstripNetworkPolicy;
  macos?: LandstripDarwinPolicy;
  windows?: LandstripWindowsPolicy;
}

export type SandboxPlatform = 'linux' | 'macos' | 'windows';

export interface FeatureCapabilities {
  filesystemTiers: string[];
  networkMediation: boolean;
  unixSocketFiltering: boolean;
  processIsolation: boolean;
}

export interface DoctorReport {
  ok: boolean;
  platform: SandboxPlatform;
  backend?: 'container' | 'machine';
  supported: FeatureCapabilities;
  available: FeatureCapabilities;
  error?: string;
}

export interface SandboxFilesystemConfig {
  denyRead: string[];
  denyReadAlways: string[];
  allowRead: string[];
  allowWrite: string[];
  denyWrite: string[];
  denyWriteAlways: string[];
}

export type ShellReadAccess = 'host' | 'policy';

export interface SandboxShellConfig {
  readAccess: ShellReadAccess;
}

export interface SandboxNetworkConfig {
  allowNetwork: boolean;
  allowLocalBinding: boolean;
  allowAllUnixSockets: boolean;
  allowUnixSockets: string[];
  allowedDomains: string[];
  deniedDomains: string[];
}

export type LandstripLinuxBackend = 'auto' | 'container' | 'machine';

export interface SandboxLinuxConfig {
  backend: LandstripLinuxBackend;
}
export interface SandboxDarwinConfig {
  /** Optional Seatbelt log correlation tag; same restrictions as LandstripDarwinPolicy.logTag. */
  logTag?: string;
  allowTrustd: boolean;
  allowMachLookup: string[];
  allowAppleEvents: boolean;
  allowPty: boolean;
}

export interface SandboxWindowsConfig {
  appContainerMode: LandstripWindowsAppContainerMode;
  allowLoopback: boolean;
  /** Accept the additive grants the restricted-user backend applies on top of the sandbox account's own rights. */
  allowAdditiveGrants?: boolean;
}

export interface SandboxConfig {
  enabled: boolean;
  shell?: SandboxShellConfig;
  network: SandboxNetworkConfig;
  filesystem: SandboxFilesystemConfig;
  linux?: SandboxLinuxConfig;
  macos?: SandboxDarwinConfig;
  windows?: SandboxWindowsConfig;
}

export type SandboxFilesystemConfigFile = Partial<SandboxFilesystemConfig>;
export type SandboxShellConfigFile = Partial<SandboxShellConfig>;
export type SandboxNetworkConfigFile = Partial<SandboxNetworkConfig>;
export type SandboxLinuxConfigFile = Partial<SandboxLinuxConfig>;
export type SandboxDarwinConfigFile = Partial<SandboxDarwinConfig>;
export type SandboxWindowsConfigFile = Partial<SandboxWindowsConfig>;

export interface SandboxConfigFile {
  enabled?: boolean;
  shell?: SandboxShellConfigFile;
  network?: SandboxNetworkConfigFile;
  filesystem?: SandboxFilesystemConfigFile;
  linux?: SandboxLinuxConfigFile;
  macos?: SandboxDarwinConfigFile;
  windows?: SandboxWindowsConfigFile;
}

export type SandboxConfigOverrides = SandboxConfigFile;

export type {
  PathAccessDecision,
  DomainAccessDecision,
  EvaluateReadOptions,
  EvaluateWriteOptions,
  EvaluateDomainOptions,
  ExtractDeniedPathOptions,
} from './shared.js';
/**
 * Canonical path to the native landstrip binary in an official Landstrip package.
 *
 * @throws if the target is unsupported, the binary is missing, or ownership cannot be verified.
 */
export function binaryPath(platform?: string, arch?: string): string;

/** Name of the binary package for the given platform. */
export function packageName(platform?: string, arch?: string): string;

export type {
  ProxyPortRange,
  FilterProxyOptions,
  FilterProxyHandle,
  ProxyEnvironmentVariable,
  ProxyCredentials,
  CreateProxyEnvironmentOptions,
} from './proxy';
