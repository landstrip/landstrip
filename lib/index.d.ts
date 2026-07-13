// SPDX-License-Identifier: Apache-2.0

/** The kernel layer an event is attributed to. */
export type LandstripMechanism =
  | 'landlock'
  | 'seccomp'
  | 'seatbelt'
  | 'appcontainer';

/**
 * `query` holds the syscall until the launcher answers with a
 * {@link LandstripControlResponse}; `info` is terminal. Queries need a socket on
 * `--trap-fd`, and only the Linux broker raises them.
 */
export type LandstripTrapState = 'query' | 'info';

/** Why a filesystem access was mediated. */
export type LandstripTrapReason = 'allow_miss' | 'deny_match';

export interface LandstripProcess {
  pid: number;
  exe: string | null;
  cwd: string | null;
}

/** A filesystem access the policy denies. */
export interface LandstripFilesystemTrap {
  kind: 'filesystem';
  code: 'FILESYSTEM_DENIED';
  state: LandstripTrapState;
  /** Decimal `u64`; `"0"` marks a terminal `info` event. */
  query_id: string;
  operation: 'read' | 'write';
  /** The resolved path. */
  path: string;
  /** The path the tool asked for, before resolution. */
  requested_path: string;
  syscall: string;
  errno: string;
  flags: string[];
  reason: LandstripTrapReason;
  /** The policy edit that would permit this access. */
  suggested_grant: { allowRead?: string; allowWrite?: string };
  process: LandstripProcess;
  mechanism: 'seccomp';
}

/** A network access the policy denies. */
export interface LandstripNetworkTrap {
  kind: 'network';
  code: 'NETWORK_DENIED';
  state: LandstripTrapState;
  /** Decimal `u64`; `"0"` marks a terminal `info` event. */
  query_id: string;
  operation: 'connect' | 'bind';
  /** `address:port`. */
  target: string;
  syscall: string;
  errno: string;
  mechanism: 'seccomp';
  process: LandstripProcess;
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
  | 'POLICY_TCP_BIND_UNSUPPORTED'
  | 'POLICY_UNIX_SOCKET_UNSUPPORTED'
  | 'POLICY_UNIX_SOCKET_PATH'
  | 'POLICY_DENY_WRITE_SYMLINK_ANCESTOR'
  | 'POLICY_INVALID_PORT'
  | 'POLICY_EMPTY_PATH'
  | 'POLICY_HOME_UNAVAILABLE'
  | 'POLICY_TRAVERSAL_DEPTH';

/** The stage that failed before the tool ran. */
export type LandstripInternalCode =
  | LandstripPolicyErrorCode
  | 'SANDBOX_SETUP_FAILED'
  | 'SUPERVISE_FAILED'
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
 * stderr; pending Linux query events are written only to `--trap-fd`.
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
 * The answer to a `state: "query"` trap, written back to the trap socket as one
 * JSON line. `query_id` is an opaque decimal `u64` copied verbatim from the
 * trap. An unanswered query holds the sandboxed syscall.
 */
export interface LandstripControlResponse {
  query_id: string;
  action: 'allow' | 'deny';
}

/**
 * Path to the native landstrip binary for the running platform.
 *
 * @throws if the platform is unsupported, or the binary package is not installed.
 */
export function binaryPath(platform?: string, arch?: string): string;

/** Name of the binary package for the given platform. */
export function packageName(platform?: string, arch?: string): string;
