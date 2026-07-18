// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { ChildProcess, SpawnOptions } from 'node:child_process';

import {
  createBashToolDefinition,
  type ExtensionAPI,
  type ExtensionContext,
} from '@earendil-works/pi-coding-agent';

import type { RpcChildProcess } from './rpc-process.ts';

export const LANDSTRIP_CONTEXT_ENV = 'LANDSTRIP_CONTEXT';
export const LANDSTRIP_RUNTIME_VERSION = 1;

const RUNTIME_REGISTER_EVENT = 'landstrip:runtime:register:v1';
const RUNTIME_DISCOVER_EVENT = 'landstrip:runtime:discover:v1';

export type LandstripSandboxState = 'enabled' | 'disabled' | 'unavailable';
export type LandstripBashTool = ReturnType<typeof createBashToolDefinition>;

export interface LandstripContextV1 {
  readonly version: 1;
  readonly host: 'pi';
  readonly role: 'primary' | 'subagent';
  readonly sandbox: LandstripSandboxState;
  readonly cwd: string;
  readonly sessionId?: string;
  readonly taskId?: string;
  readonly parentTaskId?: string;
  readonly agent?: string;
  readonly depth: number;
}

export interface LandstripWorkerExtension {
  readonly id: string;
  readonly entry: string;
}

export interface LandstripProcessOptions {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly ctx: ExtensionContext;
  readonly readPaths?: readonly string[];
  readonly writePaths?: readonly string[];
  readonly signal?: AbortSignal;
}

export interface LandstripPreparedProcess {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly spawn: LandstripSpawn;
  dispose(): Promise<void>;
}

export type LandstripSpawn = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => ChildProcess | RpcChildProcess;

export type LandstripEvent =
  | { readonly type: 'sandbox.changed'; readonly context: LandstripContextV1 }
  | { readonly type: 'subagent.start'; readonly context: LandstripContextV1 }
  | {
      readonly type: 'subagent.end';
      readonly context: LandstripContextV1;
      readonly status: 'completed' | 'cancelled' | 'error';
    };

export interface PiLandstripRuntimeV1 {
  readonly version: 1;
  getContext(ctx?: ExtensionContext): LandstripContextV1;
  createBashTool(cwd: string, ctx?: ExtensionContext): LandstripBashTool;
  prepareProcess(options: LandstripProcessOptions): Promise<LandstripPreparedProcess>;
  registerWorkerExtension(extension: LandstripWorkerExtension): () => void;
  getWorkerExtensions(): readonly LandstripWorkerExtension[];
  on<T extends LandstripEvent['type']>(
    type: T,
    handler: (event: Extract<LandstripEvent, { type: T }>) => void,
  ): () => void;
}

interface RuntimeRegistration {
  readonly version: 1;
  readonly runtime: PiLandstripRuntimeV1;
}

interface RuntimeDiscovery {
  readonly version: 1;
  register(runtime: PiLandstripRuntimeV1): void;
}

interface EventBusLike {
  emit(channel: string, data: unknown): void;
  on(channel: string, handler: (data: unknown) => void): () => void;
}

function eventBus(pi: ExtensionAPI): EventBusLike | undefined {
  return (pi as ExtensionAPI & { events?: EventBusLike }).events;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isRuntime(value: unknown): value is PiLandstripRuntimeV1 {
  return (
    isRecord(value) &&
    value.version === LANDSTRIP_RUNTIME_VERSION &&
    typeof value.getContext === 'function' &&
    typeof value.createBashTool === 'function' &&
    typeof value.prepareProcess === 'function' &&
    typeof value.registerWorkerExtension === 'function' &&
    typeof value.getWorkerExtensions === 'function' &&
    typeof value.on === 'function'
  );
}

export function useLandstrip(
  pi: ExtensionAPI,
  callback: (runtime: PiLandstripRuntimeV1) => void,
): () => void {
  const events = eventBus(pi);
  if (!events) return () => undefined;

  let current: PiLandstripRuntimeV1 | undefined;
  const register = (runtime: PiLandstripRuntimeV1): void => {
    if (runtime === current) return;
    current = runtime;
    callback(runtime);
  };
  const unsubscribe = events.on(RUNTIME_REGISTER_EVENT, (value) => {
    if (!isRecord(value) || value.version !== LANDSTRIP_RUNTIME_VERSION) return;
    if (isRuntime(value.runtime)) register(value.runtime);
  });
  events.emit(RUNTIME_DISCOVER_EVENT, {
    version: LANDSTRIP_RUNTIME_VERSION,
    register,
  } satisfies RuntimeDiscovery);
  return unsubscribe;
}

export function publishLandstripRuntime(
  pi: ExtensionAPI,
  runtime: PiLandstripRuntimeV1,
): () => void {
  const events = eventBus(pi);
  if (!events) return () => undefined;

  const unsubscribe = events.on(RUNTIME_DISCOVER_EVENT, (value) => {
    if (!isRecord(value) || value.version !== LANDSTRIP_RUNTIME_VERSION) return;
    if (typeof value.register === 'function') value.register(runtime);
  });
  events.emit(RUNTIME_REGISTER_EVENT, {
    version: LANDSTRIP_RUNTIME_VERSION,
    runtime,
  } satisfies RuntimeRegistration);
  return unsubscribe;
}

export function encodeLandstripContext(context: LandstripContextV1): string {
  return Buffer.from(JSON.stringify(context)).toString('base64url');
}

export function contextFromEnvironment(
  env: NodeJS.ProcessEnv = process.env,
): LandstripContextV1 | undefined {
  const encoded = env[LANDSTRIP_CONTEXT_ENV];
  if (!encoded) return undefined;

  try {
    const value: unknown = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (
      !isRecord(value) ||
      value.version !== LANDSTRIP_RUNTIME_VERSION ||
      value.host !== 'pi' ||
      value.role !== 'subagent' ||
      !['enabled', 'disabled', 'unavailable'].includes(String(value.sandbox)) ||
      typeof value.cwd !== 'string' ||
      !Number.isInteger(value.depth) ||
      Number(value.depth) < 0 ||
      ['sessionId', 'taskId', 'parentTaskId', 'agent'].some(
        (key) => value[key] !== undefined && typeof value[key] !== 'string',
      )
    ) {
      return undefined;
    }
    return value as unknown as LandstripContextV1;
  } catch {
    return undefined;
  }
}
