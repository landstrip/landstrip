// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { spawn, type SpawnOptions } from 'node:child_process';
import { Duplex } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';

import { formatError, isRecord } from './util.ts';
import type { LandstripRpcChildProcess } from './api.ts';
import { WORKER_AUTH_FD } from './worker-auth-channel.ts';

export type RpcRecord = Readonly<Record<string, unknown>>;

export interface RpcResponse extends RpcRecord {
  readonly type: 'response';
  readonly id: string;
  readonly command: string;
  readonly success: boolean;
  readonly data?: unknown;
  readonly error?: string;
}

export interface ExtensionUiRequest extends RpcRecord {
  readonly type: 'extension_ui_request';
  readonly id: string;
  readonly method: string;
}

export type ExtensionUiResult =
  | { readonly value: string }
  | { readonly confirmed: boolean }
  | { readonly cancelled: true }
  | void;

export type RpcChildProcess = LandstripRpcChildProcess;

export type RpcSpawn = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => RpcChildProcess;

export interface RpcProcessOptions {
  readonly command: string;
  readonly args?: readonly string[];
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly spawn?: RpcSpawn;
  /** Private auth transport on fd 4; never part of the public RPC protocol. */
  readonly onAuthPipe?: (pipe: Duplex) => () => void;
  readonly onExtensionUiRequest?: (
    request: ExtensionUiRequest,
  ) => ExtensionUiResult | Promise<ExtensionUiResult>;
  readonly requestTimeoutMs?: number;
  readonly settleTimeoutMs?: number;
  readonly stopTimeoutMs?: number;
  readonly killTimeoutMs?: number;
  readonly stderrLimitBytes?: number;
  readonly stdoutFrameLimitBytes?: number;
}

interface PendingRequest {
  readonly command: string;
  readonly resolve: (response: RpcResponse) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
}

interface SettledWaiter {
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
}

interface ChildSession {
  readonly child: RpcChildProcess;
  readonly exitedPromise: Promise<void>;
  readonly settledPromise: Promise<void>;
  spawned: boolean;
  exited: boolean;
  settled: boolean;
  stopped: boolean;
  exitCode: number | null;
  exitSignal: NodeJS.Signals | null;
  stdoutEnded: boolean;
  stderrEnded: boolean;
  drainTimer?: NodeJS.Timeout;
  disposeAuthPipe?: () => void;
  abortStartup: () => void;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_SETTLE_TIMEOUT_MS = 60_000;
const DEFAULT_STOP_TIMEOUT_MS = 1_000;
const DEFAULT_KILL_TIMEOUT_MS = 1_000;
const DEFAULT_DRAIN_TIMEOUT_MS = 100;
const DEFAULT_STDERR_LIMIT_BYTES = 64 * 1024;
const DEFAULT_STDOUT_FRAME_LIMIT_BYTES = 64 * 1024 * 1024;

function defaultSpawn(
  command: string,
  args: readonly string[],
  options: SpawnOptions,
): RpcChildProcess {
  return spawn(command, [...args], options) as RpcChildProcess;
}

export class RpcProcess {
  private readonly options: RpcProcessOptions;
  private session: ChildSession | null = null;
  private nextRequestId = 0;
  private readonly pending = new Map<string, PendingRequest>();
  private readonly eventListeners = new Set<(event: RpcRecord) => void>();
  private readonly errorListeners = new Set<(error: Error) => void>();
  private readonly settledWaiters = new Set<SettledWaiter>();
  private stderr = Buffer.alloc(0);
  private fatalError: Error | null = null;
  private stopping: Promise<void> | null = null;
  private promptQueue: Promise<void> = Promise.resolve();

  public constructor(options: RpcProcessOptions) {
    if (!options.command) throw new Error('RPC command must not be empty');
    if ((options.stderrLimitBytes ?? DEFAULT_STDERR_LIMIT_BYTES) < 0) {
      throw new Error('stderrLimitBytes must not be negative');
    }
    if ((options.stdoutFrameLimitBytes ?? DEFAULT_STDOUT_FRAME_LIMIT_BYTES) <= 0) {
      throw new Error('stdoutFrameLimitBytes must be positive');
    }
    this.options = options;
  }

  public async start(): Promise<void> {
    if (this.session) throw new Error('RPC process is already started');
    if (this.stopping) throw new Error('RPC process is stopping');
    if (this.options.onAuthPipe && process.platform === 'win32') {
      throw new Error('Authenticated subagent workers require inherited Unix file descriptors');
    }

    const spawnProcess = this.options.spawn ?? defaultSpawn;
    let child: RpcChildProcess;
    try {
      child = spawnProcess(this.options.command, this.options.args ?? [], {
        cwd: this.options.cwd,
        env: this.options.env,
        stdio: this.options.onAuthPipe
          ? ['pipe', 'pipe', 'pipe', 'ignore', 'pipe']
          : ['pipe', 'pipe', 'pipe'],
      });
    } catch (error) {
      throw this.asError(error, 'Failed to spawn RPC process');
    }

    this.fatalError = null;
    this.stderr = Buffer.alloc(0);
    const session = this.createSession(child);
    this.session = session;

    await new Promise<void>((resolve, reject) => {
      const onSpawn = () => {
        session.spawned = true;
        cleanup();
        resolve();
      };
      const onError = (error: Error) => {
        cleanup();
        session.abortStartup();
        const spawnError = this.asError(error, 'Failed to spawn RPC process');
        this.failAll(spawnError);
        reject(spawnError);
      };
      const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
        cleanup();
        void (async () => {
          await session.settledPromise;
          if (this.stopping) await this.stopping.catch(() => undefined);
          reject(
            session.stopped
              ? new Error('RPC process stopped during startup')
              : new Error(this.exitMessage(code, signal)),
          );
        })();
      };
      const cleanup = () => {
        child.off('spawn', onSpawn);
        child.off('error', onError);
        child.off('exit', onExit);
      };
      child.once('spawn', onSpawn);
      child.once('error', onError);
      child.once('exit', onExit);
    });
    if (session.stopped || this.stopping) {
      if (this.stopping) await this.stopping;
      else if (this.session === session) await this.stop();
      if (this.fatalError) throw this.fatalError;
      await session.settledPromise;
      throw new Error('RPC process stopped during startup');
    }
    if (this.session !== session || session.exited) {
      await session.settledPromise;
      if (this.stopping) await this.stopping;
      if (session.stopped) {
        if (this.fatalError) throw this.fatalError;
        throw new Error('RPC process stopped during startup');
      }
      throw new Error(this.exitMessage(session.exitCode, session.exitSignal));
    }
    if (this.fatalError) {
      const error = this.fatalError;
      await this.stop().catch(() => undefined);
      throw error;
    }
    if (this.options.onAuthPipe) {
      try {
        const pipe = this.authPipe(child);
        if (!(pipe instanceof Duplex)) {
          throw new Error('Worker launcher does not support private authentication pipes');
        }
        session.disposeAuthPipe = this.options.onAuthPipe(pipe);
      } catch (error) {
        await this.stop();
        throw error;
      }
    }
  }

  public onEvent(listener: (event: RpcRecord) => void): () => void {
    this.eventListeners.add(listener);
    return () => this.eventListeners.delete(listener);
  }

  public onError(listener: (error: Error) => void): () => void {
    this.errorListeners.add(listener);
    return () => this.errorListeners.delete(listener);
  }

  public getStderr(): string {
    return this.stderr.toString('utf8');
  }

  public async request<T = unknown>(
    type: string,
    fields: Readonly<Record<string, unknown>> = {},
  ): Promise<T> {
    if (!type) throw new Error('RPC request type must not be empty');
    if (!this.canWrite(this.session)) throw this.notRunningError();
    if (this.fatalError) throw this.fatalError;

    const id = `rpc-${++this.nextRequestId}`;
    const response = await new Promise<RpcResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(this.withStderr(`Timed out waiting for ${type} response`));
      }, this.options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);
      this.pending.set(id, { command: type, resolve, reject, timer });
      this.write({ ...fields, id, type }, (error) => {
        if (!error) return;
        const pending = this.pending.get(id);
        if (!pending) return;
        this.pending.delete(id);
        clearTimeout(pending.timer);
        pending.reject(this.asError(error, `Failed to write ${type} request`));
      });
    });

    if (!response.success) throw new Error(response.error ?? `${type} request failed`);
    return response.data as T;
  }

  public prompt(message: string): Promise<void> {
    const prompt = this.promptQueue.then(() => this.runPrompt(message));
    this.promptQueue = prompt.catch(() => undefined);
    return prompt;
  }

  public async steer(message: string): Promise<void> {
    await this.request('steer', { message });
  }

  private async runPrompt(message: string): Promise<void> {
    const settled = this.waitForAgentSettled();
    void settled.promise.catch(() => undefined);
    try {
      await this.request('prompt', { message });
      const state = await this.request<{ isStreaming: boolean }>('get_state');
      if (!state.isStreaming) {
        settled.cancel();
        return;
      }
      await settled.promise;
    } catch (error) {
      settled.cancel();
      throw error;
    }
  }

  public async getLastAssistantText(): Promise<string | null> {
    const data = await this.request<{ text: string | null }>('get_last_assistant_text');
    return data.text;
  }

  public async abort(): Promise<void> {
    await this.request('abort');
  }

  public async stop(): Promise<void> {
    const session = this.session;
    if (session) this.disposeAuthPipe(session);
    if (this.stopping) return this.stopping;
    if (!session) return;

    const stopping = this.stopChild(session).finally(() => {
      if (this.stopping === stopping) this.stopping = null;
    });
    this.stopping = stopping;
    await stopping;
  }

  private async stopChild(session: ChildSession): Promise<void> {
    session.stopped = true;
    const stopTimeout = this.options.stopTimeoutMs ?? DEFAULT_STOP_TIMEOUT_MS;
    const killTimeout = this.options.killTimeoutMs ?? DEFAULT_KILL_TIMEOUT_MS;

    if (!session.exited) {
      const abort = this.abort().catch(() => undefined);
      await this.waitWithin(abort, stopTimeout);
      session.child.stdin.end();
    }
    if (!session.exited && !(await this.waitWithin(session.exitedPromise, stopTimeout))) {
      session.child.kill('SIGTERM');
      if (!session.exited && !(await this.waitWithin(session.exitedPromise, killTimeout))) {
        session.child.kill('SIGKILL');
        if (!session.exited && !(await this.waitWithin(session.exitedPromise, killTimeout))) {
          const error = this.withStderr('RPC process did not exit after SIGKILL');
          session.abortStartup();
          this.fatalError = error;
          this.failAll(error);
          this.reportError(error);
          throw error;
        }
      }
    }
    await session.settledPromise;
  }

  private async waitWithin(promise: Promise<unknown>, timeoutMs: number): Promise<boolean> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        promise.then(() => true),
        new Promise<boolean>((resolve) => {
          timer = setTimeout(() => resolve(false), timeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private createSession(child: RpcChildProcess): ChildSession {
    let resolveExited!: () => void;
    let resolveSettled!: () => void;
    const exitedPromise = new Promise<void>((resolve) => {
      resolveExited = resolve;
    });
    const settledPromise = new Promise<void>((resolve) => {
      resolveSettled = resolve;
    });
    let detachStdout = (): void => {};

    const session: ChildSession = {
      child,
      exitedPromise,
      settledPromise,
      spawned: false,
      exited: false,
      settled: false,
      stopped: false,
      exitCode: null,
      exitSignal: null,
      stdoutEnded: child.stdout.readableEnded || child.stdout.destroyed,
      stderrEnded: child.stderr.readableEnded || child.stderr.destroyed,
      abortStartup: () => {
        if (session.settled) return;
        session.exited = true;
        session.settled = true;
        if (session.drainTimer) {
          clearTimeout(session.drainTimer);
          session.drainTimer = undefined;
        }
        detachStreams();
        child.off('exit', onSessionExit);
        this.disposeAuthPipe(session);
        if (this.session === session) this.session = null;
        resolveExited();
        resolveSettled();
      },
    };

    const finalizeExit = (): void => {
      if (session.settled) return;
      session.settled = true;
      if (session.drainTimer) {
        clearTimeout(session.drainTimer);
        session.drainTimer = undefined;
      }
      detachStreams();
      if (this.session === session) {
        this.session = null;
        this.failAll(
          this.fatalError ?? new Error(this.exitMessage(session.exitCode, session.exitSignal)),
        );
      }
      resolveSettled();
    };

    const maybeFinalizeExit = (): void => {
      if (session.exited && session.stdoutEnded && session.stderrEnded) {
        finalizeExit();
      }
    };

    const onStdoutClose = (): void => {
      session.stdoutEnded = true;
      maybeFinalizeExit();
    };
    const onStderrData = (chunk: Buffer | string): void => {
      if (this.session === session && !session.settled) this.captureStderr(chunk);
    };
    const onStderrEnd = (): void => {
      session.stderrEnded = true;
      maybeFinalizeExit();
    };
    const detachStreams = (): void => {
      detachStdout();
      child.stdout.off('close', onStdoutClose);
      child.stderr.off('data', onStderrData);
      child.stderr.off('end', onStderrEnd);
      child.stderr.off('close', onStderrEnd);
    };

    detachStdout = this.attachStdout(session, onStdoutClose);
    child.stdout.on('close', onStdoutClose);
    child.stdout.on('error', (error) => {
      this.handleChildError(session, error, 'RPC stdout error');
      onStdoutClose();
    });
    child.stderr.on('data', onStderrData);
    child.stderr.on('end', onStderrEnd);
    child.stderr.on('close', onStderrEnd);
    child.stderr.on('error', (error) => {
      this.handleChildError(session, error, 'RPC stderr error');
      onStderrEnd();
    });
    child.stdin.on('error', (error) => this.handleChildError(session, error, 'RPC stdin error'));
    child.on('error', (error) => this.handleChildError(session, error, 'RPC process error'));
    if (this.options.onAuthPipe) {
      const pipe = this.authPipe(child);
      if (pipe instanceof Duplex) pipe.on('error', () => {});
    }
    const onSessionExit = (code: number | null, signal: NodeJS.Signals | null): void => {
      if (session.settled) return;
      session.exited = true;
      session.exitCode = code;
      session.exitSignal = signal;
      this.disposeAuthPipe(session);
      resolveExited();
      if (session.stdoutEnded && session.stderrEnded) {
        finalizeExit();
        return;
      }
      session.drainTimer = setTimeout(() => {
        session.drainTimer = undefined;
        child.stdout.destroy();
        child.stderr.destroy();
        finalizeExit();
      }, DEFAULT_DRAIN_TIMEOUT_MS);
    };
    child.once('exit', onSessionExit);

    return session;
  }

  private attachStdout(session: ChildSession, onEnded: () => void): () => void {
    const { stdout } = session.child;
    const decoder = new StringDecoder('utf8');
    const limit = this.options.stdoutFrameLimitBytes ?? DEFAULT_STDOUT_FRAME_LIMIT_BYTES;
    let buffer = '';
    const rejectOversizedFrame = (): void => {
      buffer = '';
      this.failProtocol(new Error(`RPC stdout frame exceeds ${limit} bytes`));
    };
    const consume = (): void => {
      while (true) {
        const newline = buffer.indexOf('\n');
        if (newline < 0) {
          if (Buffer.byteLength(buffer) > limit) rejectOversizedFrame();
          return;
        }
        let line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (Buffer.byteLength(line) > limit) {
          rejectOversizedFrame();
          return;
        }
        if (line.endsWith('\r')) line = line.slice(0, -1);
        this.handleLine(session, line);
        if (this.fatalError) return;
      }
    };
    const onData = (chunk: Buffer | string): void => {
      if (this.session !== session || session.settled || this.fatalError) return;
      buffer += typeof chunk === 'string' ? chunk : decoder.write(chunk);
      consume();
    };
    const onEnd = (): void => {
      if (this.session === session && !session.settled && !this.fatalError) {
        buffer += decoder.end();
        consume();
        if (buffer.length > 0) {
          if (Buffer.byteLength(buffer) > limit) {
            rejectOversizedFrame();
          } else {
            if (buffer.endsWith('\r')) buffer = buffer.slice(0, -1);
            this.handleLine(session, buffer);
            buffer = '';
          }
        }
      }
      onEnded();
    };
    stdout.on('data', onData);
    stdout.on('end', onEnd);
    return () => {
      stdout.off('data', onData);
      stdout.off('end', onEnd);
    };
  }

  private handleLine(session: ChildSession, line: string): void {
    if (this.fatalError) return;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      // stdout is a JSONL control channel. A stray non-JSON line (e.g. a plugin
      // printing to the worker's stdout) is treated as noise rather than a
      // protocol break, so one stray line cannot fail all in-flight work.
      return;
    }
    if (!isRecord(value) || typeof value.type !== 'string') return;

    if (value.type === 'response') {
      this.handleResponse(value);
      return;
    }

    const event = value as RpcRecord;
    if (event.type === 'agent_settled') this.resolveSettledWaiters();
    for (const listener of this.eventListeners) listener(event);
    if (event.type === 'extension_ui_request') {
      void this.handleExtensionUiRequest(session, event);
    }
  }

  private handleResponse(value: Record<string, unknown>): void {
    if (
      typeof value.id !== 'string' ||
      typeof value.command !== 'string' ||
      typeof value.success !== 'boolean'
    ) {
      this.failProtocol(new Error('Invalid RPC response'));
      return;
    }
    const pending = this.pending.get(value.id);
    if (!pending) return;
    this.pending.delete(value.id);
    clearTimeout(pending.timer);
    if (value.command !== pending.command) {
      pending.reject(
        new Error(
          `RPC response command mismatch: expected ${pending.command}, got ${value.command}`,
        ),
      );
      return;
    }
    pending.resolve(value as unknown as RpcResponse);
  }

  private async handleExtensionUiRequest(session: ChildSession, event: RpcRecord): Promise<void> {
    if (typeof event.id !== 'string' || typeof event.method !== 'string') {
      this.failProtocol(new Error('Invalid extension_ui_request'));
      return;
    }
    if (this.session !== session || !this.canWrite(session) || session.stopped) return;
    const request = event as ExtensionUiRequest;
    const callback = this.options.onExtensionUiRequest;
    let result: ExtensionUiResult;
    if (!callback) {
      result = ['select', 'confirm', 'input', 'editor'].includes(request.method)
        ? { cancelled: true }
        : undefined;
    } else {
      try {
        result = await callback(request);
      } catch (error) {
        this.reportError(this.asError(error, 'Extension UI callback failed'));
        result = { cancelled: true };
      }
    }
    if (result === undefined) {
      if (['select', 'confirm', 'input', 'editor'].includes(request.method)) {
        result = { cancelled: true };
      } else {
        return;
      }
    }
    if (this.session !== session || !this.canWrite(session) || session.stopped) return;
    this.write({ ...result, type: 'extension_ui_response', id: request.id }, (error) => {
      if (error) this.reportError(this.asError(error, 'Failed to write extension UI response'));
    });
  }

  private waitForAgentSettled(): { promise: Promise<void>; cancel: () => void } {
    let waiter: SettledWaiter;
    const promise = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.settledWaiters.delete(waiter);
        reject(this.withStderr('Timed out waiting for agent_settled'));
      }, this.options.settleTimeoutMs ?? DEFAULT_SETTLE_TIMEOUT_MS);
      waiter = { resolve, reject, timer };
      this.settledWaiters.add(waiter);
    });
    return {
      promise,
      cancel: () => {
        if (!this.settledWaiters.delete(waiter)) return;
        clearTimeout(waiter.timer);
      },
    };
  }

  private resolveSettledWaiters(): void {
    for (const waiter of this.settledWaiters) {
      clearTimeout(waiter.timer);
      waiter.resolve();
    }
    this.settledWaiters.clear();
  }

  private authPipe(child: RpcChildProcess): unknown {
    const stdio = 'stdio' in child ? child.stdio : undefined;
    return Array.isArray(stdio) ? stdio[WORKER_AUTH_FD] : undefined;
  }

  private disposeAuthPipe(session: ChildSession): void {
    if (session.disposeAuthPipe) {
      session.disposeAuthPipe();
      session.disposeAuthPipe = undefined;
      return;
    }
    if (!this.options.onAuthPipe) return;
    const pipe = this.authPipe(session.child);
    if (pipe instanceof Duplex) pipe.destroy();
  }

  private canWrite(session: ChildSession | null): session is ChildSession {
    return (
      !!session &&
      !session.exited &&
      !session.settled &&
      !session.child.stdin.destroyed &&
      !session.child.stdin.writableEnded
    );
  }

  private write(record: RpcRecord, callback: (error?: Error | null) => void): void {
    const session = this.session;
    if (!this.canWrite(session)) {
      callback(this.notRunningError());
      return;
    }
    session.child.stdin.write(`${JSON.stringify(record)}\n`, callback);
  }

  private handleChildError(session: ChildSession, error: Error, prefix: string): void {
    if (this.session !== session || !session.spawned || session.exited || session.settled) return;
    const processError = this.asError(error, prefix);
    this.fatalError = processError;
    this.failAll(processError);
    this.reportError(processError);
  }

  private captureStderr(chunk: Buffer | string): void {
    const limit = this.options.stderrLimitBytes ?? DEFAULT_STDERR_LIMIT_BYTES;
    if (limit === 0) return;
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    this.stderr = Buffer.concat([this.stderr, data]);
    if (this.stderr.length > limit) this.stderr = this.stderr.subarray(this.stderr.length - limit);
  }

  private failProtocol(error: Error): void {
    this.fatalError = this.withStderr(error.message);
    this.failAll(this.fatalError);
    this.reportError(this.fatalError);
  }

  private failAll(error: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
    for (const waiter of this.settledWaiters) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    this.settledWaiters.clear();
  }

  private reportError(error: Error): void {
    for (const listener of this.errorListeners) listener(error);
  }

  private notRunningError(): Error {
    return this.fatalError ?? new Error('RPC process is not running');
  }

  private exitMessage(code: number | null, signal: NodeJS.Signals | null): string {
    const status = signal ? `signal ${signal}` : `code ${code ?? 'unknown'}`;
    return this.withStderr(`RPC process exited with ${status}`).message;
  }

  private withStderr(message: string): Error {
    const stderr = this.getStderr();
    return new Error(stderr ? `${message}. Stderr: ${stderr}` : message);
  }

  private asError(error: unknown, prefix: string): Error {
    const detail = formatError(error);
    return new Error(`${prefix}: ${detail}`);
  }
}
