// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { spawn, type SpawnOptions } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';

import { formatError, isRecord } from './util.ts';

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

export interface RpcChildProcess {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  readonly exitCode: number | null;
  readonly signalCode: NodeJS.Signals | null;
  kill(signal?: NodeJS.Signals | number): boolean;
  on(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  once(event: 'spawn', listener: () => void): this;
  once(event: 'error', listener: (error: Error) => void): this;
  once(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  off(event: 'spawn', listener: () => void): this;
  off(event: 'error', listener: (error: Error) => void): this;
  off(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
}

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

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_SETTLE_TIMEOUT_MS = 60_000;
const DEFAULT_STOP_TIMEOUT_MS = 1_000;
const DEFAULT_KILL_TIMEOUT_MS = 1_000;
const DEFAULT_STDERR_LIMIT_BYTES = 64 * 1024;
const DEFAULT_STDOUT_FRAME_LIMIT_BYTES = 64 * 1024 * 1024;

function defaultSpawn(
  command: string,
  args: readonly string[],
  options: SpawnOptions,
): RpcChildProcess {
  return spawn(command, [...args], options) as RpcChildProcess;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export class RpcProcess {
  private readonly options: RpcProcessOptions;
  private child: RpcChildProcess | null = null;
  private exitPromise: Promise<void> | null = null;
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
    if (this.child) throw new Error('RPC process is already started');
    if (this.stopping) throw new Error('RPC process is stopping');

    const spawnProcess = this.options.spawn ?? defaultSpawn;
    let child: RpcChildProcess;
    try {
      child = spawnProcess(this.options.command, this.options.args ?? [], {
        cwd: this.options.cwd,
        env: this.options.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (error) {
      throw this.asError(error, 'Failed to spawn RPC process');
    }

    this.child = child;
    this.fatalError = null;
    this.stderr = Buffer.alloc(0);
    this.attachStdout(child, child.stdout);
    child.stderr.on('data', (chunk: Buffer | string) => {
      if (this.child === child) this.captureStderr(chunk);
    });
    child.stdin.on('error', (error) => this.handleChildError(child, error, 'RPC stdin error'));
    child.on('error', (error) => this.handleChildError(child, error, 'RPC process error'));
    this.exitPromise = new Promise((resolve) => {
      child.once('exit', (code, signal) => {
        if (this.child === child) {
          this.child = null;
          this.failAll(new Error(this.exitMessage(code, signal)));
        }
        resolve();
      });
    });

    await new Promise<void>((resolve, reject) => {
      const onSpawn = () => {
        cleanup();
        resolve();
      };
      const onError = (error: Error) => {
        cleanup();
        if (this.child === child) this.child = null;
        const spawnError = this.asError(error, 'Failed to spawn RPC process');
        this.failAll(spawnError);
        reject(spawnError);
      };
      const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
        cleanup();
        reject(new Error(this.exitMessage(code, signal)));
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
    const child = this.child;
    if (!child || child.stdin.destroyed) throw this.notRunningError();
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

  private async runPrompt(message: string): Promise<void> {
    const settled = this.waitForAgentSettled();
    try {
      await Promise.all([this.request('prompt', { message }), settled.promise]);
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
    if (this.stopping) return this.stopping;
    const child = this.child;
    if (!child) return;

    this.stopping = this.stopChild(child);
    try {
      await this.stopping;
    } finally {
      this.stopping = null;
    }
  }

  private async stopChild(child: RpcChildProcess): Promise<void> {
    const stopTimeout = this.options.stopTimeoutMs ?? DEFAULT_STOP_TIMEOUT_MS;
    const killTimeout = this.options.killTimeoutMs ?? DEFAULT_KILL_TIMEOUT_MS;
    const exit = this.exitPromise ?? Promise.resolve();

    const abort = this.abort().catch(() => undefined);
    await Promise.race([abort, delay(stopTimeout)]);
    child.stdin.end();
    if (await this.waitForExit(exit, stopTimeout)) return;

    child.kill('SIGTERM');
    if (await this.waitForExit(exit, killTimeout)) return;

    child.kill('SIGKILL');
    if (await this.waitForExit(exit, killTimeout)) return;

    if (this.child === child) this.child = null;
    this.failAll(this.withStderr('RPC process did not exit after SIGKILL'));
  }

  private async waitForExit(exit: Promise<void>, timeout: number): Promise<boolean> {
    return Promise.race([exit.then(() => true), delay(timeout).then(() => false)]);
  }

  private attachStdout(child: RpcChildProcess, stdout: Readable): void {
    const decoder = new StringDecoder('utf8');
    const limit = this.options.stdoutFrameLimitBytes ?? DEFAULT_STDOUT_FRAME_LIMIT_BYTES;
    let buffer = '';
    const rejectOversizedFrame = (): void => {
      buffer = '';
      this.failProtocol(new Error(`RPC stdout frame exceeds ${limit} bytes`));
    };
    const consume = () => {
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
        this.handleLine(line);
        if (this.fatalError) return;
      }
    };
    stdout.on('data', (chunk: Buffer | string) => {
      if (this.child !== child || this.fatalError) return;
      buffer += typeof chunk === 'string' ? chunk : decoder.write(chunk);
      consume();
    });
    stdout.on('end', () => {
      if (this.child !== child || this.fatalError) return;
      buffer += decoder.end();
      if (buffer.length === 0) return;
      if (Buffer.byteLength(buffer) > limit) {
        rejectOversizedFrame();
        return;
      }
      if (buffer.endsWith('\r')) buffer = buffer.slice(0, -1);
      this.handleLine(buffer);
      buffer = '';
    });
  }

  private handleLine(line: string): void {
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
      void this.handleExtensionUiRequest(event);
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

  private async handleExtensionUiRequest(event: RpcRecord): Promise<void> {
    if (typeof event.id !== 'string' || typeof event.method !== 'string') {
      this.failProtocol(new Error('Invalid extension_ui_request'));
      return;
    }
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

  private write(record: RpcRecord, callback: (error?: Error | null) => void): void {
    const child = this.child;
    if (!child || child.stdin.destroyed) {
      callback(this.notRunningError());
      return;
    }
    child.stdin.write(`${JSON.stringify(record)}\n`, callback);
  }

  private handleChildError(child: RpcChildProcess, error: Error, prefix: string): void {
    if (this.child !== child) return;
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
