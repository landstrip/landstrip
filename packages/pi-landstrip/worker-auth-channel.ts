// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { Duplex } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';

import type { WorkerAuthSnapshot } from './worker-auth.ts';

// fd 3 belongs to the sandbox trap. This channel is never RPC stdin/stdout.
export const WORKER_AUTH_FD = 4;
const MAX_FRAME_BYTES = 256 * 1024;
const MAX_PENDING = 16;
const channelError = () => new Error('Subagent authentication channel failed');

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function snapshot(value: unknown): value is WorkerAuthSnapshot {
  if (!record(value) || !record(value.auth) || !record(value.auth.auth) || !record(value.model)) {
    return false;
  }
  const { auth, env } = value.auth;
  return (
    typeof value.model.provider === 'string' &&
    typeof value.model.id === 'string' &&
    typeof value.model.api === 'string' &&
    typeof value.model.baseUrl === 'string' &&
    (auth.apiKey === undefined || typeof auth.apiKey === 'string') &&
    (auth.baseUrl === undefined || typeof auth.baseUrl === 'string') &&
    (auth.headers === undefined ||
      (record(auth.headers) &&
        Object.values(auth.headers).every((v) => v === null || typeof v === 'string'))) &&
    (env === undefined || (record(env) && Object.values(env).every((v) => typeof v === 'string')))
  );
}

/** Owns framing and its listeners, but does not own the supplied pipe. */
function frames(pipe: Duplex, receive: (value: Record<string, unknown>) => void, fail: () => void) {
  const decoder = new StringDecoder('utf8');
  let buffer = '';
  let closed = false;
  const bad = () => {
    if (closed) return;
    closed = true;
    buffer = '';
    fail();
  };
  const data = (chunk: Buffer) => {
    if (closed) return;
    buffer += decoder.write(chunk);
    for (;;) {
      const newline = buffer.indexOf('\n');
      if (newline < 0) break;
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      if (Buffer.byteLength(line) > MAX_FRAME_BYTES) return bad();
      let value: unknown;
      try {
        value = JSON.parse(line);
      } catch {
        return bad();
      }
      if (!record(value)) return bad();
      receive(value);
      if (closed) return;
    }
    if (Buffer.byteLength(buffer) > MAX_FRAME_BYTES) bad();
  };
  pipe.on('data', data);
  pipe.on('error', bad);
  pipe.on('end', bad);
  pipe.on('close', bad);
  return {
    send(value: unknown) {
      if (closed || pipe.destroyed) throw channelError();
      const line = JSON.stringify(value);
      if (Buffer.byteLength(line) > MAX_FRAME_BYTES) throw channelError();
      pipe.write(`${line}\n`, (error) => {
        if (error) bad();
      });
    },
    dispose() {
      closed = true;
      buffer = '';
      pipe.off('data', data);
      pipe.off('end', bad);
      pipe.off('close', bad);
      // Keep the harmless error handler until destruction; late EPIPE must not crash the host.
    },
  };
}

/** Only the pinned resolver is callable; requests cannot select another provider. */
export function serveWorkerAuth(
  pipe: Duplex,
  resolve: (signal: AbortSignal) => Promise<WorkerAuthSnapshot>,
): () => void {
  const pending = new Map<number, AbortController>();
  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    for (const controller of pending.values()) controller.abort();
    pending.clear();
    protocol.dispose();
    pipe.destroy();
  };
  const protocol = frames(
    pipe,
    (request) => {
      const { id, type } = request;
      if (
        !Number.isSafeInteger(id) ||
        (id as number) < 1 ||
        (type !== 'auth' && type !== 'cancel')
      ) {
        dispose();
        return;
      }
      const key = id as number;
      if (type === 'cancel') {
        pending.get(key)?.abort();
        pending.delete(key);
        return;
      }
      if (pending.has(key) || pending.size >= MAX_PENDING) return dispose();
      const controller = new AbortController();
      pending.set(key, controller);
      void (async () => {
        try {
          const result = await resolve(controller.signal);
          if (!controller.signal.aborted && !disposed) protocol.send({ id, result });
        } catch {
          // Neither exceptions nor their causes cross this boundary.
          if (!controller.signal.aborted && !disposed) {
            try {
              protocol.send({ id, failed: true });
            } catch {
              dispose();
            }
          }
        } finally {
          if (pending.get(key) === controller) pending.delete(key);
        }
      })();
    },
    dispose,
  );
  return dispose;
}

export class WorkerAuthClient {
  private nextId = 0;
  private closed = false;
  private readonly pending = new Map<
    number,
    {
      resolve: (value: WorkerAuthSnapshot) => void;
      reject: () => void;
      cleanup: () => void;
    }
  >();
  private readonly protocol: ReturnType<typeof frames>;
  private readonly pipe: Duplex;

  constructor(pipe: Duplex) {
    this.pipe = pipe;
    this.protocol = frames(
      pipe,
      (response) => {
        if (!Number.isSafeInteger(response.id)) return this.dispose();
        const id = response.id as number;
        const pending = this.pending.get(id);
        if (!pending) return; // Late reply to a cancelled request.
        this.pending.delete(id);
        pending.cleanup();
        if (response.failed === true || !snapshot(response.result)) pending.reject();
        else pending.resolve(response.result);
      },
      () => this.dispose(),
    );
  }

  request(signal?: AbortSignal): Promise<WorkerAuthSnapshot> {
    if (this.closed || signal?.aborted || this.pending.size >= MAX_PENDING) {
      return Promise.reject(channelError());
    }
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const abort = () => {
        const pending = this.pending.get(id);
        if (!pending) return;
        this.pending.delete(id);
        pending.cleanup();
        pending.reject();
        try {
          this.protocol.send({ type: 'cancel', id });
        } catch {
          this.dispose();
        }
      };
      const timer = setTimeout(abort, 30_000);
      const cleanup = () => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
      };
      this.pending.set(id, { resolve, reject: () => reject(channelError()), cleanup });
      signal?.addEventListener('abort', abort, { once: true });
      try {
        this.protocol.send({ type: 'auth', id });
      } catch {
        this.dispose();
      }
    });
  }

  dispose(): void {
    if (this.closed) return;
    this.closed = true;
    for (const pending of this.pending.values()) {
      pending.cleanup();
      pending.reject();
    }
    this.pending.clear();
    this.protocol.dispose();
    this.pipe.destroy();
  }
}
