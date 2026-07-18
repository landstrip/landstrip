// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { homedir } from 'node:os';
import { join } from 'node:path';

export function expandHomePath(path: string): string {
  if (path === '~' || path === '$HOME') return homedir();
  if (path.startsWith('~/')) return join(homedir(), path.slice(2));
  if (path.startsWith('$HOME/')) return join(homedir(), path.slice(6));
  return path;
}

export function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export class AsyncQueue {
  private tail = Promise.resolve();

  async acquire(
    signal?: AbortSignal,
    cancellationMessage = 'Request cancelled',
  ): Promise<() => void> {
    let release: (() => void) | undefined;
    const previous = this.tail;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });

    if (!signal) {
      await previous;
      return release!;
    }

    let abort: (() => void) | undefined;
    try {
      await Promise.race([
        previous,
        new Promise<never>((_resolve, reject) => {
          abort = () => reject(new Error(cancellationMessage));
          signal.addEventListener('abort', abort, { once: true });
        }),
      ]);
    } catch (error) {
      void previous.finally(() => release?.());
      throw error;
    } finally {
      if (abort) signal.removeEventListener('abort', abort);
    }
    return release!;
  }

  reset(): void {
    this.tail = Promise.resolve();
  }
}
