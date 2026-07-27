// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

export function expandHomePath(path: string): string {
  if (path === '~' || path === '$HOME') return homedir();
  if (path.startsWith('~/')) return join(homedir(), path.slice(2));
  if (path.startsWith('$HOME/')) return join(homedir(), path.slice(6));
  return path;
}

/** Expand OpenCode-style `{file:path}` tokens. Relative paths use baseDir. */
export function expandFileReferences(text: string, baseDir: string): string {
  if (!text.includes('{file:')) return text;
  const matches = Array.from(text.matchAll(/\{file:[^}]+\}/g));
  if (matches.length === 0) return text;

  let out = '';
  let cursor = 0;
  for (const match of matches) {
    const token = match[0];
    const index = match.index ?? 0;
    out += text.slice(cursor, index);

    let filePath = token.slice('{file:'.length, -1);
    if (filePath.startsWith('~/')) filePath = join(homedir(), filePath.slice(2));
    const resolved = isAbsolute(filePath) ? filePath : resolve(baseDir, filePath);
    try {
      out += readFileSync(resolved, 'utf8').trim();
    } catch (error) {
      const detail =
        error instanceof Error && 'code' in error && error.code === 'ENOENT'
          ? `${resolved} does not exist`
          : error instanceof Error
            ? error.message
            : String(error);
      throw new Error(`bad file reference: "${token}" ${detail}`);
    }
    cursor = index + token.length;
  }
  out += text.slice(cursor);
  return out;
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
