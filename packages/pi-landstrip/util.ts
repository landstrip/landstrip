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

const OPENCODE_THEME_COLORS = new Set([
  'primary',
  'secondary',
  'accent',
  'success',
  'warning',
  'error',
  'info',
]);

/** Map OpenCode theme color names onto Pi ThemeColor keys. */
const THEME_COLOR_ALIASES: Record<string, string> = {
  primary: 'accent',
  // OpenCode TUI secondary is magenta; Pi has no secondary slot.
  secondary: 'customMessageLabel',
  accent: 'accent',
  success: 'success',
  warning: 'warning',
  error: 'error',
  info: 'accent',
};

/** ANSI fallbacks when no theme is available (e.g. status line). */
const NAMED_COLOR_ANSI: Record<string, string> = {
  primary: '\x1b[36m',
  secondary: '\x1b[35m',
  accent: '\x1b[36m',
  success: '\x1b[32m',
  warning: '\x1b[33m',
  error: '\x1b[31m',
  info: '\x1b[36m',
};

export function isAgentColor(value: string): boolean {
  if (/^#[0-9a-fA-F]{6}$/.test(value)) return true;
  return OPENCODE_THEME_COLORS.has(value);
}

function hexFg(hex: string, text: string): string {
  const r = Number.parseInt(hex.slice(1, 3), 16);
  const g = Number.parseInt(hex.slice(3, 5), 16);
  const b = Number.parseInt(hex.slice(5, 7), 16);
  return `\x1b[38;2;${r};${g};${b}m${text}\x1b[39m`;
}

/** Color text with an agent color (hex or OpenCode theme name). */
export function colorizeAgentText(
  color: string | undefined,
  text: string,
  themeFg?: (name: string, value: string) => string,
  fallback = 'accent',
): string {
  if (!color) return themeFg ? themeFg(fallback, text) : text;
  if (color.startsWith('#')) return hexFg(color, text);
  if (themeFg) return themeFg(THEME_COLOR_ALIASES[color] ?? fallback, text);
  const ansi = NAMED_COLOR_ANSI[color];
  return ansi ? `${ansi}${text}\x1b[39m` : text;
}

export class AsyncQueue {
  private tail = Promise.resolve();
  private generation = 0;
  private resetWaiters: Array<() => void> = [];

  async acquire(
    signal?: AbortSignal,
    cancellationMessage = 'Request cancelled',
  ): Promise<() => void> {
    if (signal?.aborted) throw new Error(cancellationMessage);
    const generation = this.generation;
    let release: (() => void) | undefined;
    const previous = this.tail;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });

    const finish = (): void => {
      release?.();
    };

    let wakeReset: (() => void) | undefined;
    const resetSignal = new Promise<void>((resolve) => {
      wakeReset = resolve;
      this.resetWaiters.push(resolve);
    });

    const dropResetWaiter = (): void => {
      if (!wakeReset) return;
      const index = this.resetWaiters.indexOf(wakeReset);
      if (index >= 0) this.resetWaiters.splice(index, 1);
      wakeReset = undefined;
    };

    try {
      if (!signal) {
        await Promise.race([previous, resetSignal]);
      } else {
        let abort: (() => void) | undefined;
        try {
          await Promise.race([
            previous,
            resetSignal,
            new Promise<never>((_resolve, reject) => {
              abort = () => reject(new Error(cancellationMessage));
              signal.addEventListener('abort', abort, { once: true });
            }),
          ]);
        } finally {
          if (abort) signal.removeEventListener('abort', abort);
        }
      }
      if (this.generation !== generation) {
        throw new Error(cancellationMessage);
      }
      return finish;
    } catch (error) {
      // Advance the abandoned chain so later waiters still make progress.
      void previous.finally(finish);
      throw error;
    } finally {
      dropResetWaiter();
    }
  }

  reset(): void {
    this.generation += 1;
    this.tail = Promise.resolve();
    const waiters = this.resetWaiters.splice(0);
    for (const wake of waiters) wake();
  }
}

export function combineAbortSignals(...sources: Array<AbortSignal | undefined>): {
  signal: AbortSignal;
  dispose: () => void;
} {
  const signals = sources.filter((source): source is AbortSignal => source !== undefined);
  const only = signals[0];
  if (signals.length === 1 && only) return { signal: only, dispose: () => undefined };

  const controller = new AbortController();
  const abort = (): void => controller.abort();
  for (const signal of signals) signal.addEventListener('abort', abort, { once: true });
  if (signals.some((signal) => signal.aborted)) controller.abort();

  return {
    signal: controller.signal,
    dispose: () => {
      for (const signal of signals) signal.removeEventListener('abort', abort);
    },
  };
}

export class PermissionPromptCoordinator {
  private readonly queue = new AsyncQueue();
  private resetController = new AbortController();

  async resolve<T>(
    current: () => T | undefined,
    request: (signal: AbortSignal) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T> {
    const immediate = current();
    if (immediate !== undefined) return immediate;

    const combined = combineAbortSignals(signal, this.resetController.signal);
    let release: (() => void) | undefined;
    try {
      release = await this.queue.acquire(combined.signal, 'Permission request cancelled');
      const resolved = current();
      if (resolved !== undefined) return resolved;
      if (combined.signal.aborted) throw new Error('Permission request cancelled');
      const result = await request(combined.signal);
      if (combined.signal.aborted) throw new Error('Permission request cancelled');
      return result;
    } finally {
      release?.();
      combined.dispose();
    }
  }

  reset(): void {
    const controller = this.resetController;
    this.resetController = new AbortController();
    this.queue.reset();
    controller.abort();
  }
}
