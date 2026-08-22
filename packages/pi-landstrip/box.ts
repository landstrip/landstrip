// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { Theme } from '@earendil-works/pi-coding-agent';
import { truncateToWidth, visibleWidth } from '@earendil-works/pi-tui';

export function dialogTabs(theme: Theme, tabs: readonly string[], active: string): string {
  return tabs
    .map((tab) =>
      tab === active ? theme.fg('accent', theme.bold(`[${tab}]`)) : theme.fg('muted', tab),
    )
    .join('  ');
}

export function dialogKeys(
  theme: Theme,
  hints: ReadonlyArray<readonly [key: string, description: string]>,
): string {
  const separator = theme.fg('dim', '  ·  ');
  return hints
    .map(([key, description]) => `${theme.fg('accent', key)} ${theme.fg('muted', description)}`)
    .join(separator);
}

export function paneTop(theme: Theme, width: number, title: string): string {
  if (width < 3) return truncateToWidth(theme.fg('accent', title), Math.max(1, width));
  const label = theme.fg('accent', theme.bold(` ${title} `));
  return `${label}${theme.fg('border', '─'.repeat(Math.max(0, width - visibleWidth(label))))}`;
}

export function paneRow(_theme: Theme, width: number, content = ''): string {
  if (width < 2) return ' '.repeat(Math.max(0, width));
  const line = truncateToWidth(content, Math.max(1, width - 2));
  return ` ${line}${' '.repeat(Math.max(0, width - visibleWidth(line) - 1))}`;
}
