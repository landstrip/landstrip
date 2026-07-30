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

export function boxTop(theme: Theme, width: number, title: string): string {
  if (width < 5) return truncateToWidth(theme.fg('accent', title), Math.max(1, width));
  const label = theme.fg('accent', ` ${title} `);
  const fill = theme.fg('border', '─'.repeat(Math.max(0, width - 4 - visibleWidth(label))));
  return `${theme.fg('border', '╭─')}${label}${fill}${theme.fg('border', '─╮')}`;
}

export function boxRow(theme: Theme, width: number, content = ''): string {
  if (width < 5) return truncateToWidth(content, Math.max(1, width));
  const innerWidth = Math.max(1, width - 4);
  const border = theme.fg('border', '│');
  const line = truncateToWidth(content, innerWidth);
  return `${border} ${line}${' '.repeat(Math.max(0, innerWidth - visibleWidth(line)))} ${border}`;
}

export function boxBottom(theme: Theme, width: number): string {
  if (width < 5) return '';
  const border = (value: string) => theme.fg('border', value);
  return `${border('╰')}${border('─'.repeat(Math.max(0, width - 2)))}${border('╯')}`;
}
