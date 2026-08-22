// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { Theme } from '@earendil-works/pi-coding-agent';
import { visibleWidth } from '@earendil-works/pi-tui';
import { describe, expect, it } from 'vitest';

import { dialogKeys, dialogTabs, paneRow, paneTop } from './box.ts';

const theme = {
  fg: (_color: string, value: string) => value,
  bold: (value: string) => value,
} as Theme;

describe('box layout', () => {
  it('renders full-width bottom-pane rows without dialog borders', () => {
    expect(paneTop(theme, 12, 'Landstrip')).toBe(' Landstrip ─');
    expect(paneRow(theme, 12, 'value')).toBe(' value      ');
    expect(visibleWidth(paneTop(theme, 1, 'Landstrip'))).toBe(1);
    expect(visibleWidth(paneRow(theme, 1, 'value'))).toBe(1);
  });

  it('renders consistent tabs and key hints', () => {
    expect(dialogTabs(theme, ['Agents', 'Tasks'], 'Agents')).toBe('[Agents]  Tasks');
    expect(
      dialogKeys(theme, [
        ['Tab', 'next tab'],
        ['Esc', 'close'],
      ]),
    ).toBe('Tab next tab  ·  Esc close');
  });
});
