// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { Theme } from '@earendil-works/pi-coding-agent';
import { visibleWidth } from '@earendil-works/pi-tui';
import { describe, expect, it } from 'vitest';

import { boxBottom, boxRow, boxTop } from './box.ts';

const theme = {
  fg: (_color: string, value: string) => value,
} as Theme;

describe('box layout', () => {
  it('renders a bordered box at normal widths', () => {
    expect(boxTop(theme, 12, 'Title')).toBe('╭─ Title ──╮');
    expect(boxRow(theme, 12, 'value')).toBe('│ value    │');
    expect(boxBottom(theme, 12)).toBe('╰──────────╯');
  });

  it('does not overflow at narrow widths', () => {
    expect(visibleWidth(boxTop(theme, 4, 'Title'))).toBe(4);
    expect(visibleWidth(boxRow(theme, 4, 'value'))).toBe(4);
    expect(boxBottom(theme, 4)).toBe('');
  });
});
