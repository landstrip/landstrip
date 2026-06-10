// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import type { TuiPlugin } from '@opencode-ai/plugin/tui';

const tui: TuiPlugin = async (api) => {
  api.command?.register(() => [
    {
      title: 'Sandbox',
      value: 'sandbox',
      description: 'Show sandbox configuration',
      category: 'plugin',
      slash: {
        name: 'sandbox',
      },
    },
  ]);
};

export { tui };
export default { tui };
