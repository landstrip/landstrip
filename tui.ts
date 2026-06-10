// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import type { TuiPlugin } from '@opencode-ai/plugin/tui';

const tui: TuiPlugin = async (api) => {
  try {
    api.keymap.registerLayer({
      commands: [
        {
          name: 'sandbox',
          title: 'Sandbox',
          description: 'Show sandbox configuration',
          category: 'plugin',
          keybind: 'ctrl+x b',
          suggested: true,
          slash: { name: 'sandbox' },
          run: async () => {
            await api.client.tui.executeCommand({ command: 'sandbox' });
            return true;
          },
        },
      ],
    });

    const client = api.client;
    if (client?.tui?.showToast) {
      client.tui
        .showToast({
          title: 'Sandbox',
          message: '/sandbox command registered',
          variant: 'info',
        })
        .catch(() => undefined);
    }
  } catch (err) {
    const client = api.client;
    if (client?.tui?.showToast) {
      client.tui
        .showToast({
          title: 'Sandbox error',
          message: err instanceof Error ? err.message : String(err),
          variant: 'error',
        })
        .catch(() => undefined);
    }
  }
};

export { tui };
export default { tui };
