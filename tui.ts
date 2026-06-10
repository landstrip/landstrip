// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

const tui = async (api: any) => {
  try {
    api.keymap.registerLayer({
      commands: [
        {
          name: 'sandbox',
          title: 'Sandbox',
          description: 'Show sandbox configuration',
          category: 'plugin',
          slash: { name: 'sandbox' },
          run: async () => {
            await api.client.tui.executeCommand({ body: { command: 'sandbox' } });
            return true;
          },
        },
      ],
    });

    const client = api.client;
    if (client?.tui?.showToast) {
      client.tui
        .showToast({
          body: {
            title: 'Sandbox',
            message: '/sandbox command registered',
            variant: 'info',
          },
        })
        .catch(() => undefined);
    }
  } catch (err) {
    const client = api.client;
    if (client?.tui?.showToast) {
      client.tui
        .showToast({
          body: {
            title: 'Sandbox error',
            message: err instanceof Error ? err.message : String(err),
            variant: 'error',
          },
        })
        .catch(() => undefined);
    }
  }

  return {};
};

export { tui };
export default { tui };
