// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import type { TuiPlugin, TuiSlotContext, TuiSlotPlugin } from '@opencode-ai/plugin/tui';

import { existsSync } from 'node:fs';

import {
  type SandboxConfigOverrides,
  getConfigPaths,
  landstripBinaryPath,
  loadConfig,
  normalizeOptions,
  permissionLabel,
  permissionResource,
  updateForPermission,
  writeConfigFile,
} from './shared.js';

// The shape shared by the `permission.asked` event payload and the entries
// returned from `api.state.session.permission()`. Both carry `permission`
// (the kind), `patterns`, and `tool.callID`; neither carries a `title`.
interface PendingPermission {
  id: string;
  sessionID: string;
  permission: string;
  patterns: string[];
  metadata: Record<string, unknown>;
  tool?: { callID: string };
}

type PermissionChoice = 'once' | 'session' | 'project' | 'global' | 'reject';

function list(values: string[]): string {
  return values.join(', ') || '(none)';
}

function configPathLine(label: string, filePath: string): string {
  return `${label}: ${filePath} ${existsSync(filePath) ? '(found)' : '(missing)'}`;
}

function sandboxSummary(baseDirectory: string, optionOverrides: SandboxConfigOverrides): string {
  const config = loadConfig(baseDirectory, optionOverrides);
  const { globalPath, projectPath } = getConfigPaths(baseDirectory);
  const networkMode = config.network.allowNetwork ? 'unrestricted' : 'proxied';

  return [
    `Status: ${config.enabled ? 'active' : 'disabled by config'}`,
    `landstrip package binary: ${landstripBinaryPath()}`,
    '',
    'Config files',
    configPathLine('project', projectPath),
    configPathLine('global', globalPath),
    '',
    `Network: ${networkMode}`,
    `allow network: ${config.network.allowNetwork ? 'yes' : 'no'}`,
    `allowed: ${list(config.network.allowedDomains)}`,
    `denied: ${list(config.network.deniedDomains)}`,
    `unix sockets: ${config.network.allowAllUnixSockets ? 'all' : list(config.network.allowUnixSockets)}`,
    '',
    'Filesystem',
    `deny read: ${list(config.filesystem.denyRead)}`,
    `allow read: ${list(config.filesystem.allowRead)}`,
    `allow write: ${list(config.filesystem.allowWrite)}`,
    `deny write: ${list(config.filesystem.denyWrite)}`,
    '',
    'esc or any key to close',
  ].join('\n');
}

function asRecord(permission: PendingPermission): Record<string, unknown> {
  return permission as unknown as Record<string, unknown>;
}

function permissionDetail(permission: PendingPermission): string {
  const label = permissionLabel(asRecord(permission));
  const resource = permissionResource(asRecord(permission));
  return resource && !label.includes(resource) ? `${label}: ${resource}` : label;
}

const tui: TuiPlugin = async (api, options, meta) => {
  const optionOverrides = normalizeOptions(options);

  // Permission requests can arrive twice (the live event and a reconnect replay
  // of `api.state`), so `resolved` tracks ids we have already answered and
  // `activeId` guards against stacking a second sandbox dialog on the first.
  const resolved = new Set<string>();
  const queue: PendingPermission[] = [];
  let activeId: string | undefined;

  function pump(): void {
    if (activeId !== undefined) return;
    let next = queue.shift();
    while (next && resolved.has(next.id)) next = queue.shift();
    if (!next) return;
    showPermission(next);
  }

  function enqueue(permission: PendingPermission): void {
    if (!permission.id || resolved.has(permission.id)) return;
    if (activeId === permission.id) return;
    if (queue.some((item) => item.id === permission.id)) return;
    queue.push(permission);
    pump();
  }

  // Safety net for missed/late events and reconnects: fold whatever the host
  // still considers pending for this session back into the queue.
  function reconcile(sessionID: string): void {
    for (const pending of api.state.session.permission(sessionID)) {
      enqueue(pending as PendingPermission);
    }
  }

  function finishActive(id: string): void {
    resolved.add(id);
    if (activeId === id) {
      activeId = undefined;
      api.ui.dialog.clear();
    }
    pump();
  }

  async function replyPermission(
    permission: PendingPermission,
    choice: PermissionChoice,
  ): Promise<void> {
    const { id, sessionID } = permission;
    if (!id || !sessionID) return;

    const directory = api.state.path.directory || process.cwd();
    const { globalPath, projectPath } = getConfigPaths(directory);

    try {
      if (choice === 'project' || choice === 'global') {
        const update = updateForPermission(asRecord(permission));
        if (update) writeConfigFile(choice === 'project' ? projectPath : globalPath, update);
      }

      await api.client.permission.reply({
        requestID: id,
        reply: choice === 'reject' ? 'reject' : choice === 'once' ? 'once' : 'always',
      });

      api.ui.toast({
        title: 'Sandbox',
        message: choice === 'reject' ? 'Permission rejected' : `Permission allowed for ${choice}`,
        variant: choice === 'reject' ? 'warning' : 'success',
      });
    } catch {
      api.ui.toast({
        title: 'Sandbox',
        message: 'Permission was already handled or could not be updated',
        variant: 'warning',
      });
    } finally {
      finishActive(id);
    }
  }

  function showPermission(permission: PendingPermission): void {
    activeId = permission.id;

    void api.attention.notify({
      title: 'Sandbox permission',
      message: permissionDetail(permission),
      sound: { name: 'permission' },
      notification: true,
    });

    api.ui.dialog.replace(
      () =>
        api.ui.DialogSelect<PermissionChoice>({
          title: 'Sandbox Permission',
          placeholder: permissionDetail(permission),
          options: [
            {
              title: 'Allow once',
              value: 'once',
              category: 'This request',
              description: 'Approve only this request',
            },
            {
              title: 'Allow for session',
              value: 'session',
              category: 'This request',
              description: 'Use OpenCode session approval for matching requests',
            },
            {
              title: 'Allow for project',
              value: 'project',
              category: 'Persist to sandbox.json',
              description: 'Persist to .opencode/sandbox.json and approve this session',
            },
            {
              title: 'Allow globally',
              value: 'global',
              category: 'Persist to sandbox.json',
              description: 'Persist to ~/.config/opencode/sandbox.json and approve this session',
            },
            {
              title: 'Reject',
              value: 'reject',
              category: 'Deny',
              description: 'Deny this request',
            },
          ],
          onSelect: (option) => {
            void replyPermission(permission, option.value);
          },
        }),
      () => {
        // Dialog dismissed (esc) without a choice: drop our hold so the next
        // pending permission can surface, but leave it unresolved upstream.
        if (activeId === permission.id) activeId = undefined;
        api.ui.dialog.clear();
        pump();
      },
    );
  }

  const unsubscribeAsked = api.event.on('permission.asked', (event) => {
    const pending = event.properties as PendingPermission;
    enqueue(pending);
    reconcile(pending.sessionID);
  });

  const unsubscribeReplied = api.event.on('permission.replied', (event) => {
    finishActive(event.properties.requestID);
  });

  const showSandbox = () => {
    const directory = api.state.path.directory || process.cwd();
    const message = sandboxSummary(directory, optionOverrides);

    api.ui.dialog.replace(
      () =>
        api.ui.DialogAlert({
          title: 'Sandbox Configuration',
          message,
          onConfirm: () => api.ui.dialog.clear(),
        }),
      () => api.ui.dialog.clear(),
    );
  };

  const executeServerCommand = async (command: string): Promise<boolean> => {
    await api.client.tui.executeCommand({ command });
    return true;
  };

  api.keymap.registerLayer({
    commands: [
      {
        namespace: 'palette',
        name: 'sandbox',
        title: 'Sandbox',
        desc: 'Show sandbox configuration',
        category: 'Sandbox',
        suggested: true,
        slashName: 'sandbox',
        run: showSandbox,
      },
      {
        namespace: 'palette',
        name: 'sandbox-disable',
        title: 'Disable sandbox',
        desc: 'Disable sandbox for this session',
        category: 'Sandbox',
        suggested: true,
        slashName: 'sandbox-disable',
        run: () => executeServerCommand('sandbox-disable'),
      },
      {
        namespace: 'palette',
        name: 'sandbox-enable',
        title: 'Enable sandbox',
        desc: 'Re-enable sandbox for this session',
        category: 'Sandbox',
        suggested: true,
        slashName: 'sandbox-enable',
        run: () => executeServerCommand('sandbox-enable'),
      },
    ],
  });

  // Persistent status badge in the prompt area. It needs the host's Solid
  // runtime, imported defensively so a host that resolves plugin imports
  // differently still loads the plugin — the badge just stays absent there.
  try {
    const { jsx } = await import('@opentui/solid/jsx-runtime');
    const statusBadge = (ctx: TuiSlotContext) => {
      const directory = api.state.path.directory || process.cwd();
      const config = loadConfig(directory, optionOverrides);
      const theme = ctx.theme.current;

      if (!config.enabled) return jsx('text', { fg: theme.textMuted, children: 'sandbox off' });

      const open = config.network.allowNetwork;
      return jsx('text', {
        fg: open ? theme.warning : theme.success,
        children: `sandbox · ${open ? 'net open' : 'net proxied'}`,
      });
    };

    const statusSlot: TuiSlotPlugin = {
      slots: {
        home_prompt_right: (ctx) => statusBadge(ctx),
        session_prompt_right: (ctx) => statusBadge(ctx),
      },
    };
    api.slots.register(statusSlot);
  } catch {
    // Solid runtime unavailable on this host — skip the status badge.
  }

  // First-run onboarding: a single quiet pointer to the default-strict policy
  // and the inspector command. `meta.state` flags a freshly installed plugin;
  // the kv flag keeps it from repeating across reloads.
  if (meta.state === 'first' && !api.kv.get<boolean>('onboarded', false)) {
    api.kv.set('onboarded', true);
    api.ui.toast({
      title: 'Sandbox active',
      message: 'Landlock policy is on (default strict). Run /sandbox to inspect it.',
      variant: 'info',
      duration: 8000,
    });
  }

  api.lifecycle.onDispose(() => {
    unsubscribeAsked();
    unsubscribeReplied();
  });
};

export { tui };
export default { tui };
