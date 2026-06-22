// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import type { TuiPlugin, TuiSlotContext, TuiSlotPlugin } from '@opencode-ai/plugin/tui';

import { existsSync } from 'node:fs';
import { type AddressInfo, createServer, type Socket as NetSocket } from 'node:net';

import {
  list,
  type SandboxConfigOverrides,
  getConfigPaths,
  landstripBinaryPath,
  loadConfig,
  normalizeOptions,
  parseLandstripTraps,
  permissionLabel,
  permissionResource,
  removeDiscoveryFile,
  updateForPermission,
  writeConfigFile,
  writeDiscoveryPort,
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

type QueryChoice = 'once' | 'session' | 'project' | 'global' | 'deny';

// A landstrip filesystem query (read or write) held pending over the fd-3
// socket. It shares the dialog stack with permission prompts so the two never
// overlap, hence the common `id`/`kind` shape.
interface FsQueryEntry {
  kind: 'fs-query';
  id: string;
  socket: NetSocket;
  queryId: number;
  operation: 'read' | 'write';
  path: string;
}

interface PermissionEntry {
  kind: 'permission';
  id: string;
  permission: PendingPermission;
}

type QueueEntry = PermissionEntry | FsQueryEntry;

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
    'Press esc or enter to close',
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
  // Write queries share the same queue so a held-write prompt never stacks on a
  // permission prompt.
  const resolved = new Set<string>();
  const queue: QueueEntry[] = [];
  let activeId: string | undefined;

  // Paths the user approved "for session": later queries for the same path are
  // auto-allowed without a dialog. This lives only in the TUI process — the
  // server regenerates the policy from on-disk config each run — so it affects
  // only live socket decisions, not the static policy.
  const sessionAllowedWritePaths = new Set<string>();
  const sessionAllowedReadPaths = new Set<string>();

  // Filesystem queries still awaiting a response, so cleanup can release held
  // syscalls instead of letting the child hang.
  const liveQueries = new Set<FsQueryEntry>();

  function pump(): void {
    if (activeId !== undefined) return;
    let next = queue.shift();
    while (next && resolved.has(next.id)) next = queue.shift();
    if (!next) return;
    if (next.kind === 'permission') showPermission(next.permission);
    else showFsQuery(next);
  }

  function enqueueEntry(entry: QueueEntry): void {
    if (!entry.id || resolved.has(entry.id)) return;
    if (activeId === entry.id) return;
    if (queue.some((item) => item.id === entry.id)) return;
    queue.push(entry);
    pump();
  }

  function enqueue(permission: PendingPermission): void {
    if (!permission.id) return;
    enqueueEntry({ kind: 'permission', id: permission.id, permission });
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
    // Defer: `clear()` above tears the dialog down by calling its `onClose`,
    // and the host pops the stack asynchronously. Opening the next dialog
    // synchronously here would race that teardown and get wiped.
    queueMicrotask(pump);
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
        // The host pops the dialog itself; calling `clear()` here would re-enter
        // this `onClose` (clear() invokes every entry's onClose) and loop until
        // the stack overflows. Defer `pump()` so the pop settles first.
        if (activeId === permission.id) activeId = undefined;
        queueMicrotask(pump);
      },
    );
  }

  function respondFsQuery(socket: NetSocket, queryId: number, action: 'allow' | 'deny'): void {
    if (!socket.destroyed) socket.write(JSON.stringify({ query_id: queryId, action }) + '\n');
  }

  function resolveFsQuery(entry: FsQueryEntry, choice: QueryChoice): void {
    if (resolved.has(entry.id)) return;
    const action = choice === 'deny' ? 'deny' : 'allow';
    const verb = entry.operation === 'read' ? 'Read' : 'Write';

    try {
      if (action === 'allow') {
        if (choice === 'session') {
          const sessionPaths =
            entry.operation === 'read' ? sessionAllowedReadPaths : sessionAllowedWritePaths;
          sessionPaths.add(entry.path);
        } else if (choice === 'project' || choice === 'global') {
          const directory = api.state.path.directory || process.cwd();
          const { globalPath, projectPath } = getConfigPaths(directory);
          const update = updateForPermission({
            permission: entry.operation,
            metadata: { filepath: entry.path },
          });
          if (update) writeConfigFile(choice === 'project' ? projectPath : globalPath, update);
        }
      }

      respondFsQuery(entry.socket, entry.queryId, action);
      api.ui.toast({
        title: 'Sandbox',
        message:
          action === 'deny' ? `${verb} denied: ${entry.path}` : `${verb} allowed (${choice})`,
        variant: action === 'deny' ? 'warning' : 'success',
      });
    } catch {
      // Persisting failed — still release the held syscall by denying it.
      respondFsQuery(entry.socket, entry.queryId, 'deny');
    } finally {
      liveQueries.delete(entry);
      finishActive(entry.id);
    }
  }

  function showFsQuery(entry: FsQueryEntry): void {
    activeId = entry.id;
    const verb = entry.operation === 'read' ? 'Read' : 'Write';
    const noun = entry.operation;
    const listName = entry.operation === 'read' ? 'allowRead' : 'allowWrite';

    void api.attention.notify({
      title: `Sandbox ${noun} blocked`,
      message: entry.path,
      sound: { name: 'permission' },
      notification: true,
    });

    // A selection pops the dialog (firing `onClose`); track it so the esc-path
    // deny does not override the user's choice. A held syscall must always be
    // answered, so esc/dismiss denies rather than leaving it unresolved.
    let selectionMade = false;

    api.ui.dialog.replace(
      () =>
        api.ui.DialogSelect<QueryChoice>({
          title: `Sandbox ${verb} Blocked`,
          placeholder: `${verb} blocked: ${entry.path}`,
          options: [
            {
              title: 'Allow once',
              value: 'once',
              category: `This ${noun}`,
              description: `Permit this ${noun} and continue`,
            },
            {
              title: 'Allow for session',
              value: 'session',
              category: `This ${noun}`,
              description: `Permit ${noun}s to this path for the rest of this session`,
            },
            {
              title: 'Allow for project',
              value: 'project',
              category: 'Persist to sandbox.json',
              description: `Add to .opencode/sandbox.json ${listName} and permit`,
            },
            {
              title: 'Allow globally',
              value: 'global',
              category: 'Persist to sandbox.json',
              description: `Add to ~/.config/opencode/sandbox.json ${listName} and permit`,
            },
            {
              title: 'Deny',
              value: 'deny',
              category: 'Deny',
              description: `Block this ${noun}`,
            },
          ],
          onSelect: (option) => {
            selectionMade = true;
            resolveFsQuery(entry, option.value);
          },
        }),
      () => {
        if (!selectionMade) resolveFsQuery(entry, 'deny');
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

  // Query-response socket server (Linux-only — landstrip's socket protocol lives
  // in the seccomp broker). The server plugin connects each sandboxed run's
  // fd 3 here via a /dev/tcp redirect and we answer held writes interactively.
  const sockets = new Set<NetSocket>();
  let socketServer: ReturnType<typeof createServer> | undefined;

  if (process.platform === 'linux') {
    const baseDirectory = api.state.path.directory || process.cwd();
    let socketSeq = 0;

    socketServer = createServer((socket) => {
      sockets.add(socket);
      socket.setEncoding('utf-8');
      const socketId = ++socketSeq;
      const seen = new Set<number>();
      let buffer = '';

      socket.on('data', (chunk: string | Buffer) => {
        buffer += chunk.toString();
        if (buffer.length > 1024 * 1024) {
          socket.destroy();
          return;
        }

        let newline: number;
        while ((newline = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, newline);
          buffer = buffer.slice(newline + 1);

          for (const trap of parseLandstripTraps(line)) {
            if (trap.kind !== 'filesystem' || trap.state !== 'query') continue;
            if (typeof trap.queryId !== 'number' || seen.has(trap.queryId)) continue;
            seen.add(trap.queryId);

            const sessionPaths =
              trap.operation === 'read' ? sessionAllowedReadPaths : sessionAllowedWritePaths;
            if (sessionPaths.has(trap.path)) {
              respondFsQuery(socket, trap.queryId, 'allow');
              continue;
            }

            const entry: FsQueryEntry = {
              kind: 'fs-query',
              id: `landstrip-${trap.operation}:${socketId}:${trap.queryId}`,
              socket,
              queryId: trap.queryId,
              operation: trap.operation,
              path: trap.path,
            };
            liveQueries.add(entry);
            enqueueEntry(entry);
          }
        }
      });

      const cleanup = () => {
        sockets.delete(socket);
        // The child is gone; drop our holds for this socket so the queue moves on.
        // Deleting the current entry mid-iteration is well-defined for a Set.
        for (const entry of liveQueries) {
          if (entry.socket !== socket) continue;
          liveQueries.delete(entry);
          finishActive(entry.id);
        }
      };
      socket.on('error', cleanup);
      socket.on('close', cleanup);
    });

    socketServer.on('error', () => {
      try {
        removeDiscoveryFile(baseDirectory);
      } catch {
        // best effort
      }
    });

    socketServer.listen(0, '127.0.0.1', () => {
      const address = socketServer?.address() as AddressInfo | null;
      if (address && typeof address === 'object') {
        try {
          writeDiscoveryPort(baseDirectory, address.port);
        } catch {
          // best effort — falls back to the server's reset model
        }
      }
    });
  }

  const showSandbox = () => {
    const directory = api.state.path.directory || process.cwd();
    const message = sandboxSummary(directory, optionOverrides);

    // No `onConfirm`/`onClose` that call `clear()`: the host already pops the
    // dialog on enter/esc/click, and its `clear()` re-invokes every entry's
    // `onClose`, so a `clear()` in there recurses forever and freezes the TUI.
    api.ui.dialog.replace(() =>
      api.ui.DialogAlert({
        title: 'Sandbox Configuration',
        message,
      }),
    );
  };

  const executeServerCommand = async (command: string): Promise<boolean> => {
    await api.client.tui.executeCommand({ command: `/${command}` });
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

  api.command?.register(() => [
    {
      title: 'Sandbox',
      value: 'sandbox',
      description: 'Show sandbox configuration',
      category: 'Sandbox',
      suggested: true,
      slash: { name: 'sandbox' },
      onSelect: showSandbox,
    },
    {
      title: 'Disable sandbox',
      value: 'sandbox-disable',
      description: 'Disable sandbox for this session',
      category: 'Sandbox',
      suggested: true,
      slash: { name: 'sandbox-disable' },
      onSelect: () => executeServerCommand('sandbox-disable'),
    },
    {
      title: 'Enable sandbox',
      value: 'sandbox-enable',
      description: 'Re-enable sandbox for this session',
      category: 'Sandbox',
      suggested: true,
      slash: { name: 'sandbox-enable' },
      onSelect: () => executeServerCommand('sandbox-enable'),
    },
  ]);

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

    // Deny any still-held queries so the sandboxed children don't hang, then
    // tear down the socket server and drop the discovery file.
    for (const entry of liveQueries) {
      respondFsQuery(entry.socket, entry.queryId, 'deny');
      liveQueries.delete(entry);
    }
    for (const socket of sockets) socket.destroy();
    if (socketServer) {
      socketServer.close();
      try {
        removeDiscoveryFile(api.state.path.directory || process.cwd());
      } catch {
        // best effort
      }
    }
  });
};

export { tui };
export default { tui };
