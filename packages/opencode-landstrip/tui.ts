// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { TuiPlugin, TuiSlotContext, TuiSlotPlugin } from '@opencode-ai/plugin/tui';
import { type AddressInfo, createServer, type Socket as NetSocket } from 'node:net';

import {
  controlResponseLine,
  getConfigPaths,
  loadConfig,
  normalizeOptions,
  parseLandstripTraps,
  permissionLabel,
  permissionResource,
  removeDiscoveryFile,
  sessionAllows,
  sandboxSummary,
  sessionScopeFor,
  setSandboxConfigEnabled,
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

// No project/global option: no landstrip policy field expresses "allow this
// address:port" the way allowRead/allowWrite express a path.
type NetworkQueryChoice = 'once' | 'session' | 'deny';

// A landstrip filesystem query (read or write) held pending over the fd-3
// socket. It shares the dialog stack with permission prompts so the two never
// overlap, hence the common `id`/`kind` shape.
interface FsQueryEntry {
  kind: 'fs-query';
  id: string;
  socket: NetSocket;
  queryId: string;
  operation: 'read' | 'write';
  path: string;
}

// A landstrip network query (connect or bind) held pending over the same
// fd-3 socket. The broker only knows `address:port`, so — unlike FsQueryEntry
// — there is no project/global persistence option: no policy field can
// express "allow this address:port".
interface NetworkQueryEntry {
  kind: 'net-query';
  id: string;
  socket: NetSocket;
  queryId: string;
  operation: string;
  target: string;
}

interface PermissionEntry {
  kind: 'permission';
  id: string;
  permission: PendingPermission;
}

type QueueEntry = PermissionEntry | FsQueryEntry | NetworkQueryEntry;

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
  let refreshSandboxStatus: (() => void) | undefined;

  // Paths the user approved "for session": later queries for the same path are
  // auto-allowed without a dialog. This lives only in the TUI process — the
  // server regenerates the policy from on-disk config each run — so it affects
  // only live socket decisions, not the static policy.
  const sessionAllowedWritePaths = new Set<string>();
  const sessionAllowedReadPaths = new Set<string>();

  // Targets the user approved "for session": address:port, since the broker
  // knows nothing more specific than that at connect/bind time.
  const sessionAllowedTargets = new Set<string>();

  // Filesystem and network queries still awaiting a response, so cleanup can
  // release held syscalls instead of letting the child hang.
  const liveQueries = new Set<FsQueryEntry | NetworkQueryEntry>();

  function pump(): void {
    if (activeId !== undefined) return;
    let next = queue.shift();
    while (next && resolved.has(next.id)) next = queue.shift();
    if (!next) return;
    if (next.kind === 'permission') showPermission(next.permission);
    else if (next.kind === 'fs-query') showFsQuery(next);
    else showNetworkQuery(next);
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

  function respondQuery(socket: NetSocket, queryId: string, action: 'allow' | 'deny'): void {
    if (!socket.destroyed) socket.write(controlResponseLine(queryId, action));
  }

  function resolveFsQuery(entry: FsQueryEntry, choice: QueryChoice): void {
    if (resolved.has(entry.id)) return;
    const action = choice === 'deny' ? 'deny' : 'allow';
    const verb = entry.operation === 'read' ? 'Read' : 'Write';
    const directory = api.state.path.directory || process.cwd();
    const scope = sessionScopeFor(entry.path, directory);
    const sessionPaths =
      entry.operation === 'read' ? sessionAllowedReadPaths : sessionAllowedWritePaths;

    try {
      if (action === 'allow') {
        // Breadth-first: seed the session set with the broadest reasonable
        // ancestor so the still-running command stops prompting for sibling
        // files under the same tree. 'once' intentionally stays exact-path.
        if (choice !== 'once') sessionPaths.add(scope);

        if (choice === 'project' || choice === 'global') {
          const { globalPath, projectPath } = getConfigPaths(directory);
          const update = updateForPermission({
            permission: entry.operation,
            metadata: { filepath: scope },
          });
          if (update) writeConfigFile(choice === 'project' ? projectPath : globalPath, update);
        }
      }

      respondQuery(entry.socket, entry.queryId, action);
      api.ui.toast({
        title: 'Sandbox',
        message:
          action === 'deny'
            ? `${verb} denied: ${entry.path}`
            : `${verb} allowed (${choice}) under ${scope}`,
        variant: action === 'deny' ? 'warning' : 'success',
      });
    } catch {
      // Persisting failed — still release the held syscall by denying it.
      respondQuery(entry.socket, entry.queryId, 'deny');
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
    const directory = api.state.path.directory || process.cwd();
    const scope = sessionScopeFor(entry.path, directory);

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
              description: `Permit only this ${noun}`,
            },
            {
              title: 'Allow for session',
              value: 'session',
              category: `This ${noun}`,
              description: `Permit ${noun}s under ${scope} for this session`,
            },
            {
              title: 'Allow for project',
              value: 'project',
              category: 'Persist to sandbox.json',
              description: `Add ${scope} to .opencode/sandbox.json ${listName}`,
            },
            {
              title: 'Allow globally',
              value: 'global',
              category: 'Persist to sandbox.json',
              description: `Add ${scope} to ~/.config/opencode/sandbox.json ${listName}`,
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

  function resolveNetworkQuery(entry: NetworkQueryEntry, choice: NetworkQueryChoice): void {
    if (resolved.has(entry.id)) return;
    const action = choice === 'deny' ? 'deny' : 'allow';

    try {
      if (action === 'allow' && choice === 'session') sessionAllowedTargets.add(entry.target);

      respondQuery(entry.socket, entry.queryId, action);
      api.ui.toast({
        title: 'Sandbox',
        message:
          action === 'deny'
            ? `${entry.operation} denied: ${entry.target}`
            : `${entry.operation} allowed (${choice}): ${entry.target}`,
        variant: action === 'deny' ? 'warning' : 'success',
      });
    } finally {
      liveQueries.delete(entry);
      finishActive(entry.id);
    }
  }

  function showNetworkQuery(entry: NetworkQueryEntry): void {
    activeId = entry.id;

    void api.attention.notify({
      title: `Sandbox ${entry.operation} blocked`,
      message: entry.target,
      sound: { name: 'permission' },
      notification: true,
    });

    // Same esc-denies-a-held-syscall reasoning as showFsQuery.
    let selectionMade = false;

    api.ui.dialog.replace(
      () =>
        api.ui.DialogSelect<NetworkQueryChoice>({
          title: 'Sandbox Network Blocked',
          placeholder: `${entry.operation} blocked: ${entry.target}`,
          options: [
            {
              title: 'Allow once',
              value: 'once',
              category: `This ${entry.operation}`,
              description: `Permit only this ${entry.operation}`,
            },
            {
              title: 'Allow for session',
              value: 'session',
              category: `This ${entry.operation}`,
              description: `Permit ${entry.target} for this session`,
            },
            {
              title: 'Deny',
              value: 'deny',
              category: 'Deny',
              description: `Block this ${entry.operation}`,
            },
          ],
          onSelect: (option) => {
            selectionMade = true;
            resolveNetworkQuery(entry, option.value);
          },
        }),
      () => {
        if (!selectionMade) resolveNetworkQuery(entry, 'deny');
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
      const seen = new Set<string>();
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
            if (trap.kind !== 'filesystem' && trap.kind !== 'network') continue;
            if (trap.state !== 'query') continue;
            if (seen.has(trap.query_id)) continue;
            seen.add(trap.query_id);

            if (trap.kind === 'filesystem') {
              const sessionPaths =
                trap.operation === 'read' ? sessionAllowedReadPaths : sessionAllowedWritePaths;
              if (sessionAllows(sessionPaths, trap.path)) {
                respondQuery(socket, trap.query_id, 'allow');
                continue;
              }

              const entry: FsQueryEntry = {
                kind: 'fs-query',
                id: `landstrip-${trap.operation}:${socketId}:${trap.query_id}`,
                socket,
                queryId: trap.query_id,
                operation: trap.operation,
                path: trap.path,
              };
              liveQueries.add(entry);
              enqueueEntry(entry);
            } else {
              if (sessionAllowedTargets.has(trap.target)) {
                respondQuery(socket, trap.query_id, 'allow');
                continue;
              }

              const entry: NetworkQueryEntry = {
                kind: 'net-query',
                id: `landstrip-net:${socketId}:${trap.query_id}`,
                socket,
                queryId: trap.query_id,
                operation: trap.operation,
                target: trap.target,
              };
              liveQueries.add(entry);
              enqueueEntry(entry);
            }
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

  // /sandbox shows the config and toggles the persisted `enabled` flag. The
  // server reads sandbox.json on every tool call, so the toggle takes effect on
  // the next command without any cross-process signalling.
  const showSandbox = () => {
    const directory = api.state.path.directory || process.cwd();
    const config = loadConfig(directory, optionOverrides);
    const { globalPath, projectPath } = getConfigPaths(directory);
    const next = !config.enabled;
    const message =
      sandboxSummary(config, globalPath, projectPath) +
      `\n\n${next ? 'Enable' : 'Disable'} the sandbox?  (enter = ${next ? 'enable' : 'disable'}, esc = close)`;

    // No `clear()` in onConfirm: the host pops the dialog itself, and its
    // `clear()` re-invokes onClose, which would recurse and freeze the TUI.
    api.ui.dialog.replace(() =>
      api.ui.DialogConfirm({
        title: 'Sandbox',
        message,
        onConfirm: () => {
          const scope = setSandboxConfigEnabled(directory, next);
          refreshSandboxStatus?.();
          api.ui.toast({
            title: 'Sandbox',
            message: `Sandbox ${next ? 'enabled' : 'disabled'} (${scope} config)`,
            variant: next ? 'success' : 'warning',
          });
        },
      }),
    );
  };

  api.keymap.registerLayer({
    commands: [
      {
        namespace: 'palette',
        name: 'sandbox',
        title: 'Sandbox',
        desc: 'Show config and toggle the sandbox',
        category: 'Sandbox',
        suggested: true,
        slash: { name: 'sandbox' },
        slashName: 'sandbox',
        run: showSandbox,
      },
    ],
  });

  api.command?.register(() => [
    {
      title: 'Sandbox',
      value: 'sandbox',
      description: 'Show config and toggle the sandbox',
      category: 'Sandbox',
      suggested: true,
      slash: { name: 'sandbox' },
      onSelect: showSandbox,
    },
  ]);

  // Persistent status badge in the prompt area. It needs the host's Solid
  // runtime, imported defensively so a host that resolves plugin imports
  // differently still loads the plugin — the badge just stays absent there.
  try {
    const { jsx } = await import('@opentui/solid/jsx-runtime');
    const { createSignal } = await import('solid-js');
    const [sandboxRevision, setSandboxRevision] = createSignal(0);
    const statusBadge = (ctx: TuiSlotContext) => {
      sandboxRevision();
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
    refreshSandboxStatus = () => setSandboxRevision((revision) => revision + 1);
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
      respondQuery(entry.socket, entry.queryId, 'deny');
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
export default { id: 'opencode-landstrip', tui };
