// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { type AddressInfo, createServer, type Socket as NetSocket } from 'node:net';
import { homedir } from 'node:os';
import path from 'node:path';

import type {
  TuiHostSlotMap,
  TuiPlugin,
  TuiSlotContext,
  TuiSlotPlugin,
} from '@opencode-ai/plugin/tui';
import { RGBA } from '@opentui/core';
import { useTerminalDimensions } from '@opentui/solid';
import { Fragment, jsx, jsxs } from '@opentui/solid/jsx-runtime';
import { createSignal, onCleanup } from 'solid-js';

import {
  controlResponseLine,
  getConfigPaths,
  loadConfig,
  normalizeOptions,
  parseLandstripTraps,
  removeDiscoveryFile,
  sessionAllows,
  sandboxSummary,
  sessionScopeFor,
  setSandboxConfigEnabled,
  updateForPermission,
  writeConfigFile,
  writeDiscoveryPort,
} from './shared.js';

type QueryChoice = 'once' | 'session' | 'project' | 'global' | 'deny';

// No project/global option: no landstrip policy field expresses "allow this
// address:port" the way allowRead/allowWrite express a path.
type NetworkQueryChoice = 'once' | 'session' | 'deny';

interface PromptOption<Value extends string> {
  label: string;
  value: Value;
}

interface PermissionPromptProps<Value extends string> {
  icon: string;
  title: string;
  options: readonly PromptOption<Value>[];
  onSelect: (value: Value) => void;
  onCancel: () => void;
}

const promptBorderChars = {
  topLeft: '',
  bottomLeft: '',
  vertical: '┃',
  topRight: '',
  bottomRight: '',
  horizontal: ' ',
  bottomT: '',
  topT: '',
  cross: '',
  leftT: '',
  rightT: '',
};

// A landstrip filesystem query (read or write) held pending over the fd-3
// socket. Filesystem and network queries share one queue so only one toolchain
// prompt is active at a time.
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

type QueueEntry = FsQueryEntry | NetworkQueryEntry;

function formatPath(input: string, base: string): string {
  const absolute = path.isAbsolute(input) ? input : path.resolve(base, input);
  const relative = path.relative(base, absolute);

  if (!relative) return '.';
  if (relative !== '..' && !relative.startsWith(`..${path.sep}`)) return relative;

  const home = homedir();
  if (absolute === home) return '~';
  if (absolute.startsWith(`${home}${path.sep}`)) return `~${absolute.slice(home.length)}`;
  return absolute;
}

function selectedForeground(theme: TuiSlotContext['theme']['current']): RGBA {
  const resolved = theme as typeof theme & { _hasSelectedListItemText?: boolean };
  if (resolved._hasSelectedListItemText) return theme.selectedListItemText;

  if (theme.background.a === 0) {
    const { r, g, b } = theme.warning;
    const luminance = 0.299 * r + 0.587 * g + 0.114 * b;
    return luminance > 0.5 ? RGBA.fromInts(0, 0, 0) : RGBA.fromInts(255, 255, 255);
  }
  return theme.background;
}

const tui: TuiPlugin = async (api, options, meta) => {
  const optionOverrides = normalizeOptions(options);

  function LandstripPermissionPrompt(rawProps: Record<string, unknown>) {
    const props = rawProps as unknown as PermissionPromptProps<string>;
    const theme = api.theme.current;
    const dimensions = useTerminalDimensions();
    const [selected, setSelected] = createSignal(0);

    function move(direction: number): void {
      setSelected((index) => (index + direction + props.options.length) % props.options.length);
    }

    function submit(): void {
      const option = props.options[selected()];
      if (option) props.onSelect(option.value);
    }

    const unregister = api.keymap.registerLayer({
      priority: 1000,
      bindings: [
        { key: 'left', cmd: () => move(-1) },
        { key: 'h', cmd: () => move(-1) },
        { key: 'right', cmd: () => move(1) },
        { key: 'l', cmd: () => move(1) },
        { key: 'return', cmd: submit },
        { key: 'escape', cmd: props.onCancel },
      ],
    });
    onCleanup(unregister);

    const optionButtons = props.options.map((option, index) =>
      jsx('box', {
        paddingLeft: 1,
        paddingRight: 1,
        flexShrink: 0,
        get backgroundColor() {
          return selected() === index ? theme.warning : theme.backgroundMenu;
        },
        onMouseOver: () => setSelected(index),
        onMouseUp: () => {
          setSelected(index);
          props.onSelect(option.value);
        },
        children: jsx('text', {
          get fg() {
            return selected() === index ? selectedForeground(theme) : theme.textMuted;
          },
          children: option.label,
        }),
      }),
    );

    return jsxs('box', {
      top: 0,
      maxHeight: 15,
      bottom: 0,
      left: 0,
      right: 0,
      position: 'relative',
      border: ['left'],
      borderColor: theme.warning,
      customBorderChars: promptBorderChars,
      backgroundColor: theme.backgroundPanel,
      children: [
        jsxs('box', {
          gap: 1,
          paddingLeft: 1,
          paddingRight: 3,
          paddingTop: 1,
          paddingBottom: 1,
          flexGrow: 1,
          children: [
            jsxs('box', {
              flexDirection: 'column',
              gap: 0,
              paddingLeft: 1,
              flexShrink: 0,
              children: [
                jsxs('box', {
                  flexDirection: 'row',
                  gap: 1,
                  flexShrink: 0,
                  children: [
                    jsx('text', { fg: theme.warning, children: '△' }),
                    jsx('text', { fg: theme.text, children: 'Permission required' }),
                  ],
                }),
                jsxs('box', {
                  flexDirection: 'row',
                  gap: 1,
                  paddingLeft: 2,
                  flexShrink: 0,
                  children: [
                    jsx('text', { fg: theme.textMuted, flexShrink: 0, children: props.icon }),
                    jsx('text', { fg: theme.text, wrapMode: 'word', children: props.title }),
                  ],
                }),
              ],
            }),
          ],
        }),
        jsxs('box', {
          get flexDirection() {
            return dimensions().width < 80 ? 'column' : 'row';
          },
          flexShrink: 0,
          gap: 1,
          paddingTop: 1,
          paddingLeft: 2,
          paddingRight: 3,
          paddingBottom: 1,
          backgroundColor: theme.backgroundElement,
          get justifyContent() {
            return dimensions().width < 80 ? 'flex-start' : 'space-between';
          },
          get alignItems() {
            return dimensions().width < 80 ? 'flex-start' : 'center';
          },
          children: [
            jsx('box', {
              flexDirection: 'row',
              gap: 1,
              flexShrink: 0,
              children: optionButtons,
            }),
            jsxs('box', {
              flexDirection: 'row',
              gap: 2,
              flexShrink: 0,
              children: [
                jsxs('text', {
                  fg: theme.text,
                  children: [
                    '⇆ ',
                    jsx('span', { style: { fg: theme.textMuted }, children: 'select' }),
                  ],
                }),
                jsxs('text', {
                  fg: theme.text,
                  children: [
                    'enter ',
                    jsx('span', { style: { fg: theme.textMuted }, children: 'confirm' }),
                  ],
                }),
              ],
            }),
          ],
        }),
      ],
    });
  }

  const resolved = new Set<string>();
  const queue: QueueEntry[] = [];
  const [activeEntry, setActiveEntry] = createSignal<QueueEntry>();
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
    if (next.kind === 'fs-query') showFsQuery(next);
    else showNetworkQuery(next);
  }

  function enqueueEntry(entry: QueueEntry): void {
    if (!entry.id || resolved.has(entry.id)) return;
    if (activeId === entry.id) return;
    if (queue.some((item) => item.id === entry.id)) return;
    queue.push(entry);
    pump();
  }

  function finishActive(id: string): void {
    resolved.add(id);
    if (activeId === id) {
      activeId = undefined;
      setActiveEntry(undefined);
    }
    queueMicrotask(pump);
  }

  function renderSessionPrompt(props: TuiHostSlotMap['session_prompt']) {
    return jsx(Fragment, {
      get children() {
        const entry = activeEntry();
        const directory =
          api.state.session.get(props.session_id)?.directory ||
          api.state.path.directory ||
          process.cwd();
        if (entry?.kind === 'fs-query') {
          const verb = entry.operation === 'read' ? 'Read' : 'Write';
          return jsx(LandstripPermissionPrompt, {
            icon: '→',
            title: `${verb} ${formatPath(entry.path, directory)}`,
            options: [
              { label: 'Allow once', value: 'once' },
              { label: 'Allow for session', value: 'session' },
              { label: 'Allow for project', value: 'project' },
              { label: 'Allow globally', value: 'global' },
              { label: 'Deny', value: 'deny' },
            ],
            onSelect: (choice: QueryChoice) => resolveFsQuery(entry, choice),
            onCancel: () => resolveFsQuery(entry, 'deny'),
          });
        }
        if (entry?.kind === 'net-query') {
          const verb = entry.operation
            ? entry.operation[0]?.toUpperCase() + entry.operation.slice(1)
            : 'Network';
          return jsx(LandstripPermissionPrompt, {
            icon: '%',
            title: `${verb} ${entry.target}`,
            options: [
              { label: 'Allow once', value: 'once' },
              { label: 'Allow for session', value: 'session' },
              { label: 'Deny', value: 'deny' },
            ],
            onSelect: (choice: NetworkQueryChoice) => resolveNetworkQuery(entry, choice),
            onCancel: () => resolveNetworkQuery(entry, 'deny'),
          });
        }
        return api.ui.Prompt({
          sessionID: props.session_id,
          ...(props.visible === undefined ? {} : { visible: props.visible }),
          ...(props.disabled === undefined ? {} : { disabled: props.disabled }),
          ...(props.on_submit === undefined ? {} : { onSubmit: props.on_submit }),
          ...(props.ref === undefined ? {} : { ref: props.ref }),
          right: api.ui.Slot({
            name: 'session_prompt_right',
            session_id: props.session_id,
          }),
        });
      },
    });
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
    setActiveEntry(entry);

    void api.attention.notify({
      title: `Sandbox ${entry.operation} blocked`,
      message: entry.path,
      sound: { name: 'permission' },
      notification: true,
    });
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
    setActiveEntry(entry);

    void api.attention.notify({
      title: `Sandbox ${entry.operation} blocked`,
      message: entry.target,
      sound: { name: 'permission' },
      notification: true,
    });
  }

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
            const directory = api.state.path.directory || process.cwd();
            if (trap.kind !== 'filesystem' && trap.kind !== 'network') continue;
            if (trap.state !== 'query') continue;
            if (seen.has(trap.query_id)) continue;
            seen.add(trap.query_id);

            if (!loadConfig(directory, optionOverrides).enabled) {
              respondQuery(socket, trap.query_id, 'allow');
              continue;
            }

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
        desc: 'Inspect and toggle the sandbox',
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
      description: 'Inspect and toggle the sandbox',
      category: 'Sandbox',
      suggested: true,
      slash: { name: 'sandbox' },
      onSelect: showSandbox,
    },
  ]);

  // Persistent status badge in the prompt area.
  try {
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
        session_prompt: (_ctx, props) => renderSessionPrompt(props),
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
      message: 'Landstrip sandbox is on. Run /sandbox to inspect it.',
      variant: 'info',
      duration: 8000,
    });
  }

  api.lifecycle.onDispose(() => {
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
