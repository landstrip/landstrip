// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { type AddressInfo, createServer, type Socket as NetSocket } from 'node:net';
import { homedir } from 'node:os';
import path from 'node:path';

import type { Plugin as TuiPlugin } from '@opencode/plugin/tui';
import type { ResolvedTheme } from '@opencode/theme/tui';
import { RGBA } from '@opentui/core';
import { Portal, useTerminalDimensions } from '@opentui/solid';
import { Fragment, jsx, jsxs } from '@opentui/solid/jsx-runtime';
import { createSignal, onMount } from 'solid-js';

import {
  controlResponseLine,
  decodeTrapSessionHello,
  getConfigPaths,
  loadConfig,
  normalizeOptions,
  nextSandboxPermissionIndex,
  parseLandstripTraps,
  removeDiscoveryFile,
  sessionAllows,
  sessionAllowancesFor,
  sandboxConfigTarget,
  sessionScopeFor,
  rootSessionIDFor,
  setSandboxConfigEnabled,
  shouldRenderSandboxPermission,
  type SessionAllowances,
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
  onShow: () => void;
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
  sessionID: string;
  sourceSessionID: string;
  directory: string;
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
  sessionID: string;
  sourceSessionID: string;
  directory: string;
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

function resolveThemeColors(theme: ResolvedTheme) {
  return {
    primary: theme.text.action.primary.base,
    text: theme.text.base,
    textMuted: theme.text.muted,
    background: theme.background.base,
    backgroundPanel: theme.background.raised.base,
    backgroundMenu: theme.background.raised.high,
    backgroundElement: theme.background.action.secondary.base,
    border: theme.border.base,
    warning: theme.text.feedback.warning.base,
    warningRgba: theme.text.feedback.warning.base,
    success: theme.text.feedback.success.base,
    error: theme.text.feedback.error.base,
  };
}

const tui: TuiPlugin.Definition = {
  id: 'opencode-landstrip',
  async setup(context: TuiPlugin.Context) {
    const directory = context.location?.directory ?? process.cwd();
    const optionOverrides = normalizeOptions(context.options);
    const enabledManagedByOptions = optionOverrides.enabled !== undefined;

    function LandstripPermissionPrompt(rawProps: Record<string, unknown>) {
      const props = rawProps as unknown as PermissionPromptProps<string>;
      const theme = resolveThemeColors(context.theme);
      const dimensions = useTerminalDimensions();
      const [selected, setSelected] = createSignal(0);
      const [expanded, setExpanded] = createSignal(false);
      onMount(props.onShow);

      function move(direction: number): void {
        setSelected((index) => (index + direction + props.options.length) % props.options.length);
      }

      function submit(): void {
        const option = props.options[selected()];
        if (option) props.onSelect(option.value);
      }

      context.keymap.layer(() => ({
        priority: 1000,
        commands: [
          { id: 'landstrip-perm-prev', bind: 'left', run: () => move(-1) },
          { id: 'landstrip-perm-next', bind: 'right', run: () => move(1) },
          { id: 'landstrip-perm-submit', bind: 'return', run: submit },
          { id: 'landstrip-perm-cancel', bind: 'escape', run: props.onCancel },
          {
            id: 'landstrip-perm-fullscreen',
            bind: 'ctrl+f',
            run: () => setExpanded((value) => !value),
          },
        ],
      }));

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
              if (selected() !== index) return theme.textMuted;
              const background = theme.warningRgba;
              const luminance =
                0.2126 * background.r + 0.7152 * background.g + 0.0722 * background.b;
              return luminance > 0.5 ? RGBA.fromInts(0, 0, 0) : RGBA.fromInts(255, 255, 255);
            },
            children: option.label,
          }),
        }),
      );

      const children = [
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
                    'ctrl+f ',
                    jsx('span', {
                      style: { fg: theme.textMuted },
                      children: expanded() ? 'minimize' : 'fullscreen',
                    }),
                  ],
                }),
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
      ];

      if (expanded()) {
        return Portal({
          children: jsxs('box', {
            top: dimensions().height * -1 + 1,
            bottom: 1,
            left: 2,
            right: 2,
            position: 'absolute',
            border: ['left'],
            borderColor: theme.warning,
            customBorderChars: promptBorderChars,
            backgroundColor: theme.backgroundPanel,
            children,
          }),
        });
      }
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
        children,
      });
    }

    const resolved = new Set<string>();
    const queue: QueueEntry[] = [];
    const [activeEntry, setActiveEntry] = createSignal<QueueEntry>();
    const [permissionRevision, setPermissionRevision] = createSignal(0);
    let activeId: string | undefined;
    let refreshSandboxStatus: (() => void) | undefined;

    const sessionAllowances = new Map<string, SessionAllowances>();
    const notified = new Set<string>();

    // Filesystem and network queries still awaiting a response, so cleanup can
    // release held syscalls instead of letting the child hang.
    const liveQueries = new Set<FsQueryEntry | NetworkQueryEntry>();

    function nativePermissionPending(entry: QueueEntry): boolean {
      if ((context.data.session.permission.list(entry.sessionID)?.length ?? 0) > 0) return true;
      return (
        entry.sourceSessionID !== entry.sessionID &&
        (context.data.session.permission.list(entry.sourceSessionID)?.length ?? 0) > 0
      );
    }

    function pump(): void {
      const route = context.ui.router.current();
      if (route.type !== 'session' || !route.sessionID) return;
      const routeSessionID = route.sessionID;

      const active = activeEntry();
      if (activeId !== undefined) {
        if (active?.sessionID === routeSessionID) return;
        if (active && !resolved.has(active.id)) queue.unshift(active);
        activeId = undefined;
        setActiveEntry(undefined);
      }

      for (let index = queue.length - 1; index >= 0; index -= 1) {
        const entry = queue[index];
        if (entry && resolved.has(entry.id)) queue.splice(index, 1);
      }

      const index = nextSandboxPermissionIndex(queue, routeSessionID, nativePermissionPending);
      if (index === -1) return;
      const [next] = queue.splice(index, 1);
      if (!next) return;
      activeId = next.id;
      setActiveEntry(next);
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
      notified.delete(id);
      if (activeId === id) {
        activeId = undefined;
        setActiveEntry(undefined);
      }
      queueMicrotask(pump);
    }

    function notifyQuery(entry: QueueEntry): void {
      if (notified.has(entry.id)) return;
      notified.add(entry.id);
      void context.attention
        .notify({
          title: `Sandbox ${entry.operation} blocked`,
          message: entry.kind === 'fs-query' ? entry.path : entry.target,
          sound: { name: 'permission' },
          notification: true,
        })
        .catch(() => undefined);
    }

    function renderSessionPrompt(props: { sessionID: string }) {
      return jsx(Fragment, {
        get children() {
          permissionRevision();
          queueMicrotask(pump);
          const entry = activeEntry();
          const hostPromptActive = Boolean(entry && nativePermissionPending(entry));
          const showEntry = Boolean(
            entry &&
            shouldRenderSandboxPermission(entry.sessionID, props.sessionID, hostPromptActive),
          );
          if (showEntry && entry?.kind === 'fs-query') {
            const verb = entry.operation === 'read' ? 'Read' : 'Write';
            return jsx(LandstripPermissionPrompt, {
              icon: '→',
              title: `${verb} ${formatPath(entry.path, entry.directory)}`,
              options: [
                { label: 'Allow once', value: 'once' },
                { label: 'Allow for session', value: 'session' },
                { label: 'Allow for project', value: 'project' },
                { label: 'Allow globally', value: 'global' },
                { label: 'Deny', value: 'deny' },
              ],
              onSelect: (choice: QueryChoice) => resolveFsQuery(entry, choice),
              onCancel: () => resolveFsQuery(entry, 'deny'),
              onShow: () => notifyQuery(entry),
            });
          }
          if (showEntry && entry?.kind === 'net-query') {
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
              onShow: () => notifyQuery(entry),
            });
          }
          return null;
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
      const directory = entry.directory;
      const scope = sessionScopeFor(entry.path, directory);
      const allowances = sessionAllowancesFor(sessionAllowances, entry.sessionID);
      const sessionPaths =
        entry.operation === 'read' ? allowances.readPaths : allowances.writePaths;

      let responseAction: 'allow' | 'deny' = action;
      try {
        if (action === 'allow') {
          if (choice === 'project' || choice === 'global') {
            const { globalPath, projectPath } = getConfigPaths(directory);
            const update = updateForPermission({
              permission: entry.operation,
              metadata: { filepath: scope },
            });
            if (update) writeConfigFile(choice === 'project' ? projectPath : globalPath, update);
          }
          if (choice !== 'once') sessionPaths.add(scope);
        }
      } catch {
        responseAction = 'deny';
      }

      try {
        respondQuery(entry.socket, entry.queryId, responseAction);
        context.ui.toast.show({
          title: 'Sandbox',
          message:
            responseAction === 'deny'
              ? `${verb} denied: ${entry.path}`
              : `${verb} allowed (${choice}) under ${scope}`,
          variant: responseAction === 'deny' ? 'warning' : 'success',
        });
      } finally {
        liveQueries.delete(entry);
        finishActive(entry.id);
      }
    }

    function resolveNetworkQuery(entry: NetworkQueryEntry, choice: NetworkQueryChoice): void {
      if (resolved.has(entry.id)) return;
      const action = choice === 'deny' ? 'deny' : 'allow';

      try {
        if (action === 'allow' && choice === 'session') {
          sessionAllowancesFor(sessionAllowances, entry.sessionID).targets.add(entry.target);
        }

        respondQuery(entry.socket, entry.queryId, action);
        context.ui.toast.show({
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

    // Query-response socket server (Linux-only — landstrip's socket protocol lives
    // in the seccomp broker). The server plugin connects each sandboxed run's
    // fd 3 here via a /dev/tcp redirect and we answer held writes interactively.
    const sockets = new Set<NetSocket>();
    let socketServer: ReturnType<typeof createServer> | undefined;

    if (process.platform === 'linux') {
      const baseDirectory = directory;
      let socketSeq = 0;

      socketServer = createServer((socket) => {
        sockets.add(socket);
        socket.setEncoding('utf-8');
        const socketId = ++socketSeq;
        const seen = new Set<string>();
        let buffer = '';
        let sourceSessionID: string | undefined;
        let routeSessionID: string | undefined;
        let sessionDirectory: string | undefined;

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

            if (!sourceSessionID || !routeSessionID || !sessionDirectory) {
              const hello = decodeTrapSessionHello(line);
              const sourceSession = hello ? context.data.session.get(hello.sessionID) : undefined;
              const rootSession = hello
                ? rootSessionIDFor(hello.sessionID, (sessionID) =>
                    context.data.session.get(sessionID),
                  )
                : undefined;
              if (!hello || !sourceSession || !rootSession) {
                socket.destroy();
                return;
              }
              sourceSessionID = hello.sessionID;
              routeSessionID = rootSession;
              sessionDirectory = sourceSession.location.directory || directory;
              continue;
            }

            const allowances = sessionAllowancesFor(sessionAllowances, routeSessionID);
            for (const trap of parseLandstripTraps(line)) {
              if (trap.kind !== 'filesystem' && trap.kind !== 'network') continue;
              if (trap.state !== 'query') continue;
              if (seen.has(trap.query_id)) continue;
              seen.add(trap.query_id);

              if (!loadConfig(sessionDirectory, optionOverrides).enabled) {
                respondQuery(socket, trap.query_id, 'allow');
                continue;
              }

              if (trap.kind === 'filesystem') {
                if (trap.operation === 'write' && trap.reason === 'deny_match') {
                  respondQuery(socket, trap.query_id, 'deny');
                  continue;
                }
                const sessionPaths =
                  trap.operation === 'read' ? allowances.readPaths : allowances.writePaths;
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
                  sessionID: routeSessionID,
                  sourceSessionID,
                  directory: sessionDirectory,
                };
                liveQueries.add(entry);
                enqueueEntry(entry);
              } else {
                if (allowances.targets.has(trap.target)) {
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
                  sessionID: routeSessionID,
                  sourceSessionID,
                  directory: sessionDirectory,
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

    const refreshPermissionPresentation = (): void => {
      queueMicrotask(() => {
        setPermissionRevision((revision) => revision + 1);
        pump();
      });
    };
    const unregisterPermissionAsked = context.data.on(
      'permission.asked',
      refreshPermissionPresentation,
    );
    const unregisterPermissionReplied = context.data.on(
      'permission.replied',
      refreshPermissionPresentation,
    );

    const [landstripOpen, setLandstripOpen] = createSignal(false);
    const [confirmingDisable, setConfirmingDisable] = createSignal(false);
    const [sandboxRevision, setSandboxRevision] = createSignal(0);
    let popLandstripMode: (() => void) | undefined;

    const closeLandstrip = () => {
      popLandstripMode?.();
      popLandstripMode = undefined;
      setConfirmingDisable(false);
      setLandstripOpen(false);
    };
    const toggleLandstrip = () => {
      if (enabledManagedByOptions) {
        context.ui.toast.show({
          title: 'Landstrip',
          message: 'Sandbox state is managed by plugin options',
          variant: 'warning',
        });
        return;
      }

      const config = loadConfig(directory, optionOverrides);
      if (config.enabled && !confirmingDisable()) {
        setConfirmingDisable(true);
        return;
      }
      setConfirmingDisable(false);
      const enabled = !config.enabled;
      const scope = setSandboxConfigEnabled(directory, enabled, optionOverrides);
      refreshSandboxStatus?.();
      context.ui.toast.show({
        title: 'Landstrip',
        message: `Sandbox ${enabled ? 'enabled' : 'disabled'} (${scope} config)`,
        variant: enabled ? 'success' : 'warning',
      });
    };
    const cancelLandstrip = () => {
      if (confirmingDisable()) setConfirmingDisable(false);
      else closeLandstrip();
    };

    function LandstripPane() {
      const theme = resolveThemeColors(context.theme);
      const dimensions = useTerminalDimensions();

      context.keymap.layer(() => ({
        enabled: () => landstripOpen(),
        priority: 1000,
        commands: [
          { id: 'landstrip-toggle', bind: 'return', run: toggleLandstrip },
          { id: 'landstrip-cancel', bind: 'escape', run: cancelLandstrip },
        ],
      }));

      const row = (label: string, value: string) =>
        jsxs('box', {
          flexDirection: 'row',
          paddingLeft: 2,
          paddingRight: 2,
          children: [
            jsx('text', { fg: theme.textMuted, width: 22, children: label }),
            jsx('text', { fg: theme.text, flexGrow: 1, wrapMode: 'word', children: value }),
          ],
        });

      return Portal({
        get children() {
          if (!landstripOpen()) return null;
          sandboxRevision();
          const config = loadConfig(directory, optionOverrides);
          const target = sandboxConfigTarget(directory);
          const values = (items: readonly string[]) => items.join(', ') || 'none';
          const status = enabledManagedByOptions
            ? config.enabled
              ? 'Active (plugin options)'
              : 'Disabled by plugin options'
            : config.enabled
              ? 'Active'
              : 'Disabled by configuration';
          return jsxs('box', {
            position: 'absolute',
            zIndex: 4000,
            bottom: 0,
            left: 0,
            right: 0,
            get height() {
              return Math.min(22, Math.max(12, dimensions().height - 2));
            },
            flexDirection: 'column',
            border: ['top'],
            borderColor: theme.primary,
            backgroundColor: theme.backgroundPanel,
            children: [
              jsxs('box', {
                flexDirection: 'row',
                paddingLeft: 2,
                paddingRight: 2,
                paddingTop: 1,
                paddingBottom: 1,
                justifyContent: 'space-between',
                children: [
                  jsx('text', { fg: theme.primary, children: 'Landstrip' }),
                  jsx('text', {
                    fg: config.enabled ? theme.success : theme.warning,
                    children: status,
                  }),
                ],
              }),
              row('Network', config.network.allowNetwork ? 'Unrestricted' : 'Proxied'),
              row('Allowed Domains', values(config.network.allowedDomains)),
              row('Denied Domains', values(config.network.deniedDomains)),
              row('Allowed Reads', values(config.filesystem.allowRead)),
              row('Denied Reads', values(config.filesystem.denyRead)),
              row('Allowed Writes', values(config.filesystem.allowWrite)),
              row('Denied Writes', values(config.filesystem.denyWrite)),
              row(
                'Configuration Scope',
                enabledManagedByOptions
                  ? 'Plugin options'
                  : target.scope === 'project'
                    ? 'Project'
                    : 'Global',
              ),
              row('Configuration File', formatPath(target.path, directory)),
              jsx('box', { flexGrow: 1 }),
              jsx('text', {
                fg: confirmingDisable() ? theme.error : theme.textMuted,
                marginLeft: 2,
                marginRight: 2,
                marginBottom: 1,
                children: confirmingDisable()
                  ? 'Disable the sandbox? Commands will run without OS isolation.  Enter confirm · Esc cancel'
                  : enabledManagedByOptions
                    ? 'Sandbox state is managed by plugin options · Esc close'
                    : `Enter ${config.enabled ? 'disable' : 'enable'} · Esc close`,
              }),
            ],
          });
        },
      });
    }

    const showLandstrip = () => {
      if (landstripOpen()) return;
      setLandstripOpen(true);
      popLandstripMode = context.keymap.mode.push('modal');
    };

    context.keymap.layer(() => ({
      commands: [
        {
          id: 'landstrip',
          title: 'Landstrip',
          description: 'Manage the Landstrip sandbox',
          palette: true,
          suggested: true,
          slash: { name: 'landstrip' },
          run: showLandstrip,
        },
      ],
    }));

    // Persistent status badge in the prompt area.
    const statusBadge = () => {
      sandboxRevision();
      const config = loadConfig(directory, optionOverrides);
      const theme = resolveThemeColors(context.theme);

      if (!config.enabled) return jsx('text', { fg: theme.textMuted, children: 'sandbox off' });

      const open = config.network.allowNetwork;
      return jsx('text', {
        fg: open ? theme.warning : theme.success,
        children: `sandbox · ${open ? 'net open' : 'net proxied'}`,
      });
    };

    context.ui.slot({
      append: 'app',
      render: () => jsx(LandstripPane, {}),
    });
    context.ui.slot({
      append: 'home.footer.status',
      render: () => statusBadge(),
    });
    context.ui.slot({
      append: 'prompt.footer.status',
      render: () => statusBadge(),
    });
    context.ui.slot({
      append: 'session.composer.top',
      render: (props) => renderSessionPrompt(props),
    });
    refreshSandboxStatus = () => setSandboxRevision((revision) => revision + 1);

    // First-run onboarding: a single quiet pointer to the default-strict policy
    // and the inspector command.
    try {
      const [persisted, setPersisted] = context.storage.store<{ onboarded?: boolean }>(
        'opencode-landstrip',
        { initial: { onboarded: false } },
      );
      if (!persisted.onboarded) {
        void setPersisted((draft) => {
          draft.onboarded = true;
        }).catch(() => undefined);
        context.ui.toast.show({
          title: 'Sandbox active',
          message: 'Landstrip sandbox is on. Run /landstrip to inspect it.',
          variant: 'info',
          duration: 8000,
        });
      }
    } catch {
      // Ignore storage errors
    }

    return () => {
      closeLandstrip();
      unregisterPermissionAsked();
      unregisterPermissionReplied();
      sessionAllowances.clear();
      // Deny any still-held queries so the sandboxed children don't hang, then
      // tear down the socket server and drop the discovery file.
      for (const entry of liveQueries) {
        respondQuery(entry.socket, entry.queryId, 'deny');
        liveQueries.delete(entry);
        finishActive(entry.id);
      }
      for (const socket of sockets) socket.destroy();
      if (socketServer) {
        socketServer.close();
        try {
          removeDiscoveryFile(directory);
        } catch {
          // best effort
        }
      }
    };
  },
};

export { tui };
export default tui;
