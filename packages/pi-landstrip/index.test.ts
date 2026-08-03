// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import type {
  ExtensionAPI,
  ExtensionContext,
  ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import { describe, expect, it, vi } from 'vitest';

import landstripExtension, {
  createLandstripIntegration,
  createLandstripLauncherEnvironment,
  createPosixShellProvider,
  createWindowsDenyRead,
  matchesPattern,
  enforcesShellReadPolicy,
  isPublicProxyAddress,
  readAllowed,
  sessionScopeFor,
  resolveProcessReadPolicy,
  shouldPromptForWrite,
  writeEnvFile,
} from './index.ts';

import { AsyncQueue, PermissionPromptCoordinator } from './util.ts';

describe('Landstrip launcher environment', () => {
  it('preserves the host ProgramData path on Windows', () => {
    expect(
      createLandstripLauncherEnvironment(
        { PATH: 'provider-path', ProgramData: 'provider-data' },
        { ProgramData: 'C:\\ProgramData' },
        'win32',
      ),
    ).toEqual({ PATH: 'provider-path', ProgramData: 'C:\\ProgramData' });
  });

  it('does not add ProgramData when the host does not require or provide it', () => {
    const providerEnv = { PATH: 'provider-path' };
    expect(createLandstripLauncherEnvironment(providerEnv, {}, 'linux')).toBe(providerEnv);
    expect(createLandstripLauncherEnvironment(providerEnv, {}, 'win32')).toBe(providerEnv);
  });
});

describe('Windows read policy', () => {
  it('drops POSIX-only deny paths before applying filesystem ACLs', () => {
    expect(createWindowsDenyRead(['/Users', '/home', 'C:\\Secrets'], 'C:\\')).toEqual([
      'C:\\Secrets',
      'C:\\',
    ]);
  });
});

describe('process read policy', () => {
  const denyRead = ['/Users', '/home'];
  const allowRead = ['.'];

  it('aligns primary shell reads with trusted host tools', () => {
    expect(resolveProcessReadPolicy('shell', 'host', denyRead, allowRead, 'darwin')).toEqual({
      denyRead: [],
      allowRead: [],
    });
  });

  it('keeps worker processes confined by the configured read policy', () => {
    expect(resolveProcessReadPolicy('worker', 'host', denyRead, allowRead, 'darwin')).toEqual({
      denyRead,
      allowRead,
    });
  });

  it('supports explicit shell read isolation', () => {
    expect(resolveProcessReadPolicy('shell', 'policy', denyRead, allowRead, 'linux')).toEqual({
      denyRead,
      allowRead,
    });
  });

  it('retains the required explicit Windows read policy', () => {
    expect(resolveProcessReadPolicy('shell', 'host', denyRead, allowRead, 'win32')).toEqual({
      denyRead,
      allowRead,
    });
  });

  it('does not reinterpret host permission failures as sandbox read denials', () => {
    expect(enforcesShellReadPolicy('host', 'darwin')).toBe(false);
    expect(enforcesShellReadPolicy('policy', 'darwin')).toBe(true);
    expect(enforcesShellReadPolicy('host', 'win32')).toBe(true);
    expect(enforcesShellReadPolicy('invalid', 'darwin')).toBe(true);
  });
});

describe('main Pi tool composition', () => {
  it('leaves filesystem tool names available to Pi plugins', () => {
    const tools: string[] = [];
    const pi = {
      registerTool(tool: ToolDefinition) {
        tools.push(tool.name);
      },
      registerFlag() {},
      registerCommand() {},
      registerShortcut() {},
      on() {},
    } as unknown as ExtensionAPI;
    landstripExtension(pi);
    expect(tools).toEqual(['task', 'bash']);
    expect(tools).not.toContain('read');
    expect(tools).not.toContain('write');
  });
});

it('prepares the default POSIX shell invocation and disposes its environment file', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'pi-landstrip-shell-provider-'));
  const invocation = await createPosixShellProvider().prepare({
    command: 'printf ready',
    cwd,
    env: { TEST_VALUE: 'provider-value' },
  });
  const envPath = invocation.readPaths?.[0];

  expect(envPath).toBeDefined();
  expect(readFileSync(envPath!, 'utf8')).toContain("export TEST_VALUE='provider-value'");
  expect(invocation.args.at(-1)).toContain(`source '${envPath}' && printf ready`);

  await invocation.dispose?.();
  expect(existsSync(envPath!)).toBe(false);
  rmSync(cwd, { recursive: true, force: true });
});

it('uses the active shell provider for the bash tool and user shell', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'pi-landstrip-active-shell-'));
  const agentDir = mkdtempSync(join(tmpdir(), 'pi-landstrip-active-shell-agent-'));
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  const handlers = new Map<string, unknown>();
  let bashTool: ToolDefinition | undefined;
  const pi = {
    registerTool(tool: ToolDefinition) {
      if (tool.name === 'bash') bashTool = tool;
    },
    registerFlag() {},
    registerCommand() {},
    getFlag() {
      return false;
    },
    on(event: string, handler: unknown) {
      handlers.set(event, handler);
    },
  } as unknown as ExtensionAPI;
  const ctx = {
    cwd,
    hasUI: false,
    mode: 'rpc',
    isProjectTrusted: () => true,
    sessionManager: { getSessionId: () => 'test-session', getSessionFile: () => undefined },
    ui: { notify() {}, setStatus() {} },
  } as unknown as ExtensionContext;
  const disposeInvocation = vi.fn();
  const prepare = vi.fn((options: { command: string; env: NodeJS.ProcessEnv }) => ({
    executable: process.execPath,
    args: ['-e', `process.stdout.write(${JSON.stringify(options.command)})`],
    launcherEnv: { PATH: options.env.PATH, HOME: options.env.HOME },
    readPaths: [process.execPath],
    dispose: disposeInvocation,
  }));
  const integration = createLandstripIntegration();
  integration.registerShellProvider({ id: 'test-shell', prepare });
  integration.register(pi);

  try {
    const sessionStart = handlers.get('session_start') as (
      event: unknown,
      context: ExtensionContext,
    ) => Promise<void>;
    await sessionStart({}, ctx);
    expect(bashTool).toBeDefined();
    await bashTool!.execute('tool-call', { command: 'tool-provider' }, undefined, undefined, ctx);

    const userBash = handlers.get('user_bash') as (
      event: unknown,
      context: ExtensionContext,
    ) => Promise<{
      operations: {
        exec(
          command: string,
          cwd: string,
          options: { onData(data: Buffer): void },
        ): Promise<unknown>;
      };
    }>;
    const userShell = await userBash({}, ctx);
    await userShell.operations.exec('user-provider', cwd, { onData() {} });

    expect(prepare.mock.calls.map(([options]) => options.command)).toEqual([
      'tool-provider',
      'user-provider',
    ]);
    expect(disposeInvocation).toHaveBeenCalledTimes(2);
  } finally {
    const shutdown = handlers.get('session_shutdown') as (() => void) | undefined;
    shutdown?.();
    vi.unstubAllEnvs();
    rmSync(cwd, { recursive: true, force: true });
    rmSync(agentDir, { recursive: true, force: true });
  }
});

it('uses the active shell provider when sandboxing is disabled', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'pi-landstrip-disabled-shell-'));
  const handlers = new Map<string, unknown>();
  let bashTool: ToolDefinition | undefined;
  const pi = {
    registerTool(tool: ToolDefinition) {
      if (tool.name === 'bash') bashTool = tool;
    },
    registerFlag() {},
    registerCommand() {},
    getFlag: (name: string) => name === 'no-sandbox',
    on(event: string, handler: unknown) {
      handlers.set(event, handler);
    },
  } as unknown as ExtensionAPI;
  const ctx = {
    cwd,
    hasUI: false,
    mode: 'rpc',
    isProjectTrusted: () => true,
    sessionManager: { getSessionId: () => 'disabled-session', getSessionFile: () => undefined },
    ui: { notify() {}, setStatus() {} },
  } as unknown as ExtensionContext;
  const disposeInvocation = vi.fn();
  const prepare = vi.fn((options: { command: string; env: NodeJS.ProcessEnv }) => ({
    executable: process.execPath,
    args: ['-e', `process.stdout.write(${JSON.stringify(options.command)})`],
    launcherEnv: { PATH: options.env.PATH, HOME: options.env.HOME },
    dispose: disposeInvocation,
  }));
  const integration = createLandstripIntegration();
  integration.registerShellProvider({ id: 'disabled-shell', prepare });
  integration.register(pi);

  try {
    const sessionStart = handlers.get('session_start') as (
      event: unknown,
      context: ExtensionContext,
    ) => Promise<void>;
    await sessionStart({}, ctx);
    expect(bashTool).toBeDefined();
    await bashTool!.execute('tool-call', { command: 'tool-provider' }, undefined, undefined, ctx);

    const userBash = handlers.get('user_bash') as (
      event: unknown,
      context: ExtensionContext,
    ) => Promise<{
      operations: {
        exec(
          command: string,
          cwd: string,
          options: { onData(data: Buffer): void },
        ): Promise<unknown>;
      };
    }>;
    const userShell = await userBash({}, ctx);
    await userShell.operations.exec('user-provider', cwd, { onData() {} });

    expect(prepare.mock.calls.map(([options]) => options.command)).toEqual([
      'tool-provider',
      'user-provider',
    ]);
    expect(disposeInvocation).toHaveBeenCalledTimes(2);
  } finally {
    const shutdown = handlers.get('session_shutdown') as (() => void) | undefined;
    shutdown?.();
    rmSync(cwd, { recursive: true, force: true });
  }
});

it('skips a queued permission prompt after a concurrent session grant', async () => {
  const coordinator = new PermissionPromptCoordinator();
  const path = join(homedir(), '.cargo');
  const sessionAllowedReadPaths = new Set<string>();
  let finishPrompt = (): void => {};
  const promptPending = new Promise<void>((resolve) => {
    finishPrompt = resolve;
  });
  const current = (): boolean | undefined => (sessionAllowedReadPaths.has(path) ? true : undefined);
  const prompt = vi.fn(async () => {
    await promptPending;
    sessionAllowedReadPaths.add(path);
    return true;
  });

  const first = coordinator.resolve(current, prompt);
  await vi.waitFor(() => expect(prompt).toHaveBeenCalledOnce());
  const second = coordinator.resolve(current, prompt);
  finishPrompt();

  await expect(Promise.all([first, second])).resolves.toEqual([true, true]);
  expect(prompt).toHaveBeenCalledOnce();
});

it('keeps allow-once permission prompts local to each execution', async () => {
  const coordinator = new PermissionPromptCoordinator();
  const path = join(homedir(), '.cargo');
  const firstAllowances = new Set<string>();
  const secondAllowances = new Set<string>();
  let finishFirstPrompt = (): void => {};
  const firstPromptPending = new Promise<void>((resolve) => {
    finishFirstPrompt = resolve;
  });
  const firstPrompt = vi.fn(async () => {
    await firstPromptPending;
    firstAllowances.add(path);
    return true;
  });
  const secondPrompt = vi.fn(async () => {
    secondAllowances.add(path);
    return true;
  });

  const first = coordinator.resolve(
    () => (firstAllowances.has(path) ? true : undefined),
    firstPrompt,
  );
  await vi.waitFor(() => expect(firstPrompt).toHaveBeenCalledOnce());
  const second = coordinator.resolve(
    () => (secondAllowances.has(path) ? true : undefined),
    secondPrompt,
  );
  finishFirstPrompt();

  await expect(Promise.all([first, second])).resolves.toEqual([true, true]);
  expect(firstPrompt).toHaveBeenCalledOnce();
  expect(secondPrompt).toHaveBeenCalledOnce();
});

it('removes cancelled queued permission prompts without blocking successors', async () => {
  const coordinator = new PermissionPromptCoordinator();
  const controller = new AbortController();
  let finishFirstPrompt = (): void => {};
  const firstPromptPending = new Promise<void>((resolve) => {
    finishFirstPrompt = resolve;
  });
  const firstPrompt = vi.fn(async () => {
    await firstPromptPending;
    return true;
  });
  const cancelledPrompt = vi.fn(async () => true);
  const successorPrompt = vi.fn(async () => true);

  const first = coordinator.resolve(() => undefined, firstPrompt);
  await vi.waitFor(() => expect(firstPrompt).toHaveBeenCalledOnce());
  const cancelled = coordinator.resolve(() => undefined, cancelledPrompt, controller.signal);
  const cancelledResult = expect(cancelled).rejects.toThrow('Permission request cancelled');
  const successor = coordinator.resolve(() => undefined, successorPrompt);
  controller.abort();
  await cancelledResult;
  finishFirstPrompt();

  await expect(Promise.all([first, successor])).resolves.toEqual([true, true]);
  expect(cancelledPrompt).not.toHaveBeenCalled();
  expect(successorPrompt).toHaveBeenCalledOnce();
});

it('releases an active permission prompt after cancellation', async () => {
  const coordinator = new PermissionPromptCoordinator();
  const controller = new AbortController();
  const activePrompt = vi.fn(
    () =>
      new Promise<boolean>((_resolve, reject) => {
        controller.signal.addEventListener(
          'abort',
          () => reject(new Error('Permission prompt cancelled')),
          { once: true },
        );
      }),
  );
  const successorPrompt = vi.fn(async () => true);

  const active = coordinator.resolve(() => undefined, activePrompt, controller.signal);
  await vi.waitFor(() => expect(activePrompt).toHaveBeenCalledOnce());
  const activeResult = expect(active).rejects.toThrow('Permission prompt cancelled');
  const successor = coordinator.resolve(() => undefined, successorPrompt);
  controller.abort();

  await activeResult;
  await expect(successor).resolves.toBe(true);
  expect(successorPrompt).toHaveBeenCalledOnce();
});

it('registers the sandbox dashboard independently from agent supervision', async () => {
  const agentDir = mkdtempSync(join(tmpdir(), 'pi-landstrip-overlay-agent-'));
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  const commandNames: string[] = [];
  const commandHandlers = new Map<string, (args: string, ctx: ExtensionContext) => Promise<void>>();
  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  const pi = {
    registerTool() {},
    registerFlag() {},
    registerCommand(
      name: string,
      command: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      commandNames.push(name);
      commandHandlers.set(name, command.handler);
    },
    on() {},
  } as unknown as ExtensionAPI;
  createLandstripIntegration({ registerBashTool: false }).register(pi);
  let customResult: unknown;
  let projectTrusted = true;
  const ctx = {
    cwd: join(tmpdir(), 'pi-landstrip-overlay-test'),
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => projectTrusted,
    ui: {
      async custom(factory: (...args: unknown[]) => unknown) {
        component = factory(
          { requestRender() {} },
          { fg: (_color: string, value: string) => value, bold: (value: string) => value },
          undefined,
          (value: unknown) => {
            customResult = value;
          },
        ) as typeof component;
      },
    },
  } as unknown as ExtensionContext;

  await commandHandlers.get('sandbox')?.('', ctx);
  const sandboxView = component?.render(78).join('\n') ?? '';
  expect(sandboxView).toContain('Sandbox');
  expect(sandboxView).toContain('[Overview]  Policy');
  expect(sandboxView).toContain('Protection');
  expect(sandboxView).toContain('Read rules');
  expect(sandboxView).toContain('Shell reads');
  expect(sandboxView).toContain('Tab next tab  ·  Enter disable in project  ·  Esc close');
  component?.handleInput('\t');
  expect(component?.render(78).join('\n')).toContain('Allowed domains');
  expect(component?.render(78).join('\n')).toContain(
    process.platform === 'win32' ? 'Policy (required)' : 'Host-aligned',
  );
  component?.handleInput('\r');
  expect(customResult).toBe(true);
  component?.handleInput('\x1b');
  expect(customResult).toBe(false);

  projectTrusted = false;
  await commandHandlers.get('sandbox')?.('', ctx);
  expect(component?.render(78).join('\n')).toContain('Enter disable in global');

  expect(commandNames).toEqual(['sandbox']);
  expect(commandNames).not.toContain('landstrip');
  expect(commandNames).not.toContain('subagents');
  vi.unstubAllEnvs();
  rmSync(agentDir, { recursive: true, force: true });
});

describe('proxy destination addresses', () => {
  it('accepts public addresses', () => {
    expect(isPublicProxyAddress('8.8.8.8')).toBe(true);
    expect(isPublicProxyAddress('2606:4700:4700::1111')).toBe(true);
  });

  it('rejects local and private addresses', () => {
    expect(isPublicProxyAddress('127.0.0.1')).toBe(false);
    expect(isPublicProxyAddress('10.0.0.1')).toBe(false);
    expect(isPublicProxyAddress('169.254.169.254')).toBe(false);
    expect(isPublicProxyAddress('::1')).toBe(false);
    expect(isPublicProxyAddress('fd00::1')).toBe(false);
  });
});

it('rejects a pre-aborted RPC worker startup before allocating resources', async () => {
  const controller = new AbortController();
  controller.abort();
  const integration = createLandstripIntegration();

  await expect(
    integration.prepareRpcWorker({
      command: 'pi',
      args: [],
      cwd: PROJECT,
      env: {},
      ctx: {} as never,
      readPaths: [],
      writePaths: [],
      signal: controller.signal,
    }),
  ).rejects.toThrow('Task cancelled');
});

it('edits sandbox enabled state in the selected scope', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'pi-landstrip-sandbox-scope-'));
  const agentDir = mkdtempSync(join(tmpdir(), 'pi-landstrip-sandbox-agent-'));
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  const integration = createLandstripIntegration({ registerBashTool: false });
  const callbacks = integration.sandboxCallbacks!;
  const ctx = {
    cwd,
    hasUI: true,
    ui: { notify() {}, setStatus() {} },
  } as unknown as ExtensionContext;

  expect(callbacks.load(cwd, true)).toEqual({ global: true });
  await callbacks.setEnabled(ctx, false, 'global');
  expect(JSON.parse(readFileSync(join(agentDir, 'sandbox.json'), 'utf8')).enabled).toBe(false);

  await callbacks.setEnabled(ctx, true, 'project');
  expect(callbacks.load(cwd, true)).toEqual({ global: false, project: true });
  await callbacks.clearProject(ctx);
  expect(callbacks.load(cwd, true)).toEqual({ global: false, project: undefined });

  vi.unstubAllEnvs();
  rmSync(cwd, { recursive: true, force: true });
  rmSync(agentDir, { recursive: true, force: true });
});

it('refuses to write over a corrupt sandbox.json', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'pi-landstrip-corrupt-sandbox-'));
  const agentDir = mkdtempSync(join(tmpdir(), 'pi-landstrip-corrupt-agent-'));
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  const integration = createLandstripIntegration({ registerBashTool: false });
  const callbacks = integration.sandboxCallbacks!;
  const ctx = {
    cwd,
    hasUI: true,
    ui: { notify() {}, setStatus() {} },
  } as unknown as ExtensionContext;

  const projectDir = join(cwd, '.pi');
  mkdirSync(projectDir, { recursive: true });
  const projectPath = join(projectDir, 'sandbox.json');
  const corrupt = '{ "enabled": true, "filesystem": { "denyWrite": ["/secret"] },';
  writeFileSync(projectPath, corrupt, 'utf8');

  await expect(callbacks.setEnabled(ctx, false, 'project')).rejects.toThrow(/sandbox\.json/);
  expect(readFileSync(projectPath, 'utf8')).toBe(corrupt);

  vi.unstubAllEnvs();
  rmSync(cwd, { recursive: true, force: true });
  rmSync(agentDir, { recursive: true, force: true });
});

it('rejects in-flight AsyncQueue waiters after reset', async () => {
  const queue = new AsyncQueue();
  const first = await queue.acquire();
  const waiting = queue.acquire();
  queue.reset();
  await expect(waiting).rejects.toThrow('Request cancelled');
  first();
  const after = await queue.acquire();
  after();
});

it('allows RPC workers when sandboxing is explicitly disabled', async () => {
  let sessionStart: ((event: unknown, ctx: ExtensionContext) => Promise<void> | void) | undefined;
  const notifications: string[] = [];
  const pi = {
    registerFlag() {},
    registerCommand() {},
    registerTool() {},
    getFlag: (name: string) => name === 'no-sandbox',
    on(event: string, handler: unknown) {
      if (event === 'session_start') sessionStart = handler as typeof sessionStart;
    },
  } as unknown as ExtensionAPI;
  const ctx = {
    cwd: process.cwd(),
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => false,
    ui: {
      notify(message: string) {
        notifications.push(message);
      },
      setStatus() {},
    },
  } as unknown as ExtensionContext;
  const integration = createLandstripIntegration({ registerBashTool: false });
  integration.register(pi);
  await sessionStart?.({}, ctx);

  const launch = await integration.prepareRpcWorker({
    command: process.execPath,
    args: ['--version'],
    cwd: process.cwd(),
    env: {},
    ctx,
    readPaths: [],
    writePaths: [],
  });

  expect(launch.command).toBe(process.execPath);
  expect(launch.args).toEqual(['--version']);
  expect(notifications).toContain('Subagent processes are running without Landstrip sandboxing');

  const child = launch.spawn?.(
    launch.command,
    [
      '-e',
      "const { spawn } = require('node:child_process'); const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' }); child.unref(); process.stdout.write(`${child.pid}\\n`);",
    ],
    { stdio: ['pipe', 'pipe', 'pipe'] },
  );
  expect(child).toBeDefined();
  const exited = new Promise<void>((resolve) => child?.once('exit', () => resolve()));
  const descendantPid = await new Promise<number>((resolve, reject) => {
    child?.once('error', reject);
    child?.stdout.once('data', (data) => resolve(Number.parseInt(data.toString(), 10)));
  });
  await exited;
  const firstDispose = launch.dispose();
  const secondDispose = launch.dispose();
  expect(secondDispose).toBe(firstDispose);
  await firstDispose;
  await vi.waitFor(() => {
    expect(() => process.kill(descendantPid, 0)).toThrow();
  });
  expect(() => launch.spawn(launch.command, launch.args, {})).toThrow(
    'Prepared process has been disposed',
  );

  const preparedPromise = integration.prepareProcess({
    command: process.execPath,
    args: ['--version'],
    cwd: process.cwd(),
    ctx,
  });
  if (process.platform === 'win32') {
    await expect(preparedPromise).rejects.toThrow(
      'Generic process preparation requires sandboxing on Windows',
    );
  } else {
    const prepared = await preparedPromise;
    expect(prepared.env.HOME).toBe(process.env.HOME);
    await prepared.dispose();
  }
});

// The broker resolves relative policy entries (notably ".") against the command
// `cwd` that landstrip uses as its policy base. Regression guard: before the fix
// these resolved against the extension process's own `process.cwd()`, so a write
// inside the project was wrongly judged outside allowWrite whenever pi was
// launched from a different directory. Every project path below is deliberately
// NOT process.cwd(), so a process.cwd()-based resolution would fail these.
const PROJECT = '/proj/workspace';

describe('matchesPattern "." resolves against the command cwd', () => {
  it('matches a path inside the cwd', () => {
    expect(matchesPattern(`${PROJECT}/src/file.ts`, ['.'], PROJECT)).toBe(true);
  });

  it('matches the cwd itself', () => {
    expect(matchesPattern(PROJECT, ['.'], PROJECT)).toBe(true);
  });

  it('does not match a path outside the cwd', () => {
    expect(matchesPattern('/other/place/file.ts', ['.'], PROJECT)).toBe(false);
  });

  it('is independent of process.cwd()', () => {
    // process.cwd() is the repo root here, never PROJECT.
    expect(process.cwd()).not.toBe(PROJECT);
    expect(matchesPattern(`${PROJECT}/x`, ['.'], PROJECT)).toBe(true);
    expect(matchesPattern(`${process.cwd()}/x`, ['.'], PROJECT)).toBe(false);
  });
});

describe('matchesPattern other entry shapes', () => {
  it('expands ~ against the home directory regardless of cwd', () => {
    expect(matchesPattern(join(homedir(), '.gitconfig'), ['~/.gitconfig'], PROJECT)).toBe(true);
  });

  it('honours absolute entries regardless of cwd', () => {
    expect(matchesPattern('/dev/null', ['/dev/null'], PROJECT)).toBe(true);
  });

  it('matches globs', () => {
    expect(matchesPattern(`${PROJECT}/a/b/.env`, ['**/.env'], PROJECT)).toBe(true);
    expect(matchesPattern(`${PROJECT}/a/b/key.pem`, ['**/*.pem'], PROJECT)).toBe(true);
    expect(matchesPattern(`${PROJECT}/a/b/file.ts`, ['**/.env'], PROJECT)).toBe(false);
  });

  // A single '*' must stop at '/', like landstrip's own matcher, so an
  // allow-glob cannot reach a deeper path the operator did not intend.
  it('a single * does not cross a directory separator', () => {
    expect(matchesPattern(`${PROJECT}/srv/a/pub`, [`${PROJECT}/srv/*/pub`], PROJECT)).toBe(true);
    expect(matchesPattern(`${PROJECT}/srv/a/deep/pub`, [`${PROJECT}/srv/*/pub`], PROJECT)).toBe(
      false,
    );
    // '**' still spans directories.
    expect(matchesPattern(`${PROJECT}/srv/a/deep/pub`, [`${PROJECT}/srv/**/pub`], PROJECT)).toBe(
      true,
    );
  });
});

describe('shouldPromptForWrite', () => {
  it('does not prompt for a path inside an allowWrite "." root', () => {
    expect(shouldPromptForWrite(`${PROJECT}/out.txt`, ['.'], PROJECT)).toBe(false);
  });

  it('prompts for a path outside allowWrite', () => {
    expect(shouldPromptForWrite('/other/out.txt', ['.'], PROJECT)).toBe(true);
  });

  it('prompts when allowWrite is empty', () => {
    expect(shouldPromptForWrite(`${PROJECT}/out.txt`, [], PROJECT)).toBe(true);
  });
});

describe('sessionScopeFor', () => {
  const HOME = homedir();
  const PROJECT = join(HOME, 'work', 'proj');

  it('widens a home file to the immediate child of $HOME', () => {
    expect(sessionScopeFor(join(HOME, '.cargo', 'registry', 'foo.rs'), PROJECT)).toBe(
      join(HOME, '.cargo'),
    );
  });

  it('widens deep home paths to the same top-level directory', () => {
    const scope = sessionScopeFor(join(HOME, '.cargo', 'a', 'b', 'c.rs'), PROJECT);
    expect(scope).toBe(join(HOME, '.cargo'));
  });

  it('does not widen a file sitting directly in $HOME (would over-broaden)', () => {
    const file = join(HOME, '.netrc');
    expect(sessionScopeFor(file, PROJECT)).toBe(file);
  });

  it('widens a path outside $HOME to its containing directory', () => {
    expect(sessionScopeFor('/etc/ssl/certs/ca.pem', '/srv/app')).toBe('/etc/ssl/certs');
  });

  it('widens a project path (outside home) to the project root', () => {
    expect(sessionScopeFor('/srv/app/src/deep/mod.ts', '/srv/app')).toBe('/srv/app');
  });
});

describe('readAllowed', () => {
  const HOME = homedir();
  const cwd = join(HOME, 'work', 'proj');
  const DENY = ['/Users', '/home'];

  it('blocks a home path that is not in allowRead (broad deny wins)', () => {
    expect(readAllowed(join(HOME, '.cache', 'x'), ['.'], DENY, cwd)).toBe(false);
  });

  it('allows a granted home scope even though denyRead lists /home', () => {
    const allow = ['.', join(HOME, '.cache')];
    expect(readAllowed(join(HOME, '.cache', 'puu', 'd', 'f'), allow, DENY, cwd)).toBe(true);
  });

  it('keeps a narrow deny carve-out beating a broad allow', () => {
    expect(readAllowed(join(HOME, '.ssh', 'id'), [HOME], [join(HOME, '.ssh')], cwd)).toBe(false);
  });

  it('lets the most specific grant override a narrow deny', () => {
    const deny = [join(HOME, '.ssh')];
    expect(
      readAllowed(join(HOME, '.ssh', 'config'), [join(HOME, '.ssh', 'config')], deny, cwd),
    ).toBe(true);
  });

  it('allows a path outside every denyRead root', () => {
    expect(readAllowed('/etc/passwd', ['.'], DENY, cwd)).toBe(true);
  });

  it('allows all reads when denyRead is empty', () => {
    expect(readAllowed(join(HOME, '.ssh', 'id'), [], [], cwd)).toBe(true);
  });
});

describe('writeEnvFile', () => {
  it('writes export statements for each env var', () => {
    const { dir, path } = writeEnvFile({ FOO: 'bar', BAZ: 'qux' }, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export FOO='bar'");
    expect(content).toContain("export BAZ='qux'");
  });

  it('skips undefined values', () => {
    const env: NodeJS.ProcessEnv = { FOO: 'bar', SKIP: undefined };
    const { dir, path } = writeEnvFile(env, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export FOO='bar'");
    expect(content).not.toContain('SKIP');
  });

  it('escapes single quotes in values', () => {
    const { dir, path } = writeEnvFile({ QUOTED: "it's a test" }, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export QUOTED='it'\\''s a test'");
  });

  it('skips names the shell cannot export', () => {
    const env: NodeJS.ProcessEnv = { FOO: 'bar', 'BASH_FUNC_greet%%': '() { echo hi; }' };
    const { dir, path } = writeEnvFile(env, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export FOO='bar'");
    expect(content).not.toContain('BASH_FUNC_greet');
  });

  it('adds proxy vars when proxyPort is provided', () => {
    const { dir, path } = writeEnvFile({ FOO: 'bar' }, 8080);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export FOO='bar'");
    expect(content).toContain("export HTTP_PROXY='http://127.0.0.1:8080'");
    expect(content).toContain("export NO_PROXY=''");
  });

  it('adds proxy credentials when a token is provided', () => {
    const { dir, path } = writeEnvFile({}, 8080, 'secret');
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export HTTP_PROXY='http://landstrip:secret@127.0.0.1:8080'");
  });

  it('does not add proxy vars when proxyPort is null', () => {
    const { dir, path } = writeEnvFile({ FOO: 'bar' }, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).not.toContain('HTTP_PROXY');
  });

  it('creates the file under tmpdir', () => {
    const { dir, path } = writeEnvFile({}, null);
    expect(dir).toContain(tmpdir());
    expect(existsSync(path)).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });
});

import {
  controlResponseLine,
  domainMatchesAny,
  formatLandstripTraps,
  extractNativeDeniedPath,
  extractRetryableNativeReadDeniedPath,
  extractNativeWriteDeniedPath,
  isQueryTrap,
  parseTrapLine,
} from './index.ts';

describe('domainMatchesAny', () => {
  it('matches exact and wildcard patterns', () => {
    expect(domainMatchesAny('github.com', ['github.com'])).toBe(true);
    expect(domainMatchesAny('api.github.com', ['*.github.com'])).toBe(true);
    expect(domainMatchesAny('evil.com', ['github.com'])).toBe(false);
  });

  // A trailing-dot FQDN resolves to the same host, so it must not slip past a
  // deny entry written without the dot.
  it('normalizes a trailing dot before matching', () => {
    expect(domainMatchesAny('pastebin.com.', ['pastebin.com'])).toBe(true);
    expect(domainMatchesAny('api.github.com.', ['*.github.com'])).toBe(true);
  });
});

const FS_TRAP = {
  kind: 'filesystem',
  code: 'FILESYSTEM_DENIED',
  state: 'query',
  query_id: '7',
  operation: 'read',
  path: '/etc/passwd',
  requested_path: '/etc/passwd',
  syscall: 'openat',
  errno: 'EACCES',
  flags: ['O_RDONLY'],
  reason: 'allow_miss',
  suggested_grant: { allowRead: '/etc/passwd' },
  process: { pid: 42, exe: '/bin/cat', cwd: '/proj' },
  mechanism: 'seccomp',
};

const NET_TRAP = {
  kind: 'network',
  code: 'NETWORK_DENIED',
  state: 'query',
  query_id: '9',
  operation: 'connect',
  target: '140.82.121.4:22',
  syscall: 'connect',
  errno: 'EACCES',
  mechanism: 'seccomp',
  process: { pid: 42, exe: '/usr/bin/ssh', cwd: '/proj' },
};

const line = (trap: object): string => JSON.stringify(trap);

describe('parseTrapLine', () => {
  it('parses a filesystem query trap', () => {
    const trap = parseTrapLine(line(FS_TRAP));
    expect(trap).toMatchObject({ kind: 'filesystem', operation: 'read', path: '/etc/passwd' });
    expect(trap?.kind === 'filesystem' && trap.query_id).toBe('7');
  });

  // landstrip 0.16 sent query_id as a JSON number. Answering such a trap with a
  // numeric id leaves the child's syscall suspended, so a numeric id must not
  // parse at all rather than reach the handshake.
  it('rejects a numeric query_id', () => {
    expect(parseTrapLine(line({ ...FS_TRAP, query_id: 7 }))).toBeNull();
    expect(parseTrapLine(line({ ...NET_TRAP, query_id: 9 }))).toBeNull();
  });

  it('parses launch, usage and internal traps', () => {
    expect(
      parseTrapLine(
        line({ kind: 'launch', code: 'LAUNCH_FAILED', program: 'nope', message: 'not found' }),
      ),
    ).toMatchObject({ kind: 'launch', program: 'nope', message: 'not found' });
    expect(
      parseTrapLine(line({ kind: 'usage', code: 'USAGE_ERROR', message: 'bad flag' })),
    ).toMatchObject({ kind: 'usage', message: 'bad flag' });
    expect(
      parseTrapLine(line({ kind: 'internal', code: 'POLICY_PARSE_FAILED', message: 'bad json' })),
    ).toMatchObject({ kind: 'internal', code: 'POLICY_PARSE_FAILED' });
  });

  it('ignores non-JSON lines and unknown kinds', () => {
    expect(parseTrapLine('cat: /etc/passwd: Permission denied')).toBeNull();
    expect(parseTrapLine('')).toBeNull();
    expect(parseTrapLine(line({ kind: 'future', message: 'x' }))).toBeNull();
  });
});

describe('native denial extraction', () => {
  it('extracts drive-qualified, UNC, and MSYS paths', () => {
    const cwd = process.cwd();
    expect(
      extractNativeDeniedPath(`cat: 'C:\\Users\\me\\secret.txt': Permission denied`, cwd),
    ).toContain('C:\\Users\\me\\secret.txt');
    expect(
      extractNativeDeniedPath(`type: '\\\\server\\share\\secret.txt': Access is denied.`, cwd),
    ).toContain('server');
    const msysPath = extractNativeDeniedPath('cat: /c/Users/me/secret.txt: Permission denied', cwd);
    expect(msysPath).toContain(process.platform === 'win32' ? 'C:\\Users\\me' : '/c/Users/me');
    expect(extractNativeDeniedPath('type: ..\\secret.txt: Access is denied.', cwd)).toContain(
      'secret.txt',
    );
  });

  it('retries native denials only when the read policy covers the path', () => {
    const cwd = process.cwd();
    const policyDenied = join(cwd, 'denied');
    const hostDenied = join(tmpdir(), 'host-denied');

    expect(
      extractRetryableNativeReadDeniedPath(
        `cat: '${policyDenied}': Permission denied`,
        cwd,
        [],
        [cwd],
      ),
    ).toBe(policyDenied);
    expect(
      extractRetryableNativeReadDeniedPath(
        `cat: '${hostDenied}': Permission denied`,
        cwd,
        [],
        [cwd],
      ),
    ).toBeNull();
  });

  it('extracts write denials only when they identify a concrete path', () => {
    const cwd = process.cwd();
    expect(
      extractNativeWriteDeniedPath(
        `touch: cannot create 'C:\\Users\\me\\output.txt': Access is denied.`,
        cwd,
      ),
    ).toContain('C:\\Users\\me\\output.txt');
    const cachePath = join(cwd, 'cache');
    expect(
      extractNativeWriteDeniedPath(
        `error: failed to create directory \`${cachePath}\`\n\nCaused by:\n  Operation not permitted (os error 1)`,
        cwd,
      ),
    ).toBe(cachePath);
    expect(extractNativeDeniedPath('Access is denied.', cwd)).toBeNull();
  });
});

describe('isQueryTrap', () => {
  it('holds for a pending filesystem or network query', () => {
    expect(isQueryTrap(parseTrapLine(line(FS_TRAP))!)).toBe(true);
    expect(isQueryTrap(parseTrapLine(line(NET_TRAP))!)).toBe(true);
  });

  it('does not hold for a terminal info trap', () => {
    const info = { ...FS_TRAP, state: 'info', query_id: '0' };
    expect(isQueryTrap(parseTrapLine(line(info))!)).toBe(false);
  });

  it('does not hold for a failure trap', () => {
    const usage = parseTrapLine(line({ kind: 'usage', code: 'USAGE_ERROR', message: 'bad flag' }));
    expect(isQueryTrap(usage!)).toBe(false);
  });
});

describe('controlResponseLine', () => {
  it('serializes query_id as a string', () => {
    expect(controlResponseLine('7', 'allow')).toBe('{"query_id":"7","action":"allow"}\n');
    expect(controlResponseLine('7', 'deny')).toBe('{"query_id":"7","action":"deny"}\n');
  });
});

describe('formatLandstripTraps', () => {
  it('renders a filesystem denial with its resolved path', () => {
    expect(formatLandstripTraps([parseTrapLine(line(FS_TRAP))!])).toBe(
      'landstrip: filesystem read denied: /etc/passwd (seccomp)',
    );
  });

  it('renders a launch failure with its message', () => {
    const trap = parseTrapLine(
      line({ kind: 'launch', code: 'LAUNCH_FAILED', program: 'nope', message: 'not found' }),
    );
    expect(formatLandstripTraps([trap!])).toBe('landstrip: launch failed: nope: not found');
  });

  it('renders an internal failure by its code, with the mechanism when present', () => {
    const policy = parseTrapLine(
      line({ kind: 'internal', code: 'POLICY_PARSE_FAILED', message: 'bad json' }),
    );
    expect(formatLandstripTraps([policy!])).toBe('landstrip: POLICY_PARSE_FAILED: bad json');

    const setup = parseTrapLine(
      line({
        kind: 'internal',
        code: 'SANDBOX_SETUP_FAILED',
        mechanism: 'landlock',
        message: 'no ABI',
      }),
    );
    expect(formatLandstripTraps([setup!])).toBe(
      'landstrip: SANDBOX_SETUP_FAILED (landlock): no ABI',
    );
  });
});
