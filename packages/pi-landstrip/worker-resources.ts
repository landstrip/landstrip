// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path';

import {
  DefaultPackageManager,
  loadProjectContextFiles,
  SettingsManager,
} from '@earendil-works/pi-coding-agent';

export interface WorkerResourceOptions {
  cwd: string;
  agentDir: string;
  projectTrusted: boolean;
  /** Parent tool/command sourceInfo paths; synthetic and missing paths are ignored. */
  provenance?: readonly { path: string }[];
  /** Pi, landstrip, and explicitly injected extension entries. */
  runtimeEntries?: readonly string[];
}

/** Resolve startup read grants without installing packages or executing extensions. */
export async function collectWorkerResourceReadPaths({
  cwd,
  agentDir,
  projectTrusted,
  provenance = [],
  runtimeEntries = [],
}: WorkerResourceOptions): Promise<string[]> {
  cwd = resolve(cwd);
  agentDir = resolve(agentDir);
  const settingsManager = SettingsManager.create(cwd, agentDir, { projectTrusted });
  const errors = settingsManager.drainErrors();
  if (errors.length > 0) {
    throw new AggregateError(
      errors.map(({ error }) => error),
      'Cannot resolve worker startup resources from settings',
    );
  }
  const resources = await new DefaultPackageManager({ cwd, agentDir, settingsManager }).resolve(
    async () => 'skip',
  );
  const paths = new Set<string>();
  const broadRoots = [agentDir, resolve(homedir())].flatMap((path) =>
    existsSync(path) ? [path, realpathSync(path)] : [path],
  );
  const isBroadRoot = (path: string): boolean =>
    dirname(path) === path ||
    basename(path) === 'node_modules' ||
    broadRoots.some((root) => root === path || root.startsWith(`${path}${sep}`));
  const addPath = (path: string): void => {
    if (!existsSync(path)) return;
    const candidates = [resolve(path), realpathSync(path)];
    // A harmless-looking symlink must not grant a protected root indirectly.
    if (candidates.some(isBroadRoot)) return;
    for (const candidate of candidates) paths.add(candidate);
  };
  const visitedPackages = new Set<string>();
  const addPackage = (directory: string): void => {
    const canonical = realpathSync(directory);
    // Protected roots may declare dependencies; addPath never grants the root.
    addPath(directory);
    if (visitedPackages.has(canonical)) return;
    visitedPackages.add(canonical);
    const manifestPath = join(canonical, 'package.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
    const require = createRequire(manifestPath);
    // Include installed optional/peer dependencies, but never development deps or
    // unrelated hoisted packages. Missing packages remain the loader's concern.
    for (const group of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      const dependencies = manifest[group];
      if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies))
        continue;
      for (const name of Object.keys(dependencies)) {
        if (
          !/^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(name) ||
          name.split('/').some((part) => part === '.' || part === '..')
        ) {
          throw new Error(`Invalid dependency name ${JSON.stringify(name)} in ${manifestPath}`);
        }
        // Locate manifests directly: package exports can hide package.json and
        // packages may expose only subpaths, with no resolvable main entry.
        const dependency = require.resolve
          .paths(name)
          ?.map((root) => join(root, name))
          .find((path) => existsSync(join(path, 'package.json')));
        if (dependency) addPackage(dependency);
      }
    }
  };
  const addExtension = (path: string): void => {
    if (!existsSync(path)) return;
    addPath(path);
    for (const entry of [resolve(path), realpathSync(path)]) {
      const directory = statSync(entry).isDirectory() ? entry : dirname(entry);
      // Loose extensions can import adjacent files. Packaged extensions get
      // their owning root and the declared installed dependency graph instead.
      addPath(directory);
      for (let parent = directory; ; parent = dirname(parent)) {
        if (existsSync(join(parent, 'package.json'))) {
          addPackage(parent);
          break;
        }
        if (isBroadRoot(parent)) break;
      }
    }
  };

  for (const resource of resources.extensions) {
    if (resource.enabled) addExtension(resource.path);
  }
  for (const entry of runtimeEntries) addExtension(entry);
  for (const resource of [...resources.skills, ...resources.prompts, ...resources.themes]) {
    if (resource.enabled) addPath(resource.path);
  }
  for (const { path } of provenance) {
    if (!isAbsolute(path)) continue;
    if (/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(path)) addExtension(path);
    else addPath(path);
  }
  // Pi applies context-file precedence and worktree shadowing here; grant files,
  // never their ancestor directories. Context loading is independent of trust.
  for (const { path } of loadProjectContextFiles({ cwd, agentDir })) addPath(path);
  return [...paths];
}
