import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

export const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export function transpile(source) {
  return ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ES2022,
      target: ts.ScriptTarget.ES2022,
      verbatimModuleSyntax: false,
    },
  }).outputText;
}

export async function installLandstripMock(tempDir, source) {
  const directory = join(tempDir, 'node_modules', '@landstrip', 'landstrip');
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, 'package.json'),
    JSON.stringify({ name: '@landstrip/landstrip', type: 'module', main: './index.mjs' }),
  );
  await writeFile(join(directory, 'index.mjs'), source);
  return directory;
}
