import { mkdir, readFile, writeFile } from 'node:fs/promises';
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
    JSON.stringify({
      name: '@landstrip/landstrip',
      main: './index.mjs',
      exports: { '.': './index.mjs', './shared': './shared.js' },
    }),
  );
  await writeFile(join(directory, 'index.mjs'), source);
  const shared = await readFile(join(packageRoot, '..', '..', 'lib', 'shared.js'), 'utf8');
  await writeFile(join(directory, 'shared.js'), shared);
  return directory;
}
