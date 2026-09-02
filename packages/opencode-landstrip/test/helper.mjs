import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

export const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

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
  const directory = join(tempDir, 'node_modules', '@landstrip', 'landstrip-api');
  await mkdir(directory, { recursive: true });
  const ipaddrRoot = dirname(require.resolve('ipaddr.js/package.json'));
  await cp(ipaddrRoot, join(tempDir, 'node_modules', 'ipaddr.js'), { recursive: true });
  await writeFile(
    join(directory, 'package.json'),
    JSON.stringify({
      name: '@landstrip/landstrip-api',
      main: './index.mjs',
      exports: { '.': './index.mjs', './shared': './shared.js', './proxy': './proxy.js' },
    }),
  );
  await writeFile(join(directory, 'index.mjs'), source);
  const shared = await readFile(
    join(packageRoot, '..', 'landstrip-api', 'lib', 'shared.js'),
    'utf8',
  );
  await writeFile(join(directory, 'shared.js'), shared);
  const proxy = await readFile(join(packageRoot, '..', 'landstrip-api', 'lib', 'proxy.js'), 'utf8');
  await writeFile(join(directory, 'proxy.js'), proxy);
  return directory;
}
