// SPDX-License-Identifier: Apache-2.0
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const packages = {
  'darwin-arm64': {
    packageName: '@landstrip/landstrip-darwin-arm64',
    binary: 'bin/landstrip',
  },
  'darwin-x64': {
    packageName: '@landstrip/landstrip-darwin-x64',
    binary: 'bin/landstrip',
  },
  'linux-x64': {
    packageName: '@landstrip/landstrip-linux-x64',
    binary: 'bin/landstrip',
  },
  'linux-arm64': {
    packageName: '@landstrip/landstrip-linux-arm64',
    binary: 'bin/landstrip',
  },
  'win32-x64': {
    packageName: '@landstrip/landstrip-win32-x64',
    binary: 'bin/landstrip.exe',
  },
  'win32-arm64': {
    packageName: '@landstrip/landstrip-win32-arm64',
    binary: 'bin/landstrip.exe',
  },
};

const officialPackageNames = new Set([
  '@landstrip/landstrip-api',
  ...Object.values(packages).map((value) => value.packageName),
]);

function target(platform = process.platform, arch = process.arch) {
  const key = `${platform}-${arch}`;
  const value = packages[key];

  if (!value) {
    throw new Error(`Unsupported landstrip platform: ${platform} ${arch}`);
  }

  return value;
}

function packageName(platform = process.platform, arch = process.arch) {
  return target(platform, arch).packageName;
}

function binaryPath(platform = process.platform, arch = process.arch) {
  const value = target(platform, arch);
  let manifest;

  try {
    manifest = require.resolve(`${value.packageName}/package.json`);
  } catch (error) {
    throw new Error(
      `The landstrip binary package ${value.packageName} is not installed. ` +
        'Reinstall @landstrip/landstrip-api with optional dependencies enabled.'
    );
  }

  const resolved = path.join(path.dirname(manifest), value.binary);

  if (!fs.statSync(resolved).isFile()) {
    throw new Error(`landstrip binary not found at ${resolved}`);
  }

  const filePath = fs.realpathSync.native(resolved);
  let probe = path.dirname(filePath);
  while (true) {
    let owner;
    try {
      owner = JSON.parse(fs.readFileSync(path.join(probe, 'package.json'), 'utf8'));
    } catch (error) {
      if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
    }
    if (
      owner !== null &&
      typeof owner === 'object' &&
      !Array.isArray(owner) &&
      officialPackageNames.has(owner.name)
    ) {
      return filePath;
    }
    const parent = path.dirname(probe);
    if (parent === probe) break;
    probe = parent;
  }
  throw new Error(
    `Refusing to use landstrip binary outside official @landstrip/landstrip-api packages: ${filePath}`,
  );
}

exports.binaryPath = binaryPath;
exports.packageName = packageName;
