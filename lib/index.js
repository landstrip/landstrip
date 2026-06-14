// SPDX-License-Identifier: Apache-2.0
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const packages = {
  'darwin-arm64': {
    packageName: '@jarkkojs/landstrip-darwin-arm64',
    binary: 'bin/landstrip',
  },
  'darwin-x64': {
    packageName: '@jarkkojs/landstrip-darwin-x64',
    binary: 'bin/landstrip',
  },
  'linux-x64': {
    packageName: '@jarkkojs/landstrip-linux-x64',
    binary: 'bin/landstrip',
  },
  'win32-x64': {
    packageName: '@jarkkojs/landstrip-win32-x64',
    binary: 'bin/landstrip.exe',
  },
};

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
        'Reinstall @jarkkojs/landstrip with optional dependencies enabled.'
    );
  }

  const resolved = path.join(path.dirname(manifest), value.binary);

  if (!fs.statSync(resolved).isFile()) {
    throw new Error(`landstrip binary not found at ${resolved}`);
  }

  return resolved;
}

exports.binaryPath = binaryPath;
exports.packageName = packageName;
