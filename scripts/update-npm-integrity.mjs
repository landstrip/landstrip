#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Jarkko Sakkinen 2026

import { execFileSync } from "node:child_process";
import fs from "node:fs";

const [version, ...extensionDirs] = process.argv.slice(2);
if (!/^\d+\.\d+\.\d+$/.test(version ?? "") || extensionDirs.length === 0) {
  throw new Error("usage: scripts/update-npm-integrity.mjs <version> <extension-dir>...");
}

const npm = process.env.NPM || "npm";
const rootPackageData = JSON.parse(fs.readFileSync("package.json", "utf8"));
const landstripPackage = rootPackageData.name;
const platformPackages = Object.keys(rootPackageData.optionalDependencies ?? {});
if (platformPackages.length !== 6) {
  throw new Error(`expected six platform packages, found ${platformPackages.length}`);
}
const packageNames = [landstripPackage, ...platformPackages];
const distributions = new Map();

for (const packageName of packageNames) {
  const output = execFileSync(npm, ["view", `${packageName}@${version}`, "dist", "--json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
  const metadata = JSON.parse(output);
  const distribution = Array.isArray(metadata) && metadata.length === 1 ? metadata[0] : metadata;
  if (!distribution?.tarball || !distribution?.integrity?.startsWith("sha512-")) {
    throw new Error(`npm returned incomplete distribution metadata for ${packageName}@${version}`);
  }
  distributions.set(packageName, distribution);
}

function updateLockedPackage(lock, packageName) {
  const lockedPackage = lock.packages[`node_modules/${packageName}`];
  if (!lockedPackage) {
    throw new Error(`package-lock.json does not contain ${packageName}`);
  }
  if (lockedPackage.version !== version) {
    throw new Error(
      `${packageName} lock version ${lockedPackage.version} does not match ${version}`,
    );
  }

  const distribution = distributions.get(packageName);
  lockedPackage.resolved = distribution.tarball;
  lockedPackage.integrity = distribution.integrity;
}

function updateLock(lockPath, packageNamesToUpdate) {
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  for (const packageName of packageNamesToUpdate) {
    updateLockedPackage(lock, packageName);
  }
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
}

updateLock("package-lock.json", platformPackages);
for (const extensionDir of extensionDirs) {
  updateLock(`${extensionDir}/package-lock.json`, packageNames);
}
