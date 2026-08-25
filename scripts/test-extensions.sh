#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--no-deprecation"
NPM="${NPM:-npm}"

list_extensions() {
  node <<'NODE'
const fs = require('node:fs');
const { workspaces } = JSON.parse(fs.readFileSync('package.json', 'utf8'));

if (!Array.isArray(workspaces)) {
  throw new Error('package.json workspaces must be an array');
}

for (const workspace of workspaces) {
  if (!workspace.endsWith('/*')) {
    throw new Error(`unsupported workspace pattern: ${workspace}`);
  }

  const parent = workspace.slice(0, -2);
  for (const entry of fs.readdirSync(parent, { withFileTypes: true })) {
    const packageDir = `${parent}/${entry.name}`;
    if (entry.isDirectory() && entry.name !== "landstrip-api" && fs.existsSync(`${packageDir}/package.json`)) {
      console.log(packageDir);
    }
  }
}
NODE
}

case "${1:-}" in
  --list)
    list_extensions
    exit 0
    ;;
  --local-root)
    local_root=1
    ;;
  '')
    local_root=0
    ;;
  *)
    printf 'usage: %s [--list|--local-root]\n' "$0" >&2
    exit 1
    ;;
esac

extension_dirs=()
while IFS= read -r extension_dir; do
  extension_dirs+=("$extension_dir")
done < <(list_extensions)
((${#extension_dirs[@]} > 0)) || {
  printf 'no extension workspaces found\n' >&2
  exit 1
}

restricted_user_setup=0

cleanup_local_root() {
  if ((restricted_user_setup)); then
    "packages/landstrip/target/debug/$binary" windows uninstall >/dev/null 2>&1 || true
  fi
  [[ -z "${tarball:-}" ]] || rm -f "$tarball"
}

if ((local_root)); then
  tarball="$("$NPM" pack ./packages/landstrip-api --silent)"
  platform_package="npm/$(node -p '`${process.platform}-${process.arch}`')"
  [[ -d "$platform_package" ]] || {
    printf 'no local binary package for %s\n' "$platform_package" >&2
    exit 1
  }
  binary="landstrip"
  [[ "$platform_package" == npm/win32-* ]] && binary="landstrip.exe"
  cargo build --locked --manifest-path packages/landstrip/Cargo.toml
  mkdir -p "$platform_package/bin"
  install -m 755 "packages/landstrip/target/debug/$binary" "$platform_package/bin/$binary"
  trap cleanup_local_root EXIT

  if [[ "$platform_package" == npm/win32-* && "${CI:-}" == true ]]; then
    "packages/landstrip/target/debug/$binary" windows install \
      --restricted-accounts 2 --unrestricted-accounts 0
    restricted_user_setup=1
    export LANDSTRIP_TEST_RESTRICTED_USER=1
  fi
fi

for package_dir in "${extension_dirs[@]}"; do
  if (( local_root )); then
    "$NPM" install --prefix "$package_dir" --workspaces=false --package-lock=false \
      --ignore-scripts --no-save "./$tarball" "./$platform_package"
  else
    "$NPM" ci --prefix "$package_dir" --workspaces=false --ignore-scripts
  fi
  "$NPM" --prefix "$package_dir" run ci:fmt
  "$NPM" --prefix "$package_dir" run ci:lint
  "$NPM" --prefix "$package_dir" run ci:check
  "$NPM" --prefix "$package_dir" run ci:test
done

if ((restricted_user_setup)); then
  "packages/landstrip/target/debug/$binary" windows uninstall
  restricted_user_setup=0
fi
