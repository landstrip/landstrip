#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

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
    if (entry.isDirectory() && fs.existsSync(`${packageDir}/package.json`)) {
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

mapfile -t extension_dirs < <(list_extensions)
((${#extension_dirs[@]} > 0)) || {
	printf 'no extension workspaces found\n' >&2
	exit 1
}

if (( local_root )); then
	tarball="$(npm pack . --silent)"
	trap 'rm -f "$tarball"' EXIT
fi

for package_dir in "${extension_dirs[@]}"; do
	if (( local_root )); then
		npm install --prefix "$package_dir" --workspaces=false --package-lock=false \
			--ignore-scripts --no-save "./$tarball"
	else
		npm ci --prefix "$package_dir" --workspaces=false --ignore-scripts
	fi
	npm --prefix "$package_dir" run ci:fmt
	npm --prefix "$package_dir" run ci:lint
	npm --prefix "$package_dir" run ci:check
	npm --prefix "$package_dir" run ci:test
done
