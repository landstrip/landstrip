#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

mkdir -p \
  "$workdir/packages/landstrip/scripts" \
  "$workdir/packages/landstrip-api" \
  "$workdir/scripts" \
  "$workdir/bin" \
  "$workdir/artifacts"
cp "$script_dir/package.sh" "$script_dir/package-target.sh" \
  "$workdir/packages/landstrip/scripts/"
cp "$repo_root/packages/landstrip/Cargo.toml" "$workdir/packages/landstrip/"
cp "$repo_root/packages/landstrip-api/package.json" "$workdir/packages/landstrip-api/"
cp "$repo_root/scripts/sha256.sh" "$workdir/scripts/"

cat >"$workdir/bin/rustc" <<'EOF'
#!/bin/sh
if [ "$1 $2" = "--print host-tuple" ]; then
  printf '%s\n' aarch64-apple-darwin
fi
EOF
chmod +x "$workdir/bin/rustc"

printf 'npm/*/bin/\nartifacts/\n' >"$workdir/.gitignore"
git -C "$workdir" init -q
git -C "$workdir" add .
git -C "$workdir" -c user.name=test -c user.email=test@example.com commit -qm fixture

for platform in linux-x64 linux-arm64 win32-x64 win32-arm64 darwin-arm64 darwin-x64; do
  binary=landstrip
  [[ "$platform" == win32-* ]] && binary=landstrip.exe
  mkdir -p "$workdir/npm/$platform/bin"
  : >"$workdir/npm/$platform/bin/$binary"
  : >"$workdir/artifacts/$platform.bin.sha256"
  : >"$workdir/artifacts/$platform.tar.gz"
  : >"$workdir/artifacts/$platform.tar.gz.sha256"
done

if (
  cd "$workdir"
  CARGO=true \
    RUSTC="$workdir/bin/rustc" \
    FILE=true \
    CARGO_ZIGBUILD=missing-cargo-zigbuild \
    ZIG=missing-zig \
    packages/landstrip/scripts/package.sh linux-x64 >/dev/null 2>&1
); then
  printf 'expected packaging prerequisite failure\n' >&2
  exit 1
fi

if find "$workdir/npm" "$workdir/artifacts" -type f -print -quit | grep -q .; then
  printf 'stale release output survived a failed subset build\n' >&2
  exit 1
fi

printf 'package freshness test passed\n'
