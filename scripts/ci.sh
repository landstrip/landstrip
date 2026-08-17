#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

CARGO="${CARGO:-cargo}"
NODE="${NODE:-node}"
NPM="${NPM:-npm}"

# Debian/Ubuntu system npm still calls url.parse(); quiet that under Node 24+.
export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--no-deprecation"

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

for command in "$CARGO" "$NODE" "$NPM" bun git; do
  require_command "$command"
done

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
  || die "not inside a Git repository"
cd "$repo_root"

printf '==> package target selection test\n'
./scripts/package-target-test.sh

host_platform="$(
  "$NODE" -e 'process.stdout.write(process.platform + "-" + process.arch)'
)"
case "$host_platform" in
  darwin-arm64|darwin-x64|linux-x64|linux-arm64|win32-x64|win32-arm64) ;;
  *)
    die "unsupported host platform for local CI: $host_platform"
    ;;
esac

binary_name=landstrip
[[ "$host_platform" == win32-* ]] && binary_name=landstrip.exe

printf '==> cargo build\n'
$CARGO build

printf '==> cargo test\n'
$CARGO test

printf '==> cargo clippy\n'
$CARGO clippy --all-targets

printf '==> cargo fmt --check\n'
$CARGO fmt --check

printf '==> stage host binary for npm/%s\n' "$host_platform"
mkdir -p "npm/$host_platform/bin"
cp "target/debug/$binary_name" "npm/$host_platform/bin/$binary_name"
chmod 755 "npm/$host_platform/bin/$binary_name" 2>/dev/null || true

printf '==> npm install local platform package\n'
tarball="$($NPM pack . --silent)"
$NPM install --package-lock=false --ignore-scripts --no-save "./$tarball" "./npm/$host_platform"
rm -f "$tarball"
$NODE bin/landstrip.js --version >/dev/null

export PATH="$repo_root/target/debug:$PATH"

printf '==> extension checks\n'
# test-extensions.sh --local-root rebuilds the host binary, npm-packs the
# meta package, installs each extension workspace, and runs its
# ci:fmt / ci:lint / ci:check / ci:test scripts.
npm run ci:extensions:local

if [[ -n "${CI_MSRV:-}" ]]; then
  version="$(sed -n 's/^[[:space:]]*rust-version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml)"
  [[ -n "$version" ]] || die "no rust-version in Cargo.toml"
  printf '==> MSRV cargo +%s\n' "$version"
  require_command rustup
  rustup toolchain install "$version"
  cargo +"$version" build
  cargo +"$version" test
fi

printf 'local CI passed on %s\n' "$host_platform"
