#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=sha256.sh
source "$script_dir/sha256.sh"

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

workdir=
cleanup() {
  local status=$?

  if [[ -n "${workdir:-}" ]]; then
    rm -rf "$workdir"
  fi
  return "$status"
}
trap cleanup EXIT

workdir="$(mktemp -d)"
asset="landstrip-0.0.0-linux-x64-musl.tar.gz"
printf 'payload\n' >"$workdir/$asset"
write_sha256_sidecar "$workdir/$asset"

sidecar="$workdir/$asset.sha256"
[[ -f "$sidecar" ]] || die "missing sidecar: $sidecar"

read -r digest name <"$sidecar"
[[ "$name" == "$asset" ]] || die "sidecar name is $name, expected $asset"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "invalid digest: $digest"
[[ "$(sha256_digest "$workdir/$asset")" == "$digest" ]] \
  || die "sidecar digest does not match file"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$workdir" && sha256sum -c "$asset.sha256") >/dev/null \
    || die "sha256sum -c rejected $asset.sha256"
fi

printf 'sha256 sidecar test passed\n'
