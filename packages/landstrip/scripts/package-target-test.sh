#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=package-target.sh
source "$script_dir/package-target.sh"

expect_driver() {
  local expected="$1"
  local host_triple="$2"
  local target_triple="$3"
  local actual

  actual="$(package_build_driver "$host_triple" "$target_triple")"
  if [[ "$actual" != "$expected" ]]; then
    printf 'expected %s for host %s and target %s; got %s\n' \
      "$expected" "$host_triple" "$target_triple" "$actual" >&2
    return 1
  fi
}

expect_driver cargo \
  x86_64-unknown-linux-gnu x86_64-unknown-linux-gnu
expect_driver cargo \
  aarch64-apple-darwin aarch64-apple-darwin
expect_driver cargo \
  x86_64-apple-darwin x86_64-apple-darwin
expect_driver zigbuild \
  x86_64-unknown-linux-gnu x86_64-unknown-linux-musl
expect_driver zigbuild \
  aarch64-apple-darwin x86_64-apple-darwin
expect_driver zigbuild \
  aarch64-apple-darwin x86_64-pc-windows-gnu
expect_driver zigbuild \
  x86_64-unknown-linux-gnu aarch64-pc-windows-gnullvm
