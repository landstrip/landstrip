#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026
#
# Export the macOS build container image containing the macOS SDK,
# so a Linux host can build Darwin targets using cargo-zigbuild:
#
#   macOS:  ./scripts/container-export-darwin.sh [out.tar]
#   Linux:  ./scripts/container-import-darwin.sh [out.tar]
#
# Env:
#   SDK       Versioned SDK dir name under CLT SDKs (default: auto-detected)
#   OUT       Target tarball path (default: dist/landstrip-darwin-build.tar)

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null)" \
  || { printf 'not inside a Git repository\n' >&2; exit 1; }
cd "$repo_root"

# shellcheck source=sha256.sh
source "$script_dir/sha256.sh"

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

[[ "$(uname -s)" == Darwin ]] \
  || die "run this script on macOS: macOS build image requires the macOS SDK"

require_command tar

archive="${1:-${OUT:-dist/landstrip-darwin-build.tar}}"

CLT_SDKS="/Library/Developer/CommandLineTools/SDKs"
sdk_path="${SDKROOT:-}"

if [[ -z "$sdk_path" ]]; then
  if [[ -n "${SDK:-}" && -d "${CLT_SDKS}/${SDK}" ]]; then
    sdk_path="${CLT_SDKS}/${SDK}"
  elif command -v xcrun >/dev/null 2>&1; then
    sdk_path="$(xcrun --show-sdk-path 2>/dev/null || true)"
  fi
fi

if [[ -z "$sdk_path" || ! -d "$sdk_path" ]]; then
  if [[ -d "$CLT_SDKS" ]]; then
    for candidate in "$CLT_SDKS"/MacOSX*.sdk; do
      if [[ -d "$candidate" && "$candidate" != *"MacOSX.sdk" ]]; then
        sdk_path="$candidate"
        break
      fi
    done
  fi
fi

[[ -n "$sdk_path" && -d "$sdk_path" ]] \
  || die "macOS SDK not found (install Xcode or Command Line Tools)"

# Resolve symlinks to find the real SDK path
sdk_real="$(cd "$sdk_path" && pwd -P)"
sdk_name="$(basename "$sdk_real")"
printf '==> packaging macOS SDK: %s (%s)\n' "$sdk_name" "$sdk_real"

workdir="$(mktemp -d)"
cleanup() {
  local status=$?
  rm -rf "$workdir"
  return "$status"
}
trap cleanup EXIT

rootfs="$workdir/rootfs"
mkdir -p "$rootfs/sdk"

# Copy SDK contents
cp -a "$sdk_real/." "$rootfs/sdk/"

# Ensure libc++ headers are inside the SDK
libcxx_src="/Library/Developer/CommandLineTools/usr/include/c++/v1"
if [[ ! -f "$rootfs/sdk/usr/include/c++/v1/version" && -d "$libcxx_src" ]]; then
  mkdir -p "$rootfs/sdk/usr/include/c++"
  cp -a "$libcxx_src" "$rootfs/sdk/usr/include/c++/"
fi

mkdir -p "$(dirname "$archive")"

# Create the archive
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  image="landstrip-darwin-build:latest"
  printf '==> building container image: %s\n' "$image"
  docker import \
    --change 'LABEL org.landstrip.description="macOS build image"' \
    --change 'ENTRYPOINT ["/dev/null"]' \
    - "$image" < <(tar --no-xattrs --no-mac-metadata -C "$rootfs" -cf - .) >/dev/null
  docker save -o "$archive" "$image"
else
  printf '==> writing archive: %s\n' "$archive"
  tar --no-xattrs --no-mac-metadata -C "$rootfs" -cf "$archive" .
fi

write_sha256_sidecar "$archive"

printf 'exported %s\n' "$archive"
printf 'sha256   %s\n' "$(sha256_digest "$archive")"
printf 'run scripts/container-import-darwin.sh %s on the packaging host\n' \
  "$archive"
