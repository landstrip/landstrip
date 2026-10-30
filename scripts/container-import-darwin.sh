#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026
#
# Import the macOS build container image (exported from macOS)
# and stage the macOS SDK so `make package` can build Darwin targets using cargo-zigbuild:
#
#   ./scripts/container-import-darwin.sh dist/landstrip-darwin-build.tar
#   make package
#
# Env:
#   CONTAINER   Container runtime to drive (default: docker)
#   SDK_DIR     Target SDK directory (default: packages/landstrip/target/sdk)

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null)" \
  || { printf 'not inside a Git repository\n' >&2; exit 1; }
cd "$repo_root"

# shellcheck source=sha256.sh
source "$script_dir/sha256.sh"

CONTAINER="${CONTAINER:-docker}"
SDK_DIR="${SDK_DIR:-packages/landstrip/target/sdk}"
IMAGE_BASE="ghcr.io/cross-rs/aarch64-apple-darwin-cross"
IMAGE_TAG="${IMAGE_TAG:-local}"

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

check_sha256() {
  local file="$1" name="${1##*/}" recorded
  if [[ ! -f "$file.sha256" ]]; then
    return 0
  fi
  read -r recorded _ <"$file.sha256" || die "unreadable: $name.sha256"
  [[ "$(sha256_digest "$file")" == "$recorded" ]] \
    || die "$name does not match its sidecar"
}

(( $# >= 1 )) || die "usage: $0 <archive.tar>"
archive="$1"
[[ -f "$archive" ]] || die "missing archive: $archive"

case "$CONTAINER" in
  docker|podman) ;;
  *) die "CONTAINER must be docker or podman, not $CONTAINER" ;;
esac

require_command "$CONTAINER"
check_sha256 "$archive"

image=""
container_id=

cleanup() {
  local status=$?
  if [[ -n "$container_id" ]]; then
    "$CONTAINER" rm -f "$container_id" >/dev/null 2>&1 || true
  fi
  return "$status"
}
trap cleanup EXIT

printf '==> importing container image from %s\n' "$archive"

# Try loading as a saved docker image first (docker save format)
load_output="$("$CONTAINER" load -i "$archive" 2>&1 || true)"
if [[ "$load_output" =~ Loaded\ image[s]?:\ ([^[:space:]]+) ]]; then
  image="${BASH_REMATCH[1]}"
  printf 'loaded %s\n' "$image"
  # Tag as :local if loaded with an arch suffix
  if [[ "$image" =~ ${IMAGE_BASE}:.+ ]]; then
    "$CONTAINER" tag "$image" "${IMAGE_BASE}:${IMAGE_TAG}" 2>/dev/null || true
  fi
else
  # If docker load did not succeed, import as rootfs tarball
  image="landstrip-darwin-build:latest"
  "$CONTAINER" import \
    --change 'LABEL org.landstrip.description="macOS build image"' \
    --change 'ENTRYPOINT ["/dev/null"]' \
    "$archive" "$image" >/dev/null || die "image import failed"
  printf 'imported %s\n' "$image"
fi

# Create a stopped container to extract the SDK; pass a dummy command to prevent
# "Error response from daemon: no command specified"
container_id="$("$CONTAINER" create "$image" /dev/null)" \
  || container_id="$("$CONTAINER" create "$image" sh)" \
  || die "container create failed"

rm -rf "$SDK_DIR"
mkdir -p "$SDK_DIR"

printf '==> extracting macOS SDK from container image...\n'

# Search inside the container for the SDK location:
# 1. /sdk (created by container-export-darwin.sh)
# 2. /osxcross/target/SDK (created by cross-rs osxcross image)
# 3. /opt/MacOSX.sdk
extracted=0
for path in "/sdk" "/osxcross/target/SDK" "/opt/MacOSX.sdk"; do
  if "$CONTAINER" cp "$container_id:$path/." "$SDK_DIR/" 2>/dev/null; then
    if [[ -d "$SDK_DIR/usr" || -d "$SDK_DIR/System" ]]; then
      extracted=1
      break
    else
      for nested in "$SDK_DIR"/MacOSX*.sdk; do
        if [[ -d "$nested/usr" || -d "$nested/System" ]]; then
          mv "$nested"/* "$SDK_DIR/" 2>/dev/null || true
          rm -rf "$nested"
          extracted=1
          break 2
        fi
      done
    fi
  fi
done

"$CONTAINER" rm -f "$container_id" >/dev/null 2>&1 || true
container_id=

if [[ "$extracted" != "1" && ! -d "$SDK_DIR/usr" && ! -d "$SDK_DIR/System" ]]; then
  printf 'warning: could not extract SDK to %s; image %s is ready in %s\n' \
    "$SDK_DIR" "$image" "$CONTAINER" >&2
else
  printf 'staged macOS SDK in %s\n' "$SDK_DIR"
fi

printf '\nReady. To build Darwin packages, run:\n'
printf '  SDKROOT="%s" make package\n' "$(cd "$SDK_DIR" 2>/dev/null && pwd || printf '%s' "$SDK_DIR")"
