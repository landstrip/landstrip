#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026
#
# Multi-platform release packaging.
#   host-native triple — cargo
#   other triples — cargo-zigbuild (Zig linker)
#
# Platforms:
#   linux-x64, linux-arm64 — x86_64/aarch64-unknown-linux-musl (static)
#   darwin-arm64, darwin-x64 — aarch64/x86_64-apple-darwin
#   win32-x64 — x86_64-pc-windows-gnu
#   win32-arm64 — aarch64-pc-windows-gnullvm
#
# Exit 0 if every requested platform was packaged.
# Exit 2 if a requested build fails while another succeeds.
# Exit 1 if nothing was packaged or a hard prerequisite is missing.
# PACKAGE_STRICT=1 fails when any requested platform is skipped or failed.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=package-target.sh
source "$script_dir/package-target.sh"

CARGO="${CARGO:-cargo}"
RUSTC="${RUSTC:-rustc}"
CARGO_ZIGBUILD="${CARGO_ZIGBUILD:-cargo-zigbuild}"
NODE="${NODE:-node}"
FILE="${FILE:-file}"
READELF="${READELF:-readelf}"
ZIG="${ZIG:-zig}"

export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--no-deprecation"
export PATH="${HOME}/.cargo/bin:${PATH}"

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

for command in "$CARGO" "$RUSTC" "$NODE" git tar "$FILE"; do
  require_command "$command"
done
if ! command -v sha256sum >/dev/null 2>&1 && \
  ! command -v shasum >/dev/null 2>&1; then
  die "required command not found: sha256sum or shasum"
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
  || die "not inside a Git repository"
# shellcheck source=../../../scripts/sha256.sh
source "$repo_root/scripts/sha256.sh"
cd "$repo_root"

[[ -z "$(git status --porcelain)" ]] || die "working directory is not clean"
package_commit="$(git rev-parse HEAD)"

version="$("$NODE" -p "require('$repo_root/packages/landstrip-api/package.json').version")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid package.json version: $version"

cargo_version="$(
  sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' \
    "$repo_root/packages/landstrip/Cargo.toml" | head -1
)"
[[ "$version" == "$cargo_version" ]] \
  || die "package.json version $version does not match Cargo.toml $cargo_version"
rust_host_triple="$("$RUSTC" --print host-tuple)"
[[ -n "$rust_host_triple" ]] || die "cannot determine rustc host triple"

# Keep packaging builds out of the developer target tree.
package_target_root="${CARGO_TARGET_DIR:-$repo_root/packages/landstrip/target/package}"

# platform|rust-triple|binary-name
platforms=(
  'linux-x64|x86_64-unknown-linux-musl|landstrip'
  'linux-arm64|aarch64-unknown-linux-musl|landstrip'
  'win32-x64|x86_64-pc-windows-gnu|landstrip.exe'
  'win32-arm64|aarch64-pc-windows-gnullvm|landstrip.exe'
  'darwin-arm64|aarch64-apple-darwin|landstrip'
  'darwin-x64|x86_64-apple-darwin|landstrip'
)
supported_platforms='linux-x64 linux-arm64 win32-x64 win32-arm64 darwin-arm64 darwin-x64'

requested=()
if (($# > 0)); then
  requested=("$@")
else
  for entry in "${platforms[@]}"; do
    IFS='|' read -r platform _ _ <<<"$entry"
    requested+=("$platform")
  done
fi

platform_entry() {
  local want="$1" entry platform
  for entry in "${platforms[@]}"; do
    IFS='|' read -r platform _ _ <<<"$entry"
    if [[ "$platform" == "$want" ]]; then
      printf '%s\n' "$entry"
      return 0
    fi
  done
  return 1
}

host_platform() {
  "$NODE" -e 'process.stdout.write(process.platform + "-" + process.arch)'
}

verify_linux_static() {
  local bin="$1"
  local description

  description="$($FILE -b "$bin")"
  printf '%s\n' "$description"
  if [[ "$description" != *"static-pie linked"* && "$description" != *"statically linked"* ]]; then
    printf 'Linux musl release is not statically linked: %s\n' "$bin" >&2
    return 1
  fi
  if command -v "$READELF" >/dev/null 2>&1; then
    if "$READELF" -l "$bin" 2>/dev/null | grep -q 'INTERP'; then
      printf 'Linux musl release declares a dynamic ELF interpreter: %s\n' "$bin" >&2
      return 1
    fi
    if "$READELF" -d "$bin" 2>/dev/null | grep -q '(NEEDED)'; then
      printf 'Linux musl release has dynamic dependencies: %s\n' "$bin" >&2
      return 1
    fi
  fi
  return 0
}

smoke_host_binary() {
  local platform="$1"
  local bin="$2"

  if [[ "$platform" == "$(host_platform)" ]]; then
    # Fresh cp of an adhoc-signed Mach-O can fail Gatekeeper (SIGKILL) until re-signed.
    if [[ "$platform" == darwin-* ]] && command -v codesign >/dev/null 2>&1; then
      codesign --force -s - "$bin" >/dev/null 2>&1 || true
    fi
    "$bin" --version >/dev/null
  fi
}

rustup_has_target() {
  local triple="$1"
  command -v rustup >/dev/null 2>&1 || return 0
  rustup target list --installed | grep -Fxq "$triple"
}

# Host ~/.cargo/config.toml (mold/clang for all Linux) sets -C linker and
# opts cargo-zigbuild out of zig cc. Use a dedicated CARGO_HOME with no config.
package_cargo_home() {
  local cargo_home="${XDG_CACHE_HOME:-$HOME/.cache}/landstrip/package-cargo"
  mkdir -p "$cargo_home"
  rm -f "$cargo_home/config.toml" "$cargo_home/config"
  printf '%s\n' "$cargo_home"
}

build_with_zigbuild() {
  local triple="$1"
  local target_dir="$package_target_root/$triple"
  local cargo_home zig_path
  cargo_home="$(package_cargo_home)"
  zig_path="$(command -v "$ZIG")"

  (
    cd "$repo_root/packages/landstrip" || exit 1
    export CARGO_HOME="$cargo_home"
    export CARGO_TARGET_DIR="$target_dir"
    export CARGO_ZIGBUILD_ZIG_PATH="$zig_path"
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
    "$CARGO_ZIGBUILD" zigbuild --release --target "$triple"
  )
}

build_native() {
  local triple="$1"
  local target_dir="$package_target_root/$triple"

  (
    cd "$repo_root/packages/landstrip" || exit 1
    CARGO_TARGET_DIR="$target_dir" "$CARGO" build --release --target "$triple"
  )
}

needs_zigbuild=0
for platform in "${requested[@]}"; do
  entry="$(platform_entry "$platform")" \
    || die "unknown platform: $platform (supported: $supported_platforms)"
  IFS='|' read -r _ triple _ <<<"$entry"
  if [[ "$(package_build_driver "$rust_host_triple" "$triple")" == zigbuild ]]; then
    needs_zigbuild=1
  fi
done
mkdir -p artifacts

# Invalidate every platform so a subset or partial build cannot mix runs.
for entry in "${platforms[@]}"; do
  IFS='|' read -r platform _ binary <<<"$entry"
  rm -f "npm/$platform/bin/$binary" \
    "artifacts/${platform}.bin.sha256" \
    "artifacts/${platform}.bin.sha256.tmp" \
    "artifacts/${platform}.tar.gz" \
    "artifacts/${platform}.tar.gz.sha256"
done

if ((needs_zigbuild)); then
  require_command "$CARGO_ZIGBUILD"
  require_command "$ZIG"
fi

built=()
skipped=()
failed=()

for platform in "${requested[@]}"; do
  entry="$(platform_entry "$platform")" \
    || die "unknown platform: $platform (supported: $supported_platforms)"

  IFS='|' read -r _ triple binary <<<"$entry"
  package_dir="npm/$platform"
  [[ -f "$package_dir/package.json" ]] || die "missing $package_dir/package.json"

  # Compare Rust triples because Node's platform omits the libc/toolchain ABI
  # (for example, linux-x64 can target x86_64-unknown-linux-musl).
  if [[ "$(package_build_driver "$rust_host_triple" "$triple")" == cargo ]]; then
    printf '==> %s (%s via cargo)\n' "$platform" "$triple"
    if ! build_native "$triple"; then
      failed+=("$platform: cargo build failed")
      printf 'fail: %s (cargo build failed)\n' "$platform" >&2
      continue
    fi
  else
    printf '==> %s (%s via cargo-zigbuild)\n' "$platform" "$triple"
    if ! rustup_has_target "$triple"; then
      failed+=("$platform: rustup target not installed: $triple")
      printf 'fail: %s (rustup target add %s)\n' "$platform" "$triple" >&2
      continue
    fi

    if ! build_with_zigbuild "$triple"; then
      if [[ "$triple" == *apple-darwin && -z "${SDKROOT:-}" ]]; then
        failed+=("$platform: cargo zigbuild failed (Darwin system libraries need SDKROOT)")
        printf 'fail: %s (set SDKROOT to a macOS SDK for Darwin system libraries)\n' "$platform" >&2
      else
        failed+=("$platform: cargo zigbuild failed")
        printf 'fail: %s (cargo zigbuild failed)\n' "$platform" >&2
      fi
      continue
    fi
  fi

  source_bin="$package_target_root/$triple/$triple/release/$binary"
  if [[ ! -f "$source_bin" ]]; then
    failed+=("$platform: missing $source_bin")
    printf 'fail: %s (missing %s)\n' "$platform" "$source_bin" >&2
    continue
  fi

  case "$platform" in
    linux-*)
      if ! verify_linux_static "$source_bin"; then
        failed+=("$platform: not statically linked")
        continue
      fi
      ;;
  esac

  mkdir -p "$package_dir/bin"
  cp "$source_bin" "$package_dir/bin/$binary"
  chmod 755 "$package_dir/bin/$binary" 2>/dev/null || true

  if ! smoke_host_binary "$platform" "$package_dir/bin/$binary"; then
    failed+=("$platform: host smoke test failed")
    printf 'fail: %s (host smoke test failed)\n' "$platform" >&2
    continue
  fi

  tar -C "$package_dir/bin" -czf "artifacts/${platform}.tar.gz" "$binary"
  write_sha256_sidecar "artifacts/${platform}.tar.gz"
  write_binary_receipt "artifacts/${platform}.bin.sha256" \
    "$package_dir/bin/$binary" "$version" "$package_commit"
  built+=("$platform")
  printf 'packaged %s -> npm/%s/bin/%s and artifacts/%s.tar.gz\n' \
    "$platform" "$platform" "$binary" "$platform"
done

printf '\n'
if ((${#built[@]})); then
  printf 'built: %s\n' "${built[*]}"
else
  printf 'built: (none)\n'
fi
if ((${#skipped[@]})); then
  printf 'skipped:\n'
  printf '  %s\n' "${skipped[@]}"
fi
if ((${#failed[@]})); then
  printf 'failed:\n' >&2
  printf '  %s\n' "${failed[@]}" >&2
fi

if ((${#built[@]} == 0)); then
  die "no platforms were packaged"
fi

if [[ "${PACKAGE_STRICT:-0}" == 1 ]]; then
  if ((${#skipped[@]} + ${#failed[@]} > 0)); then
    die "PACKAGE_STRICT=1 and some platforms were skipped or failed"
  fi
fi

if ((${#failed[@]} > 0)); then
  exit 2
fi
