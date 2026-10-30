#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026
#
# Multi-platform release packaging.
#   host-native triple — cargo
#   other triples — cargo-zigbuild (Zig linker)
#
# Platforms:
#   linux-x64, linux-arm64 — x86_64/aarch64-unknown-linux-gnu (AppImage)
#   win32-x64 — x86_64-pc-windows-gnu
#   win32-arm64 — aarch64-pc-windows-gnullvm
#   darwin-arm64, darwin-x64 — aarch64/x86_64-apple-darwin
#
# Exit 0 if every requested platform was packaged.
# Exit 2 if a requested build fails while another succeeds.
# Exit 1 if nothing was packaged or a hard prerequisite is missing.
# PACKAGE_STRICT=1 fails when any requested platform is skipped or failed.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=package-target.sh
source "$script_dir/package-target.sh"
# shellcheck source=../../../scripts/sha256.sh
source "$script_dir/../../../scripts/sha256.sh"

CARGO="${CARGO:-cargo}"
RUSTC="${RUSTC:-rustc}"
CARGO_ZIGBUILD="${CARGO_ZIGBUILD:-cargo-zigbuild}"
CONTAINER="${CONTAINER:-docker}"
NODE="${NODE:-node}"
FILE="${FILE:-file}"
GZIP="${GZIP:-gzip}"
READELF="${READELF:-readelf}"
TAR="${TAR:-tar}"
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

create_tar_artifact() {
  local source_dir="$1" binary="$2" output="$3"
  local temporary="$output.tmp.$$"

  "$NODE" -e '
    const {utimesSync} = require("node:fs");
    const seconds = Number(process.argv[2]);
    utimesSync(process.argv[1], seconds, seconds);
  ' "$source_dir/$binary" "$SOURCE_DATE_EPOCH"

  if [[ "$tar_flavor" == gnu ]]; then
    if ! "$TAR" --format=ustar --owner=0 --group=0 --numeric-owner \
      -C "$source_dir" -cf - "$binary" | "$GZIP" -n >"$temporary"; then
      rm -f "$temporary"
      return 1
    fi
  else
    if ! COPYFILE_DISABLE=1 "$TAR" --format ustar --uid 0 --gid 0 \
      --uname root --gname root -C "$source_dir" -cf - "$binary" \
      | "$GZIP" -n >"$temporary"; then
      rm -f "$temporary"
      return 1
    fi
  fi
  mv "$temporary" "$output"
}

for command in "$CARGO" "$RUSTC" "$NODE" git "$TAR" "$GZIP" "$FILE"; do
  require_command "$command"
done
if ! command -v sha256sum >/dev/null 2>&1 && \
  ! command -v shasum >/dev/null 2>&1; then
  die "required command not found: sha256sum or shasum"
fi
tar_version="$("$TAR" --version 2>&1)" || die "cannot identify $TAR"
case "$tar_version" in
  *"GNU tar"*) tar_flavor=gnu ;;
  *bsdtar*|*libarchive*) tar_flavor=bsd ;;
  *) die "unsupported tar implementation: ${tar_version%%$'\n'*}" ;;
esac

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
  || die "not inside a Git repository"
cd "$repo_root"
[[ -z "$(git status --porcelain)" ]] || die "working directory is not clean"

head_commit="$(git rev-parse HEAD)"
SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$head_commit")"
export SOURCE_DATE_EPOCH

cargo_root="$repo_root/packages/landstrip"
package_json="$repo_root/packages/landstrip-cli/package.json"
[[ -f "$cargo_root/Cargo.toml" ]] || die "missing $cargo_root/Cargo.toml"
[[ -f "$package_json" ]] || die "missing $package_json"

version="$("$NODE" -p "require('$package_json').version")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid package.json version: $version"
cargo_version="$(
  sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' \
    "$cargo_root/Cargo.toml" | head -1
)"
[[ "$version" == "$cargo_version" ]] \
  || die "package.json version $version does not match Cargo.toml $cargo_version"
printf 'packaging landstrip %s (%s)\n' "$version" "${head_commit:0:12}"
rust_host_triple="$("$RUSTC" --print host-tuple)"
[[ -n "$rust_host_triple" ]] || die "cannot determine rustc host triple"

package_target_root="${CARGO_TARGET_DIR:-$repo_root/packages/landstrip/target/package}"

# Release outputs produced on another host (e.g. ad-hoc signed Mach-O binaries
# exported from macOS) are staged as-is instead of being rebuilt here.
prebuilt_root="${PREBUILT_ROOT:-}"
if [[ -z "$prebuilt_root" && -d "$cargo_root/target/prebuilt" ]]; then
  prebuilt_root="$cargo_root/target/prebuilt"
fi
if [[ -n "$prebuilt_root" ]]; then
  prebuilt_root="$(cd "$prebuilt_root" 2>/dev/null && pwd)" \
    || die "PREBUILT_ROOT is not a directory: $prebuilt_root"
fi

if [[ -z "${SDKROOT:-}" ]]; then
  for candidate in \
    "$cargo_root/target/sdk" \
    "$cargo_root/target/sdk/MacOSX.sdk" \
    "$repo_root/packages/landstrip/target/sdk" \
    "$repo_root/packages/landstrip/target/sdk/MacOSX.sdk"; do
    if [[ -d "$candidate" && ( -d "$candidate/usr" || -d "$candidate/System" ) ]]; then
      export SDKROOT="$candidate"
      break
    fi
  done
fi

# platform|rust-triple|binary-name
platforms=(
  'linux-x64|x86_64-unknown-linux-gnu|landstrip'
  'linux-arm64|aarch64-unknown-linux-gnu|landstrip'
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

smoke_host_binary() {
  local platform="$1"
  local bin="$2"

  if [[ "$platform" == "$(host_platform)" ]]; then
    # Fresh cp of an adhoc-signed Mach-O can fail Gatekeeper (SIGKILL) until re-signed.
    if [[ "$platform" == darwin-* ]] && command -v codesign >/dev/null 2>&1; then
      codesign --force -s - "$bin" >/dev/null 2>&1 || true
    fi
    if [[ "$platform" == linux-* ]]; then
      APPIMAGE_EXTRACT_AND_RUN=1 "$bin" --version >/dev/null
    else
      "$bin" --version >/dev/null
    fi
  fi
}

stage_prebuilt() {
  local platform="$1" binary="$2" stage_package_dir="$3"
  local artifact="landstrip-$version-$platform.tar.gz"
  local source_binary="$prebuilt_root/npm/$platform/bin/$binary"
  local source_artifact="$prebuilt_root/artifacts/$artifact"
  local digest name

  [[ -n "$prebuilt_root" && "$platform" != linux-* ]] || return 1
  [[ -f "$source_binary" && -f "$source_artifact" ]] || return 1
  [[ -f "$source_artifact.sha256" && -f "$source_artifact.commit" ]] \
    || die "prebuilt $platform artifact is missing its receipts"
  read -r digest name <"$source_artifact.sha256" \
    || die "prebuilt $platform receipt is unreadable"
  [[ "$name" == "$artifact" ]] \
    || die "prebuilt $platform receipt names $name instead of $artifact"
  [[ "$(sha256_digest "$source_artifact")" == "$digest" ]] \
    || die "prebuilt $platform artifact does not match its receipt"
  [[ "$(<"$source_artifact.commit")" == "$head_commit" ]] \
    || die "prebuilt $platform artifact was built from another commit"

  mkdir -p "$stage_package_dir/bin"
  cp "$source_binary" "$stage_package_dir/bin/$binary"
  chmod 755 "$stage_package_dir/bin/$binary"
  cp "$source_artifact" "$source_artifact.sha256" "$source_artifact.commit" \
    "$stage_root/artifacts/"
  printf '==> %s (prebuilt)\n' "$platform"
}

rustup_has_target() {
  local triple="$1"
  command -v rustup >/dev/null 2>&1 || return 0
  rustup target list --installed | grep -Fx "$triple" >/dev/null
}

# Host ~/.cargo/config.toml (mold/clang for all Linux) sets -C linker and
# opts cargo-zigbuild out of zig cc. Use a dedicated CARGO_HOME with no config.
package_cargo_home() {
  local cargo_home="${XDG_CACHE_HOME:-$HOME/.cache}/landstrip/package-cargo"
  mkdir -p "$cargo_home" || return 1
  rm -f "$cargo_home/config.toml" "$cargo_home/config" || return 1
  printf '%s\n' "$cargo_home"
}

build_with_zigbuild() {
  local triple="$1"
  local target_dir="$package_target_root/$triple"
  local cargo_home zig_path
  cargo_home="$(package_cargo_home)" || return 1
  zig_path="$(command -v "$ZIG")" || return 1

  (
    cd "$cargo_root" || exit 1
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
    cd "$cargo_root" || exit 1
    CARGO_TARGET_DIR="$target_dir" "$CARGO" build --release --target "$triple"
  )
}

needs_zigbuild=0
validated=()
for platform in "${requested[@]}"; do
  entry="$(platform_entry "$platform")" \
    || die "unknown platform: $platform (supported: $supported_platforms)"
  for previous in "${validated[@]}"; do
    [[ "$platform" != "$previous" ]] || die "duplicate platform: $platform"
  done
  validated+=("$platform")
  IFS='|' read -r _ triple _ <<<"$entry"
  if [[ "$(package_build_driver "$rust_host_triple" "$triple")" == zigbuild ]]; then
    needs_zigbuild=1
  fi
done

if ((needs_zigbuild)); then
  require_command "$CARGO_ZIGBUILD"
  require_command "$ZIG"
fi

built=()
failed=()

stage_root="$(mktemp -d "$repo_root/.package-stage.XXXXXX")"
publication_started=0
publication_committed=0
publish_paths=()
backup_root="$stage_root/backup"
cleanup() {
  local status=$? path backup rollback_failed=0

  trap - EXIT
  trap '' HUP INT TERM
  if ((publication_started && !publication_committed)); then
    for path in "${publish_paths[@]}"; do
      backup="$backup_root/$path"
      if [[ -f "$backup" ]]; then
        mkdir -p "$(dirname "$path")" || rollback_failed=1
        mv -f "$backup" "$path" || rollback_failed=1
      else
        rm -f "$path" || rollback_failed=1
      fi
    done
    if ((rollback_failed)); then
      printf 'release publication and rollback failed; backups preserved at %s\n' \
        "$stage_root" >&2
      status=1
    else
      printf 'previous release outputs restored\n' >&2
    fi
  fi
  if ((rollback_failed == 0)); then
    rm -rf -- "$stage_root" || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$stage_root/artifacts"

for platform in "${requested[@]}"; do
  entry="$(platform_entry "$platform")" \
    || die "unknown platform: $platform (supported: $supported_platforms)"

  IFS='|' read -r _ triple binary <<<"$entry"
  package_dir="npm/$platform"
  stage_package_dir="$stage_root/$package_dir"
  [[ -f "$package_dir/package.json" ]] || die "missing $package_dir/package.json"

  if stage_prebuilt "$platform" "$binary" "$stage_package_dir"; then
    built+=("$platform")
    continue
  fi

  # Compare Rust triples because Node's platform omits the libc/toolchain ABI
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

  mkdir -p "$stage_package_dir/bin"
  if [[ "$platform" == linux-* ]]; then
    if ! CONTAINER="$CONTAINER" "$script_dir/make-appimage.sh" \
      "$platform" "$source_bin" "$stage_package_dir/bin/$binary"; then
      failed+=("$platform: AppImage packaging failed")
      printf 'fail: %s (AppImage packaging failed)\n' "$platform" >&2
      continue
    fi
    artifact="landstrip-$version-$platform.AppImage"
  else
    cp "$source_bin" "$stage_package_dir/bin/$binary"
    artifact="landstrip-$version-$platform.tar.gz"
  fi
  chmod 755 "$stage_package_dir/bin/$binary"

  if ! smoke_host_binary "$platform" "$stage_package_dir/bin/$binary"; then
    failed+=("$platform: host smoke test failed")
    printf 'fail: %s (host smoke test failed)\n' "$platform" >&2
    continue
  fi

  if [[ "$platform" == linux-* ]]; then
    cp "$stage_package_dir/bin/$binary" "$stage_root/artifacts/$artifact"
  else
    create_tar_artifact \
      "$stage_package_dir/bin" "$binary" "$stage_root/artifacts/$artifact"
  fi
  digest="$(sha256_digest "$stage_root/artifacts/$artifact")"
  printf '%s  %s\n' "$digest" "$artifact" \
    >"$stage_root/artifacts/$artifact.sha256"
  printf '%s\n' "$head_commit" >"$stage_root/artifacts/$artifact.commit"
  built+=("$platform")
  printf 'staged %s\n' "$platform"
done

printf '\n'
if ((${#built[@]})); then
  printf 'built: %s\n' "${built[*]}"
else
  printf 'built: (none)\n'
fi
if ((${#failed[@]})); then
  printf 'failed:\n' >&2
  printf '  %s\n' "${failed[@]}" >&2
fi

if ((${#built[@]} == 0)); then
  die "no platforms were packaged"
fi

if [[ "${PACKAGE_STRICT:-0}" == 1 ]] && ((${#failed[@]} > 0)); then
  die "PACKAGE_STRICT=1 and some platforms failed"
fi

for platform in "${built[@]}"; do
  entry="$(platform_entry "$platform")"
  IFS='|' read -r _ _ binary <<<"$entry"
  if [[ "$platform" == linux-* ]]; then
    artifact="landstrip-$version-$platform.AppImage"
    stale_artifact="artifacts/landstrip-$version-$platform.tar.gz"
  else
    artifact="landstrip-$version-$platform.tar.gz"
    stale_artifact="artifacts/landstrip-$version-$platform.AppImage"
  fi

  [[ -f "$stage_root/npm/$platform/bin/$binary" ]] \
    || die "staged binary is missing for $platform"
  publish_paths+=("npm/$platform/bin/$binary")
  for suffix in '' .sha256 .commit; do
    [[ -f "$stage_root/artifacts/$artifact$suffix" ]] \
      || die "staged artifact is missing: $artifact$suffix"
    publish_paths+=("artifacts/$artifact$suffix" "$stale_artifact$suffix")
  done
done

for path in "${publish_paths[@]}"; do
  if [[ -f "$path" ]]; then
    mkdir -p "$backup_root/$(dirname "$path")"
    cp -p "$path" "$backup_root/$path" \
      || die "cannot back up release output: $path"
  elif [[ -e "$path" ]]; then
    die "release output is not a regular file: $path"
  fi
done

publication_started=1
for platform in "${built[@]}"; do
  entry="$(platform_entry "$platform")"
  IFS='|' read -r _ _ binary <<<"$entry"
  package_dir="npm/$platform"
  if [[ "$platform" == linux-* ]]; then
    artifact="landstrip-$version-$platform.AppImage"
    stale_artifact="artifacts/landstrip-$version-$platform.tar.gz"
  else
    artifact="landstrip-$version-$platform.tar.gz"
    stale_artifact="artifacts/landstrip-$version-$platform.AppImage"
  fi

  mkdir -p "$package_dir/bin" artifacts \
    || die "cannot prepare release output for $platform"
  mv -f "$stage_root/$package_dir/bin/$binary" "$package_dir/bin/$binary" \
    || die "cannot publish binary for $platform"
  for suffix in '' .sha256 .commit; do
    mv -f "$stage_root/artifacts/$artifact$suffix" \
      "artifacts/$artifact$suffix" \
      || die "cannot publish artifact: $artifact$suffix"
    rm -f "$stale_artifact$suffix" \
      || die "cannot remove stale artifact: $stale_artifact$suffix"
  done
done
publication_committed=1

for platform in "${built[@]}"; do
  entry="$(platform_entry "$platform")"
  IFS='|' read -r _ _ binary <<<"$entry"
  if [[ "$platform" == linux-* ]]; then
    artifact="landstrip-$version-$platform.AppImage"
  else
    artifact="landstrip-$version-$platform.tar.gz"
  fi
  printf 'packaged %s -> npm/%s/bin/%s and artifacts/%s{,.sha256,.commit}\n' \
    "$platform" "$platform" "$binary" "$artifact"
done
if ((${#failed[@]} > 0)); then
  exit 2
fi
