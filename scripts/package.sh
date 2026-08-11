#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026
#
# Multi-platform release packaging.
#   linux-*/win32-x64 — cross-rs (Docker)
#   win32-arm64 — cross-rs + local MSVC image (cross-toolchains, xwin SDK)
#   darwin-* — native cargo on Apple Silicon; cross + local osxcross image on Linux
#
# Platforms:
#   linux-x64, linux-arm64, win32-x64 — official cross images
#   win32-arm64 — local cross-toolchains MSVC image (built from Dockerfile)
#   darwin-arm64, darwin-x64 — host cargo when packaging on Intel/ARM macOS;
#   else local cross-toolchains osxcross images (Apple SDK; required from Linux)
#
# Exit 0 if every requested platform was packaged.
# Exit 2 if a requested build fails while another succeeds.
# Exit 1 if nothing was packaged or a hard prerequisite is missing.
# PACKAGE_STRICT=1 fails when any requested platform is skipped or failed.

set -euo pipefail

CARGO="${CARGO:-cargo}"
CROSS="${CROSS:-cross}"
NODE="${NODE:-node}"
FILE="${FILE:-file}"
READELF="${READELF:-readelf}"

export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--no-deprecation"
export PATH="${HOME}/.cargo/bin:${PATH}"

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

for command in "$CARGO" "$CROSS" "$NODE" git tar "$FILE" docker; do
  require_command "$command"
done

if ! docker info >/dev/null 2>&1; then
  die "docker is not usable (is the daemon running?)"
fi

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
  || die "not inside a Git repository"
cd "$repo_root"

version="$("$NODE" -p "require('$repo_root/package.json').version")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid package.json version: $version"

cargo_version="$(
  sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' \
    "$repo_root/Cargo.toml" | head -1
)"
[[ "$version" == "$cargo_version" ]] \
  || die "package.json version $version does not match Cargo.toml $cargo_version"

# Share the caller's target dir so incremental cross/cargo caches still hit.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"

# platform|rust-triple|binary-name|required-image
platforms=(
  'linux-x64|x86_64-unknown-linux-musl|landstrip|'
  'linux-arm64|aarch64-unknown-linux-musl|landstrip|'
  'win32-x64|x86_64-pc-windows-gnu|landstrip.exe|'
  'win32-arm64|aarch64-pc-windows-msvc|landstrip.exe|ghcr.io/cross-rs/aarch64-pc-windows-msvc-cross:local'
  'darwin-arm64|aarch64-apple-darwin|landstrip|ghcr.io/cross-rs/aarch64-apple-darwin-cross:local'
  'darwin-x64|x86_64-apple-darwin|landstrip|ghcr.io/cross-rs/x86_64-apple-darwin-cross:local'
)

requested=()
if (($# > 0)); then
  requested=("$@")
else
  for entry in "${platforms[@]}"; do
    IFS='|' read -r platform _ _ _ <<<"$entry"
    requested+=("$platform")
  done
fi

platform_entry() {
  local want="$1" entry platform
  for entry in "${platforms[@]}"; do
    IFS='|' read -r platform _ _ _ <<<"$entry"
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

# Host ~/.cargo/config.toml (mold/clang for all Linux) breaks cross image
# linkers. Use a dedicated CARGO_HOME under the user cache with no config.
#
# Dory (and similar FEX-backed Docker engines) leave the cross container
# running after cargo exits: only FEXServer --wait_pipe remains, so `cross`
# blocks forever after "Finished `release` profile". Reap that container;
# the binary is already on the host volume.
cross_container_ids() {
  docker ps -q --filter "status=running" --filter "name=${1}" 2>/dev/null || true
}

reap_stuck_cross_containers() {
  local ids

  ids="$(cross_container_ids "$1")"
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086
    docker kill $ids >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null 2>&1 || true
  fi
}

# True when cargo has finished inside a still-running FEX cross container.
# Dory keeps FEXServer --wait_pipe alive after cargo exits; docker top still
# shows the original `sh -c '... cargo build ...'` argv under FEX, so do not
# treat the word "cargo" in that line as an active build.
fex_zombie_cross_container() {
  local triple="$1" id top logs
  local ids

  ids="$(cross_container_ids "$triple")"
  [[ -n "$ids" ]] || return 1
  for id in $ids; do
    top="$(docker top "$id" 2>/dev/null || true)"
    [[ -n "$top" ]] || continue
    printf '%s\n' "$top" | grep -Eq 'FEXServer' || continue
    # Active compile/link still running.
    if printf '%s\n' "$top" | grep -Eq 'rustc|cc1|clang|collect2'; then
      continue
    fi
    logs="$(docker logs "$id" 2>&1 || true)"
    if printf '%s\n' "$logs" | grep -Fq 'Finished `release` profile'; then
      return 0
    fi
  done
  return 1
}

build_with_cross() {
  local triple="$1"
  local cargo_home cross_pid status=0 binary source_bin
  local grace="${CROSS_FEX_GRACE_SECS:-5}"
  # Cold FEX builds of large crates (tree-sitter/pdf) exceed 30m easily.
  local timeout_secs="${CROSS_BUILD_TIMEOUT_SECS:-7200}"
  local deadline=$((SECONDS + timeout_secs))
  local cargo_jobs

  cargo_home="${XDG_CACHE_HOME:-$HOME/.cache}/landstrip/cross-cargo"
  mkdir -p "$cargo_home"
  rm -f "$cargo_home/config.toml" "$cargo_home/config"

  case "$triple" in
    *windows*) binary=landstrip.exe ;;
    *) binary=landstrip ;;
  esac
  source_bin="$CARGO_TARGET_DIR/$triple/release/$binary"

  # Dory FEX + parallel rustc often writes empty rlibs on the virtiofs mount
  # ("memory map must have a non-zero length" / rustc SIGSEGV). Serialize by
  # default on Darwin; override with CARGO_BUILD_JOBS.
  if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
    cargo_jobs="$CARGO_BUILD_JOBS"
  elif [[ "$(uname -s)" == Darwin ]]; then
    cargo_jobs=1
  else
    cargo_jobs=
  fi

  # MSVC release must statically link the CRT (matching the previous
  # GitHub Actions release.yml build), and Windows GNU builds stay dynamic.
  if [[ "$triple" == *-msvc ]]; then
    export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C target-feature=+crt-static"
  fi

  # Build from repo root; Cross.toml is read from CWD. Inherit stdout/stderr
  # so cargo progress still streams to the terminal.
  set +e
  (
    cd "$repo_root" || exit 1
    if [[ -n "$cargo_jobs" ]]; then
      export CARGO_BUILD_JOBS="$cargo_jobs"
    fi
    # Use repo Cross.toml so packaging env passthrough applies without retagging.
    CROSS_CONFIG="${CROSS_CONFIG:-$repo_root/Cross.toml}" \
      CARGO_HOME="$cargo_home" "$CROSS" build --release --target "$triple"
  ) &
  cross_pid=$!

  while kill -0 "$cross_pid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      printf 'cross build timed out for %s after %ss\n' \
        "$triple" "$timeout_secs" >&2
      reap_stuck_cross_containers "$triple"
      kill "$cross_pid" 2>/dev/null || true
      wait "$cross_pid" 2>/dev/null
      set -e
      return 1
    fi

    if fex_zombie_cross_container "$triple" && [[ -f "$source_bin" ]]; then
      # Confirm it stays finished (not a brief gap between compile steps).
      sleep "$grace"
      if kill -0 "$cross_pid" 2>/dev/null \
        && fex_zombie_cross_container "$triple" \
        && [[ -f "$source_bin" ]]; then
        printf 'warning: cross hung after cargo finished for %s (Dory FEX); killing container\n' \
          "$triple" >&2
        reap_stuck_cross_containers "$triple"
        wait "$cross_pid" 2>/dev/null
        set -e
        return 0
      fi
    fi
    sleep 2
  done

  wait "$cross_pid"
  status=$?
  set -e
  return "$status"
}

has_required_image() {
  local image="$1"
  [[ -z "$image" ]] || docker image inspect "$image" >/dev/null 2>&1
}

build_native() {
  local triple="$1"

  if command -v rustup >/dev/null 2>&1; then
    rustup target add "$triple" >/dev/null
  fi

  (
    cd "$repo_root" || exit 1
    "$CARGO" build --release --target "$triple"
  )
}

built=()
skipped=()
failed=()

mkdir -p artifacts

host="$(host_platform)"
is_darwin_host=0
if [[ "$host" == darwin-* ]]; then
  # native cargo on either macOS arch covers both darwin triples
  is_darwin_host=1
fi

for platform in "${requested[@]}"; do
  entry="$(platform_entry "$platform")" \
    || die "unknown platform: $platform (supported: linux-x64 linux-arm64 win32-x64 win32-arm64 darwin-arm64 darwin-x64)"

  IFS='|' read -r _ triple binary required_image <<<"$entry"
  package_dir="npm/$platform"
  [[ -f "$package_dir/package.json" ]] || die "missing $package_dir/package.json"

  # Host triple packages natively (no Docker). The osxcross :local images remain
  # for packaging darwin-* from Linux; the MSVC :local image for win32-arm64.
  if [[ "$platform" == "$(host_platform)" || ( "$is_darwin_host" == 1 && "$platform" == darwin-* ) ]]; then
    printf '==> %s (%s via cargo)\n' "$platform" "$triple"
    if ! build_native "$triple"; then
      failed+=("$platform: cargo build failed")
      printf 'fail: %s (cargo build failed)\n' "$platform" >&2
      continue
    fi
  else
    printf '==> %s (%s via cross)\n' "$platform" "$triple"

    if ! has_required_image "$required_image"; then
      skipped+=("$platform: missing local cross image $required_image")
      printf 'skip: %s (build local cross image %s)\n' "$platform" "$required_image"
      continue
    fi

    if ! build_with_cross "$triple"; then
      failed+=("$platform: cross build failed")
      printf 'fail: %s (cross build failed)\n' "$platform" >&2
      continue
    fi
  fi

  source_bin="$CARGO_TARGET_DIR/$triple/release/$binary"
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
