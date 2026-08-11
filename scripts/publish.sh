#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026
#
# Publish crates.io + npm packages from locally packaged binaries.
# Run `make package` (or PACKAGE_STRICT=1 make package) first.

set -euo pipefail

export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--no-deprecation"

CARGO="${CARGO:-cargo}"
GH="${GH:-gh}"
NODE="${NODE:-node}"
NPM="${NPM:-npm}"

platforms=(
  darwin-arm64
  darwin-x64
  linux-arm64
  linux-x64
  win32-arm64
  win32-x64
)
license_files=(LICENSE-APACHE-2.0 LICENSE-LGPL-2.1)

cleanup() {
  local status=$?

  if [[ -n "${workdir:-}" ]]; then
    rm -rf "$workdir"
  fi
  return "$status"
}

trap cleanup EXIT

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

npm_package_exists() {
  local error_file="$workdir/npm-view-error"
  local package_name="$1"
  local package_version

  if package_version="$($NPM view "$package_name@$version" version 2>"$error_file")"; then
    [[ "$package_version" == "$version" ]] \
      || die "npm returned version $package_version for $package_name@$version"
    return 0
  fi
  if grep -q 'E404' "$error_file"; then
    return 1
  fi
  cat "$error_file" >&2
  die "cannot query $package_name@$version from npm"
}

# Packages with prepack (bun builds) need local node_modules for lifecycle
# scripts, so tsc/bun resolve from the package-local .bin.
prepare_npm_package_build() {
  local package_dir="$1"
  local has_prepack
  local host_platform
  local host_pkg

  has_prepack="$($NODE -p "Boolean(require('$package_dir/package.json').scripts && require('$package_dir/package.json').scripts.prepack)")"
  [[ "$has_prepack" == true ]] || return 0

  require_command bun
  printf 'installing build deps for %s\n' \
    "$($NODE -p "require('$package_dir/package.json').name")"
  # Wire the local meta package (and host optional binary) so unpublished
  # versions resolve; ignore-scripts / --no-save keep the tree side-effect free.
  host_platform="$($NODE -e 'process.stdout.write(process.platform + "-" + process.arch)')"
  host_pkg="$repo_root/npm/$host_platform"
  if [[ -d "$host_pkg" ]]; then
    $NPM install --prefix "$package_dir" --package-lock=false --ignore-scripts --no-save \
      "$repo_root" "$host_pkg"
  else
    $NPM install --prefix "$package_dir" --package-lock=false --ignore-scripts --no-save \
      "$repo_root"
  fi
}

publish_npm_package() {
  local package_dir="$1"
  local package_name

  package_name="$($NODE -p "require('$package_dir/package.json').name")"
  if npm_package_exists "$package_name"; then
    printf '%s\n' "$package_name@$version is already published"
    return
  fi
  prepare_npm_package_build "$package_dir"
  $NPM publish "$package_dir" --access public
}

preflight_npm_package() {
  local package_dir="$1"
  local package_name
  local package_private
  local package_version

  package_name="$($NODE -p "require('$package_dir/package.json').name")"
  package_private="$($NODE -p "require('$package_dir/package.json').private === true")"
  package_version="$($NODE -p "require('$package_dir/package.json').version")"
  [[ "$package_private" != true ]] || die "$package_name is marked private"
  [[ "$package_version" == "$version" ]] \
    || die "$package_name version $package_version does not match $version"
  prepare_npm_package_build "$package_dir"
  $NPM publish "$package_dir" --access public --dry-run --loglevel=error >/dev/null
}

wait_for_npm_package() {
  local package_name="$1"
  local attempt

  for attempt in {1..12}; do
    if npm_package_exists "$package_name"; then
      return
    fi
    sleep 5
  done
  die "$package_name@$version did not become available from npm"
}

publish_cargo_package() {
  local output

  if output="$($CARGO info --registry crates-io "landstrip@$version" 2>&1)"; then
    printf '%s\n' "landstrip@$version is already published"
    return
  fi
  if [[ "$output" != *"could not find \`landstrip@$version\`"* ]]; then
    printf '%s\n' "$output" >&2
    die "cannot query landstrip@$version from crates.io"
  fi
  $CARGO publish --locked
}

platform_binary() {
  local platform="$1"
  if [[ "$platform" == win32-* ]]; then
    printf 'landstrip.exe\n'
  else
    printf 'landstrip\n'
  fi
}

for command in "$CARGO" "$GH" "$NODE" "$NPM" bun tar; do
  require_command "$command"
done

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" \
  || die "not inside a Git repository"
cd "$repo_root"

[[ -z "$(git status --porcelain)" ]] || die "working directory is not clean"

extension_dirs=()
while IFS= read -r extension_dir; do
  extension_dirs+=("$extension_dir")
done < <(scripts/test-extensions.sh --list)
((${#extension_dirs[@]} > 0)) || die "no extension workspaces found"

lock_files=(package-lock.json)
for extension_dir in "${extension_dirs[@]}"; do
  lock_files+=("$extension_dir/package-lock.json")
done

version="${1:-$($NODE -p 'require("./package.json").version')}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version: $version"
package_version="$($NODE -p 'require("./package.json").version')"
[[ "$version" == "$package_version" ]] \
  || die "requested version $version does not match package.json $package_version"

tag_commit="$(git rev-parse "$version^{commit}" 2>/dev/null)" \
  || die "tag $version does not exist"
[[ "$tag_commit" == "$(git rev-parse HEAD)" ]] \
  || die "tag $version does not point to HEAD"

workdir="$(mktemp -d)"
mkdir -p "$workdir/packages" "$workdir/release"

printf '%s\n' "assembling platform packages from local npm/*/bin binaries"
npm_package_dirs=()
missing=()
for platform in "${platforms[@]}"; do
  binary="$(platform_binary "$platform")"
  source_bin="npm/$platform/bin/$binary"
  if [[ ! -f "$source_bin" ]]; then
    missing+=("$source_bin")
    continue
  fi

  package_dir="$workdir/packages/$platform"
  cp -a "npm/$platform" "$package_dir"
  mkdir -p "$package_dir/bin"
  cp "$source_bin" "$package_dir/bin/$binary"
  chmod 755 "$package_dir/bin/$binary" 2>/dev/null || true
  for license_file in "${license_files[@]}"; do
    [[ -f "$license_file" ]] || die "missing $license_file"
    cp "$license_file" "$package_dir/$license_file"
  done
  asset_platform="$platform"
  [[ "$platform" == linux-* ]] && asset_platform="$platform-musl"
  tar -C "$package_dir/bin" -czf \
    "$workdir/release/landstrip-$version-$asset_platform.tar.gz" "$binary"
  npm_package_dirs+=("$package_dir")
done

if ((${#missing[@]} > 0)); then
  printf 'missing platform binaries:\n' >&2
  printf '  %s\n' "${missing[@]}" >&2
  die "run 'PACKAGE_STRICT=1 make package' before publish"
fi

npm_package_dirs+=("$repo_root")
for extension_dir in "${extension_dirs[@]}"; do
  npm_package_dirs+=("$repo_root/$extension_dir")
done

printf '%s\n' "validating npm packages"
for package_dir in "${npm_package_dirs[@]}"; do
  preflight_npm_package "$package_dir"
done

publish_cargo_package
for package_dir in "${npm_package_dirs[@]}"; do
  publish_npm_package "$package_dir"
done

package_names=("$($NODE -p 'require("./package.json").name')")
while IFS= read -r package_name; do
  package_names+=("$package_name")
done < <($NODE -p 'Object.keys(require("./package.json").optionalDependencies).join("\n")')
for package_name in "${package_names[@]}"; do
  wait_for_npm_package "$package_name"
done

if $GH release view "$version" >/dev/null 2>&1; then
  $GH release upload "$version" "$workdir"/release/*.tar.gz --clobber
else
  $GH release create "$version" "$workdir"/release/*.tar.gz \
    --notes-from-tag \
    --title "landstrip $version" \
    --verify-tag
fi

NPM="$NPM" "$NODE" scripts/update-npm-integrity.mjs "$version" "${extension_dirs[@]}"
git add -- "${lock_files[@]}"
if ! git diff --cached --quiet; then
  git commit -s -m "chore: Update package-lock.json files"
fi

printf '%s\n' "published landstrip $version"
printf '%s\n' "push the integrity commit"
