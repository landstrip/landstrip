#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026
#
# Publish crates.io + npm packages from locally packaged binaries.
# Run `make package` (or PACKAGE_STRICT=1 make package) first.
#
# Defaults to the highest semver tag reachable from HEAD.
# Tip may be ahead of the tag; cargo is published from the tagged tree.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=sha256.sh
source "$script_dir/sha256.sh"

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

cleanup() {
  local status=$?

  if [[ -n "${publish_worktree:-}" ]]; then
    if ! git -C "${repo_root:-.}" worktree remove --force "$publish_worktree" 2>/dev/null; then
      rm -rf "$publish_worktree"
      git -C "${repo_root:-.}" worktree prune >/dev/null 2>&1 || true
    fi
  fi
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
      "$repo_root/packages/landstrip" "$host_pkg"
  else
    $NPM install --prefix "$package_dir" --package-lock=false --ignore-scripts --no-save \
      "$repo_root/packages/landstrip"
  fi
}

publish_npm_package() {
  local package_dir="$1"
  local error_file="$workdir/npm-publish-error"
  local package_name

  package_name="$($NODE -p "require('$package_dir/package.json').name")"
  if npm_package_exists "$package_name"; then
    printf '%s\n' "$package_name@$version is already published"
    return
  fi
  prepare_npm_package_build "$package_dir"
  if $NPM publish "$package_dir" --access public 2>"$error_file"; then
    cat "$error_file" >&2
    return
  fi
  cat "$error_file" >&2
  if grep -q 'E409' "$error_file" \
    && grep -q 'Cannot publish over previously staged version' "$error_file"; then
    wait_for_npm_package "$package_name"
    return
  fi
  return 1
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
  if npm_package_exists "$package_name"; then
    printf '%s\n' "$package_name@$version is already published"
    return
  fi
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
  local output cargo_root="$1"

  if output="$($CARGO info --registry crates-io "landstrip@$version" 2>&1)"; then
    printf '%s\n' "landstrip@$version is already published"
    return
  fi
  if [[ "$output" != *"could not find \`landstrip@$version\`"* ]]; then
    printf '%s\n' "$output" >&2
    die "cannot query landstrip@$version from crates.io"
  fi
  (
    cd "$cargo_root" || exit 1
    $CARGO publish --locked
  )
}

github_retry() {
  local attempt
  local error_file="$workdir/gh-retry-error"

  for attempt in {1..6}; do
    if "$@" 2>"$error_file"; then
      cat "$error_file" >&2
      return 0
    fi
    cat "$error_file" >&2
    if ((attempt == 6)) || ! grep -Eq 'HTTP 502|HTTP 503|HTTP 429' "$error_file"; then
      return 1
    fi
    printf 'transient GitHub error (attempt %s/6), retrying...\n' "$attempt" >&2
    sleep $((attempt * 2))
  done
}

github_release_exists() {
  local attempt
  local error_file="$workdir/gh-release-error"

  for attempt in {1..6}; do
    if $GH api "repos/:owner/:repo/releases/tags/$version" \
      >"$workdir/gh-release.json" 2>"$error_file"; then
      return 0
    fi
    if grep -q 'HTTP 404' "$error_file"; then
      return 1
    fi
    if ((attempt == 6)) || ! grep -Eq 'HTTP 502|HTTP 503|HTTP 429' "$error_file"; then
      cat "$error_file" >&2
      die "cannot query GitHub release $version"
    fi
    printf 'transient GitHub error querying release %s (attempt %s/6), retrying...\n' \
      "$version" "$attempt" >&2
    sleep $((attempt * 2))
  done
}

publish_github_release() {
  local asset name
  local missing=()

  if github_release_exists; then
    for asset in "$workdir"/release/*.tar.gz "$workdir"/release/*.sha256; do
      name="${asset##*/}"
      if $NODE -e '
        const fs = require("fs");
        const release = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
        const name = process.argv[2];
        const assets = Array.isArray(release.assets) ? release.assets : [];
        process.exit(assets.some((asset) => asset.name === name) ? 0 : 1);
      ' "$workdir/gh-release.json" "$name"; then
        printf '%s\n' "GitHub release $version already has $name"
      else
        missing+=("$asset")
      fi
    done
    if ((${#missing[@]} == 0)); then
      printf '%s\n' "GitHub release $version is already published"
      return
    fi
    github_retry "$GH" release upload "$version" "${missing[@]}"
    return
  fi

  github_retry "$GH" release create "$version" \
    "$workdir"/release/*.tar.gz \
    "$workdir"/release/*.sha256 \
    --notes-from-tag \
    --title "landstrip $version" \
    --verify-tag
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
if ! command -v sha256sum >/dev/null 2>&1 && \
  ! command -v shasum >/dev/null 2>&1; then
  die "required command not found: sha256sum or shasum"
fi

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

# Empty VERSION from make is still a set argv; treat blank as "latest tag".
version="${1:-}"
if [[ -z "$version" ]]; then
  versions="$(git tag --merged HEAD --list '[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname)"
  version="${versions%%$'\n'*}"
  [[ -n "$version" ]] || die "no semver tag reachable from HEAD"
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version: $version"

# npm packages are assembled from the tip tree; keep tip metadata on the tag.
tip_version="$($NODE -p 'require("./packages/landstrip/package.json").version')"
[[ "$version" == "$tip_version" ]] \
  || die "tag $version does not match tip package.json $tip_version"

tag_commit="$(git rev-parse "$version^{commit}" 2>/dev/null)" \
  || die "tag $version does not exist"
head_commit="$(git rev-parse HEAD)"
if ! git merge-base --is-ancestor "$tag_commit" "$head_commit"; then
  die "tag $version is not an ancestor of HEAD"
fi

if [[ "$tag_commit" != "$head_commit" ]] \
  && ! git diff --quiet "$tag_commit" "$head_commit" -- \
    Cargo.toml Cargo.lock rust-toolchain.toml src; then
  die "Rust package sources changed since tag $version"
fi

workdir="$(mktemp -d)"
mkdir -p "$workdir/packages" "$workdir/release"
publish_worktree=
cargo_root="$repo_root"
if [[ "$tag_commit" != "$head_commit" ]]; then
  printf 'publishing tag %s (%s); HEAD is %s — cargo from tagged worktree\n' \
    "$version" "${tag_commit:0:12}" "${head_commit:0:12}"
  publish_worktree="$workdir/source"
  git worktree add --detach "$publish_worktree" "$tag_commit" \
    || die "cannot create worktree for tag $version"
  [[ -f "$publish_worktree/Cargo.toml" ]] \
    || die "worktree missing Cargo.toml: $publish_worktree"
  cargo_root="$publish_worktree"
else
  printf 'publishing tag %s (matches HEAD)\n' "$version"
fi

package_version="$($NODE -p "require('$cargo_root/packages/landstrip/package.json').version")"
[[ "$version" == "$package_version" ]] \
  || die "tag $version package.json version is $package_version"

cargo_version="$(
  sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' \
    "$cargo_root/Cargo.toml"
)"
cargo_version="${cargo_version%%$'\n'*}"
[[ "$version" == "$cargo_version" ]] \
  || die "tag $version Cargo.toml version is $cargo_version"

printf '%s\n' "assembling platform packages from local npm/*/bin binaries"
npm_package_dirs=()
missing=()
for platform in "${platforms[@]}"; do
  binary="$(platform_binary "$platform")"
  source_bin="npm/$platform/bin/$binary"
  digest_file="artifacts/${platform}.bin.sha256"
  if [[ ! -f "$source_bin" || ! -f "$digest_file" ]]; then
    missing+=("$platform binary or checksum")
    continue
  fi

  [[ "$(sha256_digest "$source_bin")" == "$(<"$digest_file")" ]] \
    || die "platform binary mismatch for $platform; rerun make package"

  package_dir="$workdir/packages/$platform"
  cp -a "npm/$platform" "$package_dir"
  mkdir -p "$package_dir/bin"
  cp "$source_bin" "$package_dir/bin/$binary"
  chmod 755 "$package_dir/bin/$binary" 2>/dev/null || true
  asset_platform="$platform"
  [[ "$platform" == linux-* ]] && asset_platform="$platform-musl"
  asset_path="$workdir/release/landstrip-$version-$asset_platform.tar.gz"
  tar -C "$package_dir/bin" -czf "$asset_path" "$binary"
  write_sha256_sidecar "$asset_path"
  npm_package_dirs+=("$package_dir")
done

if ((${#missing[@]} > 0)); then
  printf 'missing platform release inputs:\n' >&2
  printf '  %s\n' "${missing[@]}" >&2
  die "run 'PACKAGE_STRICT=1 make package' before publish"
fi

npm_package_dirs+=("$repo_root/packages/landstrip")
for extension_dir in "${extension_dirs[@]}"; do
  npm_package_dirs+=("$repo_root/$extension_dir")
done

printf '%s\n' "validating npm packages"
for package_dir in "${npm_package_dirs[@]}"; do
  preflight_npm_package "$package_dir"
done

publish_cargo_package "$cargo_root"
for package_dir in "${npm_package_dirs[@]}"; do
  publish_npm_package "$package_dir"
done

package_names=("$($NODE -p 'require("./packages/landstrip/package.json").name')")
while IFS= read -r package_name; do
  package_names+=("$package_name")
done < <($NODE -p 'Object.keys(require("./packages/landstrip/package.json").optionalDependencies).join("\n")')
for package_name in "${package_names[@]}"; do
  wait_for_npm_package "$package_name"
done

publish_github_release

NPM="$NPM" "$NODE" scripts/update-npm-integrity.mjs "$version" "${extension_dirs[@]}"
git add -- "${lock_files[@]}"
if ! git diff --cached --quiet; then
  git commit -s -m "chore: Update package-lock.json files"
fi

printf '%s\n' "published landstrip $version"
printf '%s\n' "push the integrity commit"
