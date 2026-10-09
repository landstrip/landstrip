#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026
#
# Stage locally, wait for trusted npm publishing, and finalize the release.
# Run `make package` first, then push the signed tag yourself.

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
      "$repo_root/packages/landstrip-api" "$host_pkg"
  else
    $NPM install --prefix "$package_dir" --package-lock=false --ignore-scripts --no-save \
      "$repo_root/packages/landstrip-api"
  fi
}

pack_npm_package() {
  local package_dir="$1"
  local package_name package_version archive

  package_name="$($NODE -p "require('$package_dir/package.json').name")"
  package_version="$($NODE -p "require('$package_dir/package.json').version")"
  [[ "$($NODE -p "require('$package_dir/package.json').private === true")" != true ]] \
    || die "$package_name is marked private"
  [[ "$package_version" == "$version" ]] \
    || die "$package_name version $package_version does not match $version"
  prepare_npm_package_build "$package_dir"
  archive="$(cd "$package_dir" && $NPM pack --pack-destination "$workdir/release" --silent)"
  archive="${archive##*$'\n'}"
  [[ "$archive" == *.tgz && "$archive" != */* && -f "$workdir/release/$archive" ]] \
    || die "npm pack did not create one tarball for $package_name"
  write_sha256_sidecar "$workdir/release/$archive"
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
    if $GH release view "$version" --json isDraft,tagName,assets \
      >"$workdir/gh-release.json" 2>"$error_file"; then
      return 0
    fi
    if grep -Eq '^release not found$|HTTP 404' "$error_file"; then
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

stage_github_release() {
  local asset name downloaded
  local missing=()
  local assets=("$workdir"/release/*.tar.gz "$workdir"/release/*.sha256 "$workdir"/release/*.tgz)

  if github_release_exists; then
    $NODE -e '
      const release = require(process.argv[1]);
      if (!release.isDraft || release.tagName !== process.argv[2]) process.exit(1);
    ' "$workdir/gh-release.json" "$version" \
      || die "release $version exists but is not a draft for this tag"
    for asset in "${assets[@]}"; do
      name="${asset##*/}"
      if $NODE -e '
        const release = require(process.argv[1]);
        process.exit(release.assets.some(asset => asset.name === process.argv[2]) ? 0 : 1);
      ' "$workdir/gh-release.json" "$name"; then
        mkdir -p "$workdir/existing"
        github_retry "$GH" release download "$version" --pattern "$name" --dir "$workdir/existing"
        downloaded="$workdir/existing/$name"
        if [[ ! -f "$downloaded" ]] || ! cmp -s "$asset" "$downloaded"; then
          die "existing release asset differs: $name"
        fi
      else
        missing+=("$asset")
      fi
    done
    if ((${#missing[@]} > 0)); then
      github_retry "$GH" release upload "$version" "${missing[@]}"
    fi
    return
  fi

  github_retry "$GH" release create "$version" "${assets[@]}" \
    --draft --notes-from-tag --title "landstrip $version" --verify-tag
}

wait_for_npm_workflow() {
  local run_info run_id run_status previous_run attempt pipeline_url conclusion
  local run_query="[.[] | select(.displayTitle == \"Publish npm $version\")][0] | if . == null then \"\" else \"\(.databaseId) \(.status)\" end"

  run_info="$(github_retry "$GH" run list --workflow publish-npm.yml --branch main \
    --event workflow_dispatch --limit 100 --json databaseId,displayTitle,status --jq "$run_query")"
  read -r run_id run_status <<<"$run_info"
  if [[ -z "$run_id" || "$run_status" == completed ]]; then
    previous_run="${run_id:-0}"
    # Do not retry dispatch automatically: a lost response may still have started a run.
    "$GH" workflow run publish-npm.yml --ref main -f "version=$version" \
      || die "cannot dispatch npm publishing; retry: make publish VERSION=$version"
    run_id=
    for attempt in {1..60}; do
      run_id="$(github_retry "$GH" run list --workflow publish-npm.yml --branch main \
        --event workflow_dispatch --limit 100 --json databaseId,displayTitle \
        --jq "[.[] | select(.displayTitle == \"Publish npm $version\" and .databaseId > $previous_run)][0].databaseId // empty")"
      [[ -z "$run_id" ]] || break
      ((attempt < 60)) || die "cannot find dispatched npm publish pipeline; retry: make publish VERSION=$version"
      sleep 2
    done
  fi
  pipeline_url="$(github_retry "$GH" run view "$run_id" --json url --jq .url)"
  [[ "$pipeline_url" == https://* ]] \
    || die "cannot determine npm publish pipeline URL; retry: make publish VERSION=$version"
  printf 'waiting for npm publish pipeline: %s\n' "$pipeline_url"
  while :; do
    run_info="$(github_retry "$GH" run view "$run_id" --json status,conclusion \
      --jq '"\(.status) \(.conclusion // "")"')"
    read -r run_status conclusion <<<"$run_info"
    case "$run_status" in
      completed)
        [[ "$conclusion" == success ]] && break
        die "npm publish pipeline $run_id ended with status ${conclusion:-unknown}; retry: make publish VERSION=$version"
        ;;
      queued|waiting|requested|pending|in_progress) sleep 10 ;;
      *) die "npm publish pipeline $run_id ended with status $run_status; retry: make publish VERSION=$version" ;;
    esac
  done
}

complete_release() {
  local status=0 is_draft

  is_draft="$($NODE -p 'require(process.argv[1]).isDraft' "$workdir/gh-release.json")"
  NPM="$NPM" NODE="$NODE" scripts/publish-npm-provenance.sh verify "$version" "$workdir/release"
  NPM="$NPM" NODE="$NODE" scripts/publish-npm-provenance.sh check "$version" "$workdir/release" || status=$?
  if ((status != 0)); then
    ((status == 1)) || exit "$status"
    [[ "$is_draft" == true ]] || die "public release $version has unpublished npm packages"
    wait_for_npm_workflow
    NPM="$NPM" NODE="$NODE" scripts/publish-npm-provenance.sh check "$version" "$workdir/release"
  fi

  publish_cargo_package "$repo_root/packages/landstrip"
  NPM="$NPM" "$NODE" scripts/update-npm-integrity.mjs "$version" "${extension_dirs[@]}"
  git add -- "${lock_files[@]}"
  if ! git diff --cached --quiet; then
    git commit -s -m "release: update npm package integrity metadata"
  fi
  if [[ "$is_draft" == true ]]; then
    github_retry "$GH" release edit "$version" --draft=false
  fi
  printf 'published landstrip %s\npush the integrity commit if one was created\n' "$version"
}

platform_binary() {
  local platform="$1"
  if [[ "$platform" == win32-* ]]; then
    printf 'landstrip.exe\n'
  else
    printf 'landstrip\n'
  fi
}

for command in "$CARGO" "$GH" "$NODE" "$NPM" tar; do
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

# Provenance refers to the tagged source: never package a newer tip tree.
tip_version="$($NODE -p 'require("./packages/landstrip-api/package.json").version')"
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
    packages/landstrip/Cargo.toml packages/landstrip/Cargo.lock \
    rust-toolchain.toml packages/landstrip/src; then
  die "Rust package sources changed since tag $version"
fi

workdir="$(mktemp -d)"
mkdir -p "$workdir/packages" "$workdir/release"
if github_release_exists; then
  printf 'verifying staged landstrip %s\n' "$version"
  github_retry "$GH" release download "$version" --pattern '*.tgz' \
    --pattern '*.tgz.sha256' --dir "$workdir/release"
  complete_release
  exit 0
fi

[[ "$tag_commit" == "$head_commit" ]] \
  || die "checkout the exact tag commit before packing a new release"

remote_commit="$(git ls-remote origin "refs/tags/$version^{}" | awk '{print $1}')"
[[ -n "$remote_commit" && "$remote_commit" == "$tag_commit" ]] \
  || die "push the signed tag $version to origin before staging the release"
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
[[ "$remote_main" == "$tag_commit" ]] \
  || die "push the release commit to origin/main before staging the release"
cargo_root="$repo_root"
printf 'staging tag %s\n' "$version"

package_version="$($NODE -p "require('$cargo_root/packages/landstrip-api/package.json').version")"
[[ "$version" == "$package_version" ]] \
  || die "tag $version package.json version is $package_version"

cargo_version="$(
  sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' \
    "$cargo_root/packages/landstrip/Cargo.toml"
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

  verify_binary_receipt "$digest_file" "$source_bin" "$version" "$head_commit" \
    || die "stale or mismatched platform binary for $platform; rerun make package"

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

npm_package_dirs+=("$repo_root/packages/landstrip-api")
for extension_dir in "${extension_dirs[@]}"; do
  npm_package_dirs+=("$repo_root/$extension_dir")
done

printf '%s\n' "packing npm packages locally"
for package_dir in "${npm_package_dirs[@]}"; do
  pack_npm_package "$package_dir"
done
NPM="$NPM" NODE="$NODE" scripts/publish-npm-provenance.sh preflight "$version" "$workdir/release"

publish_cargo_package "$cargo_root/packages/landstrip"
stage_github_release
github_release_exists || die "cannot find newly staged GitHub release $version"
complete_release
