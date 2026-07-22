#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

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

publish_npm_package() {
	local package_dir="$1"
	local package_name

	package_name="$($NODE -p "require('$package_dir/package.json').name")"
	if npm_package_exists "$package_name"; then
		printf '%s\n' "$package_name@$version is already published"
		return
	fi
	$NPM publish "$package_dir" --access public
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
run_id="$($GH run list \
	--workflow release.yml \
	--commit "$tag_commit" \
	--status success \
	--limit 1 \
	--json databaseId \
	--jq '.[0].databaseId')"
[[ -n "$run_id" ]] || die "no successful release workflow found for tag $version"

artifact_args=()
for platform in "${platforms[@]}"; do
	artifact_args+=(--name "$platform")
done
$GH run download "$run_id" --dir "$workdir/artifacts" "${artifact_args[@]}"

mkdir -p "$workdir/packages" "$workdir/release"
for platform in "${platforms[@]}"; do
	artifact="$workdir/artifacts/$platform/$platform.tar.gz"
	package_dir="$workdir/packages/$platform"
	[[ -f "$artifact" ]] || die "workflow artifact is missing: $platform.tar.gz"
	cp -a "npm/$platform" "$package_dir"
	mkdir -p "$package_dir/bin"
	tar -xzf "$artifact" -C "$package_dir/bin"
	binary=landstrip
	[[ "$platform" == win32-* ]] && binary=landstrip.exe
	[[ -f "$package_dir/bin/$binary" ]] \
		|| die "workflow artifact $platform.tar.gz does not contain $binary"
	for license_file in "${license_files[@]}"; do
		[[ -f "$license_file" ]] || die "missing $license_file"
		cp "$license_file" "$package_dir/$license_file"
	done
	asset_platform="$platform"
	[[ "$platform" == linux-* ]] && asset_platform="$platform-musl"
	cp "$artifact" "$workdir/release/landstrip-$version-$asset_platform.tar.gz"
done

publish_cargo_package
for platform in "${platforms[@]}"; do
	publish_npm_package "$workdir/packages/$platform"
done
publish_npm_package "$repo_root"

package_names=("$($NODE -p 'require("./package.json").name')")
while IFS= read -r package_name; do
	package_names+=("$package_name")
done < <($NODE -p 'Object.keys(require("./package.json").optionalDependencies).join("\n")')
for package_name in "${package_names[@]}"; do
	wait_for_npm_package "$package_name"
done

for extension_dir in "${extension_dirs[@]}"; do
	publish_npm_package "$repo_root/$extension_dir"
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
