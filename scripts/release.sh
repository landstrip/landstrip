#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

die() {
	printf '%s\n' "$1" >&2
	exit 1
}

ver_gt() {
	if (( $1 > $4 )); then return 0
	elif (( $1 == $4 && $2 > $5 )); then return 0
	elif (( $1 == $4 && $2 == $5 && $3 > $6 )); then return 0
	else return 1
	fi
}

version_parts() {
	[[ "$1" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] \
		|| die "invalid version: $1"
	VERSION_A="${BASH_REMATCH[1]}"
	VERSION_B="${BASH_REMATCH[2]}"
	VERSION_C="${BASH_REMATCH[3]}"
}

release_files=(
	Cargo.toml
	Cargo.lock
	package.json
	npm/darwin-arm64/package.json
	npm/darwin-x64/package.json
	npm/linux-x64/package.json
	npm/win32-x64/package.json
	man/man1/landstrip.1
	packages/pi-landstrip/package.json
	packages/pi-landstrip/package-lock.json
	packages/opencode-landstrip/package.json
	packages/opencode-landstrip/package-lock.json
)
committed=0

cleanup() {
	local status=$?

	if (( status != 0 && !committed )); then
		git restore --staged -- "${release_files[@]}" 2>/dev/null || true
		git restore -- "${release_files[@]}" 2>/dev/null || true
	fi
	return "$status"
}
trap cleanup EXIT

next_ver="${1:-}"
[[ -n "$next_ver" ]] || die "usage: scripts/release.sh <next-version>"
version_parts "$next_ver"
next_a="$VERSION_A"
next_b="$VERSION_B"
next_c="$VERSION_C"

branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)" \
	|| die "HEAD is detached; check out a branch before releasing"
[[ -z "$(git status --porcelain)" ]] \
	|| die "working directory is not clean"
[[ -z "$(git tag -l "$next_ver")" ]] \
	|| die "tag $next_ver already exists"

core_ver="$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' Cargo.toml | head -1)"
[[ -n "$core_ver" ]] || die "cannot find version in Cargo.toml"
version_parts "$core_ver"
ver_gt "$next_a" "$next_b" "$next_c" "$VERSION_A" "$VERSION_B" "$VERSION_C" \
	|| die "$next_ver is not greater than Landstrip $core_ver"

for package_dir in packages/pi-landstrip packages/opencode-landstrip; do
	extension_ver="$(node -p "require('./$package_dir/package.json').version")" \
		|| die "cannot find version in $package_dir/package.json"
	version_parts "$extension_ver"
	ver_gt "$next_a" "$next_b" "$next_c" "$VERSION_A" "$VERSION_B" "$VERSION_C" \
		|| die "$next_ver is not greater than $package_dir $extension_ver"
done

core_log="$(git log --first-parent --format='- %s (%an)' --no-merges "$core_ver"..HEAD -- . ':(exclude)packages/pi-landstrip' ':(exclude)packages/opencode-landstrip')"
pi_log="$(git log --format='- %s (%an)' --no-merges "$core_ver"..HEAD -- packages/pi-landstrip)"
opencode_log="$(git log --format='- %s (%an)' --no-merges "$core_ver"..HEAD -- packages/opencode-landstrip)"
[[ -n "$core_log" ]] || core_log='- No source changes.'
[[ -n "$pi_log" ]] || pi_log='- Merged pi-landstrip into this repository.'
[[ -n "$opencode_log" ]] || opencode_log='- Merged opencode-landstrip into this repository.'

for package_dir in packages/pi-landstrip packages/opencode-landstrip; do
	npm install --prefix "$package_dir" --package-lock=false --ignore-scripts
	npm --prefix "$package_dir" run ci:fmt
	npm --prefix "$package_dir" run ci:lint
	npm --prefix "$package_dir" run ci:check
	npm --prefix "$package_dir" run ci:test
done

node - "$next_ver" <<'NODE'
const fs = require('node:fs');

const [nextVersion] = process.argv.slice(2);
const corePackagePaths = [
  'package.json',
  'npm/darwin-arm64/package.json',
  'npm/darwin-x64/package.json',
  'npm/linux-x64/package.json',
  'npm/win32-x64/package.json',
];
const corePackages = corePackagePaths.map((packagePath) => [
  packagePath,
  JSON.parse(fs.readFileSync(packagePath, 'utf8')),
]);
const root = corePackages[0][1];

root.version = nextVersion;
for (const [, data] of corePackages.slice(1)) {
  data.version = nextVersion;
  root.optionalDependencies[data.name] = nextVersion;
}
for (const [packagePath, data] of corePackages) {
  fs.writeFileSync(packagePath, `${JSON.stringify(data, null, 2)}\n`);
}

for (const packageDir of ['packages/pi-landstrip', 'packages/opencode-landstrip']) {
  const packagePath = `${packageDir}/package.json`;
  const data = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  data.version = nextVersion;
  data.dependencies['@landstrip/landstrip'] = `^${nextVersion}`;
  fs.writeFileSync(packagePath, `${JSON.stringify(data, null, 2)}\n`);

  const lockPath = `${packageDir}/package-lock.json`;
  const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  lock.version = nextVersion;
  lock.packages[''].version = nextVersion;
  lock.packages[''].dependencies['@landstrip/landstrip'] = `^${nextVersion}`;
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
}
NODE

sed -E -i.bak "s/^([[:space:]]*version[[:space:]]*=[[:space:]]*)\"${core_ver//./\\.}\"/\1\"$next_ver\"/" Cargo.toml
rm -f Cargo.toml.bak
grep -q "^version = \"$next_ver\"" Cargo.toml \
	|| die "failed to update version in Cargo.toml"
cargo metadata --format-version 1 >/dev/null
grep -A2 '^name = "landstrip"' Cargo.lock | grep -q "^version = \"$next_ver\"" \
	|| die "failed to update version in Cargo.lock"

date="$(LC_TIME=C date '+%B %e, %Y' | sed 's/  / /')"
sed -E -i.bak "s/^\\.Dd .*/.Dd $date/" man/man1/landstrip.1
rm -f man/man1/landstrip.1.bak
grep -Fxq ".Dd $date" man/man1/landstrip.1 \
	|| die "failed to update man/man1/landstrip.1"

cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all

git add -- "${release_files[@]}"
git commit -s -m "Bump the version to $next_ver"
committed=1

sob="Signed-off-by: $(git config user.name) <$(git config user.email)>"
cat >".git/landstrip-$next_ver-tag-message.txt" <<EOF
Landstrip $next_ver

landstrip:
$core_log

pi-landstrip:
$pi_log

opencode-landstrip:
$opencode_log

$sob
EOF

git tag -s "$next_ver" -F ".git/landstrip-$next_ver-tag-message.txt"

echo "tagged $next_ver"
