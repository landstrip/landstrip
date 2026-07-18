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

extension_dirs=()
while IFS= read -r extension_dir; do
	extension_dirs+=("$extension_dir")
done < <(scripts/test-extensions.sh --list)
((${#extension_dirs[@]} > 0)) || die "no extension workspaces found"

release_files=(
	Cargo.toml
	Cargo.lock
	package.json
	npm/darwin-arm64/package.json
	npm/darwin-x64/package.json
	npm/linux-x64/package.json
	npm/linux-arm64/package.json
	npm/win32-x64/package.json
	npm/win32-arm64/package.json
	man/man1/landstrip.1
)
for package_dir in "${extension_dirs[@]}"; do
	release_files+=("$package_dir/package.json" "$package_dir/package-lock.json")
done
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

for package_dir in "${extension_dirs[@]}"; do
	extension_ver="$(node -p "require('./$package_dir/package.json').version")" \
		|| die "cannot find version in $package_dir/package.json"
	version_parts "$extension_ver"
	ver_gt "$next_a" "$next_b" "$next_c" "$VERSION_A" "$VERSION_B" "$VERSION_C" \
		|| die "$next_ver is not greater than $package_dir $extension_ver"
done

core_log_args=(.)
for package_dir in "${extension_dirs[@]}"; do
	core_log_args+=(":(exclude)$package_dir")
done
core_log="$(git log --first-parent --format='- %s (%an)' --no-merges "$core_ver"..HEAD -- "${core_log_args[@]}")"
[[ -n "$core_log" ]] || core_log='- No source changes.'

node - "$next_ver" <<'NODE'
const fs = require('node:fs');

const [nextVersion] = process.argv.slice(2);
const corePackagePaths = [
  'package.json',
  'npm/darwin-arm64/package.json',
  'npm/darwin-x64/package.json',
  'npm/linux-x64/package.json',
  'npm/linux-arm64/package.json',
  'npm/win32-x64/package.json',
  'npm/win32-arm64/package.json',
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

const landstripDependency = '@landstrip/landstrip';
const landstripRange = `^${nextVersion}`;
const platformDependencies = Object.keys(root.optionalDependencies);

function updateLockedPackage(lock, packageName) {
  const lockedPackage = lock.packages[`node_modules/${packageName}`];
  if (!lockedPackage) {
    throw new Error(`package-lock.json does not contain ${packageName}`);
  }

  const unscopedName = packageName.slice(packageName.indexOf('/') + 1);
  lockedPackage.version = nextVersion;
  lockedPackage.resolved =
    `https://registry.npmjs.org/${packageName}/-/${unscopedName}-${nextVersion}.tgz`;
  delete lockedPackage.integrity;
}

function updateExtensionLock(lock) {
  updateLockedPackage(lock, landstripDependency);
  for (const packageName of platformDependencies) updateLockedPackage(lock, packageName);

  const lockedLandstrip = lock.packages[`node_modules/${landstripDependency}`];
  for (const packageName of platformDependencies) {
    lockedLandstrip.optionalDependencies[packageName] = nextVersion;
  }
}

const { workspaces } = JSON.parse(fs.readFileSync('package.json', 'utf8'));
if (!Array.isArray(workspaces)) {
  throw new Error('package.json workspaces must be an array');
}
const packageDirs = workspaces.flatMap((workspace) => {
  if (!workspace.endsWith('/*')) {
    throw new Error(`unsupported workspace pattern: ${workspace}`);
  }
  const parent = workspace.slice(0, -2);
  return fs.readdirSync(parent, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && fs.existsSync(`${parent}/${entry.name}/package.json`))
    .map((entry) => `${parent}/${entry.name}`);
});

for (const packageDir of packageDirs) {
  const packagePath = `${packageDir}/package.json`;
  const data = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  data.version = nextVersion;
  data.dependencies[landstripDependency] = landstripRange;
  fs.writeFileSync(packagePath, `${JSON.stringify(data, null, 2)}\n`);

  const lockPath = `${packageDir}/package-lock.json`;
  const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  lock.version = nextVersion;
  lock.packages[''].version = nextVersion;
  lock.packages[''].dependencies[landstripDependency] = landstripRange;
  updateExtensionLock(lock);
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

npm run ci:extensions:local

cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all

git add -- "${release_files[@]}"
git commit -s -m "Bump the version to $next_ver"
committed=1

sob="Signed-off-by: $(git config user.name) <$(git config user.email)>"
tag_message=".git/landstrip-$next_ver-tag-message.txt"
cat >"$tag_message" <<EOF
Landstrip $next_ver

landstrip:
$core_log
EOF

for package_dir in "${extension_dirs[@]}"; do
	package_name="$(basename "$package_dir")"
	package_log="$(git log --format='- %s (%an)' --no-merges "$core_ver"..HEAD -- "$package_dir")"
	[[ -n "$package_log" ]] || package_log="- Merged $package_name into this repository."
	{
		printf '\n%s:\n%s\n' "$package_name" "$package_log"
	} >>"$tag_message"
done

printf '\n%s\n' "$sob" >>"$tag_message"

git tag -s "$next_ver" -F "$tag_message"

echo "tagged $next_ver"
