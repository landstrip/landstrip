#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

die() {
	printf '%s\n' "$1" >&2
	exit 1
}

ver_gt() {
	if   (( $1 > $4 )); then return 0
	elif (( $1 == $4 && $2 > $5 )); then return 0
	elif (( $1 == $4 && $2 == $5 && $3 > $6 )); then return 0
	else return 1
	fi
}

committed=0

cleanup() {
	local status=$?
	if (( status != 0 && !committed )); then
		git restore --staged -- package.json package-lock.json \
			2>/dev/null || true
		git restore -- package.json package-lock.json \
			2>/dev/null || true
	fi
	return "$status"
}
trap cleanup EXIT

next_ver="${1:-}"
[[ -n "$next_ver" ]] || die "usage: scripts/release.sh <next-version>"

[[ "$next_ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] \
	|| die "invalid version: $next_ver"
next_a="${BASH_REMATCH[1]}"
next_b="${BASH_REMATCH[2]}"
next_c="${BASH_REMATCH[3]}"

branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)" \
	|| die "HEAD is detached; check out a branch before releasing"

[[ -z "$(git status --porcelain)" ]] \
	|| die "working directory is not clean"

[[ -z "$(git tag -l "$next_ver")" ]] \
	|| die "tag $next_ver already exists"

cur_ver="$(node -p 'require("./package.json").version')" \
	|| die "cannot find version in package.json"
[[ -n "$cur_ver" ]] || die "cannot find version in package.json"

[[ "$cur_ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] \
	|| die "cannot parse version components from: $cur_ver"
cur_a="${BASH_REMATCH[1]}"
cur_b="${BASH_REMATCH[2]}"
cur_c="${BASH_REMATCH[3]}"

ver_gt "$next_a" "$next_b" "$next_c" "$cur_a" "$cur_b" "$cur_c" \
	|| die "$next_ver is not greater than current $cur_ver"

npm version "$next_ver" --no-git-tag-version

[[ "$(node -p 'require("./package.json").version')" == "$next_ver" ]] \
	|| die "failed to update version in package.json"
node -e '
const next = process.argv[1];
const lock = require("./package-lock.json");
if (lock.version !== next || lock.packages?.[""]?.version !== next) {
	process.exit(1);
}
' "$next_ver" || die "failed to update version in package-lock.json"

npm run ci:fmt
npm run ci:lint
npm run ci:check

git rev-parse -q --verify "refs/tags/$cur_ver" >/dev/null \
	|| die "current version tag $cur_ver does not exist"
range="${cur_ver}..HEAD"

log=""
while IFS=$'\x1f' read -r subj author; do
	log+="- $subj ($author)"$'\n'
done < <(git log --pretty=tformat:'%s%x1f%an' --no-merges "$range")
log="${log%$'\n'}"

git add package.json package-lock.json
git commit -s -m "Bump the version to $next_ver"
committed=1

sob="Signed-off-by: $(git config user.name) <$(git config user.email)>"
printf 'pi-landstrip %s\n\n%s\n\n%s\n' "$next_ver" "$log" "$sob" | git tag -s "$next_ver" -F -

echo "tagged $next_ver"
