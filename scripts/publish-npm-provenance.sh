#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

mode="${1:-}"
version="${2:-}"
assets="${3:-}"
[[ "$mode" == verify || "$mode" == preflight || "$mode" == publish || "$mode" == check ]] \
  || { printf 'usage: %s verify|preflight|publish|check VERSION ASSET_DIR\n' "$0" >&2; exit 1; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && -d "$assets" ]] \
  || { printf 'invalid version or asset directory\n' >&2; exit 1; }

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
# shellcheck source=sha256.sh
source scripts/sha256.sh
NODE="${NODE:-node}"
NPM="${NPM:-npm}"

package_dirs=(npm/* packages/landstrip-api)
while IFS= read -r extension_dir; do
  package_dirs+=("$extension_dir")
done < <(scripts/test-extensions.sh --list)

archives=()
for package_dir in "${package_dirs[@]}"; do
  [[ -f "$package_dir/package.json" ]] || { printf 'missing %s/package.json\n' "$package_dir" >&2; exit 1; }
  name="$($NODE -p "require('./$package_dir/package.json').name")"
  [[ "$($NODE -p "require('./$package_dir/package.json').version")" == "$version" ]] \
    || { printf 'source package version mismatch: %s\n' "$name" >&2; exit 1; }
  file="${name#@}"
  file="${file//\//-}-$version.tgz"
  path="$assets/$file"
  [[ -f "$path" && -f "$path.sha256" ]] \
    || { printf 'missing npm tarball or checksum: %s\n' "$file" >&2; exit 1; }
  expected="$(sha256_digest "$path")  $file"
  [[ "$(<"$path.sha256")" == "$expected" ]] \
    || { printf 'checksum mismatch: %s\n' "$file" >&2; exit 1; }
  tar -xOf "$path" package/package.json | "$NODE" -e '
    let data = "";
    process.stdin.on("data", chunk => data += chunk);
    process.stdin.on("end", () => {
      const pkg = JSON.parse(data);
      if (pkg.name !== process.argv[1] || pkg.version !== process.argv[2] ||
          pkg.repository?.url !== "git+https://github.com/landstrip/landstrip.git") {
        console.error("tarball package metadata does not match tag:", process.argv[3]);
        process.exitCode = 1;
      }
    });
  ' "$name" "$version" "$file"
  archives+=("$path")
done

# Do not silently ignore extra or missing release inputs.
count=0
sidecar_count=0
for path in "$assets"/*.tgz; do
  [[ -f "$path" ]] || continue
  ((count += 1))
done
for path in "$assets"/*.tgz.sha256; do
  [[ -f "$path" ]] || continue
  ((sidecar_count += 1))
done
[[ "$count" -eq "${#archives[@]}" && "$sidecar_count" -eq "$count" ]] \
  || { printf 'unexpected npm tarballs or checksums in %s\n' "$assets" >&2; exit 1; }
[[ "$mode" != verify ]] || exit 0

check_published() {
  local name="$1" file="$2" output error_file="$assets/npm-view-error"
  local digest
  digest="$($NODE -e 'const fs=require("fs"),crypto=require("crypto");process.stdout.write("sha512-"+crypto.createHash("sha512").update(fs.readFileSync(process.argv[1])).digest("base64"))' "$file")"
  if ! output="$($NPM view "$name@$version" dist --json --prefer-online --fetch-retries=0 2>"$error_file")"; then
    if grep -q E404 "$error_file"; then return 1; fi
    printf 'npm registry query failed for %s@%s\n' "$name" "$version" >&2
    command cat "$error_file" >&2
    return 2
  fi
  printf '%s' "$output" | "$NODE" -e '
    let data="";
    process.stdin.on("data", part => data += part);
    process.stdin.on("end", () => {
      let dist;
      try {
        dist = JSON.parse(data);
      } catch (error) {
        console.error("invalid npm registry metadata:", process.argv[2], error.message);
        process.exitCode = 2;
        return;
      }
      if (dist?.integrity !== process.argv[1] ||
          dist?.attestations?.provenance?.predicateType !== "https://slsa.dev/provenance/v1") {
        console.error("published npm package integrity or provenance differs:", process.argv[2]);
        process.exitCode = 2;
      }
    });
  ' "$digest" "$name@$version"
}

result=0
for path in "${archives[@]}"; do
  name="$(tar -xOf "$path" package/package.json | "$NODE" -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).name')"
  status=0
  check_published "$name" "$path" || status=$?
  if [[ "$mode" == publish ]]; then
    if ((status == 0)); then
      printf '%s@%s is already published\n' "$name" "$version"
      continue
    fi
    ((status == 1)) || exit "$status"
    publish_error="$assets/npm-publish-error"
    status=0
    "$NPM" publish "$path" --access public --provenance 2>"$publish_error" || status=$?
    command cat "$publish_error" >&2
    if ((status != 0)); then
      if ! grep -Fq 'npm error code E409' "$publish_error" ||
         ! grep -Fq "Cannot publish over previously staged version \"$version\"." "$publish_error"; then
        exit "$status"
      fi
      printf 'already staged; waiting for registry verification: %s@%s\n' "$name" "$version"
    fi
    for attempt in {1..60}; do
      status=0
      check_published "$name" "$path" || status=$?
      ((status == 1)) || break
      ((attempt < 60)) || { printf 'npm package not available: %s@%s\n' "$name" "$version" >&2; exit 1; }
      printf 'waiting for registry visibility: %s@%s (attempt %s/60)\n' "$name" "$version" "$attempt"
      sleep 10
    done
    ((status == 0)) || exit "$status"
  elif [[ "$mode" == preflight ]]; then
    ((status == 0 || status == 1)) || exit "$status"
  else
    ((status == 0 || status == 1)) || exit "$status"
    if ((status == 0)); then
      printf '%s@%s is already published\n' "$name" "$version"
    else
      result=1
    fi
  fi
done
exit "$result"
