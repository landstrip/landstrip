# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026

sha256_digest() {
  local output

  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum "$1")"
  else
    output="$(shasum -a 256 "$1")"
  fi
  printf '%s\n' "${output%% *}"
}

write_sha256_sidecar() {
  local path="$1"
  local name

  name="$(basename -- "$path")"
  printf '%s  %s\n' "$(sha256_digest "$path")" "$name" >"$path.sha256"
}

write_binary_receipt() {
  local receipt="$1" binary="$2" version="$3" commit="$4"
  local temporary="$receipt.tmp"

  printf '%s %s %s\n' "$(sha256_digest "$binary")" "$version" "$commit" >"$temporary"
  mv "$temporary" "$receipt"
}

verify_binary_receipt() {
  local receipt="$1" binary="$2" expected_version="$3" expected_commit="$4"
  local digest version commit extra

  read -r digest version commit extra <"$receipt" || return 1
  [[ -z "$extra" && "$digest" =~ ^[0-9a-f]{64}$ \
    && "$version" == "$expected_version" \
    && "$commit" == "$expected_commit" \
    && "$(sha256_digest "$binary")" == "$digest" ]]
}
