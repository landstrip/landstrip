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
