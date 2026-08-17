# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

package_build_driver() {
  local host_triple="$1"
  local target_triple="$2"

  if [[ "$target_triple" == "$host_triple" ]]; then
    printf 'cargo\n'
  else
    printf 'zigbuild\n'
  fi
}
