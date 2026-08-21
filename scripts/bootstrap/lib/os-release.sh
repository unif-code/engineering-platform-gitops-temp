#!/usr/bin/env bash

ubuntu_os_release_path() {
  local os_release canonical_os_release os_release_link
  os_release=$(host_path /etc/os-release)
  canonical_os_release=$(host_path /usr/lib/os-release)
  if [[ -L "$os_release" ]]; then
    os_release_link=$(readlink -- "$os_release" 2>/dev/null) || return 1
    if [[ "$os_release_link" != ../usr/lib/os-release ||
          ! -f "$canonical_os_release" || -L "$canonical_os_release" ]]; then
      return 1
    fi
    os_release=$canonical_os_release
  elif [[ ! -f "$os_release" ]]; then
    return 1
  fi
  printf '%s\n' "$os_release"
}
