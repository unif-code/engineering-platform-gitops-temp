#!/usr/bin/env bash

dpkg_package_verification_is_exact() {
  local package=$1 verification excludes exclude_count
  verification=$(dpkg --verify "$package" 2>/dev/null) || return 1
  [[ -n "$verification" ]] || return 0
  excludes=$(host_path /etc/dpkg/dpkg.cfg.d/excludes)
  [[ -f "$excludes" && ! -L "$excludes" && "$(path_mode "$excludes")" == 644 ]] || return 1
  owned_by_expected "$excludes" || return 1
  exclude_count=$(grep -Fxc 'path-exclude=/usr/share/doc/*' "$excludes") || return 1
  [[ "$exclude_count" == 1 ]] || return 1
  awk -v package="$package" '
    BEGIN {
      license="/usr/share/doc/" package "/LICENSE"
      readme="/usr/share/doc/" package "/README.md"
    }
    NF != 2 || $1 != "missing" {exit 1}
    $2 == license {if (seen_license++) exit 1; lines++; next}
    $2 == readme {if (seen_readme++) exit 1; lines++; next}
    {exit 1}
    END {
      if (lines != 2 || seen_license != 1 || seen_readme != 1) exit 1
    }
  ' <<<"$verification"
}
