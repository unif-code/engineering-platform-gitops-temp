#!/usr/bin/env bash

readonly KUBELET_DEFAULT_CONTENT='KUBELET_EXTRA_ARGS='
readonly KUBELET_DEFAULT_SIZE=20
readonly KUBELET_DEFAULT_SHA256=2737f011e1fc6995aeeb6a2071e268e37b1437481bbdb205f5075939f40d7ae7
readonly KUBELET_DEFAULT_MD5=9ba5cd2e9a1e368fa51e13f1dd6a5ec1

kubelet_registered_default_md5() {
  local conffiles
  conffiles=$(dpkg-query -W -f='${Conffiles}' kubelet 2>/dev/null) || return 1
  awk '
    NF == 0 {next}
    $1 != "/etc/default/kubelet" {next}
    NF != 2 || $2 !~ /^[0-9a-f]{32}$/ || seen++ {exit 1}
    {digest=$2}
    END {
      if (seen != 1) exit 1
      print digest
    }
  ' <<<"$conffiles"
}

kubelet_default_conffile_is_pristine() {
  local default_file=$1 mode size content actual_sha256 ownership
  local registered_md5 actual_md5
  local ownership_sentinel=__KUBELET_DEFAULT_OWNERSHIP_END__
  if [[ ! -e "$default_file" && ! -L "$default_file" ]]; then
    return 0
  fi
  [[ -f "$default_file" && ! -L "$default_file" ]] || return 1
  mode=$(path_mode "$default_file") || return 1
  [[ "$mode" == 644 ]] || return 1
  owned_by_expected "$default_file" || return 1
  size=$(path_size "$default_file") || return 1
  [[ "$size" == 0 ]] && return 0
  [[ "$size" == "$KUBELET_DEFAULT_SIZE" ]] || return 1
  content=$(cat "$default_file") || return 1
  [[ "$content" == "$KUBELET_DEFAULT_CONTENT" ]] || return 1
  actual_sha256=$(sha256_file "$default_file") || return 1
  [[ "$actual_sha256" == "$KUBELET_DEFAULT_SHA256" ]] || return 1
  ownership=$(
    dpkg-query -S /etc/default/kubelet 2>/dev/null &&
      printf '%s' "$ownership_sentinel"
  ) || return 1
  [[ "$ownership" == $'kubelet: /etc/default/kubelet\n'"$ownership_sentinel" ]] || return 1
  registered_md5=$(kubelet_registered_default_md5) || return 1
  [[ "$registered_md5" == "$KUBELET_DEFAULT_MD5" ]] || return 1
  actual_md5=$(md5sum "$default_file" 2>/dev/null) || return 1
  [[ "$actual_md5" == "${registered_md5}  ${default_file}" ]] || return 1
  [[ -f "$default_file" && ! -L "$default_file" ]] || return 1
  mode=$(path_mode "$default_file") || return 1
  [[ "$mode" == 644 ]] || return 1
  owned_by_expected "$default_file" || return 1
  size=$(path_size "$default_file") || return 1
  [[ "$size" == "$KUBELET_DEFAULT_SIZE" ]] || return 1
  actual_sha256=$(sha256_file "$default_file") || return 1
  [[ "$actual_sha256" == "$KUBELET_DEFAULT_SHA256" ]]
}
