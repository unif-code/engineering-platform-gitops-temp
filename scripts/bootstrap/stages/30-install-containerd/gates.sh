#!/usr/bin/env bash

# 30-install-containerd 的判定族：只读取状态并返回 0/1，不打印证据、不调用 complete、不退出。
# run.sh 负责流程与终止，gates.sh 负责"事实是什么"——两者分开后，判定可以被单独
# 阅读和测试，而不必跟着流程走一遍。
# 本文件由 run.sh 以 ${script_dir}/gates.sh 引入，与 run.sh 同属一个 stage 目录，
# 因此被 bootstrap-all.sh 的 stage 目录逐条目门禁覆盖（属主、权限、非符号链接）。
# 判定所需的常量与路径由 run.sh 声明；缺失时 set -u 直接报未绑定变量。
# SC2154 只对小写变量告警（全大写被当成环境变量豁免），故显式关闭。
# shellcheck disable=SC2154

stream_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

archive_member_sha256() {
  local archive=$1
  local member=$2
  tar -xOzf "$archive" "$member" 2>/dev/null | stream_sha256
}

private_staging_directory() {
  local directory=$1
  [[ -d "$directory" && ! -L "$directory" && "$(path_mode "$directory")" == 700 ]] && owned_by_expected "$directory"
}

staged_file_state() {
  local path=$1
  local expected_digest=$2
  local actual_digest
  if [[ -L "$path" || ! -f "$path" || "$(path_mode "$path")" != 600 ]] || ! owned_by_expected "$path"; then
    printf 'UNSAFE\n'
    return 0
  fi
  actual_digest=$(sha256_file "$path") || return "$?"
  if [[ "$actual_digest" == "$expected_digest" ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'DRIFT\n'
  fi
}

target_file_state() {
  local path=$1
  local expected_digest=$2
  local expected_mode=$3
  local actual_digest
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    printf 'MISSING\n'
    return 0
  fi
  if [[ -L "$path" || ! -f "$path" || "$(path_mode "$path")" != "$expected_mode" ]] || ! owned_by_expected "$path"; then
    printf 'UNKNOWN\n'
    return 0
  fi
  actual_digest=$(sha256_file "$path") || {
    printf 'UNKNOWN\n'
    return 0
  }
  if [[ "$actual_digest" == "$expected_digest" ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

directory_state() {
  local directory=$1
  if [[ ! -e "$directory" && ! -L "$directory" ]]; then
    printf 'MISSING\n'
  elif [[ -d "$directory" && ! -L "$directory" && "$(path_mode "$directory")" == 755 ]] && owned_by_expected "$directory"; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

data_root_safe() {
  local data_root=$1
  local entries
  if [[ ! -e "$data_root" && ! -L "$data_root" ]]; then
    return 0
  fi
  [[ -d "$data_root" && ! -L "$data_root" && "$(path_mode "$data_root")" == 700 ]] || return 2
  owned_by_expected "$data_root" || return 2
  shopt -s dotglob nullglob
  entries=("$data_root"/*)
  shopt -u dotglob nullglob
  (( ${#entries[@]} == 0 )) && return 0
  return 1
}

runtime_directory_state() {
  local run_dir=$1
  if [[ ! -e "$run_dir" && ! -L "$run_dir" ]]; then
    printf 'MISSING\n'
  elif [[ -d "$run_dir" && ! -L "$run_dir" && "$(path_mode "$run_dir")" == 711 ]] && owned_by_expected "$run_dir"; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

private_extract_directory() {
  local directory=$1
  local parent=$2
  [[ "${directory%/*}" == "$parent" ]] || return 1
  [[ "$(directory_state "$parent")" == COMPLIANT ]] || return 1
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  [[ "$(path_mode "$directory")" == 700 ]] && owned_by_expected "$directory"
}

atomic_publish() {
  local source=$1
  local target=$2
  local mode=$3
  local temporary
  local parent=${target%/*}
  [[ "$(directory_state "$parent")" == COMPLIANT ]] || return "$EXIT_UNKNOWN_STATE"
  temporary=$(mktemp "${target}.tmp.XXXXXX") || return "$EXIT_APPLY_FAILED"
  if [[ "$(directory_state "$parent")" != COMPLIANT ]] || ! owned_by_expected "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  [[ "$(directory_state "$parent")" == COMPLIANT ]] || { rm -f -- "$temporary"; return "$EXIT_UNKNOWN_STATE"; }
  if ! install -m "$mode" "$source" "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if [[ ! -f "$temporary" || -L "$temporary" || "$(path_mode "$temporary")" != "$mode" ]] || ! owned_by_expected "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  if ! sync "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if [[ "$(directory_state "$parent")" != COMPLIANT ]]; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  if ! mv -n "$temporary" "$target"; then
    if [[ -e "$target" || -L "$target" ]]; then
      rm -f -- "$temporary"
      return "$EXIT_UNKNOWN_STATE"
    fi
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
}

unit_contract_state() {
  local unit_target=$1
  local properties line
  local load_state='' fragment_path='' drop_in_paths=''
  local load_seen=0 fragment_seen=0 drop_in_seen=0
  properties=$(systemctl show --all \
    --property=LoadState \
    --property=FragmentPath \
    --property=DropInPaths \
    containerd.service 2>/dev/null) || {
      printf 'UNKNOWN\n'
      return 0
    }
  while IFS= read -r line; do
    case "$line" in
      LoadState=*)
        (( load_seen == 0 )) || { printf 'UNKNOWN\n'; return 0; }
        load_state=${line#LoadState=}
        load_seen=1
        ;;
      FragmentPath=*)
        (( fragment_seen == 0 )) || { printf 'UNKNOWN\n'; return 0; }
        fragment_path=${line#FragmentPath=}
        fragment_seen=1
        ;;
      DropInPaths=*)
        (( drop_in_seen == 0 )) || { printf 'UNKNOWN\n'; return 0; }
        drop_in_paths=${line#DropInPaths=}
        drop_in_seen=1
        ;;
      *) printf 'UNKNOWN\n'; return 0 ;;
    esac
  done <<<"$properties"
  if (( load_seen != 1 || fragment_seen != 1 || drop_in_seen != 1 )); then
    printf 'UNKNOWN\n'
  elif [[ "$load_state" == not-found && -z "$fragment_path" && -z "$drop_in_paths" ]]; then
    printf 'MISSING\n'
  elif [[ "$load_state" == loaded && "$fragment_path" == "$unit_target" && -z "$drop_in_paths" ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}
