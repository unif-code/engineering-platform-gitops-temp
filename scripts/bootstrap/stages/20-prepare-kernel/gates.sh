#!/usr/bin/env bash

# 20-prepare-kernel 的判定族：只读取状态并返回 0/1，不打印证据、不调用 complete、不退出。
# run.sh 负责流程与终止，gates.sh 负责"事实是什么"——两者分开后，判定可以被单独
# 阅读和测试，而不必跟着流程走一遍。
# 本文件由 run.sh 以 ${script_dir}/gates.sh 引入，与 run.sh 同属一个 stage 目录，
# 因此被 bootstrap-all.sh 的 stage 目录逐条目门禁覆盖（属主、权限、非符号链接）。
# 判定所需的常量与路径由 run.sh 声明；缺失时 set -u 直接报未绑定变量。
# SC2154 只对小写变量告警（全大写被当成环境变量豁免），故显式关闭。
# shellcheck disable=SC2154

require_managed_parent() {
  local parent=$1
  local mode

  [[ -d "$parent" && ! -L "$parent" ]] || return 1
  mode=$(path_mode "$parent") || return 1
  [[ "$mode" == 755 ]] && owned_by_expected "$parent"
}

content_file_state() {
  local target=$1
  local expected=$2
  local mode

  if [[ ! -e "$target" && ! -L "$target" ]]; then
    printf 'MISSING\n'
    return 0
  fi
  if [[ -L "$target" || ! -f "$target" ]]; then
    printf 'UNKNOWN\n'
    return 0
  fi
  mode=$(path_mode "$target") || {
    printf 'UNKNOWN\n'
    return 0
  }
  if [[ "$mode" == 644 ]] && owned_by_expected "$target" && cmp -s <(printf '%s' "$expected") "$target"; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

runtime_state() {
  local overlay_path=$1
  local br_netfilter_path=$2
  local bridge_ipv4_path=$3
  local bridge_ipv6_path=$4
  local ip_forward_path=$5
  local path
  local value

  for path in "$overlay_path" "$br_netfilter_path"; do
    if [[ -e "$path" || -L "$path" ]]; then
      [[ -d "$path" && ! -L "$path" ]] || return 2
    else
      return 1
    fi
  done
  for path in "$bridge_ipv4_path" "$bridge_ipv6_path" "$ip_forward_path"; do
    if [[ -e "$path" || -L "$path" ]]; then
      [[ -f "$path" && ! -L "$path" ]] || return 2
    else
      return 1
    fi
    IFS= read -r value <"$path" || return 2
    [[ "$value" == 1 ]] || return 1
  done
  return 0
}
