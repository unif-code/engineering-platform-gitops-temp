#!/usr/bin/env bash

# 10-stage-artifacts 的判定族：只读取状态并返回 0/1，不打印证据、不调用 complete、不退出。
# run.sh 负责流程与终止，gates.sh 负责"事实是什么"——两者分开后，判定可以被单独
# 阅读和测试，而不必跟着流程走一遍。
# 本文件由 run.sh 以 ${script_dir}/gates.sh 引入，与 run.sh 同属一个 stage 目录，
# 因此被 bootstrap-all.sh 的 stage 目录逐条目门禁覆盖（属主、权限、非符号链接）。
# 判定所需的常量与路径由 run.sh 声明；缺失时 set -u 直接报未绑定变量。
# SC2154 只对小写变量告警（全大写被当成环境变量豁免），故显式关闭。
# shellcheck disable=SC2154

is_official_url() {
  local url=$1
  local host

  if [[ ! "$url" =~ ^https://([^/:?#]+)(/[^?#]*)?$ ]]; then
    return 1
  fi
  host=${BASH_REMATCH[1]}
  case "$host" in
    github.com|get.helm.sh|helm.cilium.io)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

artifact_basename() {
  local url=$1
  local path=${url#https://*/}
  local base=${path##*/}
  [[ -n "$base" && "$base" != . && "$base" != .. && "$base" != *$'\n'* ]] || return 1
  printf '%s\n' "$base"
}

artifact_state() {
  local target=$1
  local expected_digest=$2
  local actual_digest

  if [[ ! -e "$target" && ! -L "$target" ]]; then
    printf 'MISSING\n'
    return 0
  fi
  if [[ -L "$target" || ! -f "$target" ]]; then
    printf 'DRIFT\n'
    return 0
  fi
  actual_digest=$(sha256_file "$target") || return "$?"
  if [[ "$actual_digest" == "$expected_digest" ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'DRIFT\n'
  fi
}
