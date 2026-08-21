#!/usr/bin/env bash

# 公共退出码由各阶段按需消费，单独检查本文件时并非每项都会被引用。
# shellcheck disable=SC2034
readonly EXIT_PRECONDITION=10 EXIT_SUPPLY_CHAIN=20 EXIT_UNKNOWN_STATE=30 EXIT_APPLY_FAILED=40 EXIT_VERIFY_FAILED=50

MODE=CHECK
PHASE=${PHASE:-}
EVIDENCE_FILE=
EVIDENCE_OPEN=false

# 已安装 Cilium 在宿主机上建立的网卡：CIDR 重叠检查只对这些网卡上、且落在 Pod CIDR
# 内的地址/路由豁免（装完 CNI 后 PodCIDR 段路由是设计使然，不是冲突）。
readonly -a CNI_HOST_DEVICES=(cilium_host cilium_net cilium_vxlan 'lxc*')

parse_mode() {
  MODE=CHECK
  if [[ $# -eq 0 || ( $# -eq 1 && "$1" == "--check" ) ]]; then
    return 0
  fi
  if [[ $# -eq 1 && "$1" == "--apply" ]]; then
    MODE=APPLY
    return 0
  fi
  printf 'STOP: expected no argument, --check, or --apply\n' >&2
  return "$EXIT_PRECONDITION"
}

require_root() {
  [[ "$(id -u 2>/dev/null)" == "0" ]] || {
    printf 'STOP: must run as root\n' >&2
    return "$EXIT_PRECONDITION"
  }
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'STOP: required command missing: %s\n' "$1" >&2
    return "$EXIT_PRECONDITION"
  }
}

sha256_file() {
  local path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return
  fi
  printf 'STOP: sha256sum or shasum is required\n' >&2
  return "$EXIT_PRECONDITION"
}

managed_file_state() {
  local source=$1
  local target=$2
  if [[ ! -e "$target" && ! -L "$target" ]]; then
    printf 'MISSING\n'
    return 0
  fi
  if [[ -L "$target" || ! -f "$target" ]]; then
    printf 'UNKNOWN\n'
    return 0
  fi
  if cmp -s "$source" "$target"; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

install_managed_file() {
  local source=$1
  local target=$2
  local mode=$3
  local state
  local temporary

  state=$(managed_file_state "$source" "$target") || return "$?"
  case "$state" in
    COMPLIANT)
      return 0
      ;;
    UNKNOWN)
      printf 'STOP: refusing to overwrite unknown target: %s\n' "$target" >&2
      return "$EXIT_UNKNOWN_STATE"
      ;;
    MISSING)
      ;;
    *)
      printf 'STOP: invalid managed file state: %s\n' "$state" >&2
      return "$EXIT_UNKNOWN_STATE"
      ;;
  esac

  [[ -d "$(dirname "$target")" ]] || {
    printf 'STOP: target parent does not exist: %s\n' "$(dirname "$target")" >&2
    return "$EXIT_UNKNOWN_STATE"
  }
  temporary=$(mktemp "${target}.tmp.XXXXXX") || return "$EXIT_APPLY_FAILED"
  if ! install -m "$mode" "$source" "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  sync "$temporary" 2>/dev/null || true
  if ! ln "$temporary" "$target" 2>/dev/null; then
    rm -f -- "$temporary"
    printf 'STOP: target appeared during atomic install: %s\n' "$target" >&2
    return "$EXIT_UNKNOWN_STATE"
  fi
  rm -f -- "$temporary"
}

open_evidence() {
  local phase=$1
  local directory=${2:-/root/dev-infra-evidence}
  local timestamp=${3:-}

  [[ "$phase" =~ ^[0-9]{2}-[a-z0-9-]+$ ]] || {
    printf 'STOP: invalid evidence phase: %s\n' "$phase" >&2
    return "$EXIT_PRECONDITION"
  }
  [[ -d "$directory" && ! -L "$directory" ]] || {
    printf 'STOP: evidence directory is missing or unsafe: %s\n' "$directory" >&2
    return "$EXIT_PRECONDITION"
  }
  if [[ -z "$timestamp" ]]; then
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  fi
  [[ "$timestamp" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
    printf 'STOP: invalid evidence timestamp\n' >&2
    return "$EXIT_PRECONDITION"
  }

  EVIDENCE_FILE="${directory}/${phase}-${timestamp}.txt"
  if ! (umask 077; set -o noclobber; : >"$EVIDENCE_FILE") 2>/dev/null; then
    printf 'STOP: evidence file already exists: %s\n' "$EVIDENCE_FILE" >&2
    return "$EXIT_UNKNOWN_STATE"
  fi
  chmod 600 "$EVIDENCE_FILE" || return "$EXIT_APPLY_FAILED"
  exec 3>>"$EVIDENCE_FILE"
  EVIDENCE_OPEN=true
}

log_evidence() {
  local line=$1
  if [[ "$line" == *$'\n'* || "$line" == *$'\r'* ]]; then
    printf 'STOP: multiline evidence fields are forbidden\n' >&2
    return "$EXIT_PRECONDITION"
  fi
  printf '%s\n' "$line"
  if [[ "$EVIDENCE_OPEN" == true ]]; then
    printf '%s\n' "$line" >&3
  fi
}

finish_phase() {
  local result=$1
  local reason=$2
  local exit_code=$3
  local next=$4
  local digest

  log_evidence "PHASE=${PHASE}"
  log_evidence "MODE=${MODE}"
  log_evidence "RESULT=${result}"
  log_evidence "REASON=${reason}"
  log_evidence "EVIDENCE=${EVIDENCE_FILE:-NONE}"
  log_evidence "EXIT_CODE=${exit_code}"
  log_evidence "NEXT=${next}"
  if [[ "$EVIDENCE_OPEN" == true ]]; then
    exec 3>&-
    EVIDENCE_OPEN=false
    digest=$(sha256_file "$EVIDENCE_FILE") || return "$?"
    printf 'SHA256=%s\n' "$digest"
  else
    printf 'SHA256=NONE\n'
  fi
}
