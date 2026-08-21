#!/usr/bin/env bash

# 主机身份唯一来源：bootstrap/hosts/<hostname>/host.env。
# 本库只判定：失败时把 reason 写入 HOST_CONFIG_ERROR 并返回 1，
# 由调用 stage 决定 RESULT。不 source host.env——逐行按白名单语法解析。

readonly -a HOST_CONFIG_KEYS=(
  HOST_NAME HOST_NODE_IP HOST_CLUSTER_NAME HOST_POD_CIDR HOST_SERVICE_CIDR
  HOST_SWAP_FILE HOST_SWAP_MIN_BYTES HOST_SWAP_MAX_BYTES
)
readonly -a HOST_CONFIG_FILES=(host.env kubeadm-init.yaml cilium-values.yaml pins.sha256)
HOST_CONFIG_ERROR=
HOST_CONFIG_DIR=

host_config_path_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

host_config_path_owner() {
  stat -c '%u:%g' "$1" 2>/dev/null || stat -f '%u:%g' "$1" 2>/dev/null
}

host_config_owned_by_expected() {
  local expected_uid=0 expected_gid=0
  if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 && "$EUID" -ne 0 ]]; then
    expected_uid=$EUID
    expected_gid=${GROUPS[0]}
  fi
  [[ "$(host_config_path_owner "$1")" == "${expected_uid}:${expected_gid}" ]]
}

host_config_root() {
  local lib_dir root
  if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 && -n "${BOOTSTRAP_TEST_HOSTS_DIR:-}" ]]; then
    root=$BOOTSTRAP_TEST_HOSTS_DIR
    [[ "$root" == /* && -d "$root" && ! -L "$root" && -O "$root" ]] || return 1
    printf '%s\n' "$root"
    return 0
  fi
  lib_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P) || return 1
  root=$(cd "${lib_dir}/../../../bootstrap/hosts" 2>/dev/null && pwd -P) || return 1
  printf '%s\n' "$root"
}

host_config_key_is_known() {
  local known
  for known in "${HOST_CONFIG_KEYS[@]}"; do
    [[ "$1" != "$known" ]] || return 0
  done
  return 1
}

host_config_file_is_known() {
  local known
  for known in "${HOST_CONFIG_FILES[@]}"; do
    [[ "$1" != "$known" ]] || return 0
  done
  return 1
}

host_config_ipv4_is_valid() {
  local octet
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for octet in "${BASH_REMATCH[@]:1:4}"; do
    [[ "$octet" == 0 || "$octet" =~ ^[1-9][0-9]{0,2}$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}

host_config_value_is_valid() {
  local key=$1 value=$2
  case "$key" in
    HOST_NAME|HOST_CLUSTER_NAME)
      [[ "$value" =~ ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$ ]] ;;
    HOST_NODE_IP)
      host_config_ipv4_is_valid "$value" ;;
    HOST_POD_CIDR|HOST_SERVICE_CIDR)
      [[ "$value" =~ ^[0-9.]+/([0-9]|[12][0-9]|3[0-2])$ ]] &&
        host_config_ipv4_is_valid "${value%/*}" ;;
    HOST_SWAP_FILE)
      [[ "$value" =~ ^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ && "$value" != *..* ]] ;;
    HOST_SWAP_MIN_BYTES|HOST_SWAP_MAX_BYTES)
      [[ "$value" =~ ^[1-9][0-9]{0,17}$ ]] ;;
    *) return 1 ;;
  esac
}

host_env_parse() {
  local file=$1 line key value seen=' '
  HOST_CONFIG_ERROR=
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == '#'* ]] && continue
    if [[ ! "$line" =~ ^(HOST_[A-Z_]+)=([A-Za-z0-9./_-]+)$ ]]; then
      HOST_CONFIG_ERROR=host-config-invalid
      return 1
    fi
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    if ! host_config_key_is_known "$key" || [[ "$seen" == *" $key "* ]] ||
       ! host_config_value_is_valid "$key" "$value"; then
      HOST_CONFIG_ERROR=host-config-invalid
      return 1
    fi
    printf -v "$key" '%s' "$value"
    seen+="$key "
  done <"$file"
  # 末行必须以换行结束：无终止换行时 read 返回非零并把残余留在 line 中。
  if [[ -n "$line" ]]; then
    HOST_CONFIG_ERROR=host-config-invalid
    return 1
  fi
  for key in "${HOST_CONFIG_KEYS[@]}"; do
    if [[ "$seen" != *" $key "* ]]; then
      HOST_CONFIG_ERROR=host-config-invalid
      return 1
    fi
  done
  if (( HOST_SWAP_MIN_BYTES >= HOST_SWAP_MAX_BYTES )); then
    HOST_CONFIG_ERROR=host-config-invalid
    return 1
  fi
}

# 子 shell 隔离 shopt；只允许精确 4 个已知文件名。
host_config_entries_are_exact() (
  local dir=$1 entry count=0
  shopt -s nullglob dotglob
  for entry in "$dir"/*; do
    host_config_file_is_known "${entry##*/}" || exit 1
    count=$((count + 1))
  done
  (( count == ${#HOST_CONFIG_FILES[@]} ))
)

load_host_config() {
  local actual root dir file
  HOST_CONFIG_ERROR=
  actual=$(hostname 2>/dev/null) || {
    HOST_CONFIG_ERROR=hostname-unreadable
    return 1
  }
  if [[ ! "$actual" =~ ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$ ]]; then
    HOST_CONFIG_ERROR=host-not-registered
    return 1
  fi
  root=$(host_config_root) || {
    HOST_CONFIG_ERROR=host-config-unsafe
    return 1
  }
  dir="${root}/${actual}"
  if [[ ! -e "$dir" && ! -L "$dir" ]]; then
    HOST_CONFIG_ERROR=host-not-registered
    return 1
  fi
  if [[ -L "$dir" || ! -d "$dir" || "$(host_config_path_mode "$dir")" != 755 ]] ||
     ! host_config_owned_by_expected "$dir" ||
     ! host_config_entries_are_exact "$dir"; then
    HOST_CONFIG_ERROR=host-config-unsafe
    return 1
  fi
  for file in "${HOST_CONFIG_FILES[@]}"; do
    if [[ -L "${dir}/${file}" || ! -f "${dir}/${file}" ||
          "$(host_config_path_mode "${dir}/${file}")" != 644 ]] ||
       ! host_config_owned_by_expected "${dir}/${file}"; then
      HOST_CONFIG_ERROR=host-config-unsafe
      return 1
    fi
  done
  host_env_parse "${dir}/host.env" || return 1
  if [[ "$HOST_NAME" != "$actual" ]]; then
    # HOST_CONFIG_ERROR 由调用 stage 读取；ShellCheck 只在最后一次赋值处报 SC2034。
    # shellcheck disable=SC2034
    HOST_CONFIG_ERROR=host-config-name-mismatch
    return 1
  fi
  HOST_CONFIG_DIR=$dir
  readonly HOST_CONFIG_DIR "${HOST_CONFIG_KEYS[@]}"
}

# 打印 pins.sha256 中指定文件的 digest；两行、固定顺序、sha256sum -c 兼容。
host_pin() {
  local wanted=$1 line count=0 pin_init='' pin_values=''
  [[ -n "$HOST_CONFIG_DIR" ]] || return 1
  while IFS= read -r line; do
    count=$((count + 1))
    case "$count" in
      1)
        [[ "$line" =~ ^([0-9a-f]{64})\ \ kubeadm-init\.yaml$ ]] || return 1
        pin_init=${BASH_REMATCH[1]}
        ;;
      2)
        [[ "$line" =~ ^([0-9a-f]{64})\ \ cilium-values\.yaml$ ]] || return 1
        pin_values=${BASH_REMATCH[1]}
        ;;
      *) return 1 ;;
    esac
  done <"${HOST_CONFIG_DIR}/pins.sha256"
  [[ -z "$line" && "$count" == 2 ]] || return 1
  case "$wanted" in
    kubeadm-init.yaml) printf '%s\n' "$pin_init" ;;
    cilium-values.yaml) printf '%s\n' "$pin_values" ;;
    *) return 1 ;;
  esac
}
