#!/usr/bin/env bash

# stage 50/60/90 共用的 kubectl 门禁与 admin.conf 生命周期。
# 取 stage 90 的形态：kubectl 一律读**已捕获内容**而非磁盘文件，且在每次调用前后
# 各做一次 admin_conf_is_safe（含 cmp 比对磁盘与捕获内容）。这比"直接把磁盘路径交给
# kubectl"严格得多——后者在读取期间文件被替换不会被发现。
# 依赖：safe_file（lib/exec-safety.sh）、admin_conf_json_is_exact（lib/admin-conf.sh）、
# 以及各 stage 声明的 $kubectl_binary 与 $admin_conf。这两个由 stage 提供而非本库
# 兜底，与 exec-safety.sh 对 PYTHON_BINARY/TAR_BINARY 的契约一致：缺失时 set -u 直接
# 报未绑定变量。SC2154 对小写变量才告警（全大写被当成环境变量豁免），故此处显式关闭。
# shellcheck disable=SC2154
kubectl_lib_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck disable=SC1091
source "${kubectl_lib_dir}/exec-safety.sh"
# shellcheck disable=SC1091
source "${kubectl_lib_dir}/admin-conf.sh"

admin_conf_metadata_is_safe() {
  safe_file "$admin_conf" 600
}

ADMIN_CONF_CAPTURED=0
ADMIN_CONF_CONTENT=

capture_admin_conf() {
  local captured output with_sentinel
  admin_conf_metadata_is_safe || return 1
  with_sentinel=$(/bin/cat -- "$admin_conf"; printf x) || return 1
  [[ "${with_sentinel: -1}" == x ]] || return 1
  captured=${with_sentinel%?}
  cmp -s "$admin_conf" <(printf '%s' "$captured") || return 1
  output=$(
    PYTHONDONTWRITEBYTECODE=1 KUBECTL_KUBERC=false "$kubectl_binary" \
      --kubeconfig <(printf '%s' "$captured") --cache-dir=/dev/null \
      config view --raw --merge=false --output=json 2>/dev/null
  ) || return 1
  printf '%s' "$output" | admin_conf_json_is_exact || return 1
  admin_conf_metadata_is_safe || return 1
  cmp -s "$admin_conf" <(printf '%s' "$captured") || return 1
  ADMIN_CONF_CONTENT=$captured
  ADMIN_CONF_CAPTURED=1
}

admin_conf_is_safe() {
  [[ "$ADMIN_CONF_CAPTURED" == 1 ]] || return 1
  admin_conf_metadata_is_safe || return 1
  cmp -s "$admin_conf" <(printf '%s' "$ADMIN_CONF_CONTENT")
}

kubectl_run() {
  local exit_code=0
  admin_conf_is_safe || return 1
  PYTHONDONTWRITEBYTECODE=1 KUBECTL_KUBERC=false "$kubectl_binary" \
    --kubeconfig <(printf '%s' "$ADMIN_CONF_CONTENT") \
    --cache-dir=/dev/null "$@" || exit_code=$?
  admin_conf_is_safe || return 1
  return "$exit_code"
}

kubectl_query_is_empty() {
  local captured
  captured=$(
    set +e
    kubectl_run "$@" 2>/dev/null
    printf '__EXIT_CODE__=%s\n' "$?"
  )
  [[ "$captured" == '__EXIT_CODE__=0' ]]
}
