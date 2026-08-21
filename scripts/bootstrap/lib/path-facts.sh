#!/usr/bin/env bash

# 各 stage 共用的路径事实谓词：只读取 stat，不做任何判定之外的副作用。
# stat 的 GNU/BSD 两种 -c/-f 写法都要覆盖，因为 CI 与开发机内核不同。
path_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

path_owner() {
  stat -c '%u:%g' "$1" 2>/dev/null || stat -f '%u:%g' "$1" 2>/dev/null
}

path_size() {
  stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1" 2>/dev/null
}

# 期望属主恒为 0:0；仅在 BOOTSTRAP_TEST_MODE 且非 root 时改判为当前 uid:gid。
# 两条漂移缝是 stage 20/30 的既有测试接口：前者立即改判，后者等到标记文件出现
# 才改判，用来把 mktemp 之后的属主竞态钉在 apply 中途。生产环境由各 stage 入口
# 的 "${!BOOTSTRAP_TEST_@}" 前缀通配守卫拦下，任何 BOOTSTRAP_TEST_* 变量都会以
# test-override-in-production 退出 10，与变量名无关。
owned_by_expected() {
  local path=$1
  local expected_uid=0
  local expected_gid=0
  if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 && "$EUID" -ne 0 ]]; then
    expected_uid=$EUID
    expected_gid=${GROUPS[0]}
    if [[ "${BOOTSTRAP_TEST_OWNER_DRIFT_PATH:-}" == "$path" ]]; then
      expected_uid=$((expected_uid + 1))
    fi
    if [[ "${BOOTSTRAP_TEST_DEFERRED_OWNER_DRIFT_PATH:-}" == "$path" && -e "${BOOTSTRAP_TEST_OWNER_DRIFT_AFTER_MARKER:-}" ]]; then
      expected_uid=$((expected_uid + 1))
    fi
  fi
  [[ "$(path_owner "$path")" == "${expected_uid}:${expected_gid}" ]]
}
