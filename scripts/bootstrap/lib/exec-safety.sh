#!/usr/bin/env bash

# 各 stage 共用的受控执行与路径安全谓词。
# python 与 tar 一律走 stage 钉死的绝对路径，并关掉外部输入通道：-I -B 屏蔽
# site 与 PYTHON* 环境变量以及字节码写入，TAR_OPTIONS='' 屏蔽继承来的 tar 参数。
# PYTHON_BINARY 与 TAR_BINARY 由 stage 声明为 readonly；缺失时 set -u 会直接报
# 未绑定变量，不会退回 PATH 上的同名程序。
# safe_directory/safe_file 把「类型正确 + 非符号链接 + 模式匹配 + 属主符合」四项
# 合成单一判定。两者只在被调用时才需要 path-facts.sh 的 path_mode 与
# owned_by_expected，因此 stage 先 source 哪个库都不影响判定；这里仍显式 source
# 兄弟库，只 source 本文件的消费者才不会拿到半个依赖。
exec_safety_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck disable=SC1091
source "${exec_safety_dir}/path-facts.sh"

python_isolated() {
  "$PYTHON_BINARY" -I -B "$@"
}

tar_safe() {
  TAR_OPTIONS='' "$TAR_BINARY" "$@"
}

safe_directory() {
  local path=$1 expected_mode=$2
  [[ -d "$path" && ! -L "$path" && "$(path_mode "$path")" == "$expected_mode" ]] &&
    owned_by_expected "$path"
}

safe_file() {
  local path=$1 expected_mode=$2
  [[ -f "$path" && ! -L "$path" && "$(path_mode "$path")" == "$expected_mode" ]] &&
    owned_by_expected "$path"
}
