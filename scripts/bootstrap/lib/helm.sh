#!/usr/bin/env bash

# stage 60/90 共用的 helm 调用与瞬态 kubeconfig 生命周期。
# helm 无法从管道读 kubeconfig，只能落到 /root 下的私有临时文件；该文件是
# `--check` 零写入原则唯一文档化的例外，因此目录 700、文件 600、内容与
# ADMIN_CONF_CONTENT 逐字节一致、退出时必被清理，四者都必须成立。
# helm_archive_is_safe 改为必须显式传参：60 有 staged 与 apply 快照两个来源，
# 默认参数会让调用点看不出用的是哪一个。
# 依赖：safe_file/safe_directory/python_isolated（lib/exec-safety.sh）、
# ADMIN_CONF_CONTENT（lib/kubectl.sh），以及各 stage 声明的 $helm_binary 与
# $HELM_MEMBER。同 exec-safety.sh 的契约：缺失时 set -u 直接报未绑定变量。
# SC2154 只对小写变量告警（全大写被当成环境变量豁免），故显式关闭。
# shellcheck disable=SC2154
helm_lib_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck disable=SC1091
source "${helm_lib_dir}/exec-safety.sh"
# shellcheck disable=SC1091
source "${helm_lib_dir}/kubectl.sh"

helm_run() {
  PYTHONDONTWRITEBYTECODE=1 KUBECACHEDIR=/dev/null "$helm_binary" "$@"
}

# 当前 helm kubeconfig 临时目录；EXIT trap 据此清理，成功 rmdir 后清空。
helm_kubeconfig_dir=

cleanup_helm_kubeconfig() {
  local parent
  [[ -n "$helm_kubeconfig_dir" ]] || return 0
  parent=$(host_path /root)
  [[ "${helm_kubeconfig_dir%/*}" == "$parent" &&
      "${helm_kubeconfig_dir##*/}" == .helm-kubeconfig.* ]] || return 1
  [[ -d "$helm_kubeconfig_dir" && ! -L "$helm_kubeconfig_dir" ]] || return 1
  rm -f -- "${helm_kubeconfig_dir}/config" || return 1
  rmdir -- "$helm_kubeconfig_dir" || return 1
  helm_kubeconfig_dir=
}

helm_cluster_run() {
  local exit_code=0 parent kubeconfig_dir kubeconfig
  admin_conf_is_safe || return 1
  parent=$(host_path /root)
  safe_directory "$parent" 700 || return 1
  kubeconfig_dir=$(mktemp -d "${parent}/.helm-kubeconfig.XXXXXX") || return 1
  helm_kubeconfig_dir=$kubeconfig_dir
  # 命令替换子 shell 会把 EXIT trap 重置为继承值，主 shell 的 trap 看不到子 shell
  # 里的目录名；只在子 shell 内补装，避免覆盖主 shell 的 APPLY trap。
  (( BASH_SUBSHELL == 0 )) || trap 'cleanup_helm_kubeconfig || :' EXIT
  kubeconfig="${kubeconfig_dir}/config"
  if ! safe_directory "$kubeconfig_dir" 700 ||
     ! printf '%s' "$ADMIN_CONF_CONTENT" >"$kubeconfig" ||
     ! safe_file "$kubeconfig" 600 ||
     ! cmp -s "$kubeconfig" <(printf '%s' "$ADMIN_CONF_CONTENT"); then
    rm -f -- "$kubeconfig"
    if rmdir -- "$kubeconfig_dir" 2>/dev/null; then
      helm_kubeconfig_dir=
    fi
    return 1
  fi
  PYTHONDONTWRITEBYTECODE=1 KUBECACHEDIR=/dev/null "$helm_binary" \
    --kubeconfig "$kubeconfig" "$@" || exit_code=$?
  rm -f -- "$kubeconfig" || return 1
  rmdir -- "$kubeconfig_dir" || return 1
  helm_kubeconfig_dir=
  admin_conf_is_safe || return 1
  return "$exit_code"
}

helm_kubeconfig_residue_exists() (
  local entry
  shopt -s nullglob dotglob
  for entry in "$(host_path /root)"/.helm-kubeconfig.*; do
    : "$entry"
    exit 0
  done
  exit 1
)

helm_values_json_is_exact() {
  python_isolated -c '
import json
import sys

expected = {
    "kubeProxyReplacement": True,
    "k8sServiceHost": sys.argv[1],
    "k8sServicePort": 6443,
    "cgroup": {
        "autoMount": {"enabled": False},
        "hostRoot": "/sys/fs/cgroup",
    },
    "gatewayAPI": {"enabled": True},
    "hubble": {"enabled": False},
    "image": {
        "digest": "sha256:383968cd5e8873f7976fa76aa6196045643558f4cc9518a207b9335cb24a0e93",
        "useDigest": True,
    },
    "ipam": {"mode": "kubernetes"},
    "operator": {
        "image": {
            "genericDigest": "sha256:80744a8cc7c91c2f9e6347629406844eb35d79b30a732c6d41c15b17232a74f3",
            "useDigest": True,
        },
        "replicas": 1,
    },
}

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

def reject_constant(_value):
    raise ValueError("non-finite number")

def exactly_equal(actual, wanted):
    if type(actual) is not type(wanted):
        return False
    if isinstance(wanted, dict):
        return set(actual) == set(wanted) and all(
            exactly_equal(actual[key], wanted[key]) for key in wanted
        )
    if isinstance(wanted, list):
        return len(actual) == len(wanted) and all(
            exactly_equal(left, right) for left, right in zip(actual, wanted)
        )
    return actual == wanted

try:
    actual = json.load(
        sys.stdin,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (TypeError, ValueError):
    raise SystemExit(1)
raise SystemExit(0 if exactly_equal(actual, expected) else 1)
' "$HOST_NODE_IP" >/dev/null 2>&1
}

helm_archive_is_safe() {
  local archive=$1
  python_isolated - "$archive" "$HELM_MEMBER" <<'PY' >/dev/null 2>&1
import pathlib
import sys
import tarfile

archive_path, expected_member = sys.argv[1:]
try:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        matches = []
        for member in archive.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not member.name:
                raise SystemExit(1)
            if not (member.isfile() or member.isdir()):
                raise SystemExit(1)
            if member.name == expected_member:
                matches.append(member)
        if len(matches) != 1 or not matches[0].isfile():
            raise SystemExit(1)
        if matches[0].mode & 0o111 == 0:
            raise SystemExit(1)
except (OSError, tarfile.TarError):
    raise SystemExit(1)
PY
}
