#!/bin/bash
# 运维一行入口：校验已批准的提交与仓库状态后，在干净环境中执行 bootstrap-all。
# 用法：scripts/bootstrap/run-approved.sh [<approved-sha>] --check|--apply
# 不带 SHA 时使用 CI 在 validation-gate 全绿后发布的 origin/validated；它必须仍在
# origin/main 历史上，否则 fail-closed，杜绝部署未经门禁或已被回滚的提交。
# 门禁与既往人工粘贴的脚本一致（SHA、origin、main、干净树、ff-only、helm 残留、
# umask 022），并用 env -i 白名单环境启动 bootstrap-all，杜绝交互 shell 遗留变量
# 触发 stage 的 untrusted-environment-override 拒绝。
set -Eeuo pipefail
export LC_ALL=C
umask 022

usage() {
  printf 'usage: %s [<approved-sha>] --check|--apply\n' "${0##*/}" >&2
  printf '  省略 SHA 时使用 CI 发布的 origin/validated\n' >&2
  exit 2
}

approved_sha=
case $# in
  1) mode=$1 ;;
  2)
    approved_sha=$1
    mode=$2
    ;;
  *) usage ;;
esac
case "$mode" in
  --check|--apply) ;;
  *) usage ;;
esac
if [[ -n "$approved_sha" && ! "$approved_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'STOP: invalid approved SHA'
  exit 90
fi
if [[ "$mode" == --apply && "$EUID" -ne 0 ]]; then
  echo 'STOP: --apply must run as root'
  exit 91
fi

script_source=${BASH_SOURCE[0]}
case "$script_source" in
  /*) ;;
  *) script_source="$PWD/$script_source" ;;
esac
script_dir=$(cd "${script_source%/*}" && pwd -P)
repo=$(cd "${script_dir}/../.." && pwd -P)

[[ -d "$repo/.git" && ! -L "$repo" ]] || {
  echo 'STOP: repository is missing or unsafe'
  exit 92
}
origin_url=$(/usr/bin/git -C "$repo" remote get-url origin)
case "$origin_url" in
  *unif-code/engineering-platform-gitops.git) ;;
  *)
    printf 'STOP: unexpected origin: %s\n' "$origin_url"
    exit 93
    ;;
esac
[[ "$(/usr/bin/git -C "$repo" branch --show-current)" == main ]] || {
  echo 'STOP: current branch is not main'
  exit 94
}

worktree=$(/usr/bin/git -C "$repo" status --porcelain=v1 --untracked-files=all)
[[ -z "$worktree" ]] || {
  echo 'STOP: worktree is not clean'
  printf '%s\n' "$worktree"
  exit 95
}

/usr/bin/git -C "$repo" fetch --prune origin main
if [[ -n "$approved_sha" ]]; then
  [[ "$(/usr/bin/git -C "$repo" rev-parse origin/main)" == "$approved_sha" ]] || {
    echo 'STOP: origin/main SHA mismatch'
    exit 96
  }
  approved_source=argument
else
  /usr/bin/git -C "$repo" fetch --force origin \
    'refs/heads/validated:refs/remotes/origin/validated' >/dev/null 2>&1 || {
    echo 'STOP: validated ref unavailable (CI publishes it after validation-gate)'
    exit 99
  }
  approved_sha=$(/usr/bin/git -C "$repo" rev-parse --verify --quiet \
    'refs/remotes/origin/validated^{commit}') || {
    echo 'STOP: validated ref unavailable (CI publishes it after validation-gate)'
    exit 99
  }
  /usr/bin/git -C "$repo" merge-base --is-ancestor "$approved_sha" origin/main || {
    echo 'STOP: validated ref is not on origin/main history'
    exit 100
  }
  approved_source=origin/validated
fi
printf 'APPROVED_SHA=%s (source=%s)\n' "$approved_sha" "$approved_source"
/usr/bin/git -C "$repo" merge --ff-only "$approved_sha"
[[ "$(/usr/bin/git -C "$repo" rev-parse HEAD)" == "$approved_sha" ]] || {
  echo 'STOP: local HEAD SHA mismatch'
  exit 97
}

# 上次运行被中断留下的 helm kubeconfig 残留：只检测并停止，由运维检查后手工清理。
if [[ "$EUID" -eq 0 ]]; then
  for residue in /root/.helm-kubeconfig.*; do
    [[ -e "$residue" || -L "$residue" ]] || continue
    printf 'STOP: helm kubeconfig residue present: %s\n' "$residue"
    exit 98
  done
fi

set +e
/usr/bin/env -i HOME="${HOME:-/root}" PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /bin/bash -p "$repo/scripts/bootstrap/bootstrap-all.sh" "$mode"
rc=$?
set -e
printf 'COMMAND_EXIT_CODE=%s\n' "$rc"
exit "$rc"
