#!/usr/bin/env bash

# stage 10 与 30 共用的归档校验族。两份原实现能力不同而非写法不同，这里取并集：
# - 硬链接条目（`h*` / `' link to '`）与符号链接同样受检；原先只有 30 认，10 会漏掉
#   整整一类逃逸。GNU tar 与 bsdtar 对硬链接都输出 `h` 前缀加 ' link to '（实测）。
# - 未知族 fail-closed；原先 10 的 case 没有 `*)` 分支，未知名会静默通过。两个调用点
#   今天都只传 containerd/crictl/helm，因此这是加强而非行为变更。
# - 期望成员必须是正规文件：containerd 取自 30、crictl 两边都有。
#   helm 保留 10 的"仅要求成员存在"——没有任何实现对 helm 做过正规文件检查，加上去是
#   新语义而非并集，而仓库内没有 helm 归档成员类型的实测证据（见账本 R13）。
# - approved_record 取 30，含 BOOTSTRAP_TEST_APPROVED_LOCK_FILE 测试缝；生产环境由各
#   stage 入口的 "${!BOOTSTRAP_TEST_@}" 前缀通配守卫拦下。

approved_record() {
  local name=$1
  if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 && "$EUID" -ne 0 && -n "${BOOTSTRAP_TEST_APPROVED_LOCK_FILE:-}" ]]; then
    awk -F '\t' -v approved_name="$name" '
      $1 == approved_name {
        print $2 "\t" $3 "\t" $4 "\t" $5
        count++
      }
      END { exit count != 1 }
    ' "$BOOTSTRAP_TEST_APPROVED_LOCK_FILE"
    return
  fi
  case "$name" in
    containerd) printf '%s\t%s\t%s\t%s\n' 2.3.1 'https://github.com/containerd/containerd/releases/download/v2.3.1/containerd-2.3.1-linux-amd64.tar.gz' 628448bd973610c656c1cbea8e88b32fafd85b23cc1aa4a3372eb7198478c054 /usr/local/bin ;;
    runc) printf '%s\t%s\t%s\t%s\n' 1.3.6 'https://github.com/opencontainers/runc/releases/download/v1.3.6/runc.amd64' 3f3921dbbee7723e9868f97e88e51ffc910206e3ba55646e74d93d24ea76023c /usr/local/sbin/runc ;;
    crictl) printf '%s\t%s\t%s\t%s\n' 1.36.0 'https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.36.0/crictl-v1.36.0-linux-amd64.tar.gz' 83855e114566a8a8c44c548d515670f51de3a5e1da8b2effb59870e2f10c25a3 /usr/local/bin/crictl ;;
    helm) printf '%s\t%s\t%s\t%s\n' 3.21.0 'https://get.helm.sh/helm-v3.21.0-linux-amd64.tar.gz' 0093eb572e3d2380f094df162ddb525e219249de88957afe24cfbb19632acd36 /usr/local/bin/helm ;;
    gateway-api) printf '%s\t%s\t%s\t%s\n' 1.6.1 'https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml' 24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73 'kubernetes://gateway-api/standard' ;;
    cilium-chart) printf '%s\t%s\t%s\t%s\n' 1.20.0 'https://helm.cilium.io/cilium-1.20.0.tgz' c5f013912360d1a334f44ef25f36da59ba3414cdb48f466ee12d0c4fdff27883 'kubernetes://kube-system/cilium' ;;
    *) return 1 ;;
  esac
}

array_contains() {
  local needle=$1
  local item
  shift
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

safe_archive_member() {
  local member=$1
  [[ -n "$member" && "$member" != /* && "$member" != *$'\n'* ]] || return 1
  case "/${member}/" in */../*) return 1 ;; esac
}

safe_symlink_target() {
  local target=$1
  [[ -n "$target" && "$target" != /* && "$target" != *$'\n'* ]] || return 1
  case "/${target}/" in */../*) return 1 ;; esac
}

regular_archive_member() {
  local archive=$1
  local member=$2
  local detail
  detail=$(tar -tvzf "$archive" "$member" 2>/dev/null) || return 1
  [[ "$detail" != *$'\n'* && "$detail" == -* ]]
}

validate_archive() {
  local name=$1
  local archive=$2
  local listing verbose_listing verbose_warnings member line link_target regular_required
  local expected_members
  listing=$(tar -tzf "$archive" 2>/dev/null) || return 1
  while IFS= read -r member; do
    safe_archive_member "$member" || return 1
  done <<<"$listing"
  # GNU tar 在**列表阶段**就把硬链接目标里的前导 `/` 与 `../` 剥掉（实测 1.35：
  # `bin/../../../etc/passwd`、`/etc/passwd`、`../../etc/passwd` 三者都被打印成
  # `etc/passwd`），于是下面基于打印值的检查在生产平台上永远判不出逃逸——bsdtar
  # 原样打印，所以只在 macOS 上有效。tar 净化时会往 stderr 写 "Removing leading …"，
  # 把该警告本身当作逃逸信号，两个平台就都被覆盖：GNU 靠警告、BSD 靠目标值。
  verbose_warnings=$(tar -tvzf "$archive" 2>&1 >/dev/null) || return 1
  [[ "$verbose_warnings" != *'Removing leading'* ]] || return 1
  verbose_listing=$(tar -tvzf "$archive" 2>/dev/null) || return 1
  while IFS= read -r line; do
    if [[ "$line" == l* || "$line" == h* ]]; then
      [[ "$line" == *' -> '* || "$line" == *' link to '* ]] || return 1
      if [[ "$line" == *' -> '* ]]; then
        link_target=${line##* -> }
      else
        link_target=${line##* link to }
      fi
      safe_symlink_target "$link_target" || return 1
    fi
  done <<<"$verbose_listing"
  case "$name" in
    containerd)
      expected_members=(bin/containerd bin/ctr bin/containerd-shim-runc-v2)
      regular_required=1
      ;;
    crictl)
      expected_members=(crictl)
      regular_required=1
      ;;
    helm)
      expected_members=(linux-amd64/helm)
      regular_required=0
      ;;
    *)
      return 1
      ;;
  esac
  for member in "${expected_members[@]}"; do
    grep -Fqx -- "$member" <<<"$listing" || return 1
    if [[ "$regular_required" == 1 ]]; then
      regular_archive_member "$archive" "$member" || return 1
    fi
  done
}
