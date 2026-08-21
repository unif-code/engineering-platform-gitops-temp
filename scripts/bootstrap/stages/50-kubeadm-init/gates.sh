#!/usr/bin/env bash

# 50-kubeadm-init 的判定族：只读取状态并返回 0/1，不打印证据、不调用 complete、不退出。
# run.sh 负责流程与终止，gates.sh 负责"事实是什么"——两者分开后，判定可以被单独
# 阅读和测试，而不必跟着流程走一遍。
# 本文件由 run.sh 以 ${script_dir}/gates.sh 引入，与 run.sh 同属一个 stage 目录，
# 因此被 bootstrap-all.sh 的 stage 目录逐条目门禁覆盖（属主、权限、非符号链接）。
# 判定所需的常量与路径由 run.sh 声明；缺失时 set -u 直接报未绑定变量。
# SC2154 只对小写变量告警（全大写被当成环境变量豁免），故显式关闭。
# shellcheck disable=SC2154

safe_test_gate() {
  local path=$1
  [[ "$path" == /* && -f "$path" && ! -L "$path" && -x "$path" && -O "$path" ]]
}

run_stage_gate() {
  local script=$1 expected=$2 captured
  captured=$(
    set +e
    /bin/bash "$script" --check 2>/dev/null
    printf '__EXIT_CODE__=%s\n' "$?"
  )
  [[ "$captured" == "${expected}"$'\n__EXIT_CODE__=0' ]]
}

root_is_safe_directory() {
  local root=$1 expected_mode=$2
  [[ -d "$root" && ! -L "$root" &&
     "$(path_mode "$root")" == "$expected_mode" ]] &&
    owned_by_expected "$root"
}

root_is_missing_or_safe_empty() {
  local root=$1 first_entry
  if [[ ! -e "$root" && ! -L "$root" ]]; then
    return 0
  fi
  root_is_safe_directory "$root" 755 || return 1
  first_entry=$(find "$root" -mindepth 1 -print -quit 2>/dev/null) || return 1
  [[ -z "$first_entry" ]]
}

package_owner_is_exact() {
  local logical=$1 package=$2 ownership
  local ownership_sentinel=__KUBELET_FOOTPRINT_OWNERSHIP_END__
  ownership=$(
    dpkg-query -S "$logical" 2>/dev/null &&
      printf '%s' "$ownership_sentinel"
  ) || return 1
  [[ "$ownership" == "${package}: ${logical}"$'\n'"$ownership_sentinel" ]]
}

package_directory_is_safe() {
  local logical=$1 target=$2 normal_mode=$3 mode
  [[ -d "$target" && ! -L "$target" ]] || return 1
  owned_by_expected "$target" || return 1
  mode=$(path_mode "$target") || return 1
  if [[ "$mode" == "$normal_mode" ]]; then
    return 0
  fi
  [[ "$mode" == 775 ]] || return 1
  package_owner_is_exact "$logical" kubelet
}

kubelet_package_placeholder_is_exact() {
  local logical=$1 target digest
  target=$(host_path "$logical")
  [[ -f "$target" && ! -L "$target" && ! -s "$target" &&
     "$(path_mode "$target")" == 644 ]] || return 1
  owned_by_expected "$target" || return 1
  package_owner_is_exact "$logical" kubelet || return 1
  digest=$(sha256_file "$target") || return 1
  [[ "$digest" == "$KUBELET_KEEP_SHA256" ]]
}

kubelet_keep_is_exact() {
  kubelet_package_placeholder_is_exact /etc/kubernetes/manifests/.kubelet-keep
}

kubelet_state_package_footprint_is_pristine() {
  local kubelet_root=$1 root_entries
  [[ -d "$kubelet_root" && ! -L "$kubelet_root" ]] || return 1
  owned_by_expected "$kubelet_root" || return 1
  [[ "$(path_mode "$kubelet_root")" == 775 ]] || return 1
  package_owner_is_exact /var/lib/kubelet kubelet || return 1
  root_entries=$(find "$kubelet_root" -mindepth 1 -maxdepth 1 -print 2>/dev/null |
    sed 's#.*/##' | sort) || return 1
  [[ "$root_entries" == .kubelet-keep ]] || return 1
  kubelet_package_placeholder_is_exact /var/lib/kubelet/.kubelet-keep
}

kubelet_package_footprint_is_fresh() {
  local kubernetes_root=$1 manifests root_entries manifest_entries
  manifests="${kubernetes_root}/manifests"
  package_directory_is_safe /etc/kubernetes "$kubernetes_root" 775 || return 1
  package_owner_is_exact /etc/kubernetes kubelet || return 1
  root_entries=$(find "$kubernetes_root" -mindepth 1 -maxdepth 1 -print 2>/dev/null |
    sed 's#.*/##' | sort) || return 1
  [[ "$root_entries" == manifests ]] || return 1
  package_directory_is_safe /etc/kubernetes/manifests "$manifests" 775 || return 1
  package_owner_is_exact /etc/kubernetes/manifests kubelet || return 1
  manifest_entries=$(find "$manifests" -mindepth 1 -maxdepth 1 -print 2>/dev/null |
    sed 's#.*/##' | sort) || return 1
  [[ "$manifest_entries" == .kubelet-keep ]] || return 1
  kubelet_keep_is_exact
}

initialization_state() {
  local kubernetes_root etcd_root listener
  kubernetes_root=$(host_path /etc/kubernetes)
  etcd_root=$(host_path /var/lib/etcd)

  if package_directory_is_safe /etc/kubernetes "$kubernetes_root" 755 &&
     root_is_safe_directory "$etcd_root" 700 &&
     [[ -f "${kubernetes_root}/admin.conf" &&
        ! -L "${kubernetes_root}/admin.conf" &&
        -d "${kubernetes_root}/manifests" &&
        ! -L "${kubernetes_root}/manifests" &&
        -d "${etcd_root}/member" &&
        ! -L "${etcd_root}/member" ]]; then
    printf 'CANDIDATE\n'
    return 0
  fi
  if { root_is_missing_or_safe_empty "$kubernetes_root" ||
       kubelet_package_footprint_is_fresh "$kubernetes_root"; } &&
     root_is_missing_or_safe_empty "$etcd_root"; then
    listener=$(ss -H -ltn 'sport = :6443' 2>/dev/null) || return "$EXIT_PRECONDITION"
    if [[ -z "$listener" ]]; then
      printf 'FRESH\n'
      return 0
    fi
  fi
  printf 'UNKNOWN\n'
}

config_file_is_safe() {
  local target=$1 expected_mode=$2 digest
  [[ -f "$target" && ! -L "$target" && "$(path_mode "$target")" == "$expected_mode" ]] || return 1
  owned_by_expected "$target" || return 1
  digest=$(sha256_file "$target") || return 1
  [[ "$digest" == "$CONFIG_SHA256" ]]
}

cleanup_config_snapshot() {
  local parent
  [[ -n "$config_snapshot_dir" ]] || return 0
  parent=$(host_path /var/tmp)
  [[ "$config_snapshot_dir" == "${parent}/.kubeadm-config."* ]] || return 0
  [[ -d "$config_snapshot_dir" && ! -L "$config_snapshot_dir" && "$(path_mode "$config_snapshot_dir")" == 700 ]] || return 0
  owned_by_expected "$config_snapshot_dir" || return 0
  rm -r -- "$config_snapshot_dir"
}

create_config_snapshot() {
  local parent mode
  parent=$(host_path /var/tmp)
  [[ -d "$parent" && ! -L "$parent" && -k "$parent" ]] || return "$EXIT_UNKNOWN_STATE"
  mode=$(path_mode "$parent") || return "$EXIT_UNKNOWN_STATE"
  [[ "$mode" == 1777 || "$mode" == 777 ]] || return "$EXIT_UNKNOWN_STATE"
  owned_by_expected "$parent" || return "$EXIT_UNKNOWN_STATE"
  config_snapshot_dir=$(mktemp -d "${parent}/.kubeadm-config.XXXXXX") || return "$EXIT_APPLY_FAILED"
  [[ "$(path_mode "$config_snapshot_dir")" == 700 ]] || return "$EXIT_UNKNOWN_STATE"
  owned_by_expected "$config_snapshot_dir" || return "$EXIT_UNKNOWN_STATE"
  config_snapshot="${config_snapshot_dir}/init.yaml"
  install -m 0600 "$config_source" "$config_snapshot" || return "$EXIT_APPLY_FAILED"
  sync "$config_snapshot" || return "$EXIT_APPLY_FAILED"
  config_file_is_safe "$config_source" 644 || return "$EXIT_UNKNOWN_STATE"
  config_file_is_safe "$config_snapshot" 600 || return "$EXIT_UNKNOWN_STATE"
}

control_plane_json_is_exact() {
  python3 -c '
import json
import sys

mode = sys.argv[1]
expected = ["etcd", "kube-apiserver", "kube-controller-manager", "kube-scheduler"]
try:
    document = json.load(sys.stdin)
except (TypeError, ValueError):
    raise SystemExit(1)
if not isinstance(document, dict) or set(document) != {"containers"}:
    raise SystemExit(1)
containers = document["containers"]
if not isinstance(containers, list):
    raise SystemExit(1)
if mode == "exact" and len(containers) != 4:
    raise SystemExit(1)
control_plane = []
for container in containers:
    if not isinstance(container, dict):
        raise SystemExit(1)
    metadata = container.get("metadata")
    labels = container.get("labels")
    if not isinstance(metadata, dict) or not isinstance(labels, dict):
        raise SystemExit(1)
    name = metadata.get("name")
    if not isinstance(name, str) or container.get("state") != "CONTAINER_RUNNING":
        raise SystemExit(1)
    if name in expected:
        if labels.get("io.kubernetes.pod.namespace") != "kube-system":
            raise SystemExit(1)
        control_plane.append(name)
    elif mode == "exact":
        raise SystemExit(1)
if sorted(control_plane) != expected:
    raise SystemExit(1)
' "$1" >/dev/null 2>&1
}
