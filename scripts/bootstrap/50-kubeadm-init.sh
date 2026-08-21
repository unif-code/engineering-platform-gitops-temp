#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

# 逐个收集违规变量名并在拒绝时列出（只列名不列值），便于运维定位后 unset。
untrusted_environment=
for untrusted_name in APT_CONFIG KUBECONFIG DPKG_ADMINDIR DPKG_ROOT \
    DPKG_FORCE DPKG_FRONTEND_LOCKED; do
  [[ -z "${!untrusted_name+x}" ]] ||
    untrusted_environment="${untrusted_environment:+${untrusted_environment},}${untrusted_name}"
done
if [[ -n "$untrusted_environment" ]]; then
  printf 'RESULT=STOP_PRECONDITION\nREASON=untrusted-environment-override\nVARS=%s\n' \
    "$untrusted_environment" >&2
  exit 10
fi

if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 ]]; then
  if [[ "$EUID" -eq 0 ]]; then
    printf 'RESULT=STOP_TEST_MODE\nREASON=test-mode-is-for-unprivileged-tests-only\n' >&2
    exit 10
  fi
  if [[ -z "${BOOTSTRAP_TEST_ROOT:-}" || "$BOOTSTRAP_TEST_ROOT" != /* || "$BOOTSTRAP_TEST_ROOT" == / || ! -d "$BOOTSTRAP_TEST_ROOT" || -L "$BOOTSTRAP_TEST_ROOT" || ! -O "$BOOTSTRAP_TEST_ROOT" ]]; then
    printf 'RESULT=STOP_TEST_MODE\nREASON=test-root-must-be-isolated\n' >&2
    exit 10
  fi
else
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin
  for test_override in "${!BOOTSTRAP_TEST_@}"; do
    : "$test_override"
    printf 'RESULT=STOP_TEST_OVERRIDE\nREASON=test-override-in-production\n' >&2
    exit 10
  done
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck disable=SC1091
source "${script_dir}/lib/common.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/path-facts.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/host-config.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/exec-safety.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/admin-conf.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/kubectl.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/dpkg-package-verification.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/kubelet-default.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/os-release.sh"

# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=kubeadm-init
# admin.conf 的结构校验（lib/admin-conf.sh）经 python_isolated 执行，解释器由
# 本 stage 钉死绝对路径；缺失时 set -u 报未绑定变量而不会退回 PATH。
readonly PYTHON_BINARY=/usr/bin/python3
readonly KUBELET_KEEP_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
readonly KERNEL_TRANSCRIPT=$'PHASE=prepare-kernel\nMODE=CHECK\nRESULT=ALREADY_COMPLIANT\nREASON=kernel-ready\nEVIDENCE=NONE\nEXIT_CODE=0\nNEXT=30-install-containerd\nSHA256=NONE'
readonly CONTAINERD_TRANSCRIPT=$'PHASE=containerd\nMODE=CHECK\nRESULT=ALREADY_COMPLIANT\nREASON=containerd-ready\nEVIDENCE=NONE\nEXIT_CODE=0\nNEXT=40-install-kubernetes\nSHA256=NONE'
readonly KUBERNETES_TRANSCRIPT=$'PHASE=install-kubernetes\nMODE=CHECK\nRESULT=ALREADY_COMPLIANT\nREASON=kubernetes-packages-ready\nEVIDENCE=NONE\nEXIT_CODE=0\nNEXT=50-kubeadm-init.sh --check\nSHA256=NONE'

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

kubelet_pre_init_inputs_gate() {
  local kubelet_root root_mode first_entry sensitive_path
  kubelet_root=$(host_path /var/lib/kubelet)
  if [[ -e "$kubelet_root" || -L "$kubelet_root" ]]; then
    if ! kubelet_state_package_footprint_is_pristine "$kubelet_root"; then
      if [[ ! -d "$kubelet_root" || -L "$kubelet_root" ]] || ! owned_by_expected "$kubelet_root"; then
        complete STOP_ALREADY_INITIALIZED kubelet-root-unsafe "$EXIT_UNKNOWN_STATE" NONE
      fi
      root_mode=$(path_mode "$kubelet_root") || complete STOP_ALREADY_INITIALIZED kubelet-root-unreadable "$EXIT_UNKNOWN_STATE" NONE
      [[ "$root_mode" == 700 || "$root_mode" == 750 || "$root_mode" == 755 ]] ||
        complete STOP_ALREADY_INITIALIZED kubelet-root-mode-unsafe "$EXIT_UNKNOWN_STATE" NONE
      first_entry=$(find "$kubelet_root" -mindepth 1 -print -quit 2>/dev/null) ||
        complete STOP_ALREADY_INITIALIZED kubelet-root-unreadable "$EXIT_UNKNOWN_STATE" NONE
      [[ -z "$first_entry" ]] ||
        complete STOP_ALREADY_INITIALIZED kubelet-generated-state-present "$EXIT_UNKNOWN_STATE" NONE
    fi
  fi
  for sensitive_path in \
    "${kubelet_root}/kubeadm-flags.env" \
    "${kubelet_root}/config.yaml" \
    "${kubelet_root}/instance-config.yaml" \
    "${kubelet_root}/pki"; do
    if [[ -e "$sensitive_path" || -L "$sensitive_path" ]]; then
      complete STOP_ALREADY_INITIALIZED kubelet-generated-or-identity-state-present "$EXIT_UNKNOWN_STATE" NONE
    fi
  done
  if ! kubelet_default_conffile_is_pristine "$(host_path /etc/default/kubelet)"; then
    complete STOP_ALREADY_INITIALIZED kubelet-operator-override-present "$EXIT_UNKNOWN_STATE" NONE
  fi
}

managed_kubernetes_clients_gate() {
  local package logical target shadow ownership
  for package in kubeadm kubectl; do
    shadow=$(host_path "/usr/sbin/${package}")
    if [[ -e "$shadow" || -L "$shadow" ]]; then
      complete STOP_UNKNOWN_STATE kubernetes-client-shadow-present "$EXIT_UNKNOWN_STATE" NONE
    fi
    logical="/usr/bin/${package}"
    target=$(host_path "$logical")
    if [[ ! -f "$target" || -L "$target" || ! -x "$target" || "$(path_mode "$target")" != 755 ]] || ! owned_by_expected "$target"; then
      complete STOP_UNKNOWN_STATE kubernetes-client-metadata-drift "$EXIT_UNKNOWN_STATE" NONE
    fi
    ownership=$(dpkg-query -S "$logical" 2>/dev/null) ||
      complete STOP_UNKNOWN_STATE kubernetes-client-owner-unreadable "$EXIT_UNKNOWN_STATE" NONE
    [[ "$ownership" == "${package}: ${logical}" ]] ||
      complete STOP_UNKNOWN_STATE kubernetes-client-package-owner-drift "$EXIT_UNKNOWN_STATE" NONE
    dpkg_package_verification_is_exact "$package" ||
      complete STOP_UNKNOWN_STATE kubernetes-client-package-content-drift "$EXIT_UNKNOWN_STATE" NONE
  done
}

config_file_is_safe() {
  local target=$1 expected_mode=$2 digest
  [[ -f "$target" && ! -L "$target" && "$(path_mode "$target")" == "$expected_mode" ]] || return 1
  owned_by_expected "$target" || return 1
  digest=$(sha256_file "$target") || return 1
  [[ "$digest" == "$CONFIG_SHA256" ]]
}

host_and_dependency_gates() {
  local os_release os_id os_version cgroup_path cgroup_fs
  local address_output swap_file swap_output swap_lines swap_name swap_bytes
  local route_output cidr_output
  local -a cidr_arguments
  local cni_device

  os_release=$(ubuntu_os_release_path) ||
    complete STOP_PRECONDITION os-release-unsafe "$EXIT_PRECONDITION" NONE
  os_id=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' "$os_release")
  os_version=$(awk -F= '$1 == "VERSION_ID" {gsub(/"/, "", $2); print $2}' "$os_release")
  [[ "$os_id" == ubuntu && "$os_version" == 24.04* ]] || complete STOP_PRECONDITION os-mismatch "$EXIT_PRECONDITION" NONE
  [[ "$(uname -m 2>/dev/null)" == x86_64 ]] || complete STOP_PRECONDITION architecture-mismatch "$EXIT_PRECONDITION" NONE

  cgroup_path=$(host_path /sys/fs/cgroup)
  [[ -d "$cgroup_path" && ! -L "$cgroup_path" ]] || complete STOP_PRECONDITION cgroup-path-unsafe "$EXIT_PRECONDITION" NONE
  cgroup_fs=$(stat -fc %T "$cgroup_path" 2>/dev/null) || complete STOP_PRECONDITION cgroup-state-unreadable "$EXIT_PRECONDITION" NONE
  [[ "$cgroup_fs" == cgroup2fs ]] || complete STOP_PRECONDITION cgroup-v2-required "$EXIT_PRECONDITION" NONE

  address_output=$(ip -o -4 address show up 2>/dev/null) || complete STOP_PRECONDITION address-unreadable "$EXIT_PRECONDITION" NONE
  printf '%s\n' "$address_output" | awk -v ip="$HOST_NODE_IP" '$4 ~ ("^" ip "/") {found=1} END {exit !found}' ||
    complete STOP_PRECONDITION node-ip-not-bound-up "$EXIT_PRECONDITION" NONE

  swap_file=$(host_path "$HOST_SWAP_FILE")
  [[ -f "$swap_file" && ! -L "$swap_file" ]] || complete STOP_PRECONDITION swap-file-missing "$EXIT_PRECONDITION" NONE
  swap_output=$(swapon --show=NAME,SIZE --noheadings --raw --bytes 2>/dev/null) || complete STOP_PRECONDITION swap-unreadable "$EXIT_PRECONDITION" NONE
  swap_lines=$(printf '%s\n' "$swap_output" | awk 'NF {count++} END {print count+0}')
  swap_name=$(printf '%s\n' "$swap_output" | awk 'NF {print $1}')
  swap_bytes=$(printf '%s\n' "$swap_output" | awk 'NF {print $2}')
  [[ "$swap_lines" == 1 && "$swap_name" == "$HOST_SWAP_FILE" && "$swap_bytes" =~ ^[0-9]+$ ]] ||
    complete STOP_PRECONDITION swap-layout-mismatch "$EXIT_PRECONDITION" NONE
  # HOST_SWAP_*_BYTES 由 lib/host-config.sh 限定为 ^[1-9][0-9]{0,17}$，裸算术因此无注入与溢出风险。
  (( swap_bytes >= HOST_SWAP_MIN_BYTES && swap_bytes <= HOST_SWAP_MAX_BYTES )) ||
    complete STOP_PRECONDITION swap-size-mismatch "$EXIT_PRECONDITION" NONE

  run_stage_gate "$kernel_script" "$KERNEL_TRANSCRIPT" || complete STOP_PRECONDITION kernel-gate-failed "$EXIT_PRECONDITION" NONE
  run_stage_gate "$containerd_script" "$CONTAINERD_TRANSCRIPT" || complete STOP_PRECONDITION containerd-gate-failed "$EXIT_PRECONDITION" NONE
  run_stage_gate "$kubernetes_script" "$KUBERNETES_TRANSCRIPT" || complete STOP_PRECONDITION kubernetes-gate-failed "$EXIT_PRECONDITION" NONE

  route_output=$(ip -o -4 route show table all 2>/dev/null) || complete STOP_PRECONDITION route-unreadable "$EXIT_PRECONDITION" NONE
  cidr_arguments=(--service-cidr "$HOST_SERVICE_CIDR" --pod-cidr "$HOST_POD_CIDR")
  for cni_device in "${CNI_HOST_DEVICES[@]}"; do
    cidr_arguments+=(--cni-device "$cni_device")
  done
  # 地址/路由带上网卡名（前缀@网卡），让 CIDR 检查能识别 CNI 自建条目。
  while IFS= read -r address; do
    [[ -n "$address" ]] && cidr_arguments+=(--address "$address")
  done < <(printf '%s\n' "$address_output" | awk 'NF >= 4 {print $4 "@" $2}')
  while IFS= read -r route; do
    [[ -n "$route" ]] && cidr_arguments+=(--route "$route")
  done < <(printf '%s\n' "$route_output" | awk '$1 != "default" && $1 ~ /\// {
    device = ""
    for (i = 1; i <= NF; i++) if ($i == "dev") device = $(i + 1)
    print (device != "" ? $1 "@" device : $1)
  }')
  if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 ]]; then
    cidr_output=$("$cidr_script" "${cidr_arguments[@]}" 2>/dev/null) || complete STOP_PRECONDITION cidr-gate-failed "$EXIT_PRECONDITION" NONE
  else
    cidr_output=$(python3 "$cidr_script" "${cidr_arguments[@]}" 2>/dev/null) || complete STOP_PRECONDITION cidr-gate-failed "$EXIT_PRECONDITION" NONE
  fi
  [[ "$cidr_output" == $'RESULT=PASS_CIDRS\nREASON=no-server-local-overlap\nSCOPE=SERVER_LOCAL_SCOPE_ONLY' ]] ||
    complete STOP_PRECONDITION cidr-gate-output-invalid "$EXIT_PRECONDITION" NONE
}

config_snapshot_dir=
config_snapshot=

# trap 间接调用；仅清理受验证的私有 snapshot 目录。
# shellcheck disable=SC2317,SC2329
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

fresh_pre_init_gates() {
  local current_state
  current_state=$(initialization_state) ||
    complete STOP_PRECONDITION initialized-state-unreadable \
      "$EXIT_PRECONDITION" NONE
  [[ "$current_state" == FRESH ]] ||
    complete STOP_ALREADY_INITIALIZED initialized-or-partial-state-present \
      "$EXIT_UNKNOWN_STATE" NONE
  kubelet_pre_init_inputs_gate
  managed_kubernetes_clients_gate
  config_file_is_safe "$config_source" 644 ||
    complete STOP_PRECONDITION kubeadm-config-contract-drift \
      "$EXIT_PRECONDITION" NONE
  if [[ -n "$config_snapshot" ]]; then
    config_file_is_safe "$config_snapshot" 600 ||
      complete STOP_UNKNOWN_STATE kubeadm-config-snapshot-drift \
        "$EXIT_UNKNOWN_STATE" NONE
  fi
  host_and_dependency_gates
}

# 参数 exact：刚 init 完的即时校验，运行中容器必须恰好是 4 个控制面容器（此时 CNI 未装，
# 不可能有别的）。参数 initialized：resume 判定，4 个控制面容器各恰好一个且 Running 于
# kube-system；其他运行中容器（Cilium、CoreDNS、后续 GitOps 工作负载）不属于本 stage 合同。
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

initialized_control_plane_gate() {
  local failure_result=$1 failure_code=$2 runtime_set_mode=$3 listener kubernetes_root
  local expected_manifests_with_keep

  managed_kubernetes_clients_gate
  host_and_dependency_gates
  config_file_is_safe "$config_source" 644 ||
    complete "$failure_result" kubeadm-config-contract-drift \
      "$failure_code" NONE

  listener=$(ss -H -ltn 'sport = :6443' 2>/dev/null) ||
    complete "$failure_result" apiserver-listener-state-unreadable \
      "$failure_code" NONE
  [[ -n "$listener" ]] ||
    complete "$failure_result" apiserver-listener-missing \
      "$failure_code" NONE

  kubernetes_root=$(host_path /etc/kubernetes)
  package_directory_is_safe /etc/kubernetes "$kubernetes_root" 755 ||
    complete "$failure_result" kubernetes-root-metadata-drift \
      "$failure_code" NONE
  # 由 lib/kubectl.sh 消费（source 路径含变量，shellcheck 无法跟随）。
  # shellcheck disable=SC2034
  admin_conf=$(host_path /etc/kubernetes/admin.conf)
  etcd_member=$(host_path /var/lib/etcd/member)

  admin_conf_metadata_is_safe ||
    complete "$failure_result" admin-conf-metadata-drift "$failure_code" NONE
  manifest_dir=$(host_path /etc/kubernetes/manifests)
  package_directory_is_safe /etc/kubernetes/manifests "$manifest_dir" 700 ||
    complete "$failure_result" static-manifest-directory-metadata-drift \
      "$failure_code" NONE
  actual_manifests=$(find "$manifest_dir" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sed 's#.*/##' | sort) ||
    complete "$failure_result" static-manifest-state-unreadable "$failure_code" NONE
  expected_manifests=$'etcd.yaml\nkube-apiserver.yaml\nkube-controller-manager.yaml\nkube-scheduler.yaml'
  expected_manifests_with_keep=$'.kubelet-keep\netcd.yaml\nkube-apiserver.yaml\nkube-controller-manager.yaml\nkube-scheduler.yaml'
  if [[ "$actual_manifests" == "$expected_manifests_with_keep" ]]; then
    kubelet_keep_is_exact ||
      complete "$failure_result" static-manifest-package-placeholder-drift \
        "$failure_code" NONE
  elif [[ "$actual_manifests" != "$expected_manifests" ]]; then
    complete "$failure_result" static-manifest-set-drift "$failure_code" NONE
  fi
  for component in kube-apiserver kube-controller-manager kube-scheduler etcd; do
    manifest="${manifest_dir}/${component}.yaml"
    if [[ ! -f "$manifest" || -L "$manifest" || "$(path_mode "$manifest")" != 600 ]] || ! owned_by_expected "$manifest"; then
      complete "$failure_result" "manifest-metadata-drift-${component}" "$failure_code" NONE
    fi
  done
  [[ -d "$etcd_member" && ! -L "$etcd_member" ]] ||
    complete "$failure_result" etcd-member-missing "$failure_code" NONE
  [[ "$(systemctl is-active kubelet.service 2>/dev/null)" == active ]] ||
    complete "$failure_result" kubelet-inactive "$failure_code" NONE

  crictl_binary=$(host_path /usr/local/bin/crictl)
  for binary in "$crictl_binary" "$kubectl_binary"; do
    [[ -f "$binary" && ! -L "$binary" && -x "$binary" && "$(path_mode "$binary")" == 755 ]] ||
      complete "$failure_result" post-init-client-unsafe "$failure_code" NONE
    owned_by_expected "$binary" ||
      complete "$failure_result" post-init-client-owner-drift "$failure_code" NONE
  done
  runtime_endpoint=unix:///run/containerd/containerd.sock
  set +e
  control_plane_output=$("$crictl_binary" \
    --runtime-endpoint "$runtime_endpoint" \
    --image-endpoint "$runtime_endpoint" \
    ps --state Running --output json 2>/dev/null)
  crictl_exit=$?
  set -e
  (( crictl_exit == 0 )) ||
    complete "$failure_result" control-plane-runtime-query-failed "$failure_code" NONE
  if ! printf '%s' "$control_plane_output" | control_plane_json_is_exact "$runtime_set_mode"; then
    complete "$failure_result" control-plane-runtime-set-drift "$failure_code" NONE
  fi

  # 先把 admin.conf 捕获下来并校验结构，之后所有 kubectl 都只读这份已校验的字节。
  # 直接把磁盘路径交给 kubectl，读取期间文件被替换不会被发现（Stage 90 早已是这个
  # 形态，Stage 50 此前不是）。namespace 由调用方显式传入，不再由谓词硬编码。
  capture_admin_conf ||
    complete "$failure_result" admin-conf-content-or-structure-drift "$failure_code" NONE
  kubectl_query_is_empty --namespace kube-system get daemonset kube-proxy --ignore-not-found --output=name ||
    complete "$failure_result" kube-proxy-daemonset-present-or-unreadable "$failure_code" NONE
  kubectl_query_is_empty --namespace kube-system get pods --selector k8s-app=kube-proxy --output=name ||
    complete "$failure_result" kube-proxy-pods-present-or-unreadable "$failure_code" NONE
  kubectl_query_is_empty --namespace kube-system get configmap kube-proxy --ignore-not-found --output=name ||
    complete "$failure_result" kube-proxy-configmap-present-or-unreadable "$failure_code" NONE

  certificate=$(host_path /etc/kubernetes/pki/apiserver.crt)
  [[ -f "$certificate" && ! -L "$certificate" ]] ||
    complete "$failure_result" apiserver-certificate-missing "$failure_code" NONE
  openssl x509 -checkend 0 -noout -in "$certificate" >/dev/null 2>&1 ||
    complete "$failure_result" apiserver-certificate-expired "$failure_code" NONE
  certificate_output=$(openssl x509 -in "$certificate" -noout -subject -ext subjectAltName -enddate 2>/dev/null) ||
    complete "$failure_result" apiserver-certificate-unreadable "$failure_code" NONE
  certificate_subject=$(printf '%s\n' "$certificate_output" | sed -n 's/^subject=//p')
  certificate_expiry=$(printf '%s\n' "$certificate_output" | sed -n 's/^notAfter=//p')
  [[ -n "$certificate_subject" && "$certificate_subject" != *$'\n'* ]] ||
    complete "$failure_result" certificate-subject-invalid "$failure_code" NONE
  [[ -n "$certificate_expiry" && "$certificate_expiry" != *$'\n'* ]] ||
    complete "$failure_result" certificate-expiry-invalid "$failure_code" NONE
  grep -Fq "IP Address:${HOST_NODE_IP}" <<<"$certificate_output" ||
    complete "$failure_result" certificate-san-missing "$failure_code" NONE
}

parse_mode "$@" || exit "$?"
require_root || complete STOP_PRECONDITION not-root "$EXIT_PRECONDITION" NONE
for required_command in awk cat date dpkg dpkg-query find grep hostname id install ip md5sum mktemp openssl python3 readlink rm sed sha256sum sort ss stat swapon sync systemctl tr uname; do
  if [[ "$required_command" == sha256sum ]] && command -v shasum >/dev/null 2>&1; then
    continue
  fi
  require_command "$required_command" || complete STOP_PRECONDITION "missing-command-${required_command}" "$EXIT_PRECONDITION" NONE
done
[[ -x "$PYTHON_BINARY" ]] || complete STOP_PRECONDITION missing-command-python3 "$EXIT_PRECONDITION" NONE

# 主机身份与 config digest 唯一来源：bootstrap/hosts/<hostname>/。
# 顺序固定：parse_mode → require_root → required_command（含 hostname）→ load_host_config → host_pin。
load_host_config || complete STOP_PRECONDITION "$HOST_CONFIG_ERROR" "$EXIT_PRECONDITION" NONE
CONFIG_SHA256=$(host_pin kubeadm-init.yaml) ||
  complete STOP_SUPPLY_CHAIN_MISMATCH host-pins-invalid "$EXIT_SUPPLY_CHAIN" NONE
readonly CONFIG_SHA256
readonly CONFIG_FILE="${HOST_CONFIG_DIR}/kubeadm-init.yaml"

kernel_script="${script_dir}/20-prepare-kernel.sh"
containerd_script="${script_dir}/30-install-containerd.sh"
kubernetes_script="${script_dir}/40-install-kubernetes.sh"
cidr_script="${script_dir}/check_cidrs.py"
config_source=$CONFIG_FILE
kubeadm_binary=$(host_path /usr/bin/kubeadm)
kubectl_binary=$(host_path /usr/bin/kubectl)
if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 ]]; then
  kernel_script=${BOOTSTRAP_TEST_KERNEL_SCRIPT:-$kernel_script}
  containerd_script=${BOOTSTRAP_TEST_CONTAINERD_SCRIPT:-$containerd_script}
  kubernetes_script=${BOOTSTRAP_TEST_KUBERNETES_SCRIPT:-$kubernetes_script}
  cidr_script=${BOOTSTRAP_TEST_CIDR_SCRIPT:-$cidr_script}
  config_source=${BOOTSTRAP_TEST_CONFIG_FILE:-$config_source}
  for gate in "$kernel_script" "$containerd_script" "$kubernetes_script" "$cidr_script"; do
    safe_test_gate "$gate" || complete STOP_PRECONDITION test-gate-unsafe "$EXIT_PRECONDITION" NONE
  done
  [[ "$config_source" == /* && -O "$config_source" && ! -L "$config_source" ]] ||
    complete STOP_PRECONDITION test-config-unsafe "$EXIT_PRECONDITION" NONE
fi

state=$(initialization_state) ||
  complete STOP_PRECONDITION initialized-state-unreadable "$EXIT_PRECONDITION" NONE
case "$state" in
  FRESH)
    fresh_pre_init_gates
    ;;
  CANDIDATE)
    initialized_control_plane_gate STOP_UNKNOWN_STATE "$EXIT_UNKNOWN_STATE" initialized
    complete ALREADY_COMPLIANT control-plane-initialized 0 \
      '60-install-cilium.sh --check'
    ;;
  UNKNOWN)
    complete STOP_ALREADY_INITIALIZED initialized-or-partial-state-present \
      "$EXIT_UNKNOWN_STATE" NONE
    ;;
esac

# MODE 由公共 parse_mode helper 赋值。
# shellcheck disable=SC2153
if [[ "$MODE" == CHECK ]]; then
  complete PASS_KUBEADM_CHECK apply-required 0 '50-kubeadm-init.sh --apply'
fi

trap cleanup_config_snapshot EXIT
snapshot_result=0
create_config_snapshot || snapshot_result=$?
(( snapshot_result == 0 )) || {
  (( snapshot_result == EXIT_UNKNOWN_STATE )) && complete STOP_UNKNOWN_STATE kubeadm-config-snapshot-unsafe "$EXIT_UNKNOWN_STATE" NONE
  complete STOP_APPLY_FAILED kubeadm-config-snapshot-create-failed "$EXIT_APPLY_FAILED" NONE
}

config_file_is_safe "$config_snapshot" 600 || complete STOP_UNKNOWN_STATE kubeadm-config-snapshot-drift "$EXIT_UNKNOWN_STATE" NONE
if ! "$kubeadm_binary" config validate --config "$config_snapshot" >/dev/null 2>&1; then
  complete STOP_APPLY_FAILED kubeadm-config-validation-failed "$EXIT_APPLY_FAILED" NONE
fi
fresh_pre_init_gates
config_file_is_safe "$config_snapshot" 600 || complete STOP_UNKNOWN_STATE kubeadm-config-snapshot-drift "$EXIT_UNKNOWN_STATE" NONE
if ! "$kubeadm_binary" init phase preflight --config "$config_snapshot" >/dev/null 2>&1; then
  complete STOP_APPLY_FAILED kubeadm-phase-preflight-failed "$EXIT_APPLY_FAILED" NONE
fi
fresh_pre_init_gates
config_file_is_safe "$config_snapshot" 600 || complete STOP_UNKNOWN_STATE kubeadm-config-snapshot-drift "$EXIT_UNKNOWN_STATE" NONE
kubelet_default_conffile_is_pristine "$(host_path /etc/default/kubelet)" ||
  complete STOP_ALREADY_INITIALIZED kubelet-operator-override-present \
    "$EXIT_UNKNOWN_STATE" NONE
if ! "$kubeadm_binary" init --config "$config_snapshot" >/dev/null 2>&1; then
  complete STOP_APPLY_FAILED kubeadm-init-failed "$EXIT_APPLY_FAILED" NONE
fi
config_file_is_safe "$config_snapshot" 600 || complete STOP_UNKNOWN_STATE kubeadm-config-snapshot-drift "$EXIT_UNKNOWN_STATE" NONE
initialized_control_plane_gate STOP_VERIFY_FAILED "$EXIT_VERIFY_FAILED" exact

evidence_dir=$(host_path /root/dev-infra-evidence)
open_evidence 12-kubeadm "$evidence_dir" || complete STOP_EVIDENCE evidence-open-failed "$EXIT_UNKNOWN_STATE" NONE

log_evidence "HOST_NAME=${HOST_NAME}"
log_evidence "HOST_NODE_IP=${HOST_NODE_IP}"
log_evidence CONFIG_SHA256="$CONFIG_SHA256"
log_evidence NODE="$HOST_NAME"
log_evidence CONTROL_PLANE_ENDPOINT="${HOST_NODE_IP}:6443"
log_evidence ADMIN_CONF_PRESENT=true
log_evidence ADMIN_CONF_MODE=600
log_evidence STATIC_COMPONENTS=kube-apiserver,kube-controller-manager,kube-scheduler,etcd
log_evidence RUNTIME_COMPONENTS=kube-apiserver,kube-controller-manager,kube-scheduler,etcd
log_evidence KUBE_PROXY_OBJECTS=absent
log_evidence KUBELET_ACTIVE=active
log_evidence "CERTIFICATE_SUBJECT=${certificate_subject}"
log_evidence CERTIFICATE_SAN_IP="$HOST_NODE_IP"
log_evidence "CERTIFICATE_EXPIRY=${certificate_expiry}"
complete PASS_KUBEADM_INITIALIZED control-plane-initialized 0 '60-install-cilium.sh --check'
