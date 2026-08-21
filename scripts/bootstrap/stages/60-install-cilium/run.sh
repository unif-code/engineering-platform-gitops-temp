#!/bin/bash -p
set -Eeuo pipefail
export LC_ALL=C
umask 077

# 逐个收集违规变量名并在拒绝时列出（只列名不列值），便于运维定位后 unset。
untrusted_environment=
for untrusted_name in APT_CONFIG KUBECONFIG GNUPGHOME HELM_NAMESPACE HELM_DRIVER \
    HELM_KUBECONTEXT HELM_CONFIG_HOME HELM_CACHE_HOME HELM_DATA_HOME \
    DPKG_ADMINDIR DPKG_ROOT DPKG_FORCE DPKG_FRONTEND_LOCKED \
    KUBECACHEDIR KUBECTL_EXTERNAL_DIFF TAR_OPTIONS BASH_ENV ENV; do
  [[ -z "${!untrusted_name+x}" ]] ||
    untrusted_environment="${untrusted_environment:+${untrusted_environment},}${untrusted_name}"
done
for untrusted_name in "${!HELM_@}" "${!PYTHON@}" "${!OPENSSL_@}" "${!KUBECTL_@}"; do
  [[ ",${untrusted_environment}," == *",${untrusted_name},"* ]] ||
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
  if [[ -z "${BOOTSTRAP_TEST_ROOT:-}" || "$BOOTSTRAP_TEST_ROOT" != /* ||
        "$BOOTSTRAP_TEST_ROOT" == / || ! -d "$BOOTSTRAP_TEST_ROOT" ||
        -L "$BOOTSTRAP_TEST_ROOT" || ! -O "$BOOTSTRAP_TEST_ROOT" ]]; then
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
# run.sh 比原来的平铺位置深两层；lib/ 与其它 stage 都以 bootstrap_dir 为锚点。
bootstrap_dir=$(cd "${script_dir}/../.." && pwd -P)
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/common.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/path-facts.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/exec-safety.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/host-config.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/admin-conf.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/kubectl.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/helm.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/dpkg-package-verification.sh"
# shellcheck disable=SC1091
source "${script_dir}/gates.sh"

# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=install-cilium
readonly STAGED_ROOT=/root/dev-infra-artifacts/pcs-2026-08-10.1
readonly HELM_ARCHIVE_NAME=helm-v3.21.0-linux-amd64.tar.gz
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly HELM_ARCHIVE_SHA256=0093eb572e3d2380f094df162ddb525e219249de88957afe24cfbb19632acd36
readonly GATEWAY_MANIFEST_NAME=standard-install.yaml
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly GATEWAY_MANIFEST_SHA256=24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73
readonly CILIUM_CHART_NAME=cilium-1.20.0.tgz
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly CILIUM_CHART_SHA256=c5f013912360d1a334f44ef25f36da59ba3414cdb48f466ee12d0c4fdff27883
readonly PYTHON_BINARY=/usr/bin/python3
readonly TAR_BINARY=/usr/bin/tar
readonly FIELD_MANAGER=engineering-platform-bootstrap
# helm --atomic 对 DaemonSet/Deployment 的就绪判定允许 desired - ready <= maxUnavailable，
# 单节点 + Cilium 默认 maxUnavailable 下 0 个就绪也会返回；装完后必须有界轮询直到 COMPLIANT。
readonly POST_INSTALL_READY_TIMEOUT_SECONDS=600
readonly POST_INSTALL_READY_INTERVAL_SECONDS=10
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly HELM_MEMBER=linux-amd64/helm
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly -a GATEWAY_OBJECTS=(
  customresourcedefinition.apiextensions.k8s.io/backendtlspolicies.gateway.networking.k8s.io
  customresourcedefinition.apiextensions.k8s.io/gatewayclasses.gateway.networking.k8s.io
  customresourcedefinition.apiextensions.k8s.io/gateways.gateway.networking.k8s.io
  customresourcedefinition.apiextensions.k8s.io/grpcroutes.gateway.networking.k8s.io
  customresourcedefinition.apiextensions.k8s.io/httproutes.gateway.networking.k8s.io
  customresourcedefinition.apiextensions.k8s.io/listenersets.gateway.networking.k8s.io
  customresourcedefinition.apiextensions.k8s.io/referencegrants.gateway.networking.k8s.io
  customresourcedefinition.apiextensions.k8s.io/tcproutes.gateway.networking.k8s.io
  customresourcedefinition.apiextensions.k8s.io/tlsroutes.gateway.networking.k8s.io
  customresourcedefinition.apiextensions.k8s.io/udproutes.gateway.networking.k8s.io
  validatingadmissionpolicy.admissionregistration.k8s.io/safe-upgrades.gateway.networking.k8s.io
  validatingadmissionpolicybinding.admissionregistration.k8s.io/safe-upgrades.gateway.networking.k8s.io
)

# helm 3.21 无法从进程替换的管道读取 kubeconfig（client-go 会多次加载，第二次
# 读到空配置后回退到 localhost:8080）。因此把已校验的内存内容写入 /root 下的私有
# 临时文件（0700 目录、0600 文件，umask 077 保证），按路径传给 helm，用完即删。
# helm 仍只消费校验过的字节；前后的 admin_conf_is_safe 照旧检测磁盘文件竞态。

# trap 间接调用；只删除 /root 下本进程建立的 .helm-kubeconfig.* 目录。

# 子 shell 隔离 shopt；只检测残留，绝不自动删除（留给运维检查后手工清理）。

# trap 间接调用；只清理受验证的同目录 Helm 临时文件。
# shellcheck disable=SC2329

load_cluster_state() {
  local helm_state=$1
  kube_proxy_absent || {
    CLUSTER_STATE=UNKNOWN
    return
  }
  GATEWAY_STATE=$(gateway_bundle_state) || GATEWAY_STATE=UNKNOWN
  HELM_SECRET_STATE=$(helm_secret_state) || HELM_SECRET_STATE=UNKNOWN
  CILIUM_WORKLOAD_STATE=$(cilium_workload_state) || CILIUM_WORKLOAD_STATE=UNKNOWN
  ENVOY_DAEMONSET_STATE=$(envoy_daemonset_state) || ENVOY_DAEMONSET_STATE=UNKNOWN
  ENVOY_PODS_STATE=$(envoy_pods_state) || ENVOY_PODS_STATE=UNKNOWN
  CILIUM_CONFIG_STATE=$(cilium_config_state) || CILIUM_CONFIG_STATE=UNKNOWN
  if [[ "$helm_state" == COMPLIANT ]]; then
    HELM_RELEASE_STATE=$(helm_release_state) || HELM_RELEASE_STATE=UNKNOWN
  else
    HELM_RELEASE_STATE=MISSING
  fi
  if [[ "$GATEWAY_STATE" == COMPLIANT && "$helm_state" == COMPLIANT &&
        "$HELM_SECRET_STATE" == COMPLIANT && "$CILIUM_WORKLOAD_STATE" == COMPLIANT &&
        "$ENVOY_DAEMONSET_STATE" == COMPLIANT && "$ENVOY_PODS_STATE" == COMPLIANT &&
        "$CILIUM_CONFIG_STATE" == COMPLIANT &&
        "$HELM_RELEASE_STATE" == COMPLIANT ]]; then
    CLUSTER_STATE=COMPLIANT
  elif [[ ( "$GATEWAY_STATE" == MISSING || "$GATEWAY_STATE" == COMPLIANT ) &&
          "$HELM_SECRET_STATE" == MISSING && "$CILIUM_WORKLOAD_STATE" == MISSING &&
          "$ENVOY_DAEMONSET_STATE" == MISSING && "$ENVOY_PODS_STATE" == MISSING &&
          "$CILIUM_CONFIG_STATE" == MISSING &&
          "$HELM_RELEASE_STATE" == MISSING ]]; then
    CLUSTER_STATE=APPLY_REQUIRED
  else
    CLUSTER_STATE=UNKNOWN
  fi
}

parse_mode "$@" || exit "$?"
require_root || complete STOP_PRECONDITION not-root "$EXIT_PRECONDITION" NONE
# helm kubeconfig 临时目录必须在任何退出路径（含被信号杀死）上被清掉。
trap 'cleanup_helm_kubeconfig || :' EXIT
for required_command in awk chmod cmp date dirname dpkg dpkg-query grep hostname id install ln mktemp rm rmdir sleep stat sync; do
  require_command "$required_command" || complete STOP_PRECONDITION "missing-command-${required_command}" "$EXIT_PRECONDITION" NONE
done
[[ -x "$PYTHON_BINARY" ]] || complete STOP_PRECONDITION missing-command-python3 "$EXIT_PRECONDITION" NONE
[[ -x "$TAR_BINARY" ]] || complete STOP_PRECONDITION missing-command-tar "$EXIT_PRECONDITION" NONE
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  complete STOP_PRECONDITION missing-command-sha256 "$EXIT_PRECONDITION" NONE
fi

# 主机身份与 values digest 唯一来源：bootstrap/hosts/<hostname>/。
# 必须排在 required_command（含 hostname）之后、任何读取 HOST_* 的谓词之前。
load_host_config || complete STOP_PRECONDITION "$HOST_CONFIG_ERROR" "$EXIT_PRECONDITION" NONE
# CHECK 的唯一写入是 helm kubeconfig 临时目录；上次运行被中断留下的残留说明
# 状态未知，只报告不删除，由运维检查后手工清理。
if helm_kubeconfig_residue_exists; then
  complete STOP_UNKNOWN_STATE helm-kubeconfig-residue "$EXIT_UNKNOWN_STATE" NONE
fi
VALUES_SHA256=$(host_pin cilium-values.yaml) ||
  complete STOP_SUPPLY_CHAIN_MISMATCH host-pins-invalid "$EXIT_SUPPLY_CHAIN" NONE
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly VALUES_SHA256
readonly VALUES_FILE="${HOST_CONFIG_DIR}/cilium-values.yaml"

staged_root=$(host_path "$STAGED_ROOT")
helm_archive="${staged_root}/${HELM_ARCHIVE_NAME}"
gateway_manifest="${staged_root}/${GATEWAY_MANIFEST_NAME}"
cilium_chart="${staged_root}/${CILIUM_CHART_NAME}"
values_source=$VALUES_FILE
post_install_timeout=$POST_INSTALL_READY_TIMEOUT_SECONDS
post_install_interval=$POST_INSTALL_READY_INTERVAL_SECONDS
if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 ]]; then
  values_source=${BOOTSTRAP_TEST_VALUES_FILE:-$values_source}
  [[ "$values_source" == /* && -O "$values_source" ]] ||
    complete STOP_PRECONDITION test-values-file-unsafe "$EXIT_PRECONDITION" NONE
  post_install_timeout=${BOOTSTRAP_TEST_POST_INSTALL_TIMEOUT:-$post_install_timeout}
  post_install_interval=${BOOTSTRAP_TEST_POST_INSTALL_INTERVAL:-$post_install_interval}
  [[ "$post_install_timeout" =~ ^[0-9]{1,5}$ && "$post_install_interval" =~ ^[0-9]{1,4}$ ]] ||
    complete STOP_PRECONDITION test-post-install-wait-unsafe "$EXIT_PRECONDITION" NONE
fi
readonly post_install_timeout post_install_interval
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
kubectl_binary=$(host_path /usr/bin/kubectl)
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
helm_binary=$(host_path /usr/local/bin/helm)
# 由 lib/kubectl.sh 消费（source 路径含变量，shellcheck 无法跟随，故显式关闭）。
# shellcheck disable=SC2034
admin_conf=$(host_path /etc/kubernetes/admin.conf)
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
helm_archive_input=$helm_archive
gateway_manifest_input=$gateway_manifest
cilium_chart_input=$cilium_chart
values_input=$values_source

staged_inputs_gate || complete STOP_SUPPLY_CHAIN_MISMATCH staged-input-contract-drift "$EXIT_SUPPLY_CHAIN" NONE
managed_kubectl_gate || complete STOP_UNKNOWN_STATE kubectl-provenance-drift "$EXIT_UNKNOWN_STATE" NONE
capture_admin_conf || complete STOP_UNKNOWN_STATE admin-conf-content-or-structure-drift "$EXIT_UNKNOWN_STATE" NONE
api_endpoint_is_exact || complete STOP_UNKNOWN_STATE api-endpoint-drift "$EXIT_UNKNOWN_STATE" NONE
helm_state=$(helm_binary_state)
[[ "$helm_state" != ARCHIVE_UNSAFE ]] || complete STOP_SUPPLY_CHAIN_MISMATCH helm-archive-unsafe "$EXIT_SUPPLY_CHAIN" NONE
[[ "$helm_state" != UNKNOWN ]] || complete STOP_UNKNOWN_STATE helm-binary-or-shadow-unknown "$EXIT_UNKNOWN_STATE" NONE
load_cluster_state "$helm_state"
[[ "$CLUSTER_STATE" != UNKNOWN ]] || complete STOP_UNKNOWN_STATE gateway-cilium-cluster-state-unknown "$EXIT_UNKNOWN_STATE" NONE

if [[ "$CLUSTER_STATE" == COMPLIANT ]]; then
  complete ALREADY_COMPLIANT cilium-ready 0 'stages/90-verify/run.sh --check'
fi

# MODE 由公共 parse_mode helper 赋值。
# shellcheck disable=SC2153
if [[ "$MODE" == CHECK ]]; then
  complete PASS_CILIUM_CHECK apply-required 0 'stages/60-install-cilium/run.sh --apply'
fi

trap 'cleanup_apply_state || :' EXIT
snapshot_result=0
create_apply_snapshots || snapshot_result=$?
(( snapshot_result == 0 )) || {
  (( snapshot_result == EXIT_SUPPLY_CHAIN )) && complete STOP_SUPPLY_CHAIN_MISMATCH apply-input-snapshot-drift "$EXIT_SUPPLY_CHAIN" NONE
  (( snapshot_result == EXIT_UNKNOWN_STATE )) && complete STOP_UNKNOWN_STATE apply-input-snapshot-unsafe "$EXIT_UNKNOWN_STATE" NONE
  complete STOP_APPLY_FAILED apply-input-snapshot-failed "$EXIT_APPLY_FAILED" NONE
}
if [[ "$helm_state" == MISSING ]]; then
  publish_result=0
  publish_helm_binary || publish_result=$?
  (( publish_result == 0 )) || {
    (( publish_result == EXIT_SUPPLY_CHAIN )) && complete STOP_SUPPLY_CHAIN_MISMATCH helm-extraction-or-input-raced "$EXIT_SUPPLY_CHAIN" NONE
    (( publish_result == EXIT_UNKNOWN_STATE )) && complete STOP_UNKNOWN_STATE helm-publication-raced "$EXIT_UNKNOWN_STATE" NONE
    complete STOP_APPLY_FAILED helm-publication-failed "$EXIT_APPLY_FAILED" NONE
  }
fi

staged_inputs_gate || complete STOP_SUPPLY_CHAIN_MISMATCH staged-input-contract-raced "$EXIT_SUPPLY_CHAIN" NONE
apply_snapshot_gate || complete STOP_SUPPLY_CHAIN_MISMATCH apply-input-snapshot-raced "$EXIT_SUPPLY_CHAIN" NONE
helm_state=$(helm_binary_state)
[[ "$helm_state" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE helm-binary-verification-failed "$EXIT_UNKNOWN_STATE" NONE
managed_kubectl_gate || complete STOP_UNKNOWN_STATE kubectl-provenance-raced "$EXIT_UNKNOWN_STATE" NONE
admin_conf_is_safe || complete STOP_UNKNOWN_STATE admin-conf-metadata-raced "$EXIT_UNKNOWN_STATE" NONE
api_endpoint_is_exact || complete STOP_UNKNOWN_STATE api-endpoint-raced "$EXIT_UNKNOWN_STATE" NONE
load_cluster_state "$helm_state"
[[ "$CLUSTER_STATE" == APPLY_REQUIRED ]] || complete STOP_UNKNOWN_STATE pre-gateway-cluster-state-raced "$EXIT_UNKNOWN_STATE" NONE

if [[ "$GATEWAY_STATE" == MISSING ]]; then
  managed_kubectl_gate || complete STOP_UNKNOWN_STATE kubectl-raced-before-gateway "$EXIT_UNKNOWN_STATE" NONE
  admin_conf_is_safe || complete STOP_UNKNOWN_STATE admin-conf-raced-before-gateway "$EXIT_UNKNOWN_STATE" NONE
  api_endpoint_is_exact || complete STOP_UNKNOWN_STATE api-endpoint-raced-before-gateway "$EXIT_UNKNOWN_STATE" NONE
  staged_inputs_gate || complete STOP_SUPPLY_CHAIN_MISMATCH staged-input-raced-at-gateway "$EXIT_SUPPLY_CHAIN" NONE
  apply_snapshot_gate || complete STOP_SUPPLY_CHAIN_MISMATCH apply-input-snapshot-raced-at-gateway "$EXIT_SUPPLY_CHAIN" NONE
  if ! kubectl_run apply \
    --server-side=true \
    --field-manager="$FIELD_MANAGER" \
    --filename "$gateway_manifest_input" >/dev/null 2>&1; then
    complete STOP_APPLY_FAILED gateway-server-side-apply-failed "$EXIT_APPLY_FAILED" NONE
  fi
  staged_inputs_gate || complete STOP_SUPPLY_CHAIN_MISMATCH staged-input-raced-after-gateway "$EXIT_SUPPLY_CHAIN" NONE
  apply_snapshot_gate || complete STOP_SUPPLY_CHAIN_MISMATCH apply-input-snapshot-raced-after-gateway "$EXIT_SUPPLY_CHAIN" NONE
  managed_kubectl_gate || complete STOP_UNKNOWN_STATE kubectl-raced-after-gateway "$EXIT_UNKNOWN_STATE" NONE
  admin_conf_is_safe || complete STOP_UNKNOWN_STATE admin-conf-raced-after-gateway "$EXIT_UNKNOWN_STATE" NONE
  api_endpoint_is_exact || complete STOP_UNKNOWN_STATE api-endpoint-raced-after-gateway "$EXIT_UNKNOWN_STATE" NONE
  load_cluster_state "$helm_state"
  [[ "$CLUSTER_STATE" == APPLY_REQUIRED && "$GATEWAY_STATE" == COMPLIANT ]] ||
    complete STOP_UNKNOWN_STATE gateway-post-apply-state-unknown "$EXIT_UNKNOWN_STATE" NONE
fi

staged_inputs_gate || complete STOP_SUPPLY_CHAIN_MISMATCH staged-input-raced-before-helm "$EXIT_SUPPLY_CHAIN" NONE
apply_snapshot_gate || complete STOP_SUPPLY_CHAIN_MISMATCH apply-input-snapshot-raced-before-helm "$EXIT_SUPPLY_CHAIN" NONE
managed_kubectl_gate || complete STOP_UNKNOWN_STATE kubectl-raced-before-helm "$EXIT_UNKNOWN_STATE" NONE
admin_conf_is_safe || complete STOP_UNKNOWN_STATE admin-conf-raced-before-helm "$EXIT_UNKNOWN_STATE" NONE
api_endpoint_is_exact || complete STOP_UNKNOWN_STATE api-endpoint-raced-before-helm "$EXIT_UNKNOWN_STATE" NONE
kube_proxy_absent || complete STOP_UNKNOWN_STATE kube-proxy-state-raced "$EXIT_UNKNOWN_STATE" NONE
helm_state=$(helm_binary_state)
[[ "$helm_state" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE helm-binary-raced-before-install "$EXIT_UNKNOWN_STATE" NONE
load_cluster_state "$helm_state"
[[ "$CLUSTER_STATE" == APPLY_REQUIRED && "$GATEWAY_STATE" == COMPLIANT ]] ||
  complete STOP_UNKNOWN_STATE pre-helm-cluster-state-raced "$EXIT_UNKNOWN_STATE" NONE
staged_inputs_gate || complete STOP_SUPPLY_CHAIN_MISMATCH staged-input-raced-at-helm "$EXIT_SUPPLY_CHAIN" NONE
apply_snapshot_gate || complete STOP_SUPPLY_CHAIN_MISMATCH apply-input-snapshot-raced-at-helm "$EXIT_SUPPLY_CHAIN" NONE
helm_state=$(helm_binary_state)
[[ "$helm_state" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE helm-binary-raced-at-install "$EXIT_UNKNOWN_STATE" NONE
apply_snapshot_gate || complete STOP_SUPPLY_CHAIN_MISMATCH apply-input-snapshot-raced-at-consumer "$EXIT_SUPPLY_CHAIN" NONE
if ! helm_cluster_run install cilium "$cilium_chart_input" \
  --namespace kube-system \
  --values "$values_input" \
  --atomic \
  --timeout 10m0s >/dev/null 2>&1; then
  complete STOP_APPLY_FAILED cilium-helm-install-failed "$EXIT_APPLY_FAILED" NONE
fi

staged_inputs_gate || complete STOP_SUPPLY_CHAIN_MISMATCH staged-input-raced-after-helm "$EXIT_SUPPLY_CHAIN" NONE
apply_snapshot_gate || complete STOP_SUPPLY_CHAIN_MISMATCH apply-input-snapshot-raced-after-helm "$EXIT_SUPPLY_CHAIN" NONE
managed_kubectl_gate || complete STOP_VERIFY_FAILED kubectl-post-install-drift "$EXIT_VERIFY_FAILED" NONE
admin_conf_is_safe || complete STOP_VERIFY_FAILED admin-conf-post-install-drift "$EXIT_VERIFY_FAILED" NONE
api_endpoint_is_exact || complete STOP_VERIFY_FAILED api-endpoint-post-install-drift "$EXIT_VERIFY_FAILED" NONE
helm_state=$(helm_binary_state)
[[ "$helm_state" == COMPLIANT ]] || complete STOP_VERIFY_FAILED helm-post-install-drift "$EXIT_VERIFY_FAILED" NONE
# 有界轮询：每轮完整重跑 load_cluster_state；超时仍未 COMPLIANT 才 fail-closed。
post_install_deadline=$(( SECONDS + post_install_timeout ))
while :; do
  load_cluster_state "$helm_state"
  [[ "$CLUSTER_STATE" != COMPLIANT ]] || break
  (( SECONDS < post_install_deadline )) ||
    complete STOP_VERIFY_FAILED cilium-post-install-state-invalid "$EXIT_VERIFY_FAILED" NONE
  sleep "$post_install_interval"
done

cleanup_apply_state || complete STOP_UNKNOWN_STATE apply-temporary-cleanup-unsafe "$EXIT_UNKNOWN_STATE" NONE
trap - EXIT
evidence_dir=$(host_path /root/dev-infra-evidence)
open_evidence 13-cilium "$evidence_dir" || complete STOP_EVIDENCE evidence-open-failed "$EXIT_UNKNOWN_STATE" NONE
log_evidence "HOST_NAME=${HOST_NAME}"
log_evidence "HOST_NODE_IP=${HOST_NODE_IP}"
log_evidence HELM_VERSION=v3.21.0
log_evidence GATEWAY_API_BUNDLE=v1.6.1-standard
log_evidence GATEWAY_FIELD_MANAGER="$FIELD_MANAGER"
log_evidence CILIUM_RELEASE=cilium
log_evidence CILIUM_NAMESPACE=kube-system
log_evidence CILIUM_VERSION=1.20.0
log_evidence KUBE_PROXY_OBJECTS=absent
log_evidence CILIUM_DAEMONSET_READY=true
log_evidence CILIUM_OPERATOR_READY=true
complete PASS_CILIUM_INSTALLED cilium-ready 0 'stages/90-verify/run.sh --check'
