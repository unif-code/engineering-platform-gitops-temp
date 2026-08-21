#!/bin/bash -p
set -Eeuo pipefail
export LC_ALL=C
umask 077

# 逐个收集违规变量名并在拒绝时列出（只列名不列值），便于运维定位后 unset。
untrusted_environment=
for untrusted_name in APT_CONFIG KUBECONFIG GNUPGHOME HELM_NAMESPACE HELM_DRIVER \
    HELM_KUBECONTEXT HELM_CONFIG_HOME HELM_CACHE_HOME HELM_DATA_HOME \
    DPKG_ADMINDIR DPKG_ROOT DPKG_FORCE DPKG_FRONTEND_LOCKED \
    CONTAINER_RUNTIME_ENDPOINT IMAGE_SERVICE_ENDPOINT \
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
source "${bootstrap_dir}/lib/admin-conf.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/kubectl.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/helm.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/common.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/path-facts.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/exec-safety.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/cni-manifest.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/dpkg-package-verification.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/host-config.sh"
# shellcheck disable=SC1091
source "${script_dir}/gates.sh"

# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=verify
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly CRI_ENDPOINT=unix:///run/containerd/containerd.sock
readonly STAGED_ROOT=/root/dev-infra-artifacts/pcs-2026-08-10.1
readonly HELM_ARCHIVE_NAME=helm-v3.21.0-linux-amd64.tar.gz
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly HELM_ARCHIVE_SHA256=0093eb572e3d2380f094df162ddb525e219249de88957afe24cfbb19632acd36
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly HELM_MEMBER=linux-amd64/helm
readonly GATEWAY_MANIFEST_NAME=standard-install.yaml
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly GATEWAY_MANIFEST_SHA256=24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
readonly FIELD_MANAGER=engineering-platform-bootstrap
readonly EXPECTED_KUBERNETES_VERSION=1.36.3-1.1
readonly EXPECTED_CNI_VERSION=1.9.1-1.1
readonly PYTHON_BINARY=/usr/bin/python3
readonly TAR_BINARY=/usr/bin/tar
readonly CONTAINERD_TRANSCRIPT=$'PHASE=containerd\nMODE=CHECK\nRESULT=ALREADY_COMPLIANT\nREASON=containerd-ready\nEVIDENCE=NONE\nEXIT_CODE=0\nNEXT=40-install-kubernetes\nSHA256=NONE'
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

containerd_gate_is_exact() {
  local captured
  captured=$(
    set +e
    cd "$bootstrap_dir" || exit 30
    BASH_ENV='' ENV='' PYTHONDONTWRITEBYTECODE=1 \
      /bin/bash -p "${bootstrap_dir}/stages/30-install-containerd/run.sh" --check 2>&1
    printf '__EXIT_CODE__=%s\n' "$?"
  )
  [[ "$captured" == "${CONTAINERD_TRANSCRIPT}"$'\n__EXIT_CODE__=0' ]]
}

package_state_is_exact() {
  dpkg-query -W -f='${Package}\t${Architecture}\t${db:Status-Want}\t${db:Status-Status}\t${Version}\n' 2>/dev/null |
    awk -F '\t' \
      -v kubernetes="$EXPECTED_KUBERNETES_VERSION" \
      -v cni="$EXPECTED_CNI_VERSION" '
      NF == 0 {next}
      NF != 5 || $1 !~ /^[a-z0-9][a-z0-9+.-]*$/ ||
        $2 !~ /^[a-z0-9][a-z0-9-]*$/ ||
        ($3 != "unknown" && $3 != "install" && $3 != "hold" &&
         $3 != "deinstall" && $3 != "purge") {exit 1}
      {
        key=$1 SUBSEP $2
        if (seen[key]++) exit 1
        if ($3 == "hold") {
          if ($2 != "amd64" ||
              ($1 != "kubeadm" && $1 != "kubectl" && $1 != "kubelet" &&
               $1 != "kubernetes-cni")) exit 1
          holds[$1]++
          hold_count++
        }
        if ($1 == "kubeadm" || $1 == "kubectl" || $1 == "kubelet" ||
            $1 == "kubernetes-cni") {
          expected=($1 == "kubernetes-cni" ? cni : kubernetes)
          if ($2 != "amd64" || $3 != "hold" || $4 != "installed" ||
              $5 != expected || target[$1]++) exit 1
          target_count++
        }
      }
      END {
        if (target_count != 4 || hold_count != 4 ||
            holds["kubeadm"] != 1 || holds["kubectl"] != 1 ||
            holds["kubelet"] != 1 || holds["kubernetes-cni"] != 1)
          exit 1
      }
    '
}

# 与 Stage 60 相同：helm 无法从管道读取 kubeconfig，改用 /root 下私有临时文件。

# trap 间接调用；只删除 /root 下本进程建立的 .helm-kubeconfig.* 目录。
# 静态检查 0.9 报 SC2317（不可达）、0.11 报 SC2329（未调用），均为 trap 间接调用的误报。
# shellcheck disable=SC2317,SC2329

# 子 shell 隔离 shopt；只检测残留，绝不自动删除（留给运维检查后手工清理）。

csr_summaries_are_safe() {
  local raw records name created requester usages request san_text san_marker
  CSR_SUMMARIES=()
  CSR_COUNT=0
  raw=$(kubectl_run get \
    certificatesigningrequests.certificates.k8s.io --output=json 2>/dev/null) || return 1
  records=$(printf '%s' "$raw" | python_isolated -c '
import base64
import json
import re
import sys
try:
    document = json.load(sys.stdin)
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list):
        raise ValueError
    for item in items:
        if not isinstance(item, dict):
            raise ValueError
        spec = item.get("spec")
        if not isinstance(spec, dict) or spec.get("signerName") != "kubernetes.io/kubelet-serving":
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError
        name = metadata.get("name")
        created = metadata.get("creationTimestamp")
        requester = spec.get("username")
        usages = spec.get("usages")
        request = spec.get("request")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?", name):
            raise ValueError
        if not isinstance(created, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created):
            raise ValueError
        # kubelet 的 ECDSA serving 证书不请求 key encipherment（仅 RSA 密钥传输需要）。
        expected = {"digital signature", "server auth"}
        if requester != "system:node:" + sys.argv[1] or not isinstance(usages, list) or len(usages) != 2 or set(usages) != expected:
            raise ValueError
        if not isinstance(request, str) or not request or "\t" in request or "\n" in request:
            raise ValueError
        base64.b64decode(request, validate=True)
        print("\t".join((name, created, requester, ",".join(sorted(expected)), request)))
except (TypeError, ValueError):
    raise SystemExit(1)
' "$HOST_NAME") || return 1
  while IFS=$'\t' read -r name created requester usages request; do
    [[ -n "$name" ]] || continue
    san_text=$(
      printf '%s' "$request" |
        python_isolated -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read(), validate=True))' |
        openssl_safe req -inform DER -noout -text 2>/dev/null
    ) || return 1
    san_marker=$(printf '%s' "$san_text" | python_isolated -c '
import sys
lines = sys.stdin.read().splitlines()
values = []
for index, line in enumerate(lines):
    if line.strip() == "X509v3 Subject Alternative Name:":
        if index + 1 >= len(lines):
            raise SystemExit(1)
        values.extend(part.strip() for part in lines[index + 1].strip().split(","))
if sorted(values) != ["DNS:" + sys.argv[1], "IP Address:" + sys.argv[2]]:
    raise SystemExit(1)
print("DNS:" + sys.argv[1] + ",IP:" + sys.argv[2])
' "$HOST_NAME" "$HOST_NODE_IP" 2>/dev/null) || return 1
    [[ "$san_marker" == "DNS:${HOST_NAME},IP:${HOST_NODE_IP}" ]] || return 1
    CSR_SUMMARIES+=(
      "CSR_NAME=${name}"
      "CSR_CREATION_TIMESTAMP=${created}"
      "CSR_REQUESTER=${requester}"
      "CSR_USAGES=${usages}"
      "CSR_SAN=${san_marker}"
    )
    CSR_COUNT=$((CSR_COUNT + 1))
  done <<<"$records"
}

parse_mode "$@" || exit "$?"
# MODE 由公共 parse_mode helper 赋值。
# shellcheck disable=SC2153
if [[ "$MODE" != CHECK ]]; then
  complete STOP_PRECONDITION read-only-stage-does-not-accept-apply "$EXIT_PRECONDITION" NONE
fi
require_root || complete STOP_PRECONDITION not-root "$EXIT_PRECONDITION" NONE
# helm kubeconfig 临时目录必须在任何退出路径（含被信号杀死）上被清掉。
trap 'cleanup_helm_kubeconfig || :' EXIT
for required_command in awk cmp date dpkg dpkg-query find grep hostname id mktemp rm rmdir sed sort stat swapon; do
  require_command "$required_command" || complete STOP_PRECONDITION "missing-command-${required_command}" "$EXIT_PRECONDITION" NONE
done
load_host_config || complete STOP_PRECONDITION "$HOST_CONFIG_ERROR" "$EXIT_PRECONDITION" NONE
[[ -x "$PYTHON_BINARY" ]] || complete STOP_PRECONDITION missing-command-python3 "$EXIT_PRECONDITION" NONE
[[ -x "$TAR_BINARY" ]] || complete STOP_PRECONDITION missing-command-tar "$EXIT_PRECONDITION" NONE
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  complete STOP_PRECONDITION missing-command-sha256 "$EXIT_PRECONDITION" NONE
fi

staged_root=$(host_path "$STAGED_ROOT")
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
helm_archive="${staged_root}/${HELM_ARCHIVE_NAME}"
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
gateway_manifest="${staged_root}/${GATEWAY_MANIFEST_NAME}"
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
kubeadm_binary=$(host_path /usr/bin/kubeadm)
# 由 lib/kubectl.sh 消费（source 路径含变量，shellcheck 无法跟随，故显式关闭）。
# shellcheck disable=SC2034
kubectl_binary=$(host_path /usr/bin/kubectl)
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
kubelet_binary=$(host_path /usr/bin/kubelet)
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
crictl_binary=$(host_path /usr/local/bin/crictl)
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
helm_binary=$(host_path /usr/local/bin/helm)
openssl_binary=$(host_path /usr/bin/openssl)
# 由 lib/kubectl.sh 消费（source 路径含变量，shellcheck 无法跟随，故显式关闭）。
# shellcheck disable=SC2034
admin_conf=$(host_path /etc/kubernetes/admin.conf)
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
cni_root=$(host_path /opt/cni/bin)

if [[ ! -x "$openssl_binary" ]] || ! safe_file "$openssl_binary" 755; then
  complete STOP_VERIFY_FAILED openssl-binary-metadata-drift "$EXIT_VERIFY_FAILED" NONE
fi
containerd_gate_is_exact || complete STOP_VERIFY_FAILED runtime-provenance-or-state-drift "$EXIT_VERIFY_FAILED" NONE
package_state_is_exact || complete STOP_VERIFY_FAILED package-version-selection-or-hold-drift "$EXIT_VERIFY_FAILED" NONE
managed_clients_are_exact || complete STOP_VERIFY_FAILED client-provenance-or-package-drift "$EXIT_VERIFY_FAILED" NONE
cni_payload_is_exact || complete STOP_VERIFY_FAILED cni-payload-drift "$EXIT_VERIFY_FAILED" NONE
capture_admin_conf || complete STOP_VERIFY_FAILED admin-conf-content-or-structure-drift "$EXIT_VERIFY_FAILED" NONE
# CHECK 的唯一写入是 helm kubeconfig 临时目录；上次运行被中断留下的残留说明
# 状态未知，只报告不删除，由运维检查后手工清理。
if helm_kubeconfig_residue_exists; then
  complete STOP_VERIFY_FAILED helm-kubeconfig-residue "$EXIT_VERIFY_FAILED" NONE
fi
staged_inputs_are_exact || complete STOP_VERIFY_FAILED staged-input-drift "$EXIT_VERIFY_FAILED" NONE
helm_binary_is_exact || complete STOP_VERIFY_FAILED helm-binary-provenance-drift "$EXIT_VERIFY_FAILED" NONE
version_contract_is_exact || complete STOP_VERIFY_FAILED executable-version-drift "$EXIT_VERIFY_FAILED" NONE
cri_is_healthy || complete STOP_VERIFY_FAILED cri-runtime-unhealthy "$EXIT_VERIFY_FAILED" NONE
api_is_exact_and_ready || complete STOP_VERIFY_FAILED api-endpoint-or-health-drift "$EXIT_VERIFY_FAILED" NONE
kube_proxy_is_absent || complete STOP_VERIFY_FAILED kube-proxy-object-present-or-unreadable "$EXIT_VERIFY_FAILED" NONE
helm_release_is_exact || complete STOP_VERIFY_FAILED helm-release-allowlist-drift "$EXIT_VERIFY_FAILED" NONE
gateway_bundle_is_exact || complete STOP_VERIFY_FAILED gateway-bundle-drift "$EXIT_VERIFY_FAILED" NONE
cilium_is_ready || complete STOP_VERIFY_FAILED cilium-workload-unhealthy "$EXIT_VERIFY_FAILED" NONE
node_is_ready || complete STOP_VERIFY_FAILED node-readiness-or-address-drift "$EXIT_VERIFY_FAILED" NONE
swap_is_exact || complete STOP_VERIFY_FAILED swap-contract-drift "$EXIT_VERIFY_FAILED" NONE
kubelet_swap_config_is_exact || complete STOP_VERIFY_FAILED kubelet-swap-config-drift "$EXIT_VERIFY_FAILED" NONE
csr_summaries_are_safe || complete STOP_VERIFY_FAILED kubelet-serving-csr-drift "$EXIT_VERIFY_FAILED" NONE

evidence_dir=$(host_path /root/dev-infra-evidence)
open_evidence 14-verify "$evidence_dir" || complete STOP_EVIDENCE evidence-open-failed "$EXIT_UNKNOWN_STATE" NONE
log_evidence HOST_NAME="$HOST_NAME"
log_evidence HOST_NODE_IP="$HOST_NODE_IP"
log_evidence KUBERNETES_VERSION=1.36.3
log_evidence KUBERNETES_PACKAGES=kubeadm,kubectl,kubelet,kubernetes-cni
log_evidence CRI_RUNTIME_READY=true
log_evidence API_ENDPOINT="${HOST_NODE_IP}:6443"
log_evidence KUBE_PROXY_OBJECTS=absent
log_evidence HELM_RELEASE=kube-system/cilium
log_evidence HELM_CHART=cilium-1.20.0
log_evidence CILIUM_VERSION=1.20.0
log_evidence CILIUM_DAEMONSET_READY=true
log_evidence CILIUM_OPERATOR_READY=true
log_evidence GATEWAY_API_BUNDLE=v1.6.1-standard
log_evidence NODE_NAME="$HOST_NAME"
log_evidence NODE_READY=true
log_evidence NODE_INTERNAL_IP="$HOST_NODE_IP"
log_evidence SWAP_DEVICE="$HOST_SWAP_FILE"
log_evidence SWAP_BYTES="${HOST_SWAP_MIN_BYTES}-${HOST_SWAP_MAX_BYTES}"
log_evidence KUBELET_FAIL_SWAP_ON=false
log_evidence KUBELET_SWAP_BEHAVIOR=NoSwap
if (( CSR_COUNT > 0 )); then
  for summary in "${CSR_SUMMARIES[@]}"; do
    log_evidence "$summary"
  done
fi
log_evidence "CSR_COUNT=${CSR_COUNT}"
complete PASS_BOOTSTRAP_VERIFIED bootstrap-contract-verified 0 NONE
