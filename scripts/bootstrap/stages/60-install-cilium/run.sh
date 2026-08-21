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

# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=install-cilium
readonly STAGED_ROOT=/root/dev-infra-artifacts/pcs-2026-08-10.1
readonly HELM_ARCHIVE_NAME=helm-v3.21.0-linux-amd64.tar.gz
readonly HELM_ARCHIVE_SHA256=0093eb572e3d2380f094df162ddb525e219249de88957afe24cfbb19632acd36
readonly GATEWAY_MANIFEST_NAME=standard-install.yaml
readonly GATEWAY_MANIFEST_SHA256=24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73
readonly CILIUM_CHART_NAME=cilium-1.20.0.tgz
readonly CILIUM_CHART_SHA256=c5f013912360d1a334f44ef25f36da59ba3414cdb48f466ee12d0c4fdff27883
readonly PYTHON_BINARY=/usr/bin/python3
readonly TAR_BINARY=/usr/bin/tar
readonly FIELD_MANAGER=engineering-platform-bootstrap
# helm --atomic 对 DaemonSet/Deployment 的就绪判定允许 desired - ready <= maxUnavailable，
# 单节点 + Cilium 默认 maxUnavailable 下 0 个就绪也会返回；装完后必须有界轮询直到 COMPLIANT。
readonly POST_INSTALL_READY_TIMEOUT_SECONDS=600
readonly POST_INSTALL_READY_INTERVAL_SECONDS=10
readonly HELM_MEMBER=linux-amd64/helm
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

safe_file_with_digest() {
  local path=$1 expected_mode=$2 expected_digest=$3 digest
  [[ -f "$path" && ! -L "$path" && "$(path_mode "$path")" == "$expected_mode" ]] || return 1
  owned_by_expected "$path" || return 1
  digest=$(sha256_file "$path") || return 1
  [[ "$digest" == "$expected_digest" ]]
}

values_semantics_are_exact() {
  python_isolated - "$1" "$HOST_NODE_IP" <<'PY' >/dev/null 2>&1
import pathlib
import sys

node_ip = sys.argv[2]
expected = f"""kubeProxyReplacement: true
k8sServiceHost: {node_ip}
k8sServicePort: 6443

cgroup:
  autoMount:
    enabled: false
  hostRoot: /sys/fs/cgroup

gatewayAPI:
  enabled: true

hubble:
  enabled: false

image:
  digest: sha256:383968cd5e8873f7976fa76aa6196045643558f4cc9518a207b9335cb24a0e93
  useDigest: true

ipam:
  mode: kubernetes

operator:
  image:
    genericDigest: sha256:80744a8cc7c91c2f9e6347629406844eb35d79b30a732c6d41c15b17232a74f3
    useDigest: true
  replicas: 1
"""
try:
    actual = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
except (OSError, UnicodeError):
    raise SystemExit(1)
if actual != expected:
    raise SystemExit(1)
PY
}

staged_inputs_gate() {
  safe_directory "$(host_path /root)" 700 || return 1
  safe_directory "$(host_path /root/dev-infra-artifacts)" 700 || return 1
  safe_directory "$staged_root" 700 || return 1
  safe_file_with_digest "$helm_archive" 600 "$HELM_ARCHIVE_SHA256" || return 1
  safe_file_with_digest "$gateway_manifest" 600 "$GATEWAY_MANIFEST_SHA256" || return 1
  safe_file_with_digest "$cilium_chart" 600 "$CILIUM_CHART_SHA256" || return 1
  safe_file_with_digest "$values_source" 644 "$VALUES_SHA256" || return 1
  values_semantics_are_exact "$values_source"
}

managed_kubectl_gate() {
  local shadow ownership
  for shadow in /usr/sbin/kubectl /usr/local/bin/kubectl /usr/local/sbin/kubectl; do
    shadow=$(host_path "$shadow")
    [[ ! -e "$shadow" && ! -L "$shadow" ]] || return 1
  done
  [[ -f "$kubectl_binary" && ! -L "$kubectl_binary" && -x "$kubectl_binary" &&
      "$(path_mode "$kubectl_binary")" == 755 ]] || return 1
  owned_by_expected "$kubectl_binary" || return 1
  ownership=$(dpkg-query -S /usr/bin/kubectl 2>/dev/null) || return 1
  [[ "$ownership" == 'kubectl: /usr/bin/kubectl' ]] || return 1
  dpkg_package_verification_is_exact kubectl
}

# helm 3.21 无法从进程替换的管道读取 kubeconfig（client-go 会多次加载，第二次
# 读到空配置后回退到 localhost:8080）。因此把已校验的内存内容写入 /root 下的私有
# 临时文件（0700 目录、0600 文件，umask 077 保证），按路径传给 helm，用完即删。
# helm 仍只消费校验过的字节；前后的 admin_conf_is_safe 照旧检测磁盘文件竞态。

# trap 间接调用；只删除 /root 下本进程建立的 .helm-kubeconfig.* 目录。

# 子 shell 隔离 shopt；只检测残留，绝不自动删除（留给运维检查后手工清理）。

api_endpoint_is_exact() {
  local output
  output=$(kubectl_run config view --minify \
    '--output=jsonpath={.clusters[0].cluster.server}' 2>/dev/null) || return 1
  [[ "$output" == "https://${HOST_NODE_IP}:6443" ]]
}

helm_parent_and_shadows_gate() {
  local shadow
  safe_directory "$(host_path /usr)" 755 || return 1
  safe_directory "$(host_path /usr/local)" 755 || return 1
  safe_directory "$(host_path /usr/local/bin)" 755 || return 1
  for shadow in /usr/bin/helm /usr/sbin/helm /usr/local/sbin/helm; do
    shadow=$(host_path "$shadow")
    [[ ! -e "$shadow" && ! -L "$shadow" ]] || return 1
  done
}

helm_binary_state() {
  helm_parent_and_shadows_gate || {
    printf 'UNKNOWN\n'
    return
  }
  helm_archive_is_safe "$helm_archive_input" || {
    printf 'ARCHIVE_UNSAFE\n'
    return
  }
  if [[ ! -e "$helm_binary" && ! -L "$helm_binary" ]]; then
    printf 'MISSING\n'
    return
  fi
  if [[ ! -f "$helm_binary" || -L "$helm_binary" || ! -x "$helm_binary" ||
        "$(path_mode "$helm_binary")" != 755 ]] || ! owned_by_expected "$helm_binary"; then
    printf 'UNKNOWN\n'
    return
  fi
  if cmp -s "$helm_binary" <(tar_safe -xOf "$helm_archive_input" "$HELM_MEMBER" 2>/dev/null); then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

helm_temporary=
apply_snapshot_dir=
helm_archive_input=
gateway_manifest_input=
cilium_chart_input=
values_input=

# trap 间接调用；只清理受验证的同目录 Helm 临时文件。
# shellcheck disable=SC2329
cleanup_helm_temporary() {
  local parent
  [[ -n "$helm_temporary" ]] || return 0
  parent=$(dirname "$helm_binary")
  [[ "$helm_temporary" == "${parent}/.helm.tmp."* ]] || return 0
  helm_parent_and_shadows_gate || return 1
  [[ ! -d "$helm_temporary" || -L "$helm_temporary" ]] || return 1
  rm -f -- "$helm_temporary" || return 1
  [[ ! -e "$helm_temporary" && ! -L "$helm_temporary" ]] || return 1
  helm_temporary=
}

cleanup_apply_snapshot() {
  local entry parent
  local -a entries=()
  [[ -n "$apply_snapshot_dir" ]] || return 0
  parent=$(host_path /root)
  [[ "${apply_snapshot_dir%/*}" == "$parent" &&
      "${apply_snapshot_dir##*/}" == .cilium-inputs.* ]] || return 1
  safe_directory "$apply_snapshot_dir" 700 || return 1
  for entry in \
    "${apply_snapshot_dir}/${HELM_ARCHIVE_NAME}" \
    "${apply_snapshot_dir}/${GATEWAY_MANIFEST_NAME}" \
    "${apply_snapshot_dir}/${CILIUM_CHART_NAME}" \
    "${apply_snapshot_dir}/values.yaml"; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    safe_directory "$apply_snapshot_dir" 700 || return 1
    [[ -f "$entry" && ! -L "$entry" && "$(path_mode "$entry")" == 600 ]] || return 1
    owned_by_expected "$entry" || return 1
    rm -f -- "$entry" || return 1
  done
  safe_directory "$apply_snapshot_dir" 700 || return 1
  shopt -s dotglob nullglob
  entries=("$apply_snapshot_dir"/*)
  shopt -u dotglob nullglob
  (( ${#entries[@]} == 0 )) || return 1
  rmdir -- "$apply_snapshot_dir" || return 1
  apply_snapshot_dir=
}

cleanup_apply_state() {
  local result=0
  # APPLY trap 覆盖早期 trap，因此这里必须接管 helm kubeconfig 的清理。
  cleanup_helm_kubeconfig || result=1
  cleanup_helm_temporary || result=1
  cleanup_apply_snapshot || result=1
  return "$result"
}

helm_temporary_gate() {
  local expected_mode=$1
  helm_parent_and_shadows_gate || return 1
  [[ -f "$helm_temporary" && ! -L "$helm_temporary" &&
      "$(path_mode "$helm_temporary")" == "$expected_mode" ]] || return 1
  owned_by_expected "$helm_temporary" || return 1
  cmp -s "$helm_temporary" <(tar_safe -xOf "$helm_archive_input" "$HELM_MEMBER" 2>/dev/null)
}

apply_snapshot_gate() {
  [[ -n "$apply_snapshot_dir" ]] || return 1
  safe_directory "$apply_snapshot_dir" 700 || return 1
  safe_file_with_digest "$helm_archive_input" 600 "$HELM_ARCHIVE_SHA256" || return 1
  safe_file_with_digest "$gateway_manifest_input" 600 "$GATEWAY_MANIFEST_SHA256" || return 1
  safe_file_with_digest "$cilium_chart_input" 600 "$CILIUM_CHART_SHA256" || return 1
  safe_file_with_digest "$values_input" 600 "$VALUES_SHA256" || return 1
  values_semantics_are_exact "$values_input" || return 1
  helm_archive_is_safe "$helm_archive_input"
}

create_apply_snapshots() {
  local parent source target
  parent=$(host_path /root)
  safe_directory "$parent" 700 || return "$EXIT_UNKNOWN_STATE"
  staged_inputs_gate || return "$EXIT_SUPPLY_CHAIN"
  apply_snapshot_dir=$(mktemp -d "${parent}/.cilium-inputs.XXXXXX") || return "$EXIT_APPLY_FAILED"
  safe_directory "$apply_snapshot_dir" 700 || return "$EXIT_UNKNOWN_STATE"
  for source in "$helm_archive" "$gateway_manifest" "$cilium_chart" "$values_source"; do
    safe_directory "$parent" 700 || return "$EXIT_UNKNOWN_STATE"
    case "$source" in
      "$helm_archive") target="${apply_snapshot_dir}/${HELM_ARCHIVE_NAME}" ;;
      "$gateway_manifest") target="${apply_snapshot_dir}/${GATEWAY_MANIFEST_NAME}" ;;
      "$cilium_chart") target="${apply_snapshot_dir}/${CILIUM_CHART_NAME}" ;;
      "$values_source") target="${apply_snapshot_dir}/values.yaml" ;;
      *) return "$EXIT_UNKNOWN_STATE" ;;
    esac
    install -m 0600 "$source" "$target" || return "$EXIT_APPLY_FAILED"
  done
  helm_archive_input="${apply_snapshot_dir}/${HELM_ARCHIVE_NAME}"
  gateway_manifest_input="${apply_snapshot_dir}/${GATEWAY_MANIFEST_NAME}"
  cilium_chart_input="${apply_snapshot_dir}/${CILIUM_CHART_NAME}"
  values_input="${apply_snapshot_dir}/values.yaml"
  apply_snapshot_gate || return "$EXIT_SUPPLY_CHAIN"
  staged_inputs_gate || return "$EXIT_SUPPLY_CHAIN"
}

publish_helm_binary() {
  local state
  state=$(helm_binary_state) || return "$EXIT_UNKNOWN_STATE"
  [[ "$state" == MISSING ]] || return "$EXIT_UNKNOWN_STATE"
  helm_temporary=$(mktemp "$(dirname "$helm_binary")/.helm.tmp.XXXXXX") || return "$EXIT_APPLY_FAILED"
  helm_parent_and_shadows_gate || return "$EXIT_UNKNOWN_STATE"
  [[ -f "$helm_temporary" && ! -L "$helm_temporary" ]] || return "$EXIT_UNKNOWN_STATE"
  owned_by_expected "$helm_temporary" || return "$EXIT_UNKNOWN_STATE"
  if ! tar_safe -xOf "$helm_archive_input" "$HELM_MEMBER" >"$helm_temporary" 2>/dev/null; then
    return "$EXIT_SUPPLY_CHAIN"
  fi
  helm_temporary_gate 600 || return "$EXIT_UNKNOWN_STATE"
  chmod 0755 "$helm_temporary" || return "$EXIT_APPLY_FAILED"
  sync "$helm_temporary" || return "$EXIT_APPLY_FAILED"
  helm_temporary_gate 755 || return "$EXIT_UNKNOWN_STATE"
  staged_inputs_gate || return "$EXIT_SUPPLY_CHAIN"
  apply_snapshot_gate || return "$EXIT_SUPPLY_CHAIN"
  helm_parent_and_shadows_gate || return "$EXIT_UNKNOWN_STATE"
  helm_temporary_gate 755 || return "$EXIT_UNKNOWN_STATE"
  [[ ! -e "$helm_binary" && ! -L "$helm_binary" ]] || return "$EXIT_UNKNOWN_STATE"
  if ! ln "$helm_temporary" "$helm_binary" 2>/dev/null; then
    return "$EXIT_UNKNOWN_STATE"
  fi
  rm -f -- "$helm_temporary" || return "$EXIT_UNKNOWN_STATE"
  [[ ! -e "$helm_temporary" && ! -L "$helm_temporary" ]] || return "$EXIT_UNKNOWN_STATE"
  helm_temporary=
  state=$(helm_binary_state) || return "$EXIT_UNKNOWN_STATE"
  [[ "$state" == COMPLIANT ]]
}

kubectl_empty_query() {
  local captured
  captured=$(
    set +e
    kubectl_run "$@" 2>/dev/null
    printf '__EXIT_CODE__=%s\n' "$?"
  )
  [[ "$captured" == '__EXIT_CODE__=0' ]]
}

kube_proxy_absent() {
  kubectl_empty_query --namespace kube-system get daemonset kube-proxy --ignore-not-found --output=name || return 1
  kubectl_empty_query --namespace kube-system get pods --selector k8s-app=kube-proxy --output=name || return 1
  kubectl_empty_query --namespace kube-system get configmap kube-proxy --ignore-not-found --output=name
}

gateway_json_state() {
  python_isolated -c '
import json
import sys

names = {
    "backendtlspolicies.gateway.networking.k8s.io",
    "gatewayclasses.gateway.networking.k8s.io",
    "gateways.gateway.networking.k8s.io",
    "grpcroutes.gateway.networking.k8s.io",
    "httproutes.gateway.networking.k8s.io",
    "listenersets.gateway.networking.k8s.io",
    "referencegrants.gateway.networking.k8s.io",
    "tcproutes.gateway.networking.k8s.io",
    "tlsroutes.gateway.networking.k8s.io",
    "udproutes.gateway.networking.k8s.io",
}
annotations = {
    "gateway.networking.k8s.io/bundle-version": "v1.6.1",
    "gateway.networking.k8s.io/channel": "standard",
}
crd_annotations = {
    "api-approved.kubernetes.io": "https://github.com/kubernetes-sigs/gateway-api/pull/4530",
    **annotations,
}
try:
    document = json.load(sys.stdin)
except (TypeError, ValueError):
    print("UNKNOWN")
    raise SystemExit(0)
if not isinstance(document, dict) or document.get("kind") != "List":
    print("UNKNOWN")
    raise SystemExit(0)
items = document.get("items")
if not isinstance(items, list):
    print("UNKNOWN")
    raise SystemExit(0)
if not items:
    print("MISSING")
    raise SystemExit(0)
seen_crds = set()
seen_policy = 0
seen_binding = 0
for item in items:
    if not isinstance(item, dict):
        print("UNKNOWN")
        raise SystemExit(0)
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        print("UNKNOWN")
        raise SystemExit(0)
    kind = item.get("kind")
    name = metadata.get("name")
    if kind == "CustomResourceDefinition" and name in names:
        if metadata.get("annotations") != crd_annotations or name in seen_crds:
            print("UNKNOWN")
            raise SystemExit(0)
        seen_crds.add(name)
    elif kind == "ValidatingAdmissionPolicy" and name == "safe-upgrades.gateway.networking.k8s.io":
        warnings = item.get("status", {}).get("typeChecking", {}).get("expressionWarnings", [])
        if metadata.get("annotations") != annotations or warnings != [] or seen_policy:
            print("UNKNOWN")
            raise SystemExit(0)
        seen_policy = 1
    elif kind == "ValidatingAdmissionPolicyBinding" and name == "safe-upgrades.gateway.networking.k8s.io":
        if (metadata.get("annotations") != annotations or
                item.get("spec", {}).get("validationActions") != ["Deny"] or seen_binding):
            print("UNKNOWN")
            raise SystemExit(0)
        seen_binding = 1
    else:
        print("UNKNOWN")
        raise SystemExit(0)
if seen_crds == names and seen_policy == 1 and seen_binding == 1 and len(items) == 12:
    print("COMPLIANT")
else:
    print("UNKNOWN")
' 2>/dev/null
}

gateway_bundle_state() {
  local output parsed diff_exit
  output=$(kubectl_run get \
    "${GATEWAY_OBJECTS[@]}" --ignore-not-found --output=json 2>/dev/null) || {
    printf 'UNKNOWN\n'
    return
  }
  # 按名字 get 且全部不存在时 kubectl 不输出任何字节；空输出即 MISSING，
  # 再由 server-side diff 交叉确认。
  if [[ -z "$output" ]]; then
    parsed=MISSING
  else
    parsed=$(printf '%s' "$output" | gateway_json_state) || parsed=UNKNOWN
  fi
  [[ "$parsed" == MISSING || "$parsed" == COMPLIANT ]] || {
    printf 'UNKNOWN\n'
    return
  }
  set +e
  kubectl_run diff \
    --server-side=true \
    --field-manager="$FIELD_MANAGER" \
    --filename "$gateway_manifest_input" >/dev/null 2>&1
  diff_exit=$?
  set -e
  if [[ "$parsed" == MISSING && "$diff_exit" == 1 ]]; then
    printf 'MISSING\n'
  elif [[ "$parsed" == COMPLIANT && "$diff_exit" == 0 ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

helm_secret_json_state() {
  python_isolated -c '
import json
import sys
try:
    document = json.load(sys.stdin)
except (TypeError, ValueError):
    print("UNKNOWN")
    raise SystemExit(0)
items = document.get("items") if isinstance(document, dict) else None
if not isinstance(items, list):
    print("UNKNOWN")
elif not items:
    print("MISSING")
elif len(items) == 1:
    item = items[0]
    metadata = item.get("metadata", {}) if isinstance(item, dict) else {}
    labels = metadata.get("labels", {}) if isinstance(metadata, dict) else {}
    required = {"owner": "helm", "name": "cilium", "status": "deployed", "version": "1"}
    dynamic_ok = (
        isinstance(labels, dict) and set(labels) == set(required) | {"modifiedAt"} and
        all(labels.get(key) == value for key, value in required.items()) and
        isinstance(labels.get("modifiedAt"), str) and
        labels["modifiedAt"].isdigit() and int(labels["modifiedAt"]) > 0
    )
    exact = (
        item.get("kind") == "Secret" and item.get("type") == "helm.sh/release.v1" and
        metadata.get("name") == "sh.helm.release.v1.cilium.v1" and
        metadata.get("namespace") == "kube-system" and
        dynamic_ok and isinstance(item.get("data"), dict) and
        isinstance(item["data"].get("release"), str) and bool(item["data"]["release"])
    )
    print("COMPLIANT" if exact else "UNKNOWN")
else:
    print("UNKNOWN")
' 2>/dev/null
}

helm_secret_state() {
  local output parsed
  output=$(kubectl_run get secrets,configmaps \
    --all-namespaces --selector owner=helm --output=json 2>/dev/null) || {
    printf 'UNKNOWN\n'
    return
  }
  parsed=$(printf '%s' "$output" | helm_secret_json_state) || parsed=UNKNOWN
  printf '%s\n' "$parsed"
}

cilium_workload_json_state() {
  python_isolated -c '
import json
import sys
try:
    document = json.load(sys.stdin)
except (TypeError, ValueError):
    print("UNKNOWN")
    raise SystemExit(0)
items = document.get("items") if isinstance(document, dict) else None
if not isinstance(items, list):
    print("UNKNOWN")
    raise SystemExit(0)
if not items:
    print("MISSING")
    raise SystemExit(0)
if len(items) != 2:
    print("UNKNOWN")
    raise SystemExit(0)
seen = set()
agent_labels = {
    "k8s-app": "cilium",
    "app.kubernetes.io/name": "cilium-agent",
    "app.kubernetes.io/part-of": "cilium",
    "helm.sh/chart": "cilium-1.20.0",
}
operator_labels = {
    "io.cilium/app": "operator",
    "name": "cilium-operator",
    "app.kubernetes.io/name": "cilium-operator",
    "app.kubernetes.io/part-of": "cilium",
    "helm.sh/chart": "cilium-1.20.0",
}
def container_image_is_exact(item, expected_name, expected_image):
    spec = item.get("spec") if isinstance(item, dict) else None
    template = spec.get("template") if isinstance(spec, dict) else None
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
    return (
        isinstance(containers, list) and len(containers) == 1 and
        isinstance(containers[0], dict) and
        containers[0].get("name") == expected_name and
        containers[0].get("image") == expected_image
    )
for item in items:
    if not isinstance(item, dict):
        print("UNKNOWN")
        raise SystemExit(0)
    metadata = item.get("metadata", {})
    labels = metadata.get("labels") if isinstance(metadata, dict) else None
    if metadata.get("namespace") != "kube-system" or not isinstance(labels, dict):
        print("UNKNOWN")
        raise SystemExit(0)
    name = metadata.get("name")
    status = item.get("status", {})
    if item.get("kind") == "DaemonSet" and name == "cilium":
        exact = (
            all(labels.get(key) == value for key, value in agent_labels.items()) and
            container_image_is_exact(
                item,
                "cilium-agent",
                "quay.io/cilium/cilium:v1.20.0@sha256:383968cd5e8873f7976fa76aa6196045643558f4cc9518a207b9335cb24a0e93",
            ) and
            status.get("desiredNumberScheduled") == 1 and status.get("numberReady") == 1 and
            status.get("numberAvailable") == 1 and status.get("numberUnavailable", 0) == 0
        )
    elif item.get("kind") == "Deployment" and name == "cilium-operator":
        exact = (
            all(labels.get(key) == value for key, value in operator_labels.items()) and
            container_image_is_exact(
                item,
                "cilium-operator",
                "quay.io/cilium/operator-generic:v1.20.0@sha256:80744a8cc7c91c2f9e6347629406844eb35d79b30a732c6d41c15b17232a74f3",
            ) and
            item.get("spec", {}).get("replicas") == 1 and status.get("replicas") == 1 and
            status.get("updatedReplicas") == 1 and status.get("readyReplicas") == 1 and
            status.get("availableReplicas") == 1 and status.get("unavailableReplicas", 0) == 0
        )
    else:
        exact = False
    if not exact or name in seen:
        print("UNKNOWN")
        raise SystemExit(0)
    seen.add(name)
print("COMPLIANT" if seen == {"cilium", "cilium-operator"} else "UNKNOWN")
' 2>/dev/null
}

cilium_workload_state() {
  local output parsed
  output=$(kubectl_run --namespace kube-system get \
    daemonset/cilium deployment/cilium-operator --ignore-not-found --output=json 2>/dev/null) || {
    printf 'UNKNOWN\n'
    return
  }
  [[ -n "$output" ]] || {
    printf 'MISSING\n'
    return
  }
  parsed=$(printf '%s' "$output" | cilium_workload_json_state) || parsed=UNKNOWN
  printf '%s\n' "$parsed"
}

envoy_daemonset_json_state() {
  python_isolated -c '
import json
import sys
try:
    item = json.load(sys.stdin)
    metadata = item.get("metadata") if isinstance(item, dict) else None
    labels = metadata.get("labels") if isinstance(metadata, dict) else None
    spec = item.get("spec") if isinstance(item, dict) else None
    template = spec.get("template") if isinstance(spec, dict) else None
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
    status = item.get("status") if isinstance(item, dict) else None
    required_labels = {
        "k8s-app": "cilium-envoy",
        "name": "cilium-envoy",
        "app.kubernetes.io/name": "cilium-envoy",
        "app.kubernetes.io/part-of": "cilium",
        "helm.sh/chart": "cilium-1.20.0",
    }
    valid = (
        item.get("kind") == "DaemonSet" and
        isinstance(metadata, dict) and metadata.get("name") == "cilium-envoy" and
        metadata.get("namespace") == "kube-system" and isinstance(labels, dict) and
        all(labels.get(key) == value for key, value in required_labels.items()) and
        isinstance(containers, list) and len(containers) == 1 and
        isinstance(containers[0], dict) and containers[0].get("name") == "cilium-envoy" and
        containers[0].get("image") == "quay.io/cilium/cilium-envoy:v1.37.5-1782911245-7cffc778c923f68a77954a53b1a98d6b5353f004@sha256:583057dd4f7d54cd41efff3c413aa0b148ac201f522e2c3336851fa89c78b039" and
        isinstance(status, dict) and status.get("desiredNumberScheduled") == 1 and
        status.get("numberReady") == 1 and status.get("numberAvailable") == 1 and
        status.get("numberUnavailable", 0) == 0
    )
except (TypeError, ValueError):
    valid = False
print("COMPLIANT" if valid else "UNKNOWN")
' 2>/dev/null
}

envoy_daemonset_state() {
  local output parsed
  output=$(kubectl_run --namespace kube-system get daemonset/cilium-envoy \
    --ignore-not-found --output=json 2>/dev/null) || {
    printf 'UNKNOWN\n'
    return
  }
  [[ -n "$output" ]] || {
    printf 'MISSING\n'
    return
  }
  parsed=$(printf '%s' "$output" | envoy_daemonset_json_state) || parsed=UNKNOWN
  printf '%s\n' "$parsed"
}

envoy_pods_json_state() {
  python_isolated -c '
import json
import sys
try:
    document = json.load(sys.stdin)
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list):
        raise ValueError
    if not items:
        print("MISSING")
        raise SystemExit(0)
    if len(items) != 1 or not isinstance(items[0], dict):
        raise ValueError
    item = items[0]
    metadata = item.get("metadata")
    labels = metadata.get("labels") if isinstance(metadata, dict) else None
    spec = item.get("spec")
    containers = spec.get("containers") if isinstance(spec, dict) else None
    status = item.get("status")
    conditions = status.get("conditions") if isinstance(status, dict) else None
    container_statuses = status.get("containerStatuses") if isinstance(status, dict) else None
    ready = [entry for entry in conditions if isinstance(entry, dict) and entry.get("type") == "Ready"] if isinstance(conditions, list) else []
    required_labels = {
        "k8s-app": "cilium-envoy",
        "name": "cilium-envoy",
        "app.kubernetes.io/name": "cilium-envoy",
        "app.kubernetes.io/part-of": "cilium",
        "helm.sh/chart": "cilium-1.20.0",
    }
    valid = (
        item.get("kind") == "Pod" and isinstance(metadata, dict) and
        metadata.get("namespace") == "kube-system" and isinstance(labels, dict) and
        all(labels.get(key) == value for key, value in required_labels.items()) and
        isinstance(containers, list) and len(containers) == 1 and
        isinstance(containers[0], dict) and containers[0].get("name") == "cilium-envoy" and
        containers[0].get("image") == "quay.io/cilium/cilium-envoy:v1.37.5-1782911245-7cffc778c923f68a77954a53b1a98d6b5353f004@sha256:583057dd4f7d54cd41efff3c413aa0b148ac201f522e2c3336851fa89c78b039" and
        isinstance(status, dict) and status.get("phase") == "Running" and
        len(ready) == 1 and ready[0].get("status") == "True" and
        isinstance(container_statuses, list) and len(container_statuses) == 1 and
        isinstance(container_statuses[0], dict) and container_statuses[0].get("ready") is True
    )
except (TypeError, ValueError):
    print("UNKNOWN")
    raise SystemExit(0)
print("COMPLIANT" if valid else "UNKNOWN")
' 2>/dev/null
}

envoy_pods_state() {
  local output parsed
  output=$(kubectl_run --namespace kube-system get pods \
    --selector k8s-app=cilium-envoy --output=json 2>/dev/null) || {
    printf 'UNKNOWN\n'
    return
  }
  parsed=$(printf '%s' "$output" | envoy_pods_json_state) || parsed=UNKNOWN
  printf '%s\n' "$parsed"
}

cilium_config_json_state() {
  python_isolated -c '
import json
import sys
try:
    item = json.load(sys.stdin)
    metadata = item.get("metadata") if isinstance(item, dict) else None
    data = item.get("data") if isinstance(item, dict) else None
    expected = {
        "kube-proxy-replacement": "true",
        "enable-gateway-api": "true",
        "ipam": "kubernetes",
        "cgroup-root": "/sys/fs/cgroup",
    }
    valid = (
        item.get("apiVersion") == "v1" and item.get("kind") == "ConfigMap" and
        isinstance(metadata, dict) and metadata.get("name") == "cilium-config" and
        metadata.get("namespace") == "kube-system" and isinstance(data, dict) and
        all(data.get(key) == value for key, value in expected.items())
    )
except (TypeError, ValueError):
    valid = False
print("COMPLIANT" if valid else "UNKNOWN")
' 2>/dev/null
}

cilium_config_state() {
  local output parsed
  output=$(kubectl_run --namespace kube-system get configmap/cilium-config \
    --ignore-not-found --output=json 2>/dev/null) || {
    printf 'UNKNOWN\n'
    return
  }
  [[ -n "$output" ]] || {
    printf 'MISSING\n'
    return
  }
  parsed=$(printf '%s' "$output" | cilium_config_json_state) || parsed=UNKNOWN
  printf '%s\n' "$parsed"
}

helm_list_json_state() {
  python_isolated -c '
import json
import sys
try:
    items = json.load(sys.stdin)
except (TypeError, ValueError):
    print("UNKNOWN")
    raise SystemExit(0)
if not isinstance(items, list):
    print("UNKNOWN")
elif not items:
    print("MISSING")
elif len(items) == 1 and isinstance(items[0], dict):
    item = items[0]
    expected_keys = {"name", "namespace", "revision", "updated", "status", "chart", "app_version"}
    exact = (
        set(item) == expected_keys and
        item.get("name") == "cilium" and item.get("namespace") == "kube-system" and
        isinstance(item.get("revision"), str) and item["revision"] == "1" and
        isinstance(item.get("updated"), str) and bool(item["updated"].strip()) and
        item.get("status") == "deployed" and
        item.get("chart") == "cilium-1.20.0" and item.get("app_version") == "1.20.0"
    )
    print("COMPLIANT" if exact else "UNKNOWN")
else:
    print("UNKNOWN")
' 2>/dev/null
}

helm_release_state() {
  local binary_state version output parsed values_output
  binary_state=$(helm_binary_state) || {
    printf 'UNKNOWN\n'
    return
  }
  [[ "$binary_state" == COMPLIANT ]] || {
    printf 'UNKNOWN\n'
    return
  }
  version=$(helm_run version --short 2>/dev/null) || {
    printf 'UNKNOWN\n'
    return
  }
  [[ "$version" == v3.21.0+* ]] || {
    printf 'UNKNOWN\n'
    return
  }
  output=$(helm_cluster_run list \
    --all-namespaces --all --output json 2>/dev/null) || {
    printf 'UNKNOWN\n'
    return
  }
  parsed=$(printf '%s' "$output" | helm_list_json_state) || parsed=UNKNOWN
  [[ "$parsed" == COMPLIANT ]] || {
    printf '%s\n' "$parsed"
    return
  }
  values_output=$(helm_cluster_run get values cilium \
    --namespace kube-system --revision 1 --output json 2>/dev/null) || {
    printf 'UNKNOWN\n'
    return
  }
  printf '%s' "$values_output" | helm_values_json_is_exact || {
    printf 'UNKNOWN\n'
    return
  }
  printf '%s\n' "$parsed"
}

CLUSTER_STATE=
GATEWAY_STATE=
HELM_SECRET_STATE=
CILIUM_WORKLOAD_STATE=
ENVOY_DAEMONSET_STATE=
ENVOY_PODS_STATE=
CILIUM_CONFIG_STATE=
HELM_RELEASE_STATE=

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
kubectl_binary=$(host_path /usr/bin/kubectl)
helm_binary=$(host_path /usr/local/bin/helm)
# 由 lib/kubectl.sh 消费（source 路径含变量，shellcheck 无法跟随，故显式关闭）。
# shellcheck disable=SC2034
admin_conf=$(host_path /etc/kubernetes/admin.conf)
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
