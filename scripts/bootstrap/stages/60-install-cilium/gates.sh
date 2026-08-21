#!/usr/bin/env bash

# 60-install-cilium 的判定族：只读取状态并返回 0/1，不打印证据、不调用 complete、不退出。
# run.sh 负责流程与终止，gates.sh 负责"事实是什么"——两者分开后，判定可以被单独
# 阅读和测试，而不必跟着流程走一遍。
# 本文件由 run.sh 以 ${script_dir}/gates.sh 引入，与 run.sh 同属一个 stage 目录，
# 因此被 bootstrap-all.sh 的 stage 目录逐条目门禁覆盖（属主、权限、非符号链接）。
# 判定所需的常量与路径由 run.sh 声明；缺失时 set -u 直接报未绑定变量。
# SC2154 只对小写变量告警（全大写被当成环境变量豁免），故显式关闭。
# shellcheck disable=SC2154

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

# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
CLUSTER_STATE=
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
GATEWAY_STATE=
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
HELM_SECRET_STATE=
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
CILIUM_WORKLOAD_STATE=
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
ENVOY_DAEMONSET_STATE=
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
ENVOY_PODS_STATE=
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
CILIUM_CONFIG_STATE=
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
HELM_RELEASE_STATE=
