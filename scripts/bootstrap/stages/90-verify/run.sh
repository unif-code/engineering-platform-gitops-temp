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

# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=verify
readonly CRI_ENDPOINT=unix:///run/containerd/containerd.sock
readonly STAGED_ROOT=/root/dev-infra-artifacts/pcs-2026-08-10.1
readonly HELM_ARCHIVE_NAME=helm-v3.21.0-linux-amd64.tar.gz
readonly HELM_ARCHIVE_SHA256=0093eb572e3d2380f094df162ddb525e219249de88957afe24cfbb19632acd36
readonly HELM_MEMBER=linux-amd64/helm
readonly GATEWAY_MANIFEST_NAME=standard-install.yaml
readonly GATEWAY_MANIFEST_SHA256=24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73
readonly FIELD_MANAGER=engineering-platform-bootstrap
readonly EXPECTED_KUBERNETES_VERSION=1.36.3-1.1
readonly EXPECTED_CNI_VERSION=1.9.1-1.1
readonly PYTHON_BINARY=/usr/bin/python3
readonly TAR_BINARY=/usr/bin/tar
readonly CONTAINERD_TRANSCRIPT=$'PHASE=containerd\nMODE=CHECK\nRESULT=ALREADY_COMPLIANT\nREASON=containerd-ready\nEVIDENCE=NONE\nEXIT_CODE=0\nNEXT=40-install-kubernetes\nSHA256=NONE'
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

openssl_safe() {
  OPENSSL_CONF=/dev/null OPENSSL_MODULES=/nonexistent "$openssl_binary" "$@"
}

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

managed_clients_are_exact() {
  local package logical target shadow ownership
  for package in kubeadm kubectl kubelet; do
    for shadow in "/usr/sbin/${package}" "/usr/local/bin/${package}" "/usr/local/sbin/${package}"; do
      shadow=$(host_path "$shadow")
      [[ ! -e "$shadow" && ! -L "$shadow" ]] || return 1
    done
    logical="/usr/bin/${package}"
    target=$(host_path "$logical")
    [[ -x "$target" ]] && safe_file "$target" 755 || return 1
    ownership=$(dpkg-query -S "$logical" 2>/dev/null) || return 1
    [[ "$ownership" == "${package}: ${logical}" ]] || return 1
  done
  for package in kubeadm kubectl kubelet kubernetes-cni; do
    dpkg_package_verification_is_exact "$package" || return 1
  done
  safe_directory "$(host_path /usr)" 755 || return 1
  safe_directory "$(host_path /usr/local)" 755 || return 1
  safe_directory "$(host_path /usr/local/bin)" 755 || return 1
  for shadow in /usr/bin/crictl /usr/sbin/crictl /usr/local/sbin/crictl; do
    shadow=$(host_path "$shadow")
    [[ ! -e "$shadow" && ! -L "$shadow" ]] || return 1
  done
  [[ -x "$crictl_binary" ]] && safe_file "$crictl_binary" 755
}

cni_payload_is_exact() {
  local actual_names entry_set_kind name mode size digest target actual_digest ownership
  safe_directory "$(host_path /opt)" 755 || return 1
  safe_directory "$(host_path /opt/cni)" 755 || return 1
  safe_directory "$cni_root" 755 || return 1
  actual_names=$(find "$cni_root" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sed 's#.*/##' | sort) || return 1
  entry_set_kind=$(cni_entry_set_kind "$actual_names") || return 1
  # 装完 Cilium 后 agent 会写入 cilium-cni；只按锁定的 mode/size/digest 与非包归属放行。
  if [[ "$entry_set_kind" == with-cilium ]]; then
    cilium_cni_entry_is_exact "$cni_root" || return 1
  fi
  while IFS=$'\t' read -r name mode size digest; do
    target="${cni_root}/${name}"
    safe_file "$target" "$mode" || return 1
    [[ "$(path_size "$target")" == "$size" ]] || return 1
    actual_digest=$(sha256_file "$target") || return 1
    [[ "$actual_digest" == "$digest" ]] || return 1
    ownership=$(dpkg-query -S "/opt/cni/bin/${name}" 2>/dev/null) || return 1
    [[ "$ownership" == "kubernetes-cni: /opt/cni/bin/${name}" ]] || return 1
  done < <(cni_manifest)
}

# 与 Stage 60 相同：helm 无法从管道读取 kubeconfig，改用 /root 下私有临时文件。

# trap 间接调用；只删除 /root 下本进程建立的 .helm-kubeconfig.* 目录。
# 静态检查 0.9 报 SC2317（不可达）、0.11 报 SC2329（未调用），均为 trap 间接调用的误报。
# shellcheck disable=SC2317,SC2329

# 子 shell 隔离 shopt；只检测残留，绝不自动删除（留给运维检查后手工清理）。

staged_inputs_are_exact() {
  local digest
  safe_directory "$(host_path /root)" 700 || return 1
  safe_directory "$(host_path /root/dev-infra-artifacts)" 700 || return 1
  safe_directory "$staged_root" 700 || return 1
  safe_file "$helm_archive" 600 || return 1
  digest=$(sha256_file "$helm_archive") || return 1
  [[ "$digest" == "$HELM_ARCHIVE_SHA256" ]] || return 1
  safe_file "$gateway_manifest" 600 || return 1
  digest=$(sha256_file "$gateway_manifest") || return 1
  [[ "$digest" == "$GATEWAY_MANIFEST_SHA256" ]]
}

helm_binary_is_exact() {
  local shadow
  staged_inputs_are_exact || return 1
  helm_archive_is_safe "$helm_archive" || return 1
  safe_directory "$(host_path /usr)" 755 || return 1
  safe_directory "$(host_path /usr/local)" 755 || return 1
  safe_directory "$(host_path /usr/local/bin)" 755 || return 1
  for shadow in /usr/bin/helm /usr/sbin/helm /usr/local/sbin/helm; do
    shadow=$(host_path "$shadow")
    [[ ! -e "$shadow" && ! -L "$shadow" ]] || return 1
  done
  [[ -x "$helm_binary" ]] && safe_file "$helm_binary" 755 || return 1
  cmp -s "$helm_binary" <(tar_safe -xOf "$helm_archive" "$HELM_MEMBER" 2>/dev/null)
}

version_contract_is_exact() {
  local output
  output=$("$kubeadm_binary" version -o short 2>/dev/null) || return 1
  [[ "$output" == v1.36.3 ]] || return 1
  output=$("$kubelet_binary" --version 2>/dev/null) || return 1
  [[ "$output" == 'Kubernetes v1.36.3' ]] || return 1
  output=$("$crictl_binary" --version 2>/dev/null) || return 1
  [[ "$output" == 'crictl version v1.36.0' ]] || return 1
  output=$(kubectl_run version --client=true --output=json 2>/dev/null) || return 1
  printf '%s' "$output" | python_isolated -c '
import json
import sys
try:
    value = json.load(sys.stdin)
    client = value.get("clientVersion") if isinstance(value, dict) else None
    valid = (
        isinstance(client, dict) and
        client.get("major") == "1" and client.get("minor") == "36" and
        client.get("gitVersion") == "v1.36.3" and
        client.get("platform") == "linux/amd64"
    )
except (TypeError, ValueError):
    valid = False
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1
}

cri_is_healthy() {
  "$crictl_binary" \
    --runtime-endpoint "$CRI_ENDPOINT" \
    --image-endpoint "$CRI_ENDPOINT" \
    info --output json 2>/dev/null |
    python_isolated -c '
import json
import sys
try:
    value = json.load(sys.stdin)
    conditions = value["status"]["conditions"]
    ready = [item for item in conditions if isinstance(item, dict) and item.get("type") == "RuntimeReady"]
    network = [item for item in conditions if isinstance(item, dict) and item.get("type") == "NetworkReady"]
    runtime = value["config"]["containerd"]
    runc = runtime["runtimes"]["runc"]
    valid = (
        len(ready) == 1 and ready[0].get("status") is True and
        len(network) == 1 and network[0].get("status") is True and
        runtime.get("defaultRuntimeName") == "runc" and
        runc.get("runtimeType") == "io.containerd.runc.v2" and
        runc.get("options", {}).get("SystemdCgroup") is True
    )
except (KeyError, TypeError, ValueError):
    valid = False
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1
}

api_is_exact_and_ready() {
  local output
  output=$(kubectl_run config view --minify \
    '--output=jsonpath={.clusters[0].cluster.server}' 2>/dev/null) || return 1
  [[ "$output" == "https://${HOST_NODE_IP}:6443" ]] || return 1
  output=$(kubectl_run get --raw=/readyz 2>/dev/null) || return 1
  [[ "$output" == ok ]]
}

kube_proxy_is_absent() {
  kubectl_query_is_empty --namespace kube-system get daemonset kube-proxy --ignore-not-found --output=name || return 1
  kubectl_query_is_empty --namespace kube-system get pods --selector k8s-app=kube-proxy --output=name || return 1
  kubectl_query_is_empty --namespace kube-system get configmap kube-proxy --ignore-not-found --output=name
}

helm_release_is_exact() {
  local output values_output version
  output=$(kubectl_run get secrets,configmaps --all-namespaces \
    --selector owner=helm --output=json 2>/dev/null) || return 1
  printf '%s' "$output" | python_isolated -c '
import json
import sys
try:
    document = json.load(sys.stdin)
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise ValueError
    item = items[0]
    metadata = item.get("metadata")
    labels = metadata.get("labels") if isinstance(metadata, dict) else None
    required = {"owner": "helm", "name": "cilium", "status": "deployed", "version": "1"}
    labels_ok = (
        isinstance(labels, dict) and set(labels) == set(required) | {"modifiedAt"} and
        all(labels.get(key) == value for key, value in required.items()) and
        isinstance(labels.get("modifiedAt"), str) and
        labels["modifiedAt"].isdigit() and int(labels["modifiedAt"]) > 0
    )
    valid = (
        item.get("kind") == "Secret" and item.get("type") == "helm.sh/release.v1" and
        metadata.get("name") == "sh.helm.release.v1.cilium.v1" and
        metadata.get("namespace") == "kube-system" and
        labels_ok and isinstance(item.get("data"), dict) and
        isinstance(item["data"].get("release"), str) and bool(item["data"]["release"])
    )
except (TypeError, ValueError):
    valid = False
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1 || return 1

  helm_binary_is_exact || return 1
  version=$(helm_run version --short 2>/dev/null) || return 1
  [[ "$version" == v3.21.0+* ]] || return 1
  helm_binary_is_exact || return 1
  output=$(helm_cluster_run list \
    --all-namespaces --all --output json 2>/dev/null) || return 1
  helm_binary_is_exact || return 1
  printf '%s' "$output" | python_isolated -c '
import json
import sys
expected_keys = {"name", "namespace", "revision", "updated", "status", "chart", "app_version"}
try:
    items = json.load(sys.stdin)
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise ValueError
    item = items[0]
    valid = (
        set(item) == expected_keys and item.get("name") == "cilium" and
        item.get("namespace") == "kube-system" and
        isinstance(item.get("revision"), str) and item["revision"] == "1" and
        isinstance(item.get("updated"), str) and bool(item["updated"].strip()) and
        item.get("status") == "deployed" and item.get("chart") == "cilium-1.20.0" and
        item.get("app_version") == "1.20.0"
    )
except (TypeError, ValueError):
    valid = False
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1 || return 1

  helm_binary_is_exact || return 1
  values_output=$(helm_cluster_run get values cilium \
    --namespace kube-system --revision 1 --output json 2>/dev/null) || return 1
  helm_binary_is_exact || return 1
  printf '%s' "$values_output" | helm_values_json_is_exact
}

gateway_bundle_is_exact() {
  local output diff_exit
  output=$(kubectl_run get \
    "${GATEWAY_OBJECTS[@]}" --ignore-not-found --output=json 2>/dev/null) || return 1
  printf '%s' "$output" | python_isolated -c '
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
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list) or len(items) != 12:
        raise ValueError
    crds = set()
    policy = 0
    binding = 0
    for item in items:
        if not isinstance(item, dict):
            raise ValueError
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError
        kind = item.get("kind")
        name = metadata.get("name")
        if kind == "CustomResourceDefinition" and name in names:
            if metadata.get("annotations") != crd_annotations or name in crds:
                raise ValueError
            crds.add(name)
        elif kind == "ValidatingAdmissionPolicy" and name == "safe-upgrades.gateway.networking.k8s.io":
            warnings = item.get("status", {}).get("typeChecking", {}).get("expressionWarnings", [])
            if metadata.get("annotations") != annotations or warnings != [] or policy:
                raise ValueError
            policy = 1
        elif kind == "ValidatingAdmissionPolicyBinding" and name == "safe-upgrades.gateway.networking.k8s.io":
            if (metadata.get("annotations") != annotations or
                    item.get("spec", {}).get("validationActions") != ["Deny"] or binding):
                raise ValueError
            binding = 1
        else:
            raise ValueError
    valid = crds == names and policy == 1 and binding == 1
except (TypeError, ValueError):
    valid = False
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1 || return 1
  set +e
  kubectl_run diff \
    --server-side=true \
    --field-manager="$FIELD_MANAGER" \
    --filename "$gateway_manifest" >/dev/null 2>&1
  diff_exit=$?
  set -e
  [[ "$diff_exit" == 0 ]]
}

workload_object_is_ready() {
  local kind=$1
  python_isolated -c '
import json
import sys
kind = sys.argv[1]
try:
    item = json.load(sys.stdin)
    metadata = item.get("metadata") if isinstance(item, dict) else None
    status = item.get("status") if isinstance(item, dict) else None
    if not isinstance(metadata, dict) or not isinstance(status, dict):
        raise ValueError
    labels = metadata.get("labels")
    if metadata.get("namespace") != "kube-system" or not isinstance(labels, dict):
        raise ValueError
    if kind == "DaemonSet":
        required_labels = {
            "k8s-app": "cilium",
            "app.kubernetes.io/name": "cilium-agent",
            "app.kubernetes.io/part-of": "cilium",
            "helm.sh/chart": "cilium-1.20.0",
        }
        valid = (
            item.get("kind") == "DaemonSet" and metadata.get("name") == "cilium" and
            all(labels.get(key) == value for key, value in required_labels.items()) and
            isinstance(item.get("spec"), dict) and
            isinstance(item["spec"].get("template"), dict) and
            isinstance(item["spec"]["template"].get("spec"), dict) and
            isinstance(item["spec"]["template"]["spec"].get("containers"), list) and
            len(item["spec"]["template"]["spec"]["containers"]) == 1 and
            isinstance(item["spec"]["template"]["spec"]["containers"][0], dict) and
            item["spec"]["template"]["spec"]["containers"][0].get("name") == "cilium-agent" and
            item["spec"]["template"]["spec"]["containers"][0].get("image") ==
                "quay.io/cilium/cilium:v1.20.0@sha256:383968cd5e8873f7976fa76aa6196045643558f4cc9518a207b9335cb24a0e93" and
            status.get("desiredNumberScheduled") == 1 and status.get("numberReady") == 1 and
            status.get("numberAvailable") == 1 and status.get("numberUnavailable", 0) == 0
        )
    elif kind == "EnvoyDaemonSet":
        required_labels = {
            "k8s-app": "cilium-envoy",
            "name": "cilium-envoy",
            "app.kubernetes.io/name": "cilium-envoy",
            "app.kubernetes.io/part-of": "cilium",
            "helm.sh/chart": "cilium-1.20.0",
        }
        valid = (
            item.get("kind") == "DaemonSet" and metadata.get("name") == "cilium-envoy" and
            all(labels.get(key) == value for key, value in required_labels.items()) and
            isinstance(item.get("spec"), dict) and
            isinstance(item["spec"].get("template"), dict) and
            isinstance(item["spec"]["template"].get("spec"), dict) and
            isinstance(item["spec"]["template"]["spec"].get("containers"), list) and
            len(item["spec"]["template"]["spec"]["containers"]) == 1 and
            isinstance(item["spec"]["template"]["spec"]["containers"][0], dict) and
            item["spec"]["template"]["spec"]["containers"][0].get("name") == "cilium-envoy" and
            item["spec"]["template"]["spec"]["containers"][0].get("image") ==
                "quay.io/cilium/cilium-envoy:v1.37.5-1782911245-7cffc778c923f68a77954a53b1a98d6b5353f004@sha256:583057dd4f7d54cd41efff3c413aa0b148ac201f522e2c3336851fa89c78b039" and
            status.get("desiredNumberScheduled") == 1 and status.get("numberReady") == 1 and
            status.get("numberAvailable") == 1 and status.get("numberUnavailable", 0) == 0
        )
    else:
        required_labels = {
            "io.cilium/app": "operator",
            "name": "cilium-operator",
            "app.kubernetes.io/name": "cilium-operator",
            "app.kubernetes.io/part-of": "cilium",
            "helm.sh/chart": "cilium-1.20.0",
        }
        valid = (
            item.get("kind") == "Deployment" and metadata.get("name") == "cilium-operator" and
            all(labels.get(key) == value for key, value in required_labels.items()) and
            isinstance(item.get("spec"), dict) and
            isinstance(item["spec"].get("template"), dict) and
            isinstance(item["spec"]["template"].get("spec"), dict) and
            isinstance(item["spec"]["template"]["spec"].get("containers"), list) and
            len(item["spec"]["template"]["spec"]["containers"]) == 1 and
            isinstance(item["spec"]["template"]["spec"]["containers"][0], dict) and
            item["spec"]["template"]["spec"]["containers"][0].get("name") == "cilium-operator" and
            item["spec"]["template"]["spec"]["containers"][0].get("image") ==
                "quay.io/cilium/operator-generic:v1.20.0@sha256:80744a8cc7c91c2f9e6347629406844eb35d79b30a732c6d41c15b17232a74f3" and
            item.get("spec", {}).get("replicas") == 1 and status.get("replicas") == 1 and
            status.get("updatedReplicas") == 1 and status.get("readyReplicas") == 1 and
            status.get("availableReplicas") == 1 and status.get("unavailableReplicas", 0) == 0
        )
except (TypeError, ValueError):
    valid = False
raise SystemExit(0 if valid else 1)
' "$kind" >/dev/null 2>&1
}

pod_list_is_ready() {
  local selector=$1
  python_isolated -c '
import json
import sys
selector = sys.argv[1]
try:
    document = json.load(sys.stdin)
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise ValueError
    item = items[0]
    metadata = item.get("metadata")
    status = item.get("status")
    if not isinstance(metadata, dict) or not isinstance(status, dict):
        raise ValueError
    labels = metadata.get("labels")
    conditions = status.get("conditions")
    containers = status.get("containerStatuses")
    pod_spec = item.get("spec")
    pod_containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
    ready = [entry for entry in conditions if isinstance(entry, dict) and entry.get("type") == "Ready"] if isinstance(conditions, list) else []
    if selector == "cilium":
        required_labels = {
            "k8s-app": "cilium",
            "app.kubernetes.io/name": "cilium-agent",
            "app.kubernetes.io/part-of": "cilium",
            "helm.sh/chart": "cilium-1.20.0",
        }
        expected_container_name = "cilium-agent"
        expected_image = "quay.io/cilium/cilium:v1.20.0@sha256:383968cd5e8873f7976fa76aa6196045643558f4cc9518a207b9335cb24a0e93"
    elif selector == "envoy":
        required_labels = {
            "k8s-app": "cilium-envoy",
            "name": "cilium-envoy",
            "app.kubernetes.io/name": "cilium-envoy",
            "app.kubernetes.io/part-of": "cilium",
            "helm.sh/chart": "cilium-1.20.0",
        }
        expected_container_name = "cilium-envoy"
        expected_image = "quay.io/cilium/cilium-envoy:v1.37.5-1782911245-7cffc778c923f68a77954a53b1a98d6b5353f004@sha256:583057dd4f7d54cd41efff3c413aa0b148ac201f522e2c3336851fa89c78b039"
    else:
        required_labels = {
            "io.cilium/app": "operator",
            "name": "cilium-operator",
            "app.kubernetes.io/name": "cilium-operator",
            "app.kubernetes.io/part-of": "cilium",
            "helm.sh/chart": "cilium-1.20.0",
        }
        expected_container_name = "cilium-operator"
        expected_image = "quay.io/cilium/operator-generic:v1.20.0@sha256:80744a8cc7c91c2f9e6347629406844eb35d79b30a732c6d41c15b17232a74f3"
    label_ok = (
        isinstance(labels, dict) and
        all(labels.get(key) == value for key, value in required_labels.items())
    )
    valid = (
        item.get("kind") == "Pod" and metadata.get("namespace") == "kube-system" and
        label_ok and status.get("phase") == "Running" and len(ready) == 1 and
        isinstance(pod_containers, list) and len(pod_containers) == 1 and
        isinstance(pod_containers[0], dict) and
        pod_containers[0].get("name") == expected_container_name and
        pod_containers[0].get("image") == expected_image and
        ready[0].get("status") == "True" and isinstance(containers, list) and
        len(containers) > 0 and all(entry.get("ready") is True for entry in containers if isinstance(entry, dict)) and
        all(isinstance(entry, dict) for entry in containers)
    )
except (TypeError, ValueError):
    valid = False
raise SystemExit(0 if valid else 1)
' "$selector" >/dev/null 2>&1
}

cilium_is_ready() {
  kubectl_run --namespace kube-system get daemonset/cilium --output=json 2>/dev/null |
    workload_object_is_ready DaemonSet || return 1
  kubectl_run --namespace kube-system get pods --selector k8s-app=cilium --output=json 2>/dev/null |
    pod_list_is_ready cilium || return 1
  kubectl_run --namespace kube-system get deployment/cilium-operator --output=json 2>/dev/null |
    workload_object_is_ready Deployment || return 1
  kubectl_run --namespace kube-system get pods --selector name=cilium-operator --output=json 2>/dev/null |
    pod_list_is_ready operator || return 1
  kubectl_run --namespace kube-system get daemonset/cilium-envoy --output=json 2>/dev/null |
    workload_object_is_ready EnvoyDaemonSet || return 1
  kubectl_run --namespace kube-system get pods --selector k8s-app=cilium-envoy --output=json 2>/dev/null |
    pod_list_is_ready envoy || return 1
  kubectl_run --namespace kube-system get configmap/cilium-config --output=json 2>/dev/null |
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
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1
}

node_is_ready() {
  kubectl_run get nodes --output=json 2>/dev/null |
    python_isolated -c '
import json
import sys
try:
    document = json.load(sys.stdin)
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise ValueError
    item = items[0]
    metadata = item.get("metadata")
    status = item.get("status")
    conditions = status.get("conditions") if isinstance(status, dict) else None
    addresses = status.get("addresses") if isinstance(status, dict) else None
    ready = [entry for entry in conditions if isinstance(entry, dict) and entry.get("type") == "Ready"] if isinstance(conditions, list) else []
    internal = [entry.get("address") for entry in addresses if isinstance(entry, dict) and entry.get("type") == "InternalIP"] if isinstance(addresses, list) else []
    valid = (
        isinstance(metadata, dict) and metadata.get("name") == sys.argv[1] and
        len(ready) == 1 and ready[0].get("status") == "True" and
        internal == [sys.argv[2]]
    )
except (TypeError, ValueError):
    valid = False
raise SystemExit(0 if valid else 1)
' "$HOST_NAME" "$HOST_NODE_IP" >/dev/null 2>&1
}

swap_is_exact() {
  local output lines name bytes
  safe_file "$(host_path "$HOST_SWAP_FILE")" 600 || return 1
  output=$(swapon --show=NAME,SIZE --noheadings --raw --bytes 2>/dev/null) || return 1
  lines=$(printf '%s\n' "$output" | awk 'NF {count++} END {print count+0}')
  name=$(printf '%s\n' "$output" | awk 'NF {print $1}')
  bytes=$(printf '%s\n' "$output" | awk 'NF {print $2}')
  [[ "$lines" == 1 && "$name" == "$HOST_SWAP_FILE" && "$bytes" =~ ^[0-9]+$ ]] || return 1
  # HOST_SWAP_*_BYTES 由 lib/host-config.sh 限定为 ^[1-9][0-9]{0,17}$，裸算术因此无注入与溢出风险。
  (( bytes >= HOST_SWAP_MIN_BYTES && bytes <= HOST_SWAP_MAX_BYTES ))
}

kubelet_swap_config_is_exact() {
  kubectl_run get \
    --raw="/api/v1/nodes/${HOST_NAME}/proxy/configz" 2>/dev/null |
    python_isolated -c '
import json
import sys
try:
    document = json.load(sys.stdin)
    config = document.get("kubeletconfig") if isinstance(document, dict) else None
    valid = (
        isinstance(config, dict) and config.get("failSwapOn") is False and
        config.get("memorySwap") == {"swapBehavior": "NoSwap"}
    )
except (TypeError, ValueError):
    valid = False
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1
}

CSR_SUMMARIES=()
CSR_COUNT=0

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
helm_archive="${staged_root}/${HELM_ARCHIVE_NAME}"
gateway_manifest="${staged_root}/${GATEWAY_MANIFEST_NAME}"
kubeadm_binary=$(host_path /usr/bin/kubeadm)
# 由 lib/kubectl.sh 消费（source 路径含变量，shellcheck 无法跟随，故显式关闭）。
# shellcheck disable=SC2034
kubectl_binary=$(host_path /usr/bin/kubectl)
kubelet_binary=$(host_path /usr/bin/kubelet)
crictl_binary=$(host_path /usr/local/bin/crictl)
helm_binary=$(host_path /usr/local/bin/helm)
openssl_binary=$(host_path /usr/bin/openssl)
# 由 lib/kubectl.sh 消费（source 路径含变量，shellcheck 无法跟随，故显式关闭）。
# shellcheck disable=SC2034
admin_conf=$(host_path /etc/kubernetes/admin.conf)
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
