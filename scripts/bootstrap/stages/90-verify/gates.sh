#!/usr/bin/env bash

# 90-verify 的判定族：只读取状态并返回 0/1，不打印证据、不调用 complete、不退出。
# run.sh 负责流程与终止，gates.sh 负责"事实是什么"——两者分开后，判定可以被单独
# 阅读和测试，而不必跟着流程走一遍。
# 本文件由 run.sh 以 ${script_dir}/gates.sh 引入，与 run.sh 同属一个 stage 目录，
# 因此被 bootstrap-all.sh 的 stage 目录逐条目门禁覆盖（属主、权限、非符号链接）。
# 判定所需的常量与路径由 run.sh 声明；缺失时 set -u 直接报未绑定变量。
# SC2154 只对小写变量告警（全大写被当成环境变量豁免），故显式关闭。
# shellcheck disable=SC2154

openssl_safe() {
  OPENSSL_CONF=/dev/null OPENSSL_MODULES=/nonexistent "$openssl_binary" "$@"
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
    --selector owner=helm,name=cilium --output=json 2>/dev/null) || return 1
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
    if not isinstance(items, list):
        raise ValueError
    # 只判定我们自己的 release；同集群可能有其他运维装的 release，与本 stage 无关。
    # 过滤依据是 helm 的 name 字段而非对象名——upgrade 产生的 revision 2 同样带
    # name=cilium，因此仍会被选中，再由下面的 revision 断言判成不合规。
    mine = [i for i in items if isinstance(i, dict) and i.get("name") == "cilium"]
    if len(mine) != 1:
        raise ValueError
    item = mine[0]
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

# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
CSR_SUMMARIES=()
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
CSR_COUNT=0
