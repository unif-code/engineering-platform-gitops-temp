# 60-install-cilium

用 helm 安装 Cilium 与 Gateway API，装完后有界轮询直到集群状态 COMPLIANT。

| 项 | 值 |
| --- | --- |
| PHASE | `install-cilium` |
| 成功结果 | `ALREADY_COMPLIANT` / `PASS_CILIUM_CHECK` / `PASS_CILIUM_INSTALLED` |
| 证据 | `/root/dev-infra-evidence/13-cilium-*.txt` |
| 文件 | `run.sh` 流程与终止；`gates.sh` 判定族（只返回 0/1，不打印、不退出） |

## 停止原因

一律 fail-closed，退出码固定：10 前置条件 / 20 供应链 / 30 未知或漂移 /
40 apply 失败 / 50 verify 失败，不降级为告警。

下列 62 个字面量 REASON 由 `StageReadmeTest` 与 `run.sh` 逐项比对，
文档漂移会判红。模板化的 REASON（如 `missing-command-${cmd}`）不在此列。

- `admin-conf-content-or-structure-drift`
- `admin-conf-metadata-raced`
- `admin-conf-post-install-drift`
- `admin-conf-raced-after-gateway`
- `admin-conf-raced-before-gateway`
- `admin-conf-raced-before-helm`
- `api-endpoint-drift`
- `api-endpoint-post-install-drift`
- `api-endpoint-raced`
- `api-endpoint-raced-after-gateway`
- `api-endpoint-raced-before-gateway`
- `api-endpoint-raced-before-helm`
- `apply-input-snapshot-drift`
- `apply-input-snapshot-failed`
- `apply-input-snapshot-raced`
- `apply-input-snapshot-raced-after-gateway`
- `apply-input-snapshot-raced-after-helm`
- `apply-input-snapshot-raced-at-consumer`
- `apply-input-snapshot-raced-at-gateway`
- `apply-input-snapshot-raced-at-helm`
- `apply-input-snapshot-raced-before-helm`
- `apply-input-snapshot-unsafe`
- `apply-temporary-cleanup-unsafe`
- `cilium-helm-install-failed`
- `cilium-post-install-state-invalid`
- `evidence-open-failed`
- `gateway-cilium-cluster-state-unknown`
- `gateway-post-apply-state-unknown`
- `gateway-server-side-apply-failed`
- `helm-archive-unsafe`
- `helm-binary-or-shadow-unknown`
- `helm-binary-raced-at-install`
- `helm-binary-raced-before-install`
- `helm-binary-verification-failed`
- `helm-extraction-or-input-raced`
- `helm-kubeconfig-residue`
- `helm-post-install-drift`
- `helm-publication-failed`
- `helm-publication-raced`
- `host-pins-invalid`
- `kube-proxy-state-raced`
- `kubectl-post-install-drift`
- `kubectl-provenance-drift`
- `kubectl-provenance-raced`
- `kubectl-raced-after-gateway`
- `kubectl-raced-before-gateway`
- `kubectl-raced-before-helm`
- `missing-command-python3`
- `missing-command-sha256`
- `missing-command-tar`
- `not-root`
- `pre-gateway-cluster-state-raced`
- `pre-helm-cluster-state-raced`
- `staged-input-contract-drift`
- `staged-input-contract-raced`
- `staged-input-raced-after-gateway`
- `staged-input-raced-after-helm`
- `staged-input-raced-at-gateway`
- `staged-input-raced-at-helm`
- `staged-input-raced-before-helm`
- `test-post-install-wait-unsafe`
- `test-values-file-unsafe`
