# 90-verify

只读整机验收：包、运行时、控制面、CNI、网关与证书的逐项核对。

| 项 | 值 |
| --- | --- |
| PHASE | `verify` |
| 成功结果 | `PASS_BOOTSTRAP_VERIFIED` |
| 证据 | `/root/dev-infra-evidence/14-verify-*.txt` |
| 文件 | `run.sh` 流程与终止；`gates.sh` 判定族（只返回 0/1，不打印、不退出） |

## 停止原因

一律 fail-closed，退出码固定：10 前置条件 / 20 供应链 / 30 未知或漂移 /
40 apply 失败 / 50 verify 失败，不降级为告警。

下列 26 个字面量 REASON 由 `StageReadmeTest` 与 `run.sh` 逐项比对，
文档漂移会判红。模板化的 REASON（如 `missing-command-${cmd}`）不在此列。

- `admin-conf-content-or-structure-drift`
- `api-endpoint-or-health-drift`
- `cilium-workload-unhealthy`
- `client-provenance-or-package-drift`
- `cni-payload-drift`
- `cri-runtime-unhealthy`
- `evidence-open-failed`
- `executable-version-drift`
- `gateway-bundle-drift`
- `helm-binary-provenance-drift`
- `helm-kubeconfig-residue`
- `helm-release-allowlist-drift`
- `kube-proxy-object-present-or-unreadable`
- `kubelet-serving-csr-drift`
- `kubelet-swap-config-drift`
- `missing-command-python3`
- `missing-command-sha256`
- `missing-command-tar`
- `node-readiness-or-address-drift`
- `not-root`
- `openssl-binary-metadata-drift`
- `package-version-selection-or-hold-drift`
- `read-only-stage-does-not-accept-apply`
- `runtime-provenance-or-state-drift`
- `staged-input-drift`
- `swap-contract-drift`
