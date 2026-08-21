# 50-kubeadm-init

以固定 config 执行 kubeadm init，并校验控制面与 admin.conf 的精确状态。

| 项 | 值 |
| --- | --- |
| PHASE | `kubeadm-init` |
| 成功结果 | `ALREADY_COMPLIANT` / `PASS_KUBEADM_CHECK` / `PASS_KUBEADM_INITIALIZED` |
| 证据 | `/root/dev-infra-evidence/12-kubeadm-*.txt` |
| 文件 | `run.sh` 流程与终止；`gates.sh` 判定族（只返回 0/1，不打印、不退出） |

## 停止原因

一律 fail-closed，退出码固定：10 前置条件 / 20 供应链 / 30 未知或漂移 /
40 apply 失败 / 50 verify 失败，不降级为告警。

下列 44 个字面量 REASON 由 `StageReadmeTest` 与 `run.sh` 逐项比对，
文档漂移会判红。模板化的 REASON（如 `missing-command-${cmd}`）不在此列。

- `address-unreadable`
- `architecture-mismatch`
- `cgroup-path-unsafe`
- `cgroup-state-unreadable`
- `cgroup-v2-required`
- `cidr-gate-failed`
- `cidr-gate-output-invalid`
- `containerd-gate-failed`
- `evidence-open-failed`
- `host-pins-invalid`
- `initialized-or-partial-state-present`
- `initialized-state-unreadable`
- `kernel-gate-failed`
- `kubeadm-config-contract-drift`
- `kubeadm-config-snapshot-create-failed`
- `kubeadm-config-snapshot-drift`
- `kubeadm-config-snapshot-unsafe`
- `kubeadm-config-validation-failed`
- `kubeadm-init-failed`
- `kubeadm-phase-preflight-failed`
- `kubelet-generated-or-identity-state-present`
- `kubelet-generated-state-present`
- `kubelet-operator-override-present`
- `kubelet-root-mode-unsafe`
- `kubelet-root-unreadable`
- `kubelet-root-unsafe`
- `kubernetes-client-metadata-drift`
- `kubernetes-client-owner-unreadable`
- `kubernetes-client-package-content-drift`
- `kubernetes-client-package-owner-drift`
- `kubernetes-client-shadow-present`
- `kubernetes-gate-failed`
- `missing-command-python3`
- `node-ip-not-bound-up`
- `not-root`
- `os-mismatch`
- `os-release-unsafe`
- `route-unreadable`
- `swap-file-missing`
- `swap-layout-mismatch`
- `swap-size-mismatch`
- `swap-unreadable`
- `test-config-unsafe`
- `test-gate-unsafe`
