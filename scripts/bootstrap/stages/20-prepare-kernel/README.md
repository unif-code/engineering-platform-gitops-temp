# 20-prepare-kernel

装载内核模块与 sysctl 参数，使其满足 Kubernetes 与 Cilium 的前置要求。

| 项 | 值 |
| --- | --- |
| PHASE | `prepare-kernel` |
| 成功结果 | `ALREADY_COMPLIANT` / `PASS_KERNEL_CHECK` / `PASS_KERNEL_PREPARED` |
| 证据 | `/root/dev-infra-evidence/09-prepare-kernel-*.txt` |
| 文件 | `run.sh` 流程与终止；`gates.sh` 判定族（只返回 0/1，不打印、不退出） |

## 停止原因

一律 fail-closed，退出码固定：10 前置条件 / 20 供应链 / 30 未知或漂移 /
40 apply 失败 / 50 verify 失败，不降级为告警。

下列 20 个字面量 REASON 由 `StageReadmeTest` 与 `run.sh` 逐项比对，
文档漂移会判红。模板化的 REASON（如 `missing-command-${cmd}`）不在此列。

- `evidence-open-failed`
- `kernel-runtime-path-unsafe`
- `kernel-runtime-verification-failed`
- `legacy-modules-file-present`
- `missing-command-sha256`
- `modprobe-br-netfilter-failed`
- `modprobe-overlay-failed`
- `modules-file-drift`
- `modules-file-post-publish-drift`
- `modules-file-write-failed`
- `modules-parent-unsafe`
- `modules-target-appeared`
- `not-root`
- `partial-persistent-kernel-state`
- `sysctl-file-drift`
- `sysctl-file-post-publish-drift`
- `sysctl-file-write-failed`
- `sysctl-load-failed`
- `sysctl-parent-unsafe`
- `sysctl-target-appeared`
