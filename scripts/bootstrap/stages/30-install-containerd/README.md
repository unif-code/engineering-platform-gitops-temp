# 30-install-containerd

安装并配置 containerd 与 runc、crictl，落地 systemd unit 与 CRI 配置。

| 项 | 值 |
| --- | --- |
| PHASE | `containerd` |
| 成功结果 | `ALREADY_COMPLIANT` / `PASS_CONTAINERD_CHECK` / `PASS_CONTAINERD_INSTALLED` |
| 证据 | `/root/dev-infra-evidence/10-containerd-*.txt` |
| 文件 | `run.sh` 流程与终止；`gates.sh` 判定族（只返回 0/1，不打印、不退出） |

## 停止原因

一律 fail-closed，退出码固定：10 前置条件 / 20 供应链 / 30 未知或漂移 /
40 apply 失败 / 50 verify 失败，不降级为告警。

下列 53 个字面量 REASON 由 `StageReadmeTest` 与 `run.sh` 逐项比对，
文档漂移会判红。模板化的 REASON（如 `missing-command-${cmd}`）不在此列。

- `archive-validation-failed-containerd`
- `archive-validation-failed-crictl`
- `artifact-directory-unsafe`
- `artifact-entry-unapproved`
- `artifact-root-unsafe`
- `artifact-state-unreadable`
- `containerd-data-root-unsafe`
- `containerd-enable-failed`
- `containerd-extract-create-failed`
- `containerd-extract-failed`
- `containerd-extract-parent-raced`
- `containerd-extract-pre-publish-raced`
- `containerd-extract-pre-tar-raced`
- `containerd-extract-state-raced`
- `containerd-health-verification-failed`
- `containerd-not-active`
- `containerd-not-enabled`
- `containerd-run-directory-unsafe`
- `containerd-service-contract-drift`
- `containerd-service-contract-verification-failed`
- `containerd-service-state-drift`
- `containerd-start-failed`
- `crictl-extract-create-failed`
- `crictl-extract-failed`
- `crictl-extract-parent-raced`
- `crictl-extract-pre-publish-raced`
- `crictl-extract-pre-tar-raced`
- `crictl-extract-state-raced`
- `evidence-open-failed`
- `extracted-member-not-executable`
- `extracted-member-unsafe`
- `lock-basename-duplicate`
- `lock-basename-invalid`
- `lock-digest-invalid`
- `lock-file-missing-or-unsafe`
- `lock-name-duplicate`
- `lock-name-unapproved`
- `lock-record-count-invalid`
- `lock-record-invalid`
- `lock-schema-drift`
- `missing-command-sha256`
- `not-root`
- `orphan-containerd-socket`
- `partial-containerd-installation`
- `partial-containerd-service-state`
- `partial-containerd-unit-state`
- `repository-contract-unsafe`
- `required-artifact-missing`
- `run-parent-unsafe`
- `systemd-daemon-reload-failed`
- `target-directory-create-failed`
- `target-directory-parent-raced`
- `target-directory-post-create-drift`
