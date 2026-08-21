# 10-stage-artifacts

把已批准的制品下载到 /root/dev-infra-artifacts 并校验 digest 与归档安全性。

| 项 | 值 |
| --- | --- |
| PHASE | `stage-artifacts` |
| 成功结果 | `ALREADY_COMPLIANT` / `PASS_ARTIFACTS_CHECK` / `PASS_ARTIFACTS_STAGED` |
| 证据 | 无（回执即证据） |
| 文件 | `run.sh` 流程与终止；`gates.sh` 判定族（只返回 0/1，不打印、不退出） |

## 停止原因

一律 fail-closed，退出码固定：10 前置条件 / 20 供应链 / 30 未知或漂移 /
40 apply 失败 / 50 verify 失败，不降级为告警。

下列 25 个字面量 REASON 由 `StageReadmeTest` 与 `run.sh` 逐项比对，
文档漂移会判红。模板化的 REASON（如 `missing-command-${cmd}`）不在此列。

- `artifact-directory-create-failed`
- `artifact-directory-mode-failed`
- `artifact-directory-unsafe`
- `artifact-parent-missing-or-unsafe`
- `artifact-root-create-failed`
- `artifact-root-mode-failed`
- `artifact-root-unsafe`
- `artifact-state-invalid`
- `artifact-state-unreadable`
- `artifact-temp-create-failed`
- `disk-space-below-1-gib`
- `disk-space-invalid`
- `disk-space-unreadable`
- `lock-basename-duplicate`
- `lock-digest-invalid`
- `lock-file-missing-or-unsafe`
- `lock-name-duplicate`
- `lock-name-unapproved`
- `lock-record-count-invalid`
- `lock-record-invalid`
- `lock-schema-drift`
- `missing-command-sha256`
- `not-root`
- `url-basename-invalid`
- `url-not-official-https`
