# 40-install-kubernetes

安装 kubeadm/kubelet/kubectl 与 CNI 插件，锁定 apt 源与包版本。

| 项 | 值 |
| --- | --- |
| PHASE | `install-kubernetes` |
| 成功结果 | `ALREADY_COMPLIANT` / `PASS_KUBERNETES_CHECK` / `PASS_KUBERNETES_INSTALLED` |
| 证据 | `/root/dev-infra-evidence/11-kubernetes-*.txt` |
| 文件 | `run.sh` 流程与终止；`gates.sh` 判定族（只返回 0/1，不打印、不退出） |

## 停止原因

一律 fail-closed，退出码固定：10 前置条件 / 20 供应链 / 30 未知或漂移 /
40 apply 失败 / 50 verify 失败，不降级为告警。

下列 70 个字面量 REASON 由 `StageReadmeTest` 与 `run.sh` 逐项比对，
文档漂移会判红。模板化的 REASON（如 `missing-command-${cmd}`）不在此列。

- `apt-archive-publish-failed`
- `apt-archive-publish-raced`
- `apt-archives-cache-invalid`
- `apt-archives-cache-not-empty`
- `apt-archives-cache-raced`
- `apt-parent-unsafe`
- `apt-source-file-unsafe`
- `apt-update-failed`
- `apt-workspace-create-failed`
- `apt-workspace-unsafe`
- `base-dependency-contract-drift`
- `base-dependency-contract-raced`
- `cni-package-payload-invalid`
- `cni-path-chain-post-install-unsafe`
- `cni-path-chain-raced`
- `cni-path-chain-unsafe`
- `cri-tools-hold-forbidden`
- `cri-tools-package-forbidden`
- `cri-tools-package-installed`
- `download-directory-create-failed`
- `download-directory-extra-entry`
- `download-directory-not-empty`
- `download-directory-unsafe`
- `download-parent-unsafe`
- `downloaded-deb-raced`
- `effective-apt-config-unreadable`
- `effective-apt-config-unsafe`
- `evidence-open-failed`
- `gpg-workspace-create-failed`
- `gpg-workspace-unsafe`
- `key-decode-temp-failed`
- `key-download-temp-failed`
- `keyring-publish-failed`
- `keyring-publish-raced`
- `kubelet-pre-init-inputs-not-pristine`
- `kubelet-pre-init-inputs-raced`
- `kubelet-start-failed`
- `kubelet-start-result-invalid`
- `kubelet-start-verification-failed`
- `kubernetes-binary-shadow-present`
- `kubernetes-binary-shadow-raced`
- `kubernetes-keyring-unknown`
- `kubernetes-package-verification-failed`
- `kubernetes-source-unknown`
- `local-deb-install-failed`
- `local-deb-simulation-failed`
- `local-deb-transaction-drift`
- `missing-command-sha256`
- `not-root`
- `orphan-kubernetes-hold`
- `package-hold-failed`
- `package-hold-set-unknown`
- `package-hold-state-invalid`
- `package-hold-state-unreadable`
- `package-hold-verification-failed`
- `package-selection-state-drift`
- `packages-index-provenance-invalid`
- `partial-kubernetes-contract`
- `partial-kubernetes-installation`
- `partial-repository-contract`
- `preexisting-cni-directory`
- `release-key-dearmor-failed`
- `release-key-digest-mismatch`
- `release-key-download-failed`
- `release-key-fingerprint-mismatch`
- `release-keyring-digest-mismatch`
- `repository-contract-verification-failed`
- `source-publish-failed`
- `source-publish-raced`
- `unapproved-kubernetes-source`
