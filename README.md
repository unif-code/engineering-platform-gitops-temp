# engineering-platform-gitops

本仓库是 `engineering-platform` DEV 环境唯一的 GitOps Desired State 入口。Flux 只从受保护的 `main` 分支读取 `clusters/dev/`，所有集群变更必须通过 Pull Request 审核后合并。

## 目录

```text
clusters/dev/     # DEV 环境的 Flux 入口与依赖顺序
infrastructure/   # Cluster Foundation、存储、证书、数据库与 Observability
apps/             # engineering-platform frontend/backend 工作负载
pcs/              # Platform Compatibility Set Candidate 与实际 digest
runbook/          # 人工命令、输出摘录、恢复演练与 Gate 证据
```

## 变更规则

- `main` 禁止 direct push 和 force push；所有变更通过 PR，至少一名 Reviewer 批准。
- 禁止在 Git 中保存 Secret 值、私钥、Token、kubeconfig 或密码库导出内容。
- 禁止使用 `latest`、浮动 tag 或启动时自动升级；Chart、Manifest 和 Image 必须按 PCS Candidate 固定版本，部署后的 Image 必须回填 digest。
- 带外 `kubectl apply`、手工 Patch 或临时扩缩容不会成为 Desired State，Flux 会在下一次 Reconcile 将其纠正。bootstrap 阶段确需带外执行的命令必须逐条记录在 `runbook/`。
- 每个 Flux `Kustomization`/`HelmRelease` 必须显式声明 Reconcile ServiceAccount；Controller 禁止跨 Namespace 引用。

## Architecture Decisions

> **ACTIVE：仅限 V0.1 DEV。** MinIO 与被保护的数据位于同一台服务器，整机故障会同时丢失源数据和备份。该拓扑只验证 S3/Versioning/Object Lock、备份和恢复机制，不满足 Cluster 外故障域要求。最迟必须在 **V0.5 Production Candidate 验收前**切换为真实 Cluster 外 S3-compatible Repository；PROD 永不适用。

- 基础设施与运维架构：`engineering-platform-docs/architecture/09-infrastructure-operations.md`。
- DEV-001 canonical source：`engineering-platform-docs/architecture/deviations.md`。
- DEV-002 canonical source：`engineering-platform-docs/architecture/deviations.md`。
- 架构基线清单：`engineering-platform-docs/architecture/baseline-manifest.json`。

DEV-002 使用完整功能的单用户 Kubernetes Profile：83Gi 稳态 PVC、103Gi 恢复态 PVC、130Gi 平台规划峰值，保留 7 天备份和 3.8GiB 主机 Swap；Pod 使用 `NoSwap`。local-path 的 PVC/ResourceQuota 是申请合同而非文件系统硬 quota；根盘达到 80% 告警，达到 90% 时停止新发布、PVC 变更和恢复演练。

## 本地校验

本地需要 `kubectl`、Python 3 + `PyYAML==6.0.3` 与 `shellcheck`。两个入口都只运行
unittest、GitOps manifest 合同校验和 Bash 静态检查，不会调用任何 bootstrap
`--apply`：

```bash
./scripts/validate-fast.sh  # 本地提交前运行，目标不超过 2 分钟
./scripts/validate.sh       # 可选的人工 full sequential diagnostic
```

GitHub `validation-gate` 是完整 suite 的权威部署门禁；普通 push 后必须等待该门禁成功，
才能继续服务器部署或验收。当前 direct-main 批次是用户明确批准的例外；门禁失败时只允许
新增 fix-forward commit，禁止 force push 或改写历史。

服务器 bootstrap 默认使用 `runbook/01-bootstrap.md` 中的可恢复 orchestrator；单独 stage
只作为诊断和人工应急入口。每次服务器操作仍须先提供一条完整命令，提交完整回执并获得
明确批准后，才能执行下一次 mutation。

运行态证据只有在对应 `runbook/` 已回填真实命令输出、PCS digest 与验收结果后才成立；清单可渲染不等于环境已部署。
