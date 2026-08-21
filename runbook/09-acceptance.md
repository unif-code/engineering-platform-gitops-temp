# V0.1 DEV 验收对照

GitOps commit / PR：
PCS Candidate：`pcs/candidate-1.md`
验收人：
验收时间（含时区）：

| # | 验收标准 | 证据 | 状态 |
| --- | --- | --- | --- |
| 1 | main 受保护、Flux 单向 Reconcile，带外扩容被纠正 | PR/branch protection、Flux 输出、扩容前后输出 | PENDING |
| 2 | frontend/backend 按 digest，经 Gateway 单入口通过三条 Smoke | `runbook/06-apps.md` | BLOCKED（等待应用 owner digest） |
| 3 | PG PITR 与 etcd 隔离 restore 各完成一次 | `runbook/07-restore-drill.md` | PENDING |
| 4 | 三 bucket Versioning/Object Lock 通过，DEV-001 醒目标注 | `runbook/03-minio-verify.md`、`runbook/README.md` | BLOCKED（MinIO 供应链决策） |
| 5 | PCS 与部署版本/Image ID 一致 | `pcs/candidate-1.md` 与抽查输出 | PENDING |
| 6 | DEV-002 容量包络、Metrics API 与 80%/90% Gate 有证据，整机重启后全栈自愈 | `runbook/08-capacity.md`、`runbook/07-restore-drill.md` | PENDING |

已批准的 DEV-only 差异：`stateful-rwo-lowlatency` 由 local-path provisioner 映射，无法履行目标架构的在线扩容或实际字节硬 quota Contract；清单明确设置 `allowVolumeExpansion=false`，并由 DEV-002 的 bucket quota、Prometheus 保留上限、ResourceQuota、80% 告警与 90% Stop Gate 补偿。不得把这些补偿控制表述为物理硬隔离。

## 未关闭 Stop Gates

- [ ] MinIO 供应链风险已由批准 Decision 或内部构建 digest 关闭。
- [ ] Docker/containerd 共存路径已由用户批准并有运行证据。
- [ ] `dev-cp.unif.internal` 稳定解析已落地。
- [ ] frontend/backend 真实 `linux/amd64` digest 与启动契约已由 owner 回执。
- [ ] kubelet serving certificate、metrics-server APIService 与 `kubectl top` 均通过安全 TLS 验证。

## Git 唯一 Desired State 演示

只在所有应用 Ready 后，由运维将 backend 临时扩为 2 副本；不得提交清单变更。记录 Flux 下一次 Reconcile 恢复 1 副本的时间和输出。

```text
待运维回填。
```

最终结论：`PASS / FAIL / BLOCKED`
DEV-001 状态：`ACTIVE`
DEV-002 状态：`ACTIVE`
关闭负责人 / 截止 Gate：`待登记 / V0.5 Production Candidate 前`
