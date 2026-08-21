# MinIO 与 Object Lock 验证

> **DEV-001 ACTIVE**：该同机备份只验证机制，V0.5 Production Candidate 前必须迁出 Cluster 故障域。

GitOps commit / PR：
执行人：
开始 / 结束时间（含时区）：

## 部署与安全判定

- [ ] MinIO Server Image ID 与 PCS 的 `linux/amd64` digest 一致。
- [ ] PVC 使用 `stateful-rwo-lowlatency`，容量 50Gi；`minio` Namespace 的 PVC ResourceQuota 为 1 个 / 50Gi。
- [ ] MinIO Server resources 为 `100m/256Mi` requests、`1 CPU/2Gi` limits。
- [ ] API 只使用 TLS，证书 SAN 含 `minio.minio.svc.cluster.local`。
- [ ] `postgres-backup`、`etcd-backup`、`audit-worm` 均启用 Versioning 与 Object Lock。
- [ ] 三个用户只能访问各自 bucket，匿名访问为 `none`。
- [ ] `postgres-backup` 默认 GOVERNANCE retention 为 7 天。
- [ ] bucket hard quota 分别为 `postgres-backup=30Gi`、`etcd-backup=5Gi`、`audit-worm=5Gi`，`mc quota info` 与 Desired State 一致。
- [ ] `audit-worm` 测试对象在保留期内的普通删除被拒绝。

验证资源：`runbook/examples/minio-lock-verify.yaml`。它使用 Secret 引用，不包含凭据；重复执行前先删除同名已完成 Job。

## 原始输出

```text
待运维回填 Job 日志与 MinIO bucket/versioning/retention 输出。
```

## 判定

- [ ] PASS
- [ ] FAIL（停止后续数据库与应用 Reconcile）

失败原因 / 决策链接：
