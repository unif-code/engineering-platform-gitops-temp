# CloudNativePG 与 PostgreSQL 备份验证

GitOps commit / PR：
执行人：
开始 / 结束时间（含时区）：
按需 Backup 名称：

## 判定

- [ ] CNPG Operator `1.30.0` 与 Barman Cloud Plugin `0.13.0` Ready。
- [ ] `platform/platform` 为单实例、PG `18.4`，Primary 健康。
- [ ] PVC 为 `stateful-rwo-lowlatency` 20Gi；`platform` Namespace 的额度为 2 个 PVC / 45Gi，可容纳主实例与一次恢复实例。
- [ ] Primary resources 为 `250m/512Mi` requests、`2 CPU/4Gi` limits；Barman sidecar 为 `50m/64Mi` requests、`500m/256Mi` limits。
- [ ] `audit_rw` 存在、可登录且不是 superuser。
- [ ] `archive_timeout=5min`，WAL archiving 正常。
- [ ] `platform-daily` 使用六字段表达式在 UTC 02:00 调度。
- [ ] 一次按需 Backup 达到 `completed`，MinIO 同时可见 Base Backup 与 WAL。
- [ ] Barman `data.jobs=1`、`wal.maxParallel=1`，retention 为 7 天；`postgres-backup` hard quota 为 30Gi。

## 原始输出

```text
待运维回填 cluster/scheduledbackup/backup、Pod Image ID、Barman 日志与对象列表。
```

耗时：
结果：`PASS / FAIL`
失败原因 / 决策链接：
