# DEV 恢复与重启自愈演练

> **DEV-001 ACTIVE**：恢复成功不改变同机故障域风险。演练只能由获准运维执行，瞬态资源不得加入 Flux Kustomization。

GitOps commit / PR：
执行人：
演练窗口（含时区）：

## DEV-002 容量 preflight

演练前记录根文件系统、平台实际占用与 PVC。以下条件必须同时满足，否则安全停止，不创建恢复资源：

- 根文件系统使用率低于 90%。
- 当前平台实际磁盘占用 + 20Gi 恢复预算不超过 130Gi。
- 根文件系统当前可用空间减去 20Gi 恢复预算后仍不少于 300Gi。
- `platform` Namespace 当前只有主实例 PVC，45Gi ResourceQuota 尚可接受第二个 20Gi PVC。

Preflight 证据路径 / SHA-256：
判定：`PASS / STOP`

## PostgreSQL PITR

使用 `runbook/examples/postgres-restore.yaml` 的副本，将唯一占位时间替换为已确认存在 Base+WAL 覆盖的 RFC3339 UTC 时间后再 apply。

| 项目 | 结果 |
| --- | --- |
| targetTime | |
| 可用 Base Backup | |
| 恢复开始 / Ready 时间 | |
| RTO | |
| 演练峰值平台磁盘占用 | |
| 根文件系统峰值使用率 | |
| 源 `audit.audit_event` 行数 | |
| 恢复 Cluster 行数 | |
| 校验结论 | |

原始命令与输出：

```text
待运维回填。
```

- [ ] Base + WAL PITR 完成。
- [ ] 行数一致。
- [ ] 恢复 Cluster 使用临时 20Gi PVC，resources 与 Primary/Barman Profile 一致。
- [ ] 证据留存后删除 `platform/platform-restore` Cluster 与 `platform-restore-source` ObjectStore，确认临时 PVC 已回收且未删除 `platform` Namespace 或源备份。

## etcd 隔离恢复

使用 `runbook/examples/etcd-restore-drill.yaml`。Job 只在 Pod 的隔离 `emptyDir` 恢复，不挂载或接入运行中 etcd data-dir。

| 项目 | 结果 |
| --- | --- |
| 快照对象 | |
| snapshot revision | |
| total keys | |
| restore 耗时 | |
| 校验结论 | |

```text
待运维回填 download/restore/status 日志。
```

- [ ] `etcdutl snapshot restore` 成功。
- [ ] revision / total keys 合理。
- [ ] 没有修改运行中 `/var/lib/etcd` 或静态 Pod。
- [ ] 演练期间未越过 130Gi 平台峰值或 90% 根盘 Stop Gate。

## 整机重启自愈

重启前 / 后时间：
恢复至全栈 Ready 耗时：

```text
待运维回填 reboot 后 nodes/pods/Flux/Gateway smoke 输出。
```

- [ ] Node Ready。
- [ ] 所有预期 Pod Running/Completed，PVC 正常挂载。
- [ ] Flux Kustomization/HelmRelease 全 Ready。
- [ ] Gateway 三条 Smoke 再次通过。
