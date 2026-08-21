# DEV 单节点稳态容量测量

> DEV-002 Profile：可调整长期 workload 的 requests 不超过 `2 CPU / 6Gi`；当前静态合同合计为 `1115m / 2720Mi`。平台稳态实际磁盘不超过 100Gi，恢复演练峰值不超过 130Gi，并为其他程序保留至少 300Gi。

GitOps commit / PR：
执行人：
采样窗口（含时区，至少 15 分钟）：
节点：

## CPU / 内存

| 对象 | CPU request | CPU steady | CPU peak | Memory request | Memory steady | Memory peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Node total / allocatable | | | | | | |
| platform | | | | | | |
| cnpg-system | | | | | | |
| monitoring | | | | | | |
| minio | | | | | | |
| flux-system | | | | | | |
| kube-system | | | | | | |
| **DEV-002 可调整长期 workload 合计** | **1115m** | | | **2720Mi** | | |

Metrics API 证据：

| 检查 | 判定 | 回执 |
| --- | --- | --- |
| `v1beta1.metrics.k8s.io` APIService | `Available=True`，`insecureSkipTLSVerify=false` | |
| metrics-server Image ID | PCS `linux/amd64` digest 一致 | |
| kubelet serving certificate | Cluster CA 签发、节点 SAN 匹配 | |
| `kubectl top node` / `kubectl top pods -A` | 连续采样可用，无 TLS scrape 错误 | |

## 磁盘

| 路径 / PVC | Provisioned | Used | Available | 使用率 | 增长观察 |
| --- | ---: | ---: | ---: | ---: | --- |
| 根文件系统 `/` | 489Gi filesystem / 497Gi LV | | | | 80% 告警 / 90% Stop Gate |
| `/var/lib/containerd` | | | | | |
| `/var/lib/engineering-platform/local-path` | | | | | |
| MinIO PVC 50Gi | 50Gi | | | | bucket quota：30Gi + 5Gi + 5Gi |
| PostgreSQL PVC 20Gi | 20Gi | | | | 主实例 |
| Prometheus PVC 10Gi | 10Gi | | | | 7d / `retentionSize=8GB` |
| Grafana PVC 2Gi | 2Gi | | | | |
| Alertmanager PVC 1Gi | 1Gi | | | | |
| PostgreSQL restore PVC 20Gi | 20Gi（瞬时） | | | | 只在获准演练期间存在 |

> local-path 不执行实际字节硬 quota，也不支持在线扩容。`Provisioned` 是 PVC/ResourceQuota 申请合同；`Used` 必须由节点 `du`、PVC 挂载点与服务指标共同证明。

## 磁盘包络与保护 Gate

| 检查 | 目标 | 实测 / 证据 |
| --- | ---: | --- |
| 稳态 PVC 合计 | 83Gi | |
| 恢复态 PVC 合计 | 103Gi | |
| 平台稳态实际占用 | ≤100Gi | |
| 平台恢复峰值实际占用 | ≤130Gi | |
| 为其他程序保留空间 | ≥300Gi | |
| 根盘 80% 告警 | `NodeRootFilesystemUsageHigh` active/pending 可验证 | |
| 根盘 90% Stop Gate | `NodeRootFilesystemUsageCritical` active/pending 可验证 | |

达到 90% 后停止新的应用发布、PVC 创建/扩容和恢复演练；不自动删除数据库、WORM 对象或备份。常规 PG/etcd 备份继续尝试，失败必须告警。

## 原始输出与结论

```text
待运维回填 kubectl top、requests/limits、df/du 与 PVC 输出。
```

- [ ] CPU、内存和磁盘均保留可解释余量。
- [ ] 无 MemoryPressure / DiskPressure / PIDPressure。
- [ ] 至少 15 分钟的 `kubectl top`、RSS、`df`、`du` 与 PVC 证据已留存。
- [ ] 80% 告警和 90% Stop Gate 已用安全方式验证，不制造真实磁盘耗尽。
- [ ] 容量不足时已停止验收并关联 DEV-002 局部调优或后继 Decision。
