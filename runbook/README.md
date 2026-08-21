# DEV 运维证据索引

> **DEV-001 ACTIVE（仅 V0.1 DEV）**：MinIO 与被保护数据位于同一台服务器，整机故障会同时丢失源数据和备份。本拓扑只验证备份/恢复机制，不满足 Cluster 外故障域要求；最迟在 **V0.5 Production Candidate** 前关闭，PROD 永不适用。canonical 记录位于 `engineering-platform-docs/architecture/deviations.md`。

> **DEV-002 ACTIVE（仅单用户 DEV）**：完整功能与 7 天保留不变；平台稳态实际磁盘目标不超过 100Gi、恢复峰值不超过 130Gi，根盘 80% 告警、90% Stop Gate。canonical 记录位于 `engineering-platform-docs/architecture/deviations.md`。

所有标记为【运维】的命令只能由获准人员在目标服务器执行。执行前记录 Git commit，执行后保留 UTC 时间、完整命令、关键 stdout/stderr、退出码与判定；Secret 值、Token、私钥、kubeconfig 不得写入本目录。

bootstrap 使用固定的 07～14 顺序：`07 preflight`、`08 artifact staging`、
`09 kernel`、`10 containerd`、`11 Kubernetes packages`、`12 kubeadm`、
`13 Cilium`、`14 final verify`。除只读的 07 与 14 外，每一阶段都必须先执行
`--check` 并停止；只有回执审核通过后，下一条【运维】命令才可以使用 `--apply`。
任一 `RESULT=STOP_*` 或非零退出码都会终止当前验收链，不得跳过或把后续阶段标为通过。

| 文件 | 证据 |
| --- | --- |
| `00-server-baseline.md` | 服务器容量、架构、OS、时间与 Swap 基线 |
| `01-bootstrap.md` | containerd、kubeadm、Cilium、Gateway API、Flux bootstrap |
| `02-secrets.md` | Secret 名称、Key contract、保管人与轮换登记（无值） |
| `03-minio-verify.md` | 三 bucket、Versioning、Object Lock 与最小用户策略 |
| `04-postgres.md` | CNPG 健康、WAL 与按需 Base Backup |
| `05-etcd.md` | 三小时快照、校验、上传与七天清理 |
| `06-apps.md` | Gateway Web/API/Ready smoke |
| `07-restore-drill.md` | PostgreSQL PITR、etcd 隔离恢复、整机重启自愈 |
| `08-capacity.md` | 稳态 CPU、内存与磁盘容量 |
| `09-acceptance.md` | V0.1 六条验收标准对照 |
| `10-image-owner-handoff.md` | frontend/backend owner 制品回执与应用 Desired State 阻塞 |

`examples/` 仅保存人工恢复/验证时使用的瞬态资源，不属于 Flux Desired State，禁止加入任何 Kustomization。
