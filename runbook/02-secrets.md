# DEV Secret 登记

> 只登记 metadata 和 Key contract，严禁记录值。创建命令由 agent 在【运维】检查点一次性提供，人工执行后回填本表。

GitOps commit / PR：
执行人：
执行时间（含时区）：
密码库记录 ID：

| Namespace / Secret | Type / 必需 Key | 用途 | 保管人 | 已创建 | 最近轮换 |
| --- | --- | --- | --- | --- | --- |
| `minio/minio-root` | Opaque：`user`、`password` | MinIO bootstrap 管理身份 | | [ ] | |
| `minio/minio-bootstrap-users` | Opaque：`postgresAccessKey`、`postgresSecretKey`、`etcdAccessKey`、`etcdSecretKey`、`auditAccessKey`、`auditSecretKey` | 初始化三个最小权限用户 | | [ ] | |
| `platform/pg-backup-minio` | Opaque：`ACCESS_KEY_ID`、`ACCESS_SECRET_KEY` | Barman 写 `postgres-backup` | | [ ] | |
| `platform/platform-audit-rw` | `kubernetes.io/basic-auth`：`username=audit_rw`、`password` | CNPG managed role | | [ ] | |
| `kube-system/etcd-backup-minio` | Opaque：`ACCESS_KEY_ID`、`ACCESS_SECRET_KEY` | etcd CronJob 写 `etcd-backup` | | [ ] | |
| `platform/minio-ca` | Opaque：`ca.crt` | Barman 验证 MinIO TLS | | [ ] | |
| `kube-system/minio-ca` | Opaque：`ca.crt` | etcd CronJob 验证 MinIO TLS | | [ ] | |
| `monitoring/minio-ca` | Opaque：`ca.crt` | Prometheus 验证 MinIO TLS | | [ ] | |

CNPG 在 `platform` Cluster 初始化后生成 `platform-app` 与 `platform-superuser`；只登记存在性、ownerReference 和 Secret type，不导出内容。

```text
待运维回填 kubectl get secret 的 metadata-only 输出。
```
