# 瞬态验证资源

本目录中的 YAML 只供已批准的人工验证/恢复窗口使用：

- 不属于 Flux Desired State，不得加入 `apps/`、`infrastructure/` 或任何 Kustomization。
- 执行前核对当前 Git commit、目标 context、Namespace 和 Image digest。
- `postgres-restore.yaml` 含一个显式时间占位，必须在副本中替换并复核，禁止原文件直接 apply。
- 证据留存后按对应 runbook 删除瞬态 Job/Cluster/Namespace。
- 所有凭据只由已存在的 Kubernetes Secret 引用，不得写入 YAML 或日志。
