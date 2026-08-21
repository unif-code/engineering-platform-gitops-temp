# 应用 Image Owner Handoff

检查时间：`2026-08-09`
状态：`BLOCKED`

只读检查确认：

- frontend `engineering-platform` 位于 `d182113`，当前没有 Dockerfile/镜像发布 Workflow，登录 Shell 计划分支仍指向同一提交。
- backend `engineering-platform-backend` 位于 `27d8691`，当前只有 uv/package skeleton；实施计划要求的 `control_plane.app.bootstrap.app:create_app`、健康端点与 Alembic 配置尚不存在。
- GHCR 匿名 pull token 请求返回 403，本地 `gh` 凭据无效，无法证明两个包已有可用制品。

因此不得生成带伪造 digest 的 Deployment。两个仓各自 owner 完成应用前置实现与镜像发布后，必须回执：

| 字段 | frontend | backend |
| --- | --- | --- |
| Repository | `unif-code/engineering-platform` | `unif-code/engineering-platform-backend` |
| Source commit（完整 40 位 SHA） | | |
| CI run URL | | |
| Image tag `sha-<short-sha>` | | |
| OCI index digest | | |
| `linux/amd64` manifest digest | | |
| 启动命令 / 监听端口 | nginx / 80（owner 确认） | uvicorn / 8000（owner 确认） |
| Smoke 结果 | `/` 登录页 | `/api/v1/me`、`/healthz`、`/readyz` |

应用 Desired State 只接受 Registry 查询结果或 CI provenance 中的 digest，并将 `linux/amd64` manifest digest 直接写入 Deployment。digest 到齐后再提交 backend/frontend Deployment、Service、HTTPRoute 与 Alembic migration Job。

DEV-002 初始资源合同也必须由应用 owner 验证并随首个清单提交：

| Workload | requests | limits |
| --- | ---: | ---: |
| frontend | `10m / 64Mi` | `250m / 256Mi` |
| backend | `100m / 256Mi` | `1 CPU / 1Gi` |
| Alembic migration Job | `100m / 256Mi` | `1 CPU / 1Gi` |

若真实启动或迁移无法在起始值内稳定完成，只能按运行证据局部上调并同步 DEV-002；不得删除 migration、健康检查或镜像 Digest Gate。
