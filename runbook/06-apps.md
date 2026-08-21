# Gateway 应用 Smoke

> frontend/backend 两个 owner 提供真实镜像 digest 且应用 Desired State 合并前，本 runbook 保持 `BLOCKED`。

GitOps commit / PR：
frontend digest：
backend digest：
执行人：
执行时间（含时区）：
Gateway address：
Hostname：`platform.dev.local`

| 请求 | 预期 | HTTP 状态 | 证据 |
| --- | --- | --- | --- |
| `GET /` | 前端登录页可渲染 | 200 | |
| `GET /api/v1/me` | stub JSON | 200 | |
| `GET /readyz` | backend ready | 200 | |

```text
待运维回填三条 curl 的状态、响应摘要与浏览器截图链接；不得记录 Session/Cookie/Token。
```

- [ ] 只存在 Gateway 北向入口，没有 NodePort/额外 Ingress。
- [ ] Gateway TLS 证书 SAN、Serial、有效期与 Secret 一致。
- [ ] Deployment 实际 Image ID 与 GitOps digest 一致。
- [ ] frontend 起始 resources 为 `10m/64Mi` requests、`250m/256Mi` limits；backend 为 `100m/256Mi` requests、`1 CPU/1Gi` limits。
- [ ] Alembic migration Job 为 `100m/256Mi` requests、`1 CPU/1Gi` limits，并在成功后才放行应用 Reconcile。
- [ ] PASS
