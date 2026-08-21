# Repository Guidelines

本仓是 `engineering-platform` DEV 环境的 GitOps Desired State 与运维证据仓，不存放前端或 backend 业务代码。

## 架构事实源

- 架构文档已独立到同级 `engineering-platform-docs` 仓，成员仓禁止复制架构文档。
- 基础设施、GitOps、Kubernetes 与运维目标契约以 `engineering-platform-docs/architecture/09-infrastructure-operations.md` 为准。
- 版本、容量、端口与阶段参数以 `engineering-platform-docs/architecture/appendix-parameters.md` 为准。
- DEV-001 与 DEV-002 的 canonical source 是 `engineering-platform-docs/architecture/deviations.md`。
- 治理例外先登记后引用：任何 `DEV-xxx` 编号必须先存在于 `engineering-platform-docs/architecture/deviations.md` 的登记条目，才可在本仓 runbook、文档、清单或注释中引用；铸造新编号的一方负责在同一工作批次内完成 docs 仓登记。
- 架构基线号与文档摘要以 `engineering-platform-docs/architecture/baseline-manifest.json` 为准。

## 变更与验证

- 禁止提交 Secret、Token、私钥、kubeconfig 或密码库导出内容。
- Image、Chart 与 Manifest 必须固定版本或 digest，禁止 `latest` 与浮动 tag。
- 【运维】命令必须先给出完整命令并等待服务器回执；证据不得记录敏感值。
- 本地提交前运行受影响的 focused tests 和 `./scripts/validate-fast.sh`；普通 push 后必须等待 GitHub `validation-gate` 全部通过，才可继续服务器部署或验收。
- `./scripts/validate.sh` 保留为人工完整顺序验证入口，不再要求每次本地提交运行；提交历史保持线性并使用 Conventional Commits。
- CI 钉死 shellcheck `0.9.0`；本地版本不同会出现「本地绿、CI 红」。`validate-static.sh` 会打印实际版本，需要完全对齐时运行 `python3 -m venv /tmp/sc && /tmp/sc/bin/pip install shellcheck-py==0.9.0.6` 并用该 venv 的 shellcheck 复核。
- 服务器执行统一用 `scripts/bootstrap/run-approved.sh --check|--apply`（不带 SHA 时取 CI 在 `validation-gate` 全绿后发布的 `origin/validated`；显式传 SHA 时该 SHA 必须等于 `origin/main`）：它内建 SHA/origin/分支/干净树/ff-only/umask/helm 残留门禁，并以 `env -i` 干净环境启动 bootstrap，避免交互 shell 遗留变量触发 `untrusted-environment-override`。

## Codex 原生记忆

- 平台共享记忆位于同级 `engineering-platform-docs/memories_1.sqlite`，同步规则以该仓 `MEMORIES.md` 为准。
- 仅当用户明确发送 `【同步记忆】` 时，进入同级 `engineering-platform-docs` 运行 `npm run memory:sync`；禁止直接复制或覆盖任一 SQLite 文件。
- 共享记忆同步进本机 Codex 原生数据库后由 Codex 自身消费，不在成员仓展开、复制或提交记忆正文。
- 记忆与事实冲突时，以当前用户指令、本仓当前 Git/代码、docs 架构文档和可执行测试为准。

## Superpowers 开发进度

- 开始或恢复开发任务时，先读取 `docs/superpowers/progress/current.md`；验证其中 `Based On Commit` 存在且是当前 HEAD 的祖先，再检查该提交之后的 Git log、工作树与测试证据。
- 恢复顺序固定为 `current.md → active plan/spec → Git log/status → 测试证据 → Codex memory`。信息冲突时，优先级为当前用户指令、当前 Git/代码、架构文档与测试、progress、memory。
- 仅当用户明确发送 `【同步进度】` 时更新本仓 `current.md` 并推送；不得自动提交业务源码，不得复制 `.superpowers/sdd`、会话或工作树 diff。首次初始化允许同一提交包含本节与 `current.md`。
- `Remote Recoverable: yes` 只表示继续开发所需的源码、计划和证据均已提交并推送；存在本机独有改动时必须写 `no`。
