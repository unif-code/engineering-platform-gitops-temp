# 00-preflight

只读前置检查：主机身份、内核与运行时基线、CIDR 冲突、清理证据摘要。不写任何东西。

| 项 | 值 |
| --- | --- |
| PHASE | `preflight` |
| 成功结果 | `PASS_PREFLIGHT` |
| 证据 | `/root/dev-infra-evidence/07-preflight-*.txt` |
| 文件 | `run.sh` 流程与终止（本 stage 逻辑全在顶层，无判定函数，故无 gates.sh） |

## 停止原因

一律 fail-closed，退出码固定：10 前置条件 / 20 供应链 / 30 未知或漂移 /
40 apply 失败 / 50 verify 失败，不降级为告警。

下列 20 个字面量 REASON 由 `StageReadmeTest` 与 `run.sh` 逐项比对，
文档漂移会判红。模板化的 REASON（如 `missing-command-${cmd}`）不在此列。

- `architecture-mismatch`
- `architecture-unreadable`
- `cgroup-unreadable`
- `cgroup-v2-required`
- `cleanup-evidence-digest-mismatch`
- `cleanup-evidence-missing`
- `cleanup-evidence-unreadable`
- `ip-address-unreadable`
- `ip-route-unreadable`
- `missing-command-sha256`
- `node-ip-not-bound-up`
- `not-root`
- `os-mismatch`
- `os-release-missing`
- `port-3001-listening`
- `swap-file-missing`
- `swap-layout-mismatch`
- `swap-size-mismatch`
- `swapon-unreadable`
- `unexpected-old-unit`
