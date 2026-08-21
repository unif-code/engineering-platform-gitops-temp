# DEV Cluster Bootstrap 记录

> 仅记录 bootstrap 阶段获准的带外命令。后续 Desired State 只能通过本仓 PR 变更。

> **STOP GATE**：旧 Docker/Caddy 清退、全新 Kubernetes CRI runtime、稳定 DNS 与维护路径均完成并取得证据前，本页不得把任何运行时判定标为通过。

执行人：`root`
执行时间（含时区）：`2026-08-10 10:36:55 CST`（审计采集时间）；bootstrap 全流程完成 `2026-08-19 10:12 CST`
服务器标识：`example-node`
GitOps commit / PR：bootstrap 完成于 `a3eb3945c733b77f2594c9ff10e99dcd8587cd4d`

## 当前状态：bootstrap 已完成

`2026-08-19` 在 `a3eb394` 上执行 `--apply`，编排器全部 8 个 stage 通过：

| Stage | 结果 |
| --- | --- |
| 00 preflight | `PASS_PREFLIGHT`（证据 `/root/dev-infra-evidence/07-preflight-20260819T021035Z.txt`，SHA-256 `74a80a473e0f571abe6a087d92f30e1f83db6b564f8ab0b2f501a6f21534bf51`） |
| 10–60 | `ALREADY_COMPLIANT` |
| 90 verify | `PASS_BOOTSTRAP_VERIFIED`（证据 `/root/dev-infra-evidence/14-verify-20260819T021224Z.txt`，SHA-256 `dde4cfdc04d199a44b2c0855468c01e5358a82a62fec1f52d540b6427215f75f`） |

编排器汇总：`RESULT=PASS_BOOTSTRAP_ALL`、`REASON=bootstrap-complete`、`NEXT_STAGE=NONE`、`EXIT_CODE=0`。

集群构成：kubeadm 单节点控制面（`clusterName=example-cluster`）、containerd 2.3.1 + runc、
Kubernetes 1.36.3 四包 hold、Cilium 1.20.0（kube-proxy replacement、Gateway API v1.6.1 standard、Envoy DaemonSet）。

## 可恢复的一次性执行合同

每轮只执行一条【运维】命令，并回填完整
命令、stdout/stderr、退出码、`RESULT`、`REASON`、`NEXT`、证据路径与 SHA-256；
agent 审核回执前不得执行下一条。不得把 Secret、Token、私钥或 kubeconfig 回填到仓库。

### 正常路径

服务器执行统一使用一行式入口（内建全部门禁，并以 `env -i` 干净环境启动编排器）：

```bash
scripts/bootstrap/run-approved.sh --check
```

不带 SHA 时，入口取 CI 发布的 `origin/validated`——`validate.yml` 的
`publish-validated` 只在 `push` 到 `main` 且 `validation-gate` 全绿后，把该引用指向
被验证的那个提交。运维因此无需转述 40 位字符；引用缺失或不在 `origin/main`
历史上（例如被回滚）时 fail-closed，绝不部署未过门禁的提交。

它按序校验：SHA 形态（显式传参时）、`--apply` 必须 root、仓库非软链、origin 为
`unif-code/engineering-platform-gitops.git`、当前分支 `main`、工作树干净、
`origin/main` 等于已批准 SHA（显式传参）或 `origin/validated` 可解析且在
`origin/main` 历史上（默认）、`merge --ff-only` 后本地 HEAD 等于该 SHA、
`/root/.helm-kubeconfig.*` 无残留；任一不满足即以固定退出码停止
（90/91/92/93/94/95/96/97/98/99/100）。输出的
`APPROVED_SHA=<sha> (source=origin/validated|argument)` 记录本轮部署的提交来源。

审核完整回执并明确批准 mutation 后，另行执行：

```bash
scripts/bootstrap/run-approved.sh --apply
```

需要部署某个更早的已批准提交（而非最新绿提交）时，仍可显式传参：
`scripts/bootstrap/run-approved.sh <approved-sha> --check`，此时该 SHA 必须等于
`origin/main`。

历史上手工粘贴的等价门禁脚本已由该入口取代：粘贴长脚本曾多次因终端丢字符导致
`APPROVED_SHA` 截断或行断裂，也曾遗漏 `merge --ff-only`（`exit 97`）。

保留的底层入口（仅在明确需要绕过门禁诊断时使用）：

```bash
./scripts/bootstrap/bootstrap-all.sh --check
```

`--check` 全程只读，在第一个需要 APPLY 的 stage 停止，不执行任何 APPLY。审核完整回执并
明确批准 mutation 后，另行执行：

```bash
./scripts/bootstrap/bootstrap-all.sh --apply
```

`--apply` 会先检查每个 stage，跳过返回 `ALREADY_COMPLIANT` 的 stage，仅对需要变更的
stage 执行 apply，并要求 apply 后的 post-check 回到 compliant；否则立即停止。运行失败后，
重跑同一条命令即可恢复：orchestrator 根据真实主机状态重建进度，不读取或维护 progress file。

当前服务器已完成全部 stage `00`～`90`。GitHub `validation-gate` 成功后重跑
orchestrator，它必须依据各 stage 的检查结果跳过这些已完成 stage，并直接抵达 stage `90`。

### 单阶段诊断和人工应急入口

下表保留为诊断和人工应急入口，不是正常 bootstrap 路径。使用任一单独 stage 时仍须每次
先提供一条完整命令并等待服务器回执；agent 审核前不得执行下一次 mutation。

| 阶段 | 入口 | 首次模式 | 通过结果 | 运行证据 |
| --- | --- | --- | --- | --- |
| 07 | `stages/00-preflight/run.sh` | 仅 `--check` | `PASS_PREFLIGHT` | `/root/dev-infra-evidence/07-preflight-*.txt` |
| 08 | `stages/10-stage-artifacts/run.sh` | `--check` 后批准 `--apply` | `PASS_ARTIFACTS_STAGED` 或 `ALREADY_COMPLIANT` | 终端回执及 `/root/dev-infra-artifacts/pcs-2026-08-10.1` 摘要清单 |
| 09 | `stages/20-prepare-kernel/run.sh` | `--check` 后批准 `--apply` | `PASS_KERNEL_PREPARED` 或 `ALREADY_COMPLIANT` | `/root/dev-infra-evidence/09-prepare-kernel-*.txt` |
| 10 | `stages/30-install-containerd/run.sh` | `--check` 后批准 `--apply` | `PASS_CONTAINERD_INSTALLED` 或 `ALREADY_COMPLIANT` | `/root/dev-infra-evidence/10-containerd-*.txt` |
| 11 | `40-install-kubernetes.sh` | `--check` 后批准 `--apply` | `PASS_KUBERNETES_INSTALLED` 或 `ALREADY_COMPLIANT` | `/root/dev-infra-evidence/11-kubernetes-*.txt` |
| 12 | `50-kubeadm-init.sh` | `--check` 后批准 `--apply` | `PASS_KUBEADM_INITIALIZED` 或 `ALREADY_COMPLIANT` | `/root/dev-infra-evidence/12-kubeadm-*.txt` |
| 13 | `60-install-cilium.sh` | `--check` 后批准 `--apply` | `PASS_CILIUM_INSTALLED` 或 `ALREADY_COMPLIANT` | `/root/dev-infra-evidence/13-cilium-*.txt` |
| 14 | `90-verify.sh` | 仅 `--check` | `PASS_BOOTSTRAP_VERIFIED` | `/root/dev-infra-evidence/14-verify-*.txt` |

固定退出码：`0` 表示当前阶段按输出判定完成或需要获批 APPLY；`10` 为前置条件失败，
`20` 为供应链不匹配，`30` 为未知/漂移状态，`40` 为 APPLY 失败，`50` 为部署后
验证失败。任何非零退出码都必须停止。

## 排错：已知 STOP 与处置

`--check`/`--apply` 的 STOP 一律 fail-closed，先看 `REASON=` 再对照下表。以下条目均为
`2026-08-19` 打通全流程期间实际遇到并已修复的情形；除标注「运维动作」外，代码侧已容忍。

| REASON | 含义 | 处置 |
| --- | --- | --- |
| `untrusted-environment-override` | 调用方环境里存在被禁止的变量。输出的 `VARS=` 列出违规变量名 | 用 `run-approved.sh` 执行即可（`env -i` 干净环境）。若手工执行，先 `unset` `VARS=` 列出的变量 |
| `host-not-registered` / `host-config-*` | `bootstrap/hosts/<hostname>/` 缺失或不合规 | 确认主机名与目录名一致；目录 `0755`、四个文件 `0644` 且 root 拥有（合并时用 `umask 022`） |
| `host-pins-invalid` | `pins.sha256` 形态错误 | 改过 host 目录的 yaml 后运行 `scripts/bootstrap/pin-host.sh bootstrap/hosts/<hostname>` |
| `helm-kubeconfig-residue` | 上次运行被信号中断，`/root/.helm-kubeconfig.*` 有残留（内含已校验的 admin.conf 字节） | 人工检查后删除该目录，再重跑；脚本只检测不自动删除 |
| `kubelet-swap-config-drift` | kubelet configz 不可达，通常因 `serverTLSBootstrap` 的 serving CSR 未批准 | 见下节「kubelet serving CSR 人工批准」 |
| `cidr-overlap-or-invalid` | Pod/Service CIDR 与本机地址或路由重叠 | 若重叠项在 CNI 网卡（`cilium_host`/`lxc*`）且完全落在 Pod CIDR 内，属正常，已被豁免；其余为真实冲突，需调整网络规划 |
| `partial-kubernetes-contract` | `/opt/cni/bin` 条目集或包 payload 不符 | 允许的集合只有「kubernetes-cni 包清单」或「包清单 + 锁定的 `cilium-cni`」；其他多余文件需人工核实来源 |
| `control-plane-runtime-set-drift` | 4 个控制面容器未各恰好一个 Running 于 kube-system | 检查 `crictl ps`；装完 CNI 后额外的 cilium/coredns 容器属正常，已被容忍 |
| `cilium-post-install-state-invalid` | helm 装完后 Cilium 工作负载在超时窗口内未就绪 | 脚本在装后有界轮询（默认 10 分钟）；仍超时说明 Pod 真的没起来，查 `kubectl -n kube-system get pods` |

### kubelet serving CSR 人工批准（运维动作）

`bootstrap/hosts/<hostname>/kubeadm-init.yaml` 设 `serverTLSBootstrap: true`，kubelet 因此通过 CSR
申请服务端证书，而核心 Kubernetes 不自动批准 `kubernetes.io/kubelet-serving`。未批准时 kubelet
无服务端证书，apiserver 代理到 kubelet 报 `tls: internal error`，Stage 90 停在 `kubelet-swap-config-drift`。

批准前必须逐条核对（与 Stage 90 `csr_summaries_are_safe` 的判据一致）：

- requester 为 `system:node:<hostname>`
- usages 恰好 `digital signature` + `server auth`（ECDSA serving 证书不请求 `key encipherment`）
- SAN 恰好 `DNS:<hostname>` + `IP Address:<node-ip>`

只读核对：

```bash
KC=/etc/kubernetes/admin.conf
for c in $(kubectl --kubeconfig $KC get csr -o name); do
  u=$(kubectl --kubeconfig $KC get "$c" -o jsonpath='{.spec.username}')
  g=$(kubectl --kubeconfig $KC get "$c" -o jsonpath='{.spec.usages}')
  s=$(kubectl --kubeconfig $KC get "$c" -o jsonpath='{.spec.request}' \
      | base64 -d | openssl req -noout -text \
      | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/^ *//')
  echo "$c | $u | $g | $s"
done
```

核对无误后批准（kubelet 每次重试可能换密钥，全批可确保命中当前私钥）：

```bash
kubectl --kubeconfig /etc/kubernetes/admin.conf get csr -o name \
  | xargs -r kubectl --kubeconfig /etc/kubernetes/admin.conf certificate approve
```

`2026-08-19` 本机批准 20 条，`conditions` 全为 `Approved`，configz 恢复可达
（`failSwapOn=False`、`memorySwap={'swapBehavior': 'NoSwap'}`）。禁止为绕过该步骤给
metrics-server 添加 `--kubelet-insecure-tls`。

## 旧 Docker/containerd 审计与清退决定

| 证据 | 回执 |
| --- | --- |
| 前置基线 | `/root/dev-infra-evidence/00-server-baseline-20260810T004203Z.txt`；SHA-256 `c100b23fbcc48253704c32bf7954b4dfc7e42ba9b831c2efb3fce488f56ea067` |
| 审计文件 | `/root/dev-infra-evidence/01-platform-server-pre-cleanup-20260810T023655Z.txt` |
| SHA-256 | `4634d71119324f451d0a055d10c373e08a208551f1b71c8ce5ee329d5cb1fc3c` |
| Docker / containerd.io / runc | Docker `29.6.1`；containerd.io `2.2.5`；runc `1.3.6` |
| Docker 与 containerd service/socket | 两个 service 均 enabled/running；Docker 通过 `/run/containerd/containerd.sock` 使用同一个 containerd |
| containerd config / CRI | config version `3`；`io.containerd.grpc.v1.cri` 被禁用；runc `SystemdCgroup = false`，不满足 Kubernetes 目标配置 |
| 运行容器 | 15 个：10 running、5 stopped；Coze Loop 全套与独立 `uni-mysql`；ClickHouse 处于持续重启状态 |
| 数据路径 | Docker volume 位于 `/var/lib/docker/volumes`；Coze Loop bind mount 位于 `/data/coze-loop` |
| 实际占用 | `/var/lib/docker` `6.1G`；`/var/lib/containerd` `20G` |
| 监听端口 | Docker 暴露 `3306`、`8082`、`8888`；Caddy 使用 `80`/`2019`；宿主机 `3001` 进程身份仍待核验 |
| 批准路径 | 用户确认旧业务与数据均可删除；服务器定位为“研发平台专有服务器”，不是 Kubernetes-only 节点 |

批准维护路径为：清退 Docker Engine、Caddy、Coze Loop、独立 `uni-mysql` 及旧共享 containerd 数据；随后从干净状态安装 PCS 锁定的 Kubernetes CRI runtime。不得把现有 Docker runtime 原地改造成 Kubernetes runtime。

当前 Docker APT 源只回报 containerd.io candidate `2.3.3`，未提供 PCS 锁定的 `2.3.1`。清退完成后，必须先验证 `2.3.1` 的可信供应路径与 digest；不得静默改装 `2.3.3`。

### 清退边界

允许永久删除：

- Docker 的全部 container、image、network、volume 与 `/var/lib/docker`。
- 旧共享 runtime 数据 `/var/lib/containerd` 及 Docker 提供的 `/etc/containerd/config.toml`。
- `/data/coze-loop`、Caddy package/config/data/log，以及 Docker APT source/key。

必须保留：

- Ubuntu 基础系统、SSH、systemd-networkd、systemd-resolved、chrony、APT、LVM、Swap、VMware Tools。
- `/root/dev-infra-evidence` 中的全部证据。
- 身份未核验的宿主机 `3001` 进程；在取得 executable、cwd 与启动来源证据前不得结束或删除。

### 清退执行记录

第一次执行：

| 字段 | 回执 |
| --- | --- |
| 证据文件 | `/root/dev-infra-evidence/03-legacy-runtime-cleanup-20260810T025142Z.txt` |
| SHA-256 | `e758df7f2af5ce2ea43e10ef3aa75f18e7d936808ffa363ecda9bee6556c83af` |
| Exit code | `100`（未完成） |
| 已执行 | 15 个容器已关闭并删除；Caddy、Docker 与旧 containerd service 已 disable/stop |
| 未执行 | APT package purge、数据目录删除、bridge 删除及最终验证均未开始 |
| 根因 | Docker 相关 package 被 APT hold；`apt-get purge -y` 拒绝变更 held package |
| 续跑约束 | 仅解除 7 个明确清退目标的 hold；允许 purge held package；禁止执行 `apt autoremove` |

APT 报告的可自动移除项包含 `iptables`、`nftables`、`libnetfilter-conntrack3` 等后续 Kubernetes/Cilium 仍可能使用的宿主机网络组件，因此本阶段必须保留。

第二次执行：

| 字段 | 回执 |
| --- | --- |
| 证据文件 | `/root/dev-infra-evidence/04-legacy-runtime-cleanup-resume-20260810T025913Z.txt` |
| SHA-256 | `166d8a71b5c459356f6c668770d9e8565ced5ef3a3ebe21372333f50a42b4aed` |
| Exit code | `0`（成功） |
| Package | Caddy、Docker Engine/CLI/plugins/rootless extras 与 containerd.io 均已 purge；目标 package hold 已清空 |
| 数据 | `/var/lib/docker`、`/var/lib/containerd`、`/etc/{docker,containerd,caddy}`、`/opt/containerd`、`/data/coze-loop` 均已删除 |
| 网络 | `docker0`、`br-28cd7b020fce` 与旧端口 `80`、`2019`、`3306`、`8082`、`8888` 均已清退 |
| 主机健康 | SSH、chrony、systemd-networkd、systemd-resolved active；`ens160` up；Swap `3.8Gi` 保留 |
| 清退后容量 | 根文件系统使用 `11G/489G`，可用 `458G`，使用率 `3%`；内存可用 `61Gi` |

旧 Docker/Caddy/runtime 清退已关闭；没有执行 `apt autoremove`。宿主机仍有以下旧应用待单独审计和清退：

- `uniflow` 用户的 Node 进程监听 `*:3001`。
- executable：`/usr/local/lib/node-v24.18.0/bin/node`。
- cwd：`/data/workflow/apps/server`。
- cgroup：`/user.slice/user-0.slice/session-397.scope`，未发现 system service 归属证据。

### 宿主机 Workflow/Node 审计

| 字段 | 回执 |
| --- | --- |
| 证据文件 | `/root/dev-infra-evidence/05-host-workflow-audit-20260810T030918Z.txt` |
| SHA-256 | `3f3432d0e3a5fdef9da4f292e0329d598e7554f8af0e7ded2f2728b9dbdb4933` |
| 监听进程 | `*:3001`；PID `1034757`；用户 `uniflow`；executable `/usr/local/lib/node-v24.18.0/bin/node`；cwd `/data/workflow/apps/server` |
| 父进程链 | 两层 Node `MainThread` → `sh` → `npm exec tsx` → `bash`；整条链均属于 `uniflow`，cwd 均为 `/data/workflow/apps/server` |
| 会话归属 | 全部进程位于 `/user.slice/user-0.slice/session-397.scope`；对应旧 root SSH session `397`，RemoteHost `10.96.125.33`，状态 `closing` |
| 持久化检查 | root/uniflow crontab 均不存在；未发现用户 systemd unit、已安装 Workflow systemd unit、PM2、forever 或 Supervisor |
| 账号 | `uniflow` 为 UID/GID `1000`，仅属于 `uniflow` 与旧 `docker` 组；未登录且未启用 lingering；home 占用 `76K` |
| 应用数据 | `/data/workflow` 位于根文件系统，归 `uniflow` 所有；旧 Git 项目及依赖合计约 `2.2G`，包含应用 `.env`、`.git`、构建产物与 `node_modules` |
| Node runtime | `/usr/local/lib/node-v24.18.0` 为非 dpkg 管理的手工安装，约 `203M`；`node`、`npm`、`npx`、`corepack`、`pnpm`、`pnpx` 的 `/usr/local/bin` 链接均指向该目录 |
| 其余监听 | 除 DNS、NTP、SSH 与 `3001` 外，无其他旧应用监听端口 |

审计已确认 `3001` 为旧 Workflow 应用的孤立进程链，不属于当前 SSH 会话，也没有发现宿主机持久化启动入口。用户已批准清除旧安装及数据；下一维护动作可永久删除该进程链、`/data/workflow`、手工 Node runtime、`uniflow` 账号/home，以及清空后的旧 `docker` 组。

执行清退前仍须以进程 UID、cwd、executable、cgroup 与证据 SHA-256 做 fail-closed 复核；任一身份漂移必须停止，不得扩大删除范围。不得执行 `apt autoremove`，且必须保留 `/root/dev-infra-evidence` 与基础系统服务。

### 宿主机 Workflow/Node 清退执行记录

| 字段 | 回执 |
| --- | --- |
| 证据文件 | `/root/dev-infra-evidence/06-host-workflow-cleanup-20260810T033358Z.txt` |
| SHA-256 | `a68a3d2ff340bcdcb4265853107a3a2c22a9f7328728473d81d9be2d1486e635` |
| Exit code | 脚本 `0`；外层命令 `0`；结果 `SUCCESS` |
| Fail-closed 复核 | 前序 `04`、`05` 证据 SHA-256 均通过；目标进程 UID、cwd、executable 与旧 `session-397.scope` 全部匹配；执行命令位于当前 `session-875.scope` |
| 进程 | 已结束 PID `1034710`、`1034712`、`1034740`、`1034741`、`1034757` 的完整旧 Workflow 进程链；`*:3001` 已关闭 |
| 永久删除 | `/data/workflow`、`/usr/local/lib/node-v24.18.0`、对应的 6 个 `/usr/local/bin` 链接、`uniflow` 账号/home/私有组，以及已无成员的旧 `docker` 组 |
| 非致命提示 | `userdel` 报告 `/var/mail/uniflow` 不存在；不影响账号删除与最终验证 |
| 主机健康 | SSH、DNS、NTP 与基础网络监听保留；未发现其他旧应用监听；证据目录未删除 |
| 清退后容量 | 根文件系统使用 `9.9G/489G`，可用 `459G`，使用率 `3%`；内存可用 `61Gi` |
| Swap | `/swap.img` `3.8Gi` 保留且当前未使用 |

清退完成回执：

```text
Docker/Caddy/旧 containerd 与宿主机 Workflow/Node 清退完成；服务器旧应用清退 CLOSED。
```

## containerd 与内核前置

命令与输出：

```text
待运维回填。
```

判定：

- [ ] containerd 版本、service、socket 与 data-root 符合已批准路径；若不是 `2.3.1`，已关联独立 DEV-only Decision。
- [ ] `SystemdCgroup = true`，cgroup v2 生效。
- [ ] `overlay`、`br_netfilter` 已加载，`net.ipv4.ip_forward = 1`。

## kubeadm 单节点

kubeadm 配置必须包含以下 kubelet 配置；保留主机 Swap，但 Pod 不使用 Swap。为安全提供 Metrics API，同时请求由 Cluster CA 签发的 kubelet serving certificate：

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
failSwapOn: false
memorySwap:
  swapBehavior: NoSwap
serverTLSBootstrap: true
```

`serverTLSBootstrap` 产生的 `kubernetes.io/kubelet-serving` CSR 必须由运维核对请求者、用途及节点 DNS/IP SAN 后人工批准；核心 Kubernetes 不自动批准 serving CSR。禁止为通过 metrics-server 验收添加 `--kubelet-insecure-tls`。

命令与输出：

```text
待运维回填。
```

判定：

- [ ] Kubernetes 为 `v1.36.3`，节点为 `Ready`。
- [ ] kubelet 为 `failSwapOn=false`、`memorySwap.swapBehavior=NoSwap`；`/swap.img` 保留且 Pod 不使用 Swap。
- [ ] kubelet serving certificate 由 Cluster CA 签发、SAN 匹配节点；CSR 审批证据已留存。
- [ ] 使用稳定端点 `dev-cp.unif.internal:6443`。
- [ ] 未部署 kube-proxy，Cilium `1.20.0` Ready。
- [ ] Gateway API Standard CRD `v1.6.1` 已安装。
- [ ] local-path-provisioner 已安装且 `local-path` 不是默认 StorageClass。

`kubectl get nodes -o wide`：

```text
待运维回填。
```

## Flux bootstrap

命令与输出：

```text
待运维回填。
```

判定：

- [ ] Flux CLI / Controller 为 `v2.9.3`。
- [ ] Git deploy key 为只读。
- [ ] 仅 source/kustomize/helm/notification 四个 Controller。
- [ ] `kustomize-controller` 与 `helm-controller` 启用 `--no-cross-namespace-refs=true`。
- [ ] `flux check` 通过。
