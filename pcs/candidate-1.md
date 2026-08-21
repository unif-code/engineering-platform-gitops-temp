# Platform Compatibility Set Candidate 1

状态：`CANDIDATE`  
环境：`DEV` / `NON_HA`  
基线：`2026-08-10.1`

基础设施与运维架构：`engineering-platform-docs/architecture/09-infrastructure-operations.md`

架构参数：`engineering-platform-docs/architecture/appendix-parameters.md`

治理例外（DEV-001 / DEV-002）：`engineering-platform-docs/architecture/deviations.md`

容量 Profile：`DEV-002` / `SINGLE_USER_MINIMAL`
目标平台：`linux/amd64`（必须由 `runbook/00-server-baseline.md` 的 `uname -m=x86_64` 回执确认）

任何版本、Chart、Manifest 或 Image 变化都必须建立新的 PCS Candidate。`候选 / 实际 digest` 只允许来自官方 Registry/Chart index 查询或部署 Image ID；不得填写猜测值。Registry 查询值仍需在部署后与实际 Image ID 比对。

| 领域 | 组件 | 锁定版本 / Artifact | Image / Chart | 候选 / 实际 digest | 状态与备注 |
| --- | --- | --- | --- | --- | --- |
| Runtime | Kubernetes | `v1.36.3` | `registry.k8s.io/kube-{apiserver,controller-manager,scheduler}:v1.36.3` | 待部署回填 | kube-proxy 不部署 |
| Runtime | containerd | `2.3.1` | OS package / 官方二进制 | 待安装回填 | CRI v1、config v4、cgroup v2 |
| Runtime | etcd | `3.6.8-0` | `registry.k8s.io/etcd:3.6.8-0` | index `sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5`；amd64 `sha256:aa2b41e3f99c9a337b82f687875a63c5119e6d39bc43fc76b6c40a96f55cf391` | kubeadm v1.36.3 锁定；CronJob 按 amd64 digest 引用 |
| Runtime | CoreDNS | `v1.14.2` | `registry.k8s.io/coredns/coredns:v1.14.2` | 待部署回填 | kubeadm v1.36.3 锁定 |
| Network | Cilium | `1.20.0` | Helm `cilium/cilium` | 待部署回填 | kube-proxy replacement、Gateway API enabled |
| Network | Gateway API CRD | `v1.6.1` Standard | upstream release manifest | 待部署回填 | bootstrap 带外安装，命令留证 |
| GitOps | Flux | `v2.9.3` | bootstrap manifests | 待部署回填 | 仅四个 Controller；无 image automation |
| Storage | local-path-provisioner | `v0.0.31` | `docker.io/rancher/local-path-provisioner` | amd64 `sha256:5fb0394abf87407a27cc56db94334eb0c92d0b5de2636683a7ec51f38143dfc9` | **DEV-002 GAP**：不支持在线扩容或实际字节硬 quota；`allowVolumeExpansion=false`，由 ResourceQuota、容量告警和 Stop Gate 补偿 |
| Storage | local-path helper | `1.36.1-1` | `registry.k8s.io/e2e-test-images/busybox` | amd64 `sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb` | provisioner helper Pod |
| PKI | cert-manager | `v1.21.1` | Helm chart `v1.21.1` | 待部署回填 | `dev-selfsigned` 仅限 DEV |
| Object Storage | MinIO Server | `RELEASE.2025-09-07T16-13-09Z` | `quay.io/minio/minio` | index `sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`；amd64 `sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2` | **BLOCKED：上游已归档且该预构建版本早于最后 CVE 修复版本；合并前需风险决策或提供内部构建 digest** |
| Object Storage | MinIO Client (`mc`) | `RELEASE.2025-08-13T08-35-41Z` | `quay.io/minio/mc` | index `sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727`；amd64 `sha256:eb4ea9884b77704230e2423e9004d2fa738dc272876b9cc41a297d29443b8780` | 初始化、验证与 etcd 上传工具 |
| Database | CloudNativePG Operator | `1.30.0` | Helm chart `cloudnative-pg` `0.29.0` | chart `sha256:668e065ff53508d58238788fd35b355a925060843629a951df0e6a9362e6d32f`；运行镜像待部署回填 | Chart `appVersion=1.30.0` |
| Database | PostgreSQL | `18.4` | `ghcr.io/cloudnative-pg/postgresql:18.4-standard-trixie` | index `sha256:f0cc49632b5cc1e51f65ba03658c89bd31d64ea2672b14843a808a8d281417e1`；amd64 `sha256:ae0ec6943c3c24b0de87f93b73ac531a8e546a4cc895655f793547eed2fdbef1` | Cluster 清单按 amd64 digest 引用 |
| Database | Barman Cloud Plugin | `0.13.0` | Helm chart `plugin-barman-cloud` `0.7.0` | chart `sha256:683494c04cc94f7d33c4ac5f3d8d64c209634b48bd0e84da31d7d1fad22cdcdb`；运行镜像待部署回填 | Chart `appVersion=v0.13.0` |
| Observability | kube-prometheus-stack | `88.1.5` | Helm chart `kube-prometheus-stack` | 待部署回填 | 单副本；Grafana Managed Alerting off |
| Observability | Metrics Server | app `0.8.1` / chart `3.13.1` | Helm chart `metrics-server` | chart `sha256:084e6edb680cf4e2acc30bd496568c53fdf663cbacf6e17876b25785c35b7a13`；index `sha256:b2d2efaf5ac3b366ed0f839d2412a2c4279d4fc2a2a733f12c52133faed36c41`；amd64 `sha256:6231fb0a1ffab76c92ab880f51a0d11b290f688373647bcedff85af025dfd8a9` | Kubernetes 1.31+；cert-manager 保护 APIService TLS；kubelet serving certificate 必须由 Cluster CA 签发，禁止任何 insecure TLS 参数 |
| Application | engineering-platform-backend | 待应用 owner 构建 | `ghcr.io/unif-code/engineering-platform-backend@sha256:…` | **BLOCKED** | 由 backend owner 提供首个 digest |
| Application | engineering-platform frontend | 待应用 owner 构建 | `ghcr.io/unif-code/engineering-platform@sha256:…` | **BLOCKED** | 由 frontend owner 提供首个 digest |

## 部署后核验

```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{end}'
```

- [ ] 所有计划组件逐项与实际版本、Chart Revision、Image digest 对齐。
- [ ] 无 `latest`、无浮动 tag、无未解释的 digest 漂移。
- [ ] MinIO 供应链阻塞已关闭并记录决策证据。
- [x] local-path 与在线扩容/硬 quota Contract 的差异已登记为 DEV-002；运行补偿控制仍待验收。
- [ ] frontend/backend 首个发布 digest 已回填。
