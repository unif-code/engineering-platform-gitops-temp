#!/usr/bin/env bash

# kubernetes-cni 1.9.1-1.1 在 /opt/cni/bin 下的锁定 payload：
# name<TAB>mode<TAB>size<TAB>sha256。Stage 40 与 Stage 90 共用同一份事实源。
cni_manifest() {
  cat <<'EOF'
LICENSE	644	11357	b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1
README.md	644	2343	43c32d29316a4a9fe23af500917bd89e51d6a84fa0dcbfcc75b5fbd834c3145a
bandwidth	755	5042926	01c59cee777ade0608361d94bf3bfe01bda82bc8da276d8be917e225aa660639
bridge	755	5698763	3553f5e8f47ed62aec728ab6f7444f6bf1624f916769852c6deb52cd216e22ba
dhcp	755	13725422	bf0552ff2ef54fbd8846b21ffe149f4de63dcd98d86d6b91de5e0bd94473870d
dummy	755	5251069	88f9c9d018681a2b806db2c33184a0a4a532773cb71a60e975a9bf2f017199f6
firewall	755	5702145	ecbd112d77192a125e85ab1fa4ded6cfaf4e9732172e072ee248caa81eba7aed
host-device	755	5159967	a891bd77c5e25b6c4dfa65c8b78cf7f0a00be5ba5d5bbeccd902c08d7f0ea7f3
host-local	755	4350778	ac5ff19b1120bd1d58203b20d45165f244691fcf9776ba55d6dd1747f043c90f
ipvlan	755	5274322	40ceded59770a0f28e7a45a0ed5f8c49044e786bc728f34d6c9de7bc5d3fb660
loopback	755	4302030	02956bdd03b9b71693b3efd72afce88384e4472b644a1c6410fe817f618c1a83
macvlan	755	5307111	33d2730d229dea786c56465a1a96db84ca27b3d5ac552bbc9aa5cdc942622814
portmap	755	5108385	10cc11a28d9c16465889eb59968be76cf04fa884939edf70c27b722cec2c0156
ptp	755	5475470	1cbbce28e96accfef5fe6021762a55ad2b114705f410b8837361a201df6c0b03
sbr	755	4525826	bb886c24182afbad535f158b585524b08a9f1cf0618679987d6b0e11ebf50bb5
static	755	3776708	7bf980bedb303f6d314239413fd4aca5479a9affcd38509057ae203b0da67058
tap	755	5453308	ebff11573fa4ed5793cc08776b8811a3c0f44705b2b530fd5014e6bf69275c1a
tuning	755	4389084	4659e9129d8c669c21c932cd778dc1ac17a717d100768ea23242883401cbb536
vlan	755	5267679	5f6973d15ad2b0d44d1dc0e59982ed05e34e4709630ecd367f766202f9034ac8
vrf	755	4685012	3f3363182c4777bd0d3ead028147f9ecebd60bb32f2d47b7c181877a00ae049b
EOF
}

# 已安装 Cilium（镜像 digest 在 values 中锁定）由 agent 写入 /opt/cni/bin 的 CNI 插件：
# 装 CNI 之前不存在，装完后必须精确匹配；它不属于任何 dpkg 包。
cilium_cni_manifest() {
  cat <<'EOF'
cilium-cni	755	17270840	6b7c1300294f522f5731629c9c53c756c2c55f6aace656fe08e95418769796ce
EOF
}

# /opt/cni/bin 的条目集只允许两种：kubernetes-cni 清单，或清单 + cilium-cni。
# 返回 0 且输出 with-cilium/without-cilium；其他集合返回 1。
cni_entry_set_kind() {
  local actual=$1 expected
  expected=$(cni_manifest | awk -F '\t' '{print $1}' | sort)
  if [[ "$actual" == "$expected" ]]; then
    printf 'without-cilium\n'
    return 0
  fi
  expected=$( { cni_manifest; cilium_cni_manifest; } | awk -F '\t' '{print $1}' | sort)
  if [[ "$actual" == "$expected" ]]; then
    printf 'with-cilium\n'
    return 0
  fi
  return 1
}

# cilium-cni 必须是 root 拥有的 0755 常规非软链文件、size/sha256 精确、且不属于任何 dpkg 包。
# 依赖调用 stage 提供 path_mode / path_size / owned_by_expected / sha256_file。
cilium_cni_entry_is_exact() {
  local root=$1 name mode size digest target actual_digest
  IFS=$'\t' read -r name mode size digest < <(cilium_cni_manifest)
  target="${root}/${name}"
  [[ -f "$target" && ! -L "$target" && "$(path_mode "$target")" == "$mode" ]] || return 1
  owned_by_expected "$target" || return 1
  [[ "$(path_size "$target")" == "$size" ]] || return 1
  actual_digest=$(sha256_file "$target") || return 1
  [[ "$actual_digest" == "$digest" ]] || return 1
  ! dpkg-query -S "/opt/cni/bin/${name}" >/dev/null 2>&1
}
