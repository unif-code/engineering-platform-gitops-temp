#!/usr/bin/env bash

# 40-install-kubernetes 的判定族：只读取状态并返回 0/1，不打印证据、不调用 complete、不退出。
# run.sh 负责流程与终止，gates.sh 负责"事实是什么"——两者分开后，判定可以被单独
# 阅读和测试，而不必跟着流程走一遍。
# 本文件由 run.sh 以 ${script_dir}/gates.sh 引入，与 run.sh 同属一个 stage 目录，
# 因此被 bootstrap-all.sh 的 stage 目录逐条目门禁覆盖（属主、权限、非符号链接）。
# 判定所需的常量与路径由 run.sh 声明；缺失时 set -u 直接报未绑定变量。
# SC2154 只对小写变量告警（全大写被当成环境变量豁免），故显式关闭。
# shellcheck disable=SC2154

managed_parent_safe() {
  [[ -d "$1" && ! -L "$1" && "$(path_mode "$1")" == 755 ]] && owned_by_expected "$1"
}

managed_directory_state() {
  local target=$1
  if [[ ! -e "$target" && ! -L "$target" ]]; then
    printf 'MISSING\n'
    return
  fi
  if [[ -L "$target" || ! -d "$target" || "$(path_mode "$target")" != 755 ]] || ! owned_by_expected "$target"; then
    printf 'UNKNOWN\n'
    return
  fi
  printf 'COMPLIANT\n'
}

cni_path_chain_safe() {
  local opt_root cni_root bin_root opt_state cni_state bin_state
  opt_root=$(host_path /opt)
  cni_root=$(host_path /opt/cni)
  bin_root=$(host_path /opt/cni/bin)
  opt_state=$(managed_directory_state "$opt_root") || return 1
  cni_state=$(managed_directory_state "$cni_root") || return 1
  bin_state=$(managed_directory_state "$bin_root") || return 1
  [[ "$opt_state" == COMPLIANT ]] || return 1
  [[ "$cni_state" == MISSING || "$cni_state" == COMPLIANT ]] || return 1
  [[ "$bin_state" == MISSING || "$bin_state" == COMPLIANT ]] || return 1
}

kubelet_generated_state_is_pristine() {
  local kubelet_root root_mode first_entry sensitive_path
  kubelet_root=$(host_path /var/lib/kubelet)
  if [[ -e "$kubelet_root" || -L "$kubelet_root" ]]; then
    [[ -d "$kubelet_root" && ! -L "$kubelet_root" ]] || return 1
    owned_by_expected "$kubelet_root" || return 1
    root_mode=$(path_mode "$kubelet_root") || return 1
    [[ "$root_mode" == 700 || "$root_mode" == 750 || "$root_mode" == 755 ]] || return 1
    first_entry=$(find "$kubelet_root" -mindepth 1 -print -quit 2>/dev/null) || return 1
    [[ -z "$first_entry" ]] || return 1
  fi
  for sensitive_path in \
    "${kubelet_root}/kubeadm-flags.env" \
    "${kubelet_root}/config.yaml" \
    "${kubelet_root}/instance-config.yaml" \
    "${kubelet_root}/pki"; do
    [[ ! -e "$sensitive_path" && ! -L "$sensitive_path" ]] || return 1
  done
}

kubelet_mutable_inputs_are_pristine() {
  kubelet_generated_state_is_pristine &&
    kubelet_default_conffile_is_pristine "$(host_path /etc/default/kubelet)"
}

kubernetes_shadow_paths_absent() {
  local binary_name shadow
  for binary_name in kubeadm kubectl kubelet; do
    shadow=$(host_path "/usr/sbin/${binary_name}")
    [[ ! -e "$shadow" && ! -L "$shadow" ]] || return 1
  done
}

managed_kubernetes_binaries_are_exact() {
  local package logical target ownership
  for package in kubeadm kubectl kubelet; do
    logical="/usr/bin/${package}"
    target=$(host_path "$logical")
    [[ -f "$target" && ! -L "$target" && -x "$target" && "$(path_mode "$target")" == 755 ]] || return 1
    owned_by_expected "$target" || return 1
    ownership=$(dpkg-query -S "$logical" 2>/dev/null) || return 1
    [[ "$ownership" == "${package}: ${logical}" ]] || return 1
  done
  for package in "${PACKAGES[@]}"; do
    dpkg_package_verification_is_exact "$package" || return 1
  done
}

unit_package_ownership_is_exact() {
  local logical=$1 package=$2 ownership alias
  local lib_root canonical_file alias_file canonical_real alias_real
  if ownership=$(dpkg-query -S "$logical" 2>/dev/null); then
    [[ "$ownership" == "${package}: ${logical}" ]]
    return
  fi
  case "$logical" in
    /usr/lib/systemd/system/kubelet.service|/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf)
      alias=${logical#/usr}
      ;;
    *) return 1 ;;
  esac
  lib_root=$(host_path /lib)
  [[ -L "$lib_root" && "$(readlink "$lib_root")" == usr/lib ]] || return 1
  owned_by_expected "$lib_root" || return 1
  canonical_file=$(host_path "$logical")
  alias_file=$(host_path "$alias")
  [[ -f "$canonical_file" && ! -L "$canonical_file" && -f "$alias_file" && ! -L "$alias_file" ]] || return 1
  canonical_real=$(readlink -f "$canonical_file") || return 1
  alias_real=$(readlink -f "$alias_file") || return 1
  [[ -n "$canonical_real" && "$canonical_real" == "$alias_real" ]] || return 1
  ownership=$(dpkg-query -S "$alias" 2>/dev/null) || return 1
  [[ "$ownership" == "${package}: ${alias}" ]]
}

download_parent_safe() {
  local mode
  mode=$(path_mode "$1") || return 1
  [[ -d "$1" && ! -L "$1" && -k "$1" && ( "$mode" == 1777 || "$mode" == 777 ) ]] && owned_by_expected "$1"
}

package_version() {
  case "$1" in
    kubeadm|kubectl|kubelet) printf '1.36.3-1.1\n' ;;
    kubernetes-cni) printf '1.9.1-1.1\n' ;;
    *) return 1 ;;
  esac
}

package_sha256() {
  case "$1" in
    kubeadm) printf '7225b4b7928de8bb9b7a69b75524c2df1a6f78fcbb40724f7e5b49926119c2af\n' ;;
    kubectl) printf '22c1bbcecfdee50ad013ab7ab9e90ea9d3aaa01d3ac38ac578534976f856c330\n' ;;
    kubelet) printf '99c77d7c814ac0b0f1f346c11074160fbbab8243c27ba4236f84f2e536c8eaca\n' ;;
    kubernetes-cni) printf '4cd72d8cef4499d3dc410874287b40e8b4241e0772938c5820cbee37986c1d93\n' ;;
    *) return 1 ;;
  esac
}

package_size() {
  case "$1" in
    kubeadm) printf '12558824\n' ;;
    kubectl) printf '11766348\n' ;;
    kubelet) printf '13386608\n' ;;
    kubernetes-cni) printf '38991216\n' ;;
    *) return 1 ;;
  esac
}

package_filename() {
  local package=$1
  printf 'amd64/%s_%s_amd64.deb\n' "$package" "$(package_version "$package")"
}

package_depends() {
  local package=$1 representation=$2 separator
  case "$representation" in
    packages-index) separator=',' ;;
    dpkg-deb) separator=', ' ;;
    *) return 1 ;;
  esac
  case "$package" in
    kubelet)
      printf 'iptables (>= 1.4.21)%skubernetes-cni (>= 1.2.0)%smount%sutil-linux%slibc6\n' \
        "$separator" "$separator" "$separator" "$separator"
      ;;
    kubeadm|kubectl|kubernetes-cni) printf 'NONE\n' ;;
    *) return 1 ;;
  esac
}

source_state() {
  local target=$1 actual
  if [[ ! -e "$target" && ! -L "$target" ]]; then
    printf 'MISSING\n'
    return
  fi
  if [[ -L "$target" || ! -f "$target" || "$(path_mode "$target")" != 644 ]] || ! owned_by_expected "$target"; then
    printf 'UNKNOWN\n'
    return
  fi
  actual=$(<"$target") || {
    printf 'UNKNOWN\n'
    return
  }
  if [[ "$actual" == "$SOURCE_CONTENT" && "$(wc -l <"$target" | tr -d ' ')" == 1 ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

keyring_state() {
  local target=$1 actual_digest
  if [[ ! -e "$target" && ! -L "$target" ]]; then
    printf 'MISSING\n'
    return
  fi
  if [[ -L "$target" || ! -f "$target" || "$(path_mode "$target")" != 644 ]] || ! owned_by_expected "$target"; then
    printf 'UNKNOWN\n'
    return
  fi
  actual_digest=$(sha256_file "$target") || {
    printf 'UNKNOWN\n'
    return
  }
  if [[ "$actual_digest" == "$RELEASE_KEYRING_SHA256" ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

publish_new_file() {
  local source=$1 target=$2 mode=$3 temporary
  managed_parent_safe "${target%/*}" || return "$EXIT_UNKNOWN_STATE"
  temporary=$(mktemp "${target}.tmp.XXXXXX") || return "$EXIT_APPLY_FAILED"
  if ! install -m "$mode" "$source" "$temporary" || ! sync "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if ! managed_parent_safe "${target%/*}" || ! owned_by_expected "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  if ! ln "$temporary" "$target" 2>/dev/null; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  rm -f -- "$temporary"
}

publish_source() {
  local target=$1 temporary
  managed_parent_safe "${target%/*}" || return "$EXIT_UNKNOWN_STATE"
  temporary=$(mktemp "${target}.content.XXXXXX") || return "$EXIT_APPLY_FAILED"
  if ! printf '%s\n' "$SOURCE_CONTENT" >"$temporary" || ! chmod 0644 "$temporary" || ! sync "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if ! managed_parent_safe "${target%/*}" || ! owned_by_expected "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  if ! ln "$temporary" "$target" 2>/dev/null; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  rm -f -- "$temporary"
}

installed_record() {
  dpkg-query -W -f='${Status}\t${Version}\t${Architecture}\n' "$1" 2>/dev/null
}

base_dependencies_are_exact() {
  local dependency record status version architecture extra
  for dependency in "${BASE_DEPENDENCIES[@]}"; do
    record=$(dpkg-query -W -f='${Status}\t${Version}\t${Architecture}\n' "$dependency" 2>/dev/null) || return 1
    IFS=$'\t' read -r status version architecture extra <<<"$record"
    [[ "$status" == 'install ok installed' && -n "$version" && "$architecture" == amd64 && -z "$extra" ]] || return 1
    if [[ "$dependency" == iptables ]]; then
      dpkg --compare-versions "$version" ge 1.4.21 || return 1
    fi
  done
}

bound_packages_index() {
  local apt_config=$1 lists_dir output line_count line
  local identifier uri filename extra mode
  lists_dir="${apt_workspace}/lists"
  # APT 自己展开 indextargets 的占位符，shell 不应展开。
  # shellcheck disable=SC2016
  output=$(APT_CONFIG="$apt_config" apt-get indextargets --format '$(IDENTIFIER)|$(URI)|$(FILENAME)' 2>/dev/null) || return 1
  line_count=$(awk 'NF {count++} END {print count+0}' <<<"$output") || return 1
  [[ "$line_count" == 1 ]] || return 1
  line=$(awk 'NF {print}' <<<"$output") || return 1
  IFS='|' read -r identifier uri filename extra <<<"$line"
  [[ -z "$extra" && "$identifier" == Packages && "$uri" == "${REPOSITORY_URL}Packages" ]] || return 1
  [[ "${filename%/*}" == "$lists_dir" && -f "$filename" && ! -L "$filename" ]] || return 1
  mode=$(path_mode "$filename") || return 1
  [[ "$mode" == 600 || "$mode" == 644 ]] || return 1
  owned_by_expected "$filename" || return 1
  printf '%s\n' "$filename"
}

downloaded_debs_are_exact() {
  local package deb expected_digest actual_digest
  download_directory_exact "$download_dir" "${deb_basenames[@]}" || return 1
  for package in "${PACKAGES[@]}"; do
    deb="${download_dir}/${package}_$(package_version "$package")_amd64.deb"
    [[ -f "$deb" && ! -L "$deb" ]] || return 1
    owned_by_expected "$deb" || return 1
    [[ "$(path_size "$deb")" == "$(package_size "$package")" ]] || return 1
    expected_digest=$(package_sha256 "$package") || return 1
    actual_digest=$(sha256_file "$deb") || return 1
    [[ "$actual_digest" == "$expected_digest" ]] || return 1
  done
}

apt_archive_directory_safe() {
  local archives_dir="${apt_workspace}/archives"
  [[ -d "$archives_dir" && ! -L "$archives_dir" && "$(path_mode "$archives_dir")" == 700 ]] || return 1
  owned_by_expected "$archives_dir"
}

cached_debs_are_exact() {
  local package archive expected_digest actual_digest
  local archives_dir="${apt_workspace}/archives"
  apt_archive_directory_safe || return 1
  download_directory_exact "$archives_dir" "${deb_basenames[@]}" || return 1
  for package in "${PACKAGES[@]}"; do
    archive="${archives_dir}/${package}_$(package_version "$package")_amd64.deb"
    [[ -f "$archive" && ! -L "$archive" && "$(path_mode "$archive")" == 600 ]] || return 1
    owned_by_expected "$archive" || return 1
    [[ "$(path_size "$archive")" == "$(package_size "$package")" ]] || return 1
    expected_digest=$(package_sha256 "$package") || return 1
    actual_digest=$(sha256_file "$archive") || return 1
    [[ "$actual_digest" == "$expected_digest" ]] || return 1
  done
}

publish_verified_deb_to_cache() {
  local source=$1 basename=$2 target
  local archives_dir="${apt_workspace}/archives"
  apt_archive_directory_safe || return "$EXIT_UNKNOWN_STATE"
  target="${archives_dir}/${basename}"
  [[ ! -e "$target" && ! -L "$target" ]] || return "$EXIT_UNKNOWN_STATE"
  chmod 0600 "$source" || return "$EXIT_APPLY_FAILED"
  sync "$source" || return "$EXIT_APPLY_FAILED"
  [[ -f "$source" && ! -L "$source" && "$(path_mode "$source")" == 600 ]] || return "$EXIT_UNKNOWN_STATE"
  owned_by_expected "$source" || return "$EXIT_UNKNOWN_STATE"
  ln "$source" "$target" 2>/dev/null || return "$EXIT_UNKNOWN_STATE"
  apt_archive_directory_safe || return "$EXIT_UNKNOWN_STATE"
  [[ -f "$target" && ! -L "$target" && "$(path_mode "$target")" == 600 ]] || return "$EXIT_UNKNOWN_STATE"
  owned_by_expected "$target" || return "$EXIT_UNKNOWN_STATE"
}

deb_dependency_contract_is_exact() {
  local deb=$1 package=$2 field value expected_depends
  expected_depends=$(package_depends "$package" dpkg-deb) || return 1
  for field in Depends Pre-Depends Recommends Suggests Conflicts Breaks Replaces Provides; do
    value=$(dpkg-deb -f "$deb" "$field" 2>/dev/null) || return 1
    if [[ "$field" == Depends ]]; then
      if [[ "$expected_depends" == NONE ]]; then
        [[ -z "$value" ]] || return 1
      else
        [[ "$value" == "$expected_depends" ]] || return 1
      fi
    else
      [[ -z "$value" ]] || return 1
    fi
  done
}

cni_directory_state() {
  local root=$1 logical_root=/opt/cni/bin actual_names entry_set_kind
  local name mode size digest target actual_digest ownership
  if [[ ! -e "$root" && ! -L "$root" ]]; then
    printf 'MISSING\n'
    return
  fi
  if [[ -L "$root" || ! -d "$root" || "$(path_mode "$root")" != 755 ]] || ! owned_by_expected "$root"; then
    printf 'UNKNOWN\n'
    return
  fi
  actual_names=$(find "$root" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sed 's#.*/##' | sort) || {
    printf 'UNKNOWN\n'
    return
  }
  entry_set_kind=$(cni_entry_set_kind "$actual_names") || {
    printf 'UNKNOWN\n'
    return
  }
  # 装完 Cilium 后 agent 会写入 cilium-cni；只按锁定的 mode/size/digest 与非包归属放行。
  if [[ "$entry_set_kind" == with-cilium ]] && ! cilium_cni_entry_is_exact "$root"; then
    printf 'UNKNOWN\n'
    return
  fi
  while IFS=$'\t' read -r name mode size digest; do
    target="${root}/${name}"
    if [[ -L "$target" || ! -f "$target" || "$(path_mode "$target")" != "$mode" || "$(path_size "$target")" != "$size" ]] || ! owned_by_expected "$target"; then
      printf 'UNKNOWN\n'
      return
    fi
    actual_digest=$(sha256_file "$target") || {
      printf 'UNKNOWN\n'
      return
    }
    [[ "$actual_digest" == "$digest" ]] || {
      printf 'UNKNOWN\n'
      return
    }
    ownership=$(dpkg-query -S "${logical_root}/${name}" 2>/dev/null) || {
      printf 'UNKNOWN\n'
      return
    }
    [[ "$ownership" == "kubernetes-cni: ${logical_root}/${name}" ]] || {
      printf 'UNKNOWN\n'
      return
    }
  done < <(cni_manifest)
  printf 'COMPLIANT\n'
}

HOLDS_RAW=

load_hold_state() {
# 判定移入 gates.sh 后，这个常量只被它消费；source 路径含变量，shellcheck
# 无法跟随，故显式关闭。
# shellcheck disable=SC2034
  HOLDS_RAW=$(dpkg-query -W -f='${Package}\t${Architecture}\t${db:Status-Want}\n' 2>/dev/null) || return 1
}

verify_installed_package_payload_state() {
  verify_package_selection_and_holds || return "$?"
  kubernetes_shadow_paths_absent || return 1
  managed_kubernetes_binaries_are_exact || return 1
  [[ "$(cni_directory_state "$(host_path /opt/cni/bin)")" == COMPLIANT ]] || return 1
  kubelet_default_conffile_is_pristine "$(host_path /etc/default/kubelet)"
}

verify_installed_package_state() {
  verify_installed_package_payload_state || return "$?"
  [[ "$(kubelet_unit_state)" == READY ]]
}

verify_package_selection_and_holds() {
  local package expected record holds
  for package in "${PACKAGES[@]}"; do
    expected=$(package_version "$package")
    record=$(installed_record "$package") || return 1
    [[ "$record" == $'hold ok installed\t'"${expected}"$'\tamd64' ]] || return 1
  done
  load_hold_state || return 2
  holds=$(all_holds_from_loaded_state) || return 1
  [[ "$holds" == $'kubeadm\nkubectl\nkubelet\nkubernetes-cni' ]] || return 1
}

restart_kubelet_and_verify() {
  local verification_result=0
  verify_installed_package_payload_state || verification_result=$?
  (( verification_result != 2 )) || return 3
  (( verification_result == 0 )) || return 2
  systemctl restart kubelet.service >/dev/null 2>&1 || return 1
  verification_result=0
  verify_installed_package_state || verification_result=$?
  (( verification_result != 2 )) || return 3
  (( verification_result == 0 )) || return 2
}

cleanup_apt_workspace() {
  local download_parent
  [[ -n "$apt_workspace" ]] || return 0
  download_parent=$(host_path /var/tmp)
  [[ "$apt_workspace" == "${download_parent}/.kubernetes-apt."* ]] || return 0
  [[ -d "$apt_workspace" && ! -L "$apt_workspace" ]] || return 0
  rm -r -- "$apt_workspace"
}

cleanup_gpg_workspace() {
  local parent
  [[ -n "$gpg_workspace" ]] || return 0
  parent=$(host_path /var/tmp)
  [[ "$gpg_workspace" == "${parent}/.kubernetes-gpg."* ]] || return 0
  [[ -d "$gpg_workspace" && ! -L "$gpg_workspace" && "$(path_mode "$gpg_workspace")" == 700 ]] || return 0
  owned_by_expected "$gpg_workspace" || return 0
  rm -r -- "$gpg_workspace"
}

cleanup_temporary_workspaces() {
  cleanup_apt_workspace || true
  cleanup_gpg_workspace || true
}

create_gpg_workspace() {
  local parent
  parent=$(host_path /var/tmp)
  download_parent_safe "$parent" || return "$EXIT_UNKNOWN_STATE"
  gpg_workspace=$(mktemp -d "${parent}/.kubernetes-gpg.XXXXXX") || return "$EXIT_APPLY_FAILED"
  [[ "$(path_mode "$gpg_workspace")" == 700 ]] || return "$EXIT_UNKNOWN_STATE"
  owned_by_expected "$gpg_workspace" || return "$EXIT_UNKNOWN_STATE"
}

create_apt_workspace() {
  local download_parent status_source lists_dir archives_dir state_dir
  download_parent=$(host_path /var/tmp)
  download_parent_safe "$download_parent" || return "$EXIT_UNKNOWN_STATE"
  status_source=$(host_path /var/lib/dpkg/status)
  [[ -f "$status_source" && ! -L "$status_source" ]] || return "$EXIT_UNKNOWN_STATE"
  owned_by_expected "$status_source" || return "$EXIT_UNKNOWN_STATE"
  apt_workspace=$(mktemp -d "${download_parent}/.kubernetes-apt.XXXXXX") || return "$EXIT_APPLY_FAILED"
  [[ "$(path_mode "$apt_workspace")" == 700 ]] || return "$EXIT_UNKNOWN_STATE"
  owned_by_expected "$apt_workspace" || return "$EXIT_UNKNOWN_STATE"
  lists_dir="${apt_workspace}/lists"
  archives_dir="${apt_workspace}/archives"
  state_dir="${apt_workspace}/state"
  mkdir -m 0700 -- "$lists_dir" "$archives_dir" "$state_dir" || return "$EXIT_APPLY_FAILED"
  apt_config="${apt_workspace}/apt.conf"
  if ! printf '%s\n' \
    'Dir::Etc::main "-";' \
    'Dir::Etc::parts "-";' \
    "Dir::Etc::sourcelist \"${source_target}\";" \
    'Dir::Etc::sourceparts "-";' \
    "Dir::State::lists \"${lists_dir}\";" \
    "Dir::State::status \"${status_source}\";" \
    "Dir::State::extended_states \"${state_dir}/extended_states\";" \
    "Dir::Cache::archives \"${archives_dir}\";" \
    'Dir::Cache::pkgcache "";' \
    'Dir::Cache::srcpkgcache "";' \
    'Acquire::Languages "none";' \
    'Acquire::GzipIndexes "false";' \
    'APT::Get::List-Cleanup "0";' >"$apt_config"; then
    return "$EXIT_APPLY_FAILED"
  fi
  chmod 0600 "$apt_config" || return "$EXIT_APPLY_FAILED"
}

effective_apt_configuration_is_safe() {
  local dump=$1 status_source directive expected key_count exact_count
  status_source=$(host_path /var/lib/dpkg/status)
  while IFS='|' read -r directive expected; do
    key_count=$(awk -v key="$directive" '$1 == key {count++} END {print count+0}' <<<"$dump") || return 1
    exact_count=$(grep -Fxc "$expected" <<<"$dump") || true
    [[ "$key_count" == 1 && "$exact_count" == 1 ]] || return 1
  done <<EOF
Dir::Etc::main|Dir::Etc::main "-";
Dir::Etc::parts|Dir::Etc::parts "-";
Dir::Etc::sourcelist|Dir::Etc::sourcelist "${source_target}";
Dir::Etc::sourceparts|Dir::Etc::sourceparts "-";
Dir::State::lists|Dir::State::lists "${apt_workspace}/lists";
Dir::State::status|Dir::State::status "${status_source}";
Dir::State::extended_states|Dir::State::extended_states "${apt_workspace}/state/extended_states";
Dir::Cache::archives|Dir::Cache::archives "${apt_workspace}/archives";
Dir::Cache::pkgcache|Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache|Dir::Cache::srcpkgcache "";
EOF
  if grep -Eiq '^(DPkg::(Pre-Invoke|Post-Invoke|Pre-Install-Pkgs)|APT::Update::[^[:space:]]*Invoke[^[:space:]]*)(::|[[:space:]])' <<<"$dump"; then
    return 1
  fi
  [[ -f "$apt_config" && ! -L "$apt_config" && "$(path_mode "$apt_config")" == 600 ]] || return 1
  owned_by_expected "$apt_config"
}
