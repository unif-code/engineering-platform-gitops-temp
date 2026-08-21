#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

# 逐个收集违规变量名并在拒绝时列出（只列名不列值），便于运维定位后 unset。
untrusted_environment=
for untrusted_name in APT_CONFIG KUBECONFIG GNUPGHOME DPKG_ADMINDIR \
    DPKG_ROOT DPKG_FORCE DPKG_FRONTEND_LOCKED; do
  [[ -z "${!untrusted_name+x}" ]] ||
    untrusted_environment="${untrusted_environment:+${untrusted_environment},}${untrusted_name}"
done
if [[ -n "$untrusted_environment" ]]; then
  printf 'RESULT=STOP_PRECONDITION\nREASON=untrusted-environment-override\nVARS=%s\n' \
    "$untrusted_environment" >&2
  exit 10
fi

if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 ]]; then
  if [[ "$EUID" -eq 0 ]]; then
    printf 'RESULT=STOP_TEST_MODE\nREASON=test-mode-is-for-unprivileged-tests-only\n' >&2
    exit 10
  fi
  if [[ -z "${BOOTSTRAP_TEST_ROOT:-}" || "$BOOTSTRAP_TEST_ROOT" != /* || "$BOOTSTRAP_TEST_ROOT" == / || ! -d "$BOOTSTRAP_TEST_ROOT" || -L "$BOOTSTRAP_TEST_ROOT" || ! -O "$BOOTSTRAP_TEST_ROOT" ]]; then
    printf 'RESULT=STOP_TEST_MODE\nREASON=test-root-must-be-isolated\n' >&2
    exit 10
  fi
else
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin
  for test_override in "${!BOOTSTRAP_TEST_@}"; do
    : "$test_override"
    printf 'RESULT=STOP_TEST_OVERRIDE\nREASON=test-override-in-production\n' >&2
    exit 10
  done
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck disable=SC1091
source "${script_dir}/lib/common.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/path-facts.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/cni-manifest.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/dpkg-package-verification.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/kubelet-default.sh"

# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=install-kubernetes
readonly REPOSITORY_URL='https://pkgs.k8s.io/core:/stable:/v1.36/deb/'
readonly RELEASE_KEY_URL="${REPOSITORY_URL}Release.key"
readonly RELEASE_KEY_SHA256=7627818cf7bae52f9008c93e8b1f961f53dea11d40891778de216fb1b43be54d
readonly RELEASE_KEYRING_SHA256=5c463ffcfcb24088da4b049ac7b2c7b61dd9d6a7fa4f24e74eb0a533c53bfa17
readonly RELEASE_KEY_FINGERPRINT=DE15B14486CD377B9E876E1A234654DA9A296436
readonly SOURCE_CONTENT='deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.36/deb/ /'
readonly -a PACKAGES=(kubeadm kubectl kubelet kubernetes-cni)
readonly -a BASE_DEPENDENCIES=(iptables mount util-linux libc6)

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

keyring_fingerprint() {
  local target=$1 homedir=$2
  gpg --batch --no-options --no-autostart --homedir "$homedir" \
    --show-keys --with-colons --fingerprint "$target" 2>/dev/null |
    awk -F: '
      $1 == "pub" {pubs++; awaiting_primary=1; next}
      $1 == "sub" {subkeys++; awaiting_primary=0; next}
      $1 == "fpr" {
        fingerprints++
        if (awaiting_primary == 1) {
          primary=$10
          awaiting_primary=0
        } else {
          unexpected_fingerprint=1
        }
      }
      END {
        if (pubs != 1 || subkeys != 0 || fingerprints != 1 ||
            unexpected_fingerprint == 1 || primary == "") exit 1
        print primary
      }
    '
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

signed_index_record() {
  local package=$1 index_file=$2 version
  version=$(package_version "$package")
  awk -v expected_package="$package" -v expected_version="$version" '
    BEGIN {RS=""; FS="\n"}
    {
      split("", count)
      split("", value)
      for (i=1; i<=NF; i++) {
        separator=index($i, ": ")
        if (separator == 0) continue
        field=substr($i, 1, separator-1)
        field_value=substr($i, separator+2)
        if (field == "Package" || field == "Version" || field == "Architecture" ||
            field == "Filename" || field == "Size" || field == "SHA256" ||
            field == "Depends" || field == "Pre-Depends" || field == "Recommends" ||
            field == "Suggests" || field == "Conflicts" || field == "Breaks" ||
            field == "Replaces" || field == "Provides") {
          count[field]++
          value[field]=field_value
        }
      }
      if (value["Package"] == expected_package && value["Version"] == expected_version &&
          value["Architecture"] == "amd64") {
        matches++
        valid=(count["Package"] == 1 && count["Version"] == 1 &&
               count["Architecture"] == 1 && count["Filename"] == 1 &&
               count["Size"] == 1 && count["SHA256"] == 1 &&
               count["Depends"] <= 1 && count["Pre-Depends"] <= 1 &&
               count["Recommends"] <= 1 && count["Suggests"] <= 1 &&
               count["Conflicts"] <= 1 && count["Breaks"] <= 1 &&
               count["Replaces"] <= 1 && count["Provides"] <= 1)
        selected_valid=valid
        selected_package=value["Package"]
        selected_version=value["Version"]
        selected_architecture=value["Architecture"]
        selected_filename=value["Filename"]
        selected_size=value["Size"]
        selected_sha256=value["SHA256"]
        selected_depends=value["Depends"]
        relationship_count=count["Pre-Depends"]
        relationship_count+=count["Recommends"]
        relationship_count+=count["Suggests"]
        relationship_count+=count["Conflicts"]
        relationship_count+=count["Breaks"]
        relationship_count+=count["Replaces"]
        relationship_count+=count["Provides"]
      }
    }
    END {
      if (matches != 1 || selected_valid != 1) exit 1
      if (selected_depends == "") selected_depends="NONE"
      print selected_package "\t" selected_version "\t" selected_architecture "\t" \
        selected_filename "\t" selected_size "\t" selected_sha256 "\t" \
        selected_depends "\t" relationship_count
    }
  ' "$index_file"
}

simulation_transaction_is_exact() {
  awk '
    function expected_version(package) {
      if (package == "kubeadm" || package == "kubectl" || package == "kubelet") {
        return "1.36.3-1.1"
      }
      if (package == "kubernetes-cni") return "1.9.1-1.1"
      return ""
    }
    $1 == "Inst" || $1 == "Conf" {
      action=$1
      package=$2
      version_field=$3
      if (version_field !~ /^\(/ || $NF != "[amd64])") exit 1
      sub(/^\(/, "", version_field)
      sub(/\)$/, "", version_field)
      expected=expected_version(package)
      if (expected == "" || version_field != expected ||
          ++seen[action, package] != 1) exit 1
      action_count[action]++
      next
    }
    $1 == "Remv" || $1 == "Purg" {exit 1}
    END {
      if (action_count["Inst"] != 4 || action_count["Conf"] != 4) exit 1
      split("kubeadm kubectl kubelet kubernetes-cni", packages, " ")
      for (i=1; i<=4; i++) {
        if (seen["Inst", packages[i]] != 1 ||
            seen["Conf", packages[i]] != 1) exit 1
      }
    }
  '
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
  HOLDS_RAW=$(dpkg-query -W -f='${Package}\t${Architecture}\t${db:Status-Want}\n' 2>/dev/null) || return 1
}

all_holds_from_loaded_state() {
  awk -F '\t' '
    NF == 0 {next}
    NF != 3 || $1 !~ /^[a-z0-9][a-z0-9+.-]*$/ ||
      $2 !~ /^[a-z0-9][a-z0-9-]*$/ ||
      ($3 != "unknown" && $3 != "install" && $3 != "hold" &&
       $3 != "deinstall" && $3 != "purge") {exit 1}
    {key=$1 SUBSEP $2; if (seen[key]++) exit 1}
    $3 == "hold" {if ($2 == "amd64") print $1; else print $1 ":" $2}
  ' <<<"$HOLDS_RAW" | sort
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

kubelet_unit_state() {
  local output state fragment dropin fragment_file dropin_file unit_file
  output=$(systemctl show kubelet.service \
    --property=LoadState \
    --property=UnitFileState \
    --property=ActiveState \
    --property=SubState \
    --property=FragmentPath \
    --property=DropInPaths \
    --property=Result 2>/dev/null) || {
      printf 'UNKNOWN\n'
      return
    }
  state=$(awk -F= '
    NF != 2 {exit 1}
    $1 != "LoadState" && $1 != "UnitFileState" && $1 != "ActiveState" &&
      $1 != "SubState" && $1 != "FragmentPath" && $1 != "DropInPaths" &&
      $1 != "Result" {exit 1}
    {if (seen[$1]++) exit 1; value[$1]=$2; field_count++}
    END {
      fragment_ok=(value["FragmentPath"] == "/usr/lib/systemd/system/kubelet.service" ||
                   value["FragmentPath"] == "/lib/systemd/system/kubelet.service")
      dropin_ok=(value["DropInPaths"] == "/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf" ||
                 value["DropInPaths"] == "/lib/systemd/system/kubelet.service.d/10-kubeadm.conf")
      if (field_count != 7 || value["LoadState"] != "loaded" ||
          value["UnitFileState"] != "enabled" || !fragment_ok || !dropin_ok) exit 1
      if ((value["ActiveState"] == "activating" && value["SubState"] == "auto-restart") ||
          (value["ActiveState"] == "active" && value["SubState"] == "running")) {
        print "READY"
      } else if (value["Result"] == "success" &&
                 value["ActiveState"] == "inactive" && value["SubState"] == "dead") {
        print "START_REQUIRED"
      } else {
        print "UNKNOWN"
      }
    }
  ' <<<"$output") || {
    printf 'UNKNOWN\n'
    return
  }
  fragment=$(awk -F= '$1 == "FragmentPath" {print $2}' <<<"$output") || {
    printf 'UNKNOWN\n'
    return
  }
  dropin=$(awk -F= '$1 == "DropInPaths" {print $2}' <<<"$output") || {
    printf 'UNKNOWN\n'
    return
  }
  fragment_file=$(host_path "$fragment")
  dropin_file=$(host_path "$dropin")
  for unit_file in "$fragment_file" "$dropin_file"; do
    [[ -f "$unit_file" && ! -L "$unit_file" && "$(path_mode "$unit_file")" == 644 ]] || {
      printf 'UNKNOWN\n'
      return
    }
    owned_by_expected "$unit_file" || {
      printf 'UNKNOWN\n'
      return
    }
  done
  unit_package_ownership_is_exact "$fragment" kubelet || {
    printf 'UNKNOWN\n'
    return
  }
  unit_package_ownership_is_exact "$dropin" kubeadm || {
    printf 'UNKNOWN\n'
    return
  }
  printf '%s\n' "$state"
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

complete_successful_kubernetes_install() {
  local evidence_dir package package_upper
  evidence_dir=$(host_path /root/dev-infra-evidence)
  open_evidence 11-kubernetes "$evidence_dir" || complete STOP_EVIDENCE evidence-open-failed "$EXIT_UNKNOWN_STATE" NONE

  log_evidence REPOSITORY_MINOR=v1.36
  log_evidence RELEASE_KEY_SHA256="$RELEASE_KEY_SHA256"
  log_evidence RELEASE_KEY_FINGERPRINT="$RELEASE_KEY_FINGERPRINT"
  for package in "${PACKAGES[@]}"; do
    package_upper=$(printf '%s' "$package" | tr '[:lower:]-' '[:upper:]_')
    log_evidence "PACKAGE_${package_upper}_VERSION=$(package_version "$package")"
    log_evidence "PACKAGE_${package_upper}_SHA256=$(package_sha256 "$package")"
  done
  log_evidence PACKAGE_HOLD=kubeadm,kubectl,kubelet,kubernetes-cni
  log_evidence CNI_FILE_COUNT=20
  log_evidence CNI_OWNERSHIP=kubernetes-cni
  complete PASS_KUBERNETES_INSTALLED kubernetes-packages-ready 0 '50-kubeadm-init.sh --check'
}

apt_workspace=
apt_config=
gpg_workspace=

# trap 在 APT workspace 创建后间接调用该清理函数。
# shellcheck disable=SC2317,SC2329
cleanup_apt_workspace() {
  local download_parent
  [[ -n "$apt_workspace" ]] || return 0
  download_parent=$(host_path /var/tmp)
  [[ "$apt_workspace" == "${download_parent}/.kubernetes-apt."* ]] || return 0
  [[ -d "$apt_workspace" && ! -L "$apt_workspace" ]] || return 0
  rm -r -- "$apt_workspace"
}

# trap 在 GnuPG workspace 创建后间接调用该清理函数。
# shellcheck disable=SC2317,SC2329
cleanup_gpg_workspace() {
  local parent
  [[ -n "$gpg_workspace" ]] || return 0
  parent=$(host_path /var/tmp)
  [[ "$gpg_workspace" == "${parent}/.kubernetes-gpg."* ]] || return 0
  [[ -d "$gpg_workspace" && ! -L "$gpg_workspace" && "$(path_mode "$gpg_workspace")" == 700 ]] || return 0
  owned_by_expected "$gpg_workspace" || return 0
  rm -r -- "$gpg_workspace"
}

# trap 间接调用。
# shellcheck disable=SC2317,SC2329
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

download_directory_exact() {
  local directory=$1
  shift
  local actual expected path
  actual=$(find "$directory" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sed 's#.*/##' | sort) || return 1
  expected=$(printf '%s\n' "$@" | sort)
  [[ "$actual" == "$expected" ]] || return 1
  while IFS= read -r path; do
    [[ -f "$path" && ! -L "$path" ]] || return 1
    owned_by_expected "$path" || return 1
  done < <(find "$directory" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sort)
}

parse_mode "$@" || exit "$?"
require_root || complete STOP_PRECONDITION not-root "$EXIT_PRECONDITION" NONE
for required_command in apt-config apt-get apt-mark awk cat chmod curl date dpkg dpkg-deb dpkg-query find gpg grep id install ln md5sum mkdir mktemp readlink rm sed sort stat sync systemctl tr wc; do
  require_command "$required_command" || complete STOP_PRECONDITION "missing-command-${required_command}" "$EXIT_PRECONDITION" NONE
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  complete STOP_PRECONDITION missing-command-sha256 "$EXIT_PRECONDITION" NONE
fi

cni_path_chain_safe || complete STOP_UNKNOWN_STATE cni-path-chain-unsafe "$EXIT_UNKNOWN_STATE" NONE
kubernetes_shadow_paths_absent || complete STOP_UNKNOWN_STATE kubernetes-binary-shadow-present "$EXIT_UNKNOWN_STATE" NONE
base_dependencies_are_exact || complete STOP_UNKNOWN_STATE base-dependency-contract-drift "$EXIT_UNKNOWN_STATE" NONE
if dpkg-query -W -f='${Status}\t${Version}\t${Architecture}\n' cri-tools >/dev/null 2>&1; then
  complete STOP_UNKNOWN_STATE cri-tools-package-forbidden "$EXIT_UNKNOWN_STATE" NONE
fi
load_hold_state || complete STOP_UNKNOWN_STATE package-hold-state-unreadable "$EXIT_UNKNOWN_STATE" NONE
if grep -Fxq cri-tools <<<"$HOLDS_RAW"; then
  complete STOP_UNKNOWN_STATE cri-tools-hold-forbidden "$EXIT_UNKNOWN_STATE" NONE
fi

keyring_target=$(host_path /etc/apt/keyrings/kubernetes-apt-keyring.gpg)
source_target=$(host_path /etc/apt/sources.list.d/kubernetes.list)
for parent in "${keyring_target%/*}" "${source_target%/*}"; do
  managed_parent_safe "$parent" || complete STOP_UNKNOWN_STATE apt-parent-unsafe "$EXIT_UNKNOWN_STATE" NONE
done
while IFS= read -r source_file; do
  if [[ -L "$source_file" || ! -f "$source_file" ]]; then
    complete STOP_UNKNOWN_STATE apt-source-file-unsafe "$EXIT_UNKNOWN_STATE" NONE
  fi
  if [[ "$source_file" != "$source_target" ]] && grep -Eiq 'pkgs\.k8s\.io|apt\.kubernetes\.io|packages\.cloud\.google\.com.*kubernetes|kubernetes' "$source_file"; then
    complete STOP_UNKNOWN_STATE unapproved-kubernetes-source "$EXIT_UNKNOWN_STATE" NONE
  fi
done < <(find "$(host_path /etc/apt)" -maxdepth 2 \( -name '*.list' -o -name '*.sources' \) -print 2>/dev/null | sort)

source_contract=$(source_state "$source_target")
keyring_contract=$(keyring_state "$keyring_target")
[[ "$source_contract" != UNKNOWN ]] || complete STOP_UNKNOWN_STATE kubernetes-source-unknown "$EXIT_UNKNOWN_STATE" NONE
[[ "$keyring_contract" != UNKNOWN ]] || complete STOP_UNKNOWN_STATE kubernetes-keyring-unknown "$EXIT_UNKNOWN_STATE" NONE
[[ "$source_contract" == "$keyring_contract" ]] || complete STOP_UNKNOWN_STATE partial-repository-contract "$EXIT_UNKNOWN_STATE" NONE

installed_count=0
held_selection_count=0
for package in "${PACKAGES[@]}"; do
  if record=$(installed_record "$package"); then
    expected=$(package_version "$package")
    if [[ "$record" == $'hold ok installed\t'"${expected}"$'\tamd64' ]]; then
      ((held_selection_count += 1))
    elif [[ "$record" != $'install ok installed\t'"${expected}"$'\tamd64' ]]; then
      complete STOP_UNKNOWN_STATE "installed-package-drift-${package}" "$EXIT_UNKNOWN_STATE" NONE
    fi
    ((installed_count += 1))
  fi
done
(( installed_count == 0 || installed_count == ${#PACKAGES[@]} )) || complete STOP_UNKNOWN_STATE partial-kubernetes-installation "$EXIT_UNKNOWN_STATE" NONE
holds=$(all_holds_from_loaded_state) || complete STOP_UNKNOWN_STATE package-hold-state-invalid "$EXIT_UNKNOWN_STATE" NONE
hold_count=$(awk 'NF {count++} END {print count+0}' <<<"$holds")
if (( hold_count != 0 )) && [[ "$holds" != $'kubeadm\nkubectl\nkubelet\nkubernetes-cni' ]]; then
  complete STOP_UNKNOWN_STATE package-hold-set-unknown "$EXIT_UNKNOWN_STATE" NONE
fi
if (( installed_count == 0 && hold_count != 0 )); then
  complete STOP_UNKNOWN_STATE orphan-kubernetes-hold "$EXIT_UNKNOWN_STATE" NONE
fi
if (( installed_count != 0 )) &&
  { (( hold_count == 0 && held_selection_count != 0 )) ||
    (( hold_count == ${#PACKAGES[@]} && held_selection_count != ${#PACKAGES[@]} )); }; then
  complete STOP_UNKNOWN_STATE package-selection-state-drift "$EXIT_UNKNOWN_STATE" NONE
fi
cni_state=$(cni_directory_state "$(host_path /opt/cni/bin)")
if (( installed_count == 0 )); then
  kubelet_mutable_inputs_are_pristine || complete STOP_UNKNOWN_STATE kubelet-pre-init-inputs-not-pristine "$EXIT_UNKNOWN_STATE" NONE
  [[ "$cni_state" == MISSING ]] || complete STOP_UNKNOWN_STATE preexisting-cni-directory "$EXIT_UNKNOWN_STATE" NONE
else
  [[ "$source_contract" == COMPLIANT && "$hold_count" == "${#PACKAGES[@]}" && "$cni_state" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE partial-kubernetes-contract "$EXIT_UNKNOWN_STATE" NONE
  verification_result=0
  verify_installed_package_payload_state || verification_result=$?
  (( verification_result != 2 )) || complete STOP_UNKNOWN_STATE package-hold-state-unreadable "$EXIT_UNKNOWN_STATE" NONE
  (( verification_result == 0 )) || complete STOP_VERIFY_FAILED kubernetes-package-verification-failed "$EXIT_VERIFY_FAILED" NONE
  kubelet_state=$(kubelet_unit_state)
  case "$kubelet_state" in
    READY)
      complete ALREADY_COMPLIANT kubernetes-packages-ready 0 '50-kubeadm-init.sh --check'
      ;;
    START_REQUIRED)
      # MODE 由公共 parse_mode helper 赋值。
      # shellcheck disable=SC2153
      if [[ "$MODE" == CHECK ]]; then
        complete PASS_KUBERNETES_CHECK apply-required 0 '40-install-kubernetes.sh --apply'
      fi
      restart_result=0
      restart_kubelet_and_verify || restart_result=$?
      case "$restart_result" in
        0) ;;
        1) complete STOP_APPLY_FAILED kubelet-start-failed "$EXIT_APPLY_FAILED" NONE ;;
        2) complete STOP_VERIFY_FAILED kubelet-start-verification-failed "$EXIT_VERIFY_FAILED" NONE ;;
        3) complete STOP_UNKNOWN_STATE package-hold-state-unreadable "$EXIT_UNKNOWN_STATE" NONE ;;
        *) complete STOP_UNKNOWN_STATE kubelet-start-result-invalid "$EXIT_UNKNOWN_STATE" NONE ;;
      esac
      complete_successful_kubernetes_install
      ;;
    *)
      complete STOP_VERIFY_FAILED kubernetes-package-verification-failed "$EXIT_VERIFY_FAILED" NONE
      ;;
  esac
fi

# MODE 由公共 parse_mode helper 赋值。
# shellcheck disable=SC2153
if [[ "$MODE" == CHECK ]]; then
  complete PASS_KUBERNETES_CHECK apply-required 0 '40-install-kubernetes.sh --apply'
fi

if [[ "$source_contract" == MISSING ]]; then
  workspace_result=0
  create_gpg_workspace || workspace_result=$?
  (( workspace_result == 0 )) || {
    (( workspace_result == EXIT_UNKNOWN_STATE )) && complete STOP_UNKNOWN_STATE gpg-workspace-unsafe "$EXIT_UNKNOWN_STATE" NONE
    complete STOP_APPLY_FAILED gpg-workspace-create-failed "$EXIT_APPLY_FAILED" NONE
  }
  trap cleanup_temporary_workspaces EXIT
  armored_key=$(mktemp "${keyring_target}.armored.XXXXXX") || complete STOP_APPLY_FAILED key-download-temp-failed "$EXIT_APPLY_FAILED" NONE
  decoded_key=$(mktemp "${keyring_target}.decoded.XXXXXX") || complete STOP_APPLY_FAILED key-decode-temp-failed "$EXIT_APPLY_FAILED" NONE
  if ! curl --fail --location --proto '=https' --tlsv1.2 --output "$armored_key" "$RELEASE_KEY_URL" >/dev/null 2>&1; then
    rm -f -- "$armored_key" "$decoded_key"
    complete STOP_APPLY_FAILED release-key-download-failed "$EXIT_APPLY_FAILED" NONE
  fi
  armored_digest=$(sha256_file "$armored_key") || true
  [[ "$armored_digest" == "$RELEASE_KEY_SHA256" ]] || {
    rm -f -- "$armored_key" "$decoded_key"
    complete STOP_SUPPLY_CHAIN_MISMATCH release-key-digest-mismatch "$EXIT_SUPPLY_CHAIN" NONE
  }
  armored_fingerprints=$(keyring_fingerprint "$armored_key" "$gpg_workspace") || true
  [[ "$armored_fingerprints" == "$RELEASE_KEY_FINGERPRINT" ]] || {
    rm -f -- "$armored_key" "$decoded_key"
    complete STOP_SUPPLY_CHAIN_MISMATCH release-key-fingerprint-mismatch "$EXIT_SUPPLY_CHAIN" NONE
  }
  if ! gpg --batch --no-options --no-autostart --homedir "$gpg_workspace" --yes --dearmor --output "$decoded_key" "$armored_key" >/dev/null 2>&1; then
    rm -f -- "$armored_key" "$decoded_key"
    complete STOP_APPLY_FAILED release-key-dearmor-failed "$EXIT_APPLY_FAILED" NONE
  fi
  decoded_digest=$(sha256_file "$decoded_key") || true
  [[ "$decoded_digest" == "$RELEASE_KEYRING_SHA256" ]] || {
    rm -f -- "$armored_key" "$decoded_key"
    complete STOP_SUPPLY_CHAIN_MISMATCH release-keyring-digest-mismatch "$EXIT_SUPPLY_CHAIN" NONE
  }
  publish_result=0
  publish_new_file "$decoded_key" "$keyring_target" 0644 || publish_result=$?
  rm -f -- "$armored_key" "$decoded_key"
  (( publish_result == 0 )) || {
    (( publish_result == EXIT_UNKNOWN_STATE )) && complete STOP_UNKNOWN_STATE keyring-publish-raced "$EXIT_UNKNOWN_STATE" NONE
    complete STOP_APPLY_FAILED keyring-publish-failed "$EXIT_APPLY_FAILED" NONE
  }
  publish_result=0
  publish_source "$source_target" || publish_result=$?
  (( publish_result == 0 )) || {
    (( publish_result == EXIT_UNKNOWN_STATE )) && complete STOP_UNKNOWN_STATE source-publish-raced "$EXIT_UNKNOWN_STATE" NONE
    complete STOP_APPLY_FAILED source-publish-failed "$EXIT_APPLY_FAILED" NONE
  }
fi

[[ "$(keyring_state "$keyring_target")" == COMPLIANT && "$(source_state "$source_target")" == COMPLIANT ]] || complete STOP_VERIFY_FAILED repository-contract-verification-failed "$EXIT_VERIFY_FAILED" NONE
workspace_result=0
create_apt_workspace || workspace_result=$?
(( workspace_result == 0 )) || {
  (( workspace_result == EXIT_UNKNOWN_STATE )) && complete STOP_UNKNOWN_STATE apt-workspace-unsafe "$EXIT_UNKNOWN_STATE" NONE
  complete STOP_APPLY_FAILED apt-workspace-create-failed "$EXIT_APPLY_FAILED" NONE
}
trap cleanup_temporary_workspaces EXIT
effective_apt_config=$(APT_CONFIG="$apt_config" apt-config dump 2>/dev/null) || complete STOP_UNKNOWN_STATE effective-apt-config-unreadable "$EXIT_UNKNOWN_STATE" NONE
effective_apt_configuration_is_safe "$effective_apt_config" || complete STOP_UNKNOWN_STATE effective-apt-config-unsafe "$EXIT_UNKNOWN_STATE" NONE
APT_CONFIG="$apt_config" apt-get -o APT::Update::Error-Mode=any update >/dev/null 2>&1 || complete STOP_APPLY_FAILED apt-update-failed "$EXIT_APPLY_FAILED" NONE
packages_index=$(bound_packages_index "$apt_config") || complete STOP_SUPPLY_CHAIN_MISMATCH packages-index-provenance-invalid "$EXIT_SUPPLY_CHAIN" NONE

download_parent=$(host_path /var/tmp)
download_parent_safe "$download_parent" || complete STOP_UNKNOWN_STATE download-parent-unsafe "$EXIT_UNKNOWN_STATE" NONE
download_dir=$(mktemp -d "${download_parent}/.kubernetes-debs.XXXXXX") || complete STOP_APPLY_FAILED download-directory-create-failed "$EXIT_APPLY_FAILED" NONE
if [[ "$(path_mode "$download_dir")" != 700 ]] || ! owned_by_expected "$download_dir"; then
  complete STOP_UNKNOWN_STATE download-directory-unsafe "$EXIT_UNKNOWN_STATE" NONE
fi
download_directory_exact "$download_dir" || complete STOP_UNKNOWN_STATE download-directory-not-empty "$EXIT_UNKNOWN_STATE" NONE
declare -a debs=() deb_basenames=() package_selections=()
for package in "${PACKAGES[@]}"; do
  version=$(package_version "$package")
  expected_filename=$(package_filename "$package")
  expected_size=$(package_size "$package")
  expected_digest=$(package_sha256 "$package")
  expected_depends=$(package_depends "$package" packages-index)
  index_record=$(signed_index_record "$package" "$packages_index") || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "signed-index-metadata-invalid-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  IFS=$'\t' read -r index_package index_version index_architecture index_filename index_size index_digest index_depends index_relationship_count <<<"$index_record"
  [[ "$index_package" == "$package" && "$index_version" == "$version" && "$index_architecture" == amd64 && "$index_filename" == "$expected_filename" && "$index_size" == "$expected_size" && "$index_digest" == "$expected_digest" && "$index_depends" == "$expected_depends" && "$index_relationship_count" == 0 ]] || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "signed-index-metadata-drift-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  (cd "$download_dir" && APT_CONFIG="$apt_config" apt-get download "${package}=${version}" >/dev/null 2>&1) || {
    rm -r -- "$download_dir"
    complete STOP_APPLY_FAILED "package-download-failed-${package}" "$EXIT_APPLY_FAILED" NONE
  }
  deb_basename="${package}_${version}_amd64.deb"
  deb_basenames+=("$deb_basename")
  download_directory_exact "$download_dir" "${deb_basenames[@]}" || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH download-directory-extra-entry "$EXIT_SUPPLY_CHAIN" NONE
  }
  deb="${download_dir}/${deb_basename}"
  [[ "$(path_size "$deb")" == "$expected_size" ]] || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "deb-size-drift-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  actual_digest=$(sha256_file "$deb") || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "deb-digest-unreadable-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  [[ "$actual_digest" == "$expected_digest" && "$actual_digest" == "$index_digest" ]] || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "deb-digest-drift-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  deb_package=$(dpkg-deb -f "$deb" Package 2>/dev/null) || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "deb-metadata-unreadable-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  deb_version=$(dpkg-deb -f "$deb" Version 2>/dev/null) || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "deb-metadata-unreadable-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  deb_architecture=$(dpkg-deb -f "$deb" Architecture 2>/dev/null) || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "deb-metadata-unreadable-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  [[ "$deb_package" == "$package" && "$deb_version" == "$version" && "$deb_architecture" == amd64 ]] || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "deb-metadata-drift-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  deb_dependency_contract_is_exact "$deb" "$package" || {
    rm -r -- "$download_dir"
    complete STOP_SUPPLY_CHAIN_MISMATCH "deb-dependency-drift-${package}" "$EXIT_SUPPLY_CHAIN" NONE
  }
  debs+=("$deb")
  package_selections+=("${package}=${version}")
done

download_directory_exact "${apt_workspace}/archives" || {
  rm -r -- "$download_dir"
  complete STOP_UNKNOWN_STATE apt-archives-cache-not-empty "$EXIT_UNKNOWN_STATE" NONE
}
for deb_basename in "${deb_basenames[@]}"; do
  publish_result=0
  publish_verified_deb_to_cache "${download_dir}/${deb_basename}" "$deb_basename" || publish_result=$?
  (( publish_result == 0 )) || {
    rm -r -- "$download_dir"
    (( publish_result == EXIT_APPLY_FAILED )) && complete STOP_APPLY_FAILED apt-archive-publish-failed "$EXIT_APPLY_FAILED" NONE
    complete STOP_UNKNOWN_STATE apt-archive-publish-raced "$EXIT_UNKNOWN_STATE" NONE
  }
done
cached_debs_are_exact || {
  rm -r -- "$download_dir"
  complete STOP_SUPPLY_CHAIN_MISMATCH apt-archives-cache-invalid "$EXIT_SUPPLY_CHAIN" NONE
}

simulation_output=$(LC_ALL=C APT_CONFIG="$apt_config" apt-get -s install --no-install-recommends --no-download "${package_selections[@]}" 2>&1) || {
  rm -r -- "$download_dir"
  complete STOP_APPLY_FAILED local-deb-simulation-failed "$EXIT_APPLY_FAILED" NONE
}
simulation_transaction_is_exact <<<"$simulation_output" || {
  rm -r -- "$download_dir"
  complete STOP_SUPPLY_CHAIN_MISMATCH local-deb-transaction-drift "$EXIT_SUPPLY_CHAIN" NONE
}
cached_debs_are_exact || {
  rm -r -- "$download_dir"
  complete STOP_SUPPLY_CHAIN_MISMATCH apt-archives-cache-raced "$EXIT_SUPPLY_CHAIN" NONE
}
cni_path_chain_safe || {
  rm -r -- "$download_dir"
  complete STOP_UNKNOWN_STATE cni-path-chain-raced "$EXIT_UNKNOWN_STATE" NONE
}
kubernetes_shadow_paths_absent || {
  rm -r -- "$download_dir"
  complete STOP_UNKNOWN_STATE kubernetes-binary-shadow-raced "$EXIT_UNKNOWN_STATE" NONE
}
kubelet_mutable_inputs_are_pristine || {
  rm -r -- "$download_dir"
  complete STOP_UNKNOWN_STATE kubelet-pre-init-inputs-raced "$EXIT_UNKNOWN_STATE" NONE
}
base_dependencies_are_exact || {
  rm -r -- "$download_dir"
  complete STOP_UNKNOWN_STATE base-dependency-contract-raced "$EXIT_UNKNOWN_STATE" NONE
}
downloaded_debs_are_exact || {
  rm -r -- "$download_dir"
  complete STOP_SUPPLY_CHAIN_MISMATCH downloaded-deb-raced "$EXIT_SUPPLY_CHAIN" NONE
}
cached_debs_are_exact || {
  rm -r -- "$download_dir"
  complete STOP_SUPPLY_CHAIN_MISMATCH apt-archives-cache-raced "$EXIT_SUPPLY_CHAIN" NONE
}
APT_CONFIG="$apt_config" apt-get install -y --no-install-recommends --no-download "${package_selections[@]}" >/dev/null 2>&1 || {
  rm -r -- "$download_dir"
  complete STOP_APPLY_FAILED local-deb-install-failed "$EXIT_APPLY_FAILED" NONE
}
APT_CONFIG="$apt_config" apt-mark hold "${PACKAGES[@]}" >/dev/null 2>&1 || complete STOP_APPLY_FAILED package-hold-failed "$EXIT_APPLY_FAILED" NONE
hold_verification_result=0
verify_package_selection_and_holds || hold_verification_result=$?
(( hold_verification_result != 2 )) || complete STOP_UNKNOWN_STATE package-hold-state-unreadable "$EXIT_UNKNOWN_STATE" NONE
(( hold_verification_result == 0 )) || complete STOP_VERIFY_FAILED package-hold-verification-failed "$EXIT_VERIFY_FAILED" NONE
cni_path_chain_safe || {
  rm -r -- "$download_dir"
  complete STOP_UNKNOWN_STATE cni-path-chain-post-install-unsafe "$EXIT_UNKNOWN_STATE" NONE
}
[[ "$(cni_directory_state "$(host_path /opt/cni/bin)")" == COMPLIANT ]] || {
  rm -r -- "$download_dir"
  complete STOP_VERIFY_FAILED cni-package-payload-invalid "$EXIT_VERIFY_FAILED" NONE
}
rm -r -- "$download_dir"
verification_result=0
verify_installed_package_payload_state || verification_result=$?
(( verification_result != 2 )) || complete STOP_UNKNOWN_STATE package-hold-state-unreadable "$EXIT_UNKNOWN_STATE" NONE
(( verification_result == 0 )) || complete STOP_VERIFY_FAILED kubernetes-package-verification-failed "$EXIT_VERIFY_FAILED" NONE
kubelet_state=$(kubelet_unit_state)
[[ "$kubelet_state" == READY || "$kubelet_state" == START_REQUIRED ]] || complete STOP_VERIFY_FAILED kubernetes-package-verification-failed "$EXIT_VERIFY_FAILED" NONE
restart_result=0
restart_kubelet_and_verify || restart_result=$?
case "$restart_result" in
  0) ;;
  1) complete STOP_APPLY_FAILED kubelet-start-failed "$EXIT_APPLY_FAILED" NONE ;;
  2) complete STOP_VERIFY_FAILED kubelet-start-verification-failed "$EXIT_VERIFY_FAILED" NONE ;;
  3) complete STOP_UNKNOWN_STATE package-hold-state-unreadable "$EXIT_UNKNOWN_STATE" NONE ;;
  *) complete STOP_UNKNOWN_STATE kubelet-start-result-invalid "$EXIT_UNKNOWN_STATE" NONE ;;
esac
if dpkg-query -W -f='${Status}\n' cri-tools >/dev/null 2>&1; then
  complete STOP_VERIFY_FAILED cri-tools-package-installed "$EXIT_VERIFY_FAILED" NONE
fi
complete_successful_kubernetes_install
