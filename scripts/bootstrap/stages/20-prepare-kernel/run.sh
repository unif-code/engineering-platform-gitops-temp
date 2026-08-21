#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

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
# run.sh 比原来的平铺位置深两层；lib/ 与 check_cidrs.py 仍留在
# scripts/bootstrap/ 下，因此一律以 bootstrap_dir 为锚点。
bootstrap_dir=$(cd "${script_dir}/../.." && pwd -P)
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/common.sh"
# shellcheck disable=SC1091
source "${bootstrap_dir}/lib/path-facts.sh"
# shellcheck disable=SC1091
source "${script_dir}/gates.sh"

# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=prepare-kernel
readonly MODULES_CONTENT=$'overlay\nbr_netfilter\n'
readonly SYSCTL_CONTENT=$'net.bridge.bridge-nf-call-iptables = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\nnet.ipv4.ip_forward = 1\n'

atomic_publish_content() {
  local target=$1
  local content=$2
  local temporary

  require_managed_parent "${target%/*}" || return "$EXIT_UNKNOWN_STATE"
  temporary=$(mktemp "${target}.tmp.XXXXXX") || return "$EXIT_APPLY_FAILED"
  if ! require_managed_parent "${target%/*}" || ! owned_by_expected "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  if ! printf '%s' "$content" >"$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if ! chmod 0644 "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if [[ "$(path_mode "$temporary")" != 644 ]] || ! owned_by_expected "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  if ! sync "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if ! require_managed_parent "${target%/*}"; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  if ! mv -n "$temporary" "$target"; then
    if [[ -e "$target" || -L "$target" ]]; then
      rm -f -- "$temporary"
      return "$EXIT_UNKNOWN_STATE"
    fi
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
}

parse_mode "$@" || exit "$?"
require_root || complete STOP_PRECONDITION not-root "$EXIT_PRECONDITION" NONE
for required_command in chmod cmp date id mktemp modprobe mv rm stat sync sysctl; do
  require_command "$required_command" || complete STOP_PRECONDITION "missing-command-${required_command}" "$EXIT_PRECONDITION" NONE
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  complete STOP_PRECONDITION missing-command-sha256 "$EXIT_PRECONDITION" NONE
fi
modules_file=$(host_path /etc/modules-load.d/99-kubernetes.conf)
legacy_modules_file=$(host_path /etc/modules-load.d/containerd.conf)
sysctl_file=$(host_path /etc/sysctl.d/99-kubernetes-cri.conf)
modules_parent=$(dirname "$modules_file")
sysctl_parent=$(dirname "$sysctl_file")
require_managed_parent "$modules_parent" || complete STOP_UNKNOWN_STATE modules-parent-unsafe "$EXIT_UNKNOWN_STATE" NONE
require_managed_parent "$sysctl_parent" || complete STOP_UNKNOWN_STATE sysctl-parent-unsafe "$EXIT_UNKNOWN_STATE" NONE
if [[ -e "$legacy_modules_file" || -L "$legacy_modules_file" ]]; then
  complete STOP_UNKNOWN_STATE legacy-modules-file-present "$EXIT_UNKNOWN_STATE" NONE
fi

modules_state=$(content_file_state "$modules_file" "$MODULES_CONTENT")
sysctl_state=$(content_file_state "$sysctl_file" "$SYSCTL_CONTENT")
[[ "$modules_state" != UNKNOWN ]] || complete STOP_UNKNOWN_STATE modules-file-drift "$EXIT_UNKNOWN_STATE" NONE
[[ "$sysctl_state" != UNKNOWN ]] || complete STOP_UNKNOWN_STATE sysctl-file-drift "$EXIT_UNKNOWN_STATE" NONE
if [[ "$modules_state" != "$sysctl_state" ]]; then
  complete STOP_UNKNOWN_STATE partial-persistent-kernel-state "$EXIT_UNKNOWN_STATE" NONE
fi

overlay_path=$(host_path /sys/module/overlay)
br_netfilter_path=$(host_path /sys/module/br_netfilter)
bridge_ipv4_path=$(host_path /proc/sys/net/bridge/bridge-nf-call-iptables)
bridge_ipv6_path=$(host_path /proc/sys/net/bridge/bridge-nf-call-ip6tables)
ip_forward_path=$(host_path /proc/sys/net/ipv4/ip_forward)

runtime_result=0
runtime_state "$overlay_path" "$br_netfilter_path" "$bridge_ipv4_path" "$bridge_ipv6_path" "$ip_forward_path" || runtime_result=$?
if [[ "$runtime_result" == 2 ]]; then
  complete STOP_UNKNOWN_STATE kernel-runtime-path-unsafe "$EXIT_UNKNOWN_STATE" NONE
fi
if [[ "$modules_state" == COMPLIANT && "$runtime_result" == 0 ]]; then
  complete ALREADY_COMPLIANT kernel-ready 0 30-install-containerd
fi
# MODE 由公共 parse_mode helper 赋值。
# shellcheck disable=SC2153
if [[ "$MODE" == CHECK ]]; then
  complete PASS_KERNEL_CHECK apply-required 0 20-prepare-kernel--apply
fi

evidence_dir=$(host_path /root/dev-infra-evidence)
open_evidence 09-prepare-kernel "$evidence_dir" || complete STOP_EVIDENCE evidence-open-failed "$EXIT_UNKNOWN_STATE" NONE

if [[ "$modules_state" == MISSING ]]; then
  publish_result=0
  atomic_publish_content "$modules_file" "$MODULES_CONTENT" || publish_result=$?
  case "$publish_result" in
    0) ;;
    30) complete STOP_UNKNOWN_STATE modules-target-appeared "$EXIT_UNKNOWN_STATE" NONE ;;
    *) complete STOP_APPLY_FAILED modules-file-write-failed "$EXIT_APPLY_FAILED" NONE ;;
  esac
  [[ "$(content_file_state "$modules_file" "$MODULES_CONTENT")" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE modules-file-post-publish-drift "$EXIT_UNKNOWN_STATE" NONE

  publish_result=0
  atomic_publish_content "$sysctl_file" "$SYSCTL_CONTENT" || publish_result=$?
  case "$publish_result" in
    0) ;;
    30) complete STOP_UNKNOWN_STATE sysctl-target-appeared "$EXIT_UNKNOWN_STATE" NONE ;;
    *) complete STOP_APPLY_FAILED sysctl-file-write-failed "$EXIT_APPLY_FAILED" NONE ;;
  esac
  [[ "$(content_file_state "$sysctl_file" "$SYSCTL_CONTENT")" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE sysctl-file-post-publish-drift "$EXIT_UNKNOWN_STATE" NONE
fi

modprobe overlay >/dev/null 2>&1 || complete STOP_APPLY_FAILED modprobe-overlay-failed "$EXIT_APPLY_FAILED" NONE
modprobe br_netfilter >/dev/null 2>&1 || complete STOP_APPLY_FAILED modprobe-br-netfilter-failed "$EXIT_APPLY_FAILED" NONE
sysctl --load "$sysctl_file" >/dev/null 2>&1 || complete STOP_APPLY_FAILED sysctl-load-failed "$EXIT_APPLY_FAILED" NONE

runtime_result=0
runtime_state "$overlay_path" "$br_netfilter_path" "$bridge_ipv4_path" "$bridge_ipv6_path" "$ip_forward_path" || runtime_result=$?
[[ "$runtime_result" == 0 ]] || complete STOP_VERIFY_FAILED kernel-runtime-verification-failed "$EXIT_VERIFY_FAILED" NONE

log_evidence MODULE_OVERLAY=loaded
log_evidence MODULE_BR_NETFILTER=loaded
log_evidence SYSCTL_BRIDGE_IPV4=1
log_evidence SYSCTL_BRIDGE_IPV6=1
log_evidence SYSCTL_IP_FORWARD=1
complete PASS_KERNEL_PREPARED kernel-ready 0 30-install-containerd
