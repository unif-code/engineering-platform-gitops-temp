#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "${script_dir}/../.." && pwd -P)
# shellcheck source=scripts/bootstrap/lib/common.sh
source "${script_dir}/lib/common.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/host-config.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/os-release.sh"

# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=preflight
readonly CLEANUP_EVIDENCE_SHA256=a68a3d2ff340bcdcb4265853107a3a2c22a9f7328728473d81d9be2d1486e635

host_path() {
  local absolute=$1
  if [[ "${BOOTSTRAP_TEST_MODE:-0}" == "1" ]]; then
    printf '%s%s\n' "${BOOTSTRAP_TEST_ROOT:?}" "$absolute"
  else
    printf '%s\n' "$absolute"
  fi
}

complete() {
  local result=$1
  local reason=$2
  local code=$3
  local next=$4
  finish_phase "$result" "$reason" "$code" "$next"
  exit "$code"
}

parse_mode "$@" || exit "$?"
if [[ "$MODE" != CHECK ]]; then
  printf 'RESULT=STOP_MODE\nREASON=preflight-is-read-only\n' >&2
  exit "$EXIT_PRECONDITION"
fi
if [[ "${BOOTSTRAP_TEST_MODE:-0}" == "1" && "$EUID" -eq 0 ]]; then
  printf 'RESULT=STOP_TEST_MODE\nREASON=test-mode-is-for-unprivileged-tests-only\n' >&2
  exit "$EXIT_PRECONDITION"
fi

evidence_dir=$(host_path /root/dev-infra-evidence)
if ! open_evidence 07-preflight "$evidence_dir"; then
  printf 'RESULT=STOP_EVIDENCE\nREASON=evidence-open-failed\n' >&2
  exit "$EXIT_UNKNOWN_STATE"
fi

for required_command in awk cmp date dpkg-query grep hostname id ip python3 readlink ss stat swapon systemctl tr uname; do
  require_command "$required_command" || complete STOP_PRECONDITION "missing-command-${required_command}" "$EXIT_PRECONDITION" NONE
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  complete STOP_PRECONDITION missing-command-sha256 "$EXIT_PRECONDITION" NONE
fi

if ! require_root; then
  complete STOP_HOST_IDENTITY not-root "$EXIT_PRECONDITION" NONE
fi

load_host_config || complete STOP_PRECONDITION "$HOST_CONFIG_ERROR" "$EXIT_PRECONDITION" NONE
log_evidence "HOSTNAME=${HOST_NAME}"

os_release=$(ubuntu_os_release_path) ||
  complete STOP_HOST_IDENTITY os-release-missing "$EXIT_PRECONDITION" NONE
os_id=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' "$os_release")
os_version=$(awk -F= '$1 == "VERSION_ID" {gsub(/"/, "", $2); print $2}' "$os_release")
if [[ "$os_id" != ubuntu || "$os_version" != 24.04* ]]; then
  complete STOP_HOST_IDENTITY os-mismatch "$EXIT_PRECONDITION" NONE
fi
log_evidence "OS=${os_id}-${os_version}"

architecture=$(uname -m 2>/dev/null) || complete STOP_HOST_IDENTITY architecture-unreadable "$EXIT_PRECONDITION" NONE
if [[ "$architecture" != x86_64 ]]; then
  complete STOP_HOST_IDENTITY architecture-mismatch "$EXIT_PRECONDITION" NONE
fi
log_evidence "ARCHITECTURE=${architecture}"

cgroup_path=$(host_path /sys/fs/cgroup)
cgroup_fs=$(stat -fc %T "$cgroup_path" 2>/dev/null) || complete STOP_HOST_IDENTITY cgroup-unreadable "$EXIT_PRECONDITION" NONE
if [[ "$cgroup_fs" != cgroup2fs ]]; then
  complete STOP_HOST_IDENTITY cgroup-v2-required "$EXIT_PRECONDITION" NONE
fi
log_evidence "CGROUP_FS=${cgroup_fs}"

address_output=$(ip -o -4 address show up 2>/dev/null) || complete STOP_NETWORK ip-address-unreadable "$EXIT_PRECONDITION" NONE
if ! printf '%s\n' "$address_output" | awk -v ip="$HOST_NODE_IP" '$4 ~ ("^" ip "/") {found=1} END {exit !found}'; then
  complete STOP_NETWORK node-ip-not-bound-up "$EXIT_PRECONDITION" NONE
fi
log_evidence "NODE_IP=${HOST_NODE_IP}"

swap_file=$(host_path "$HOST_SWAP_FILE")
if [[ ! -f "$swap_file" || -L "$swap_file" ]]; then
  complete STOP_SWAP swap-file-missing "$EXIT_PRECONDITION" NONE
fi
swap_output=$(swapon --show=NAME,SIZE --noheadings --raw --bytes 2>/dev/null) || complete STOP_SWAP swapon-unreadable "$EXIT_PRECONDITION" NONE
swap_lines=$(printf '%s\n' "$swap_output" | awk 'NF {count++} END {print count+0}')
swap_name=$(printf '%s\n' "$swap_output" | awk 'NF {print $1}')
swap_bytes=$(printf '%s\n' "$swap_output" | awk 'NF {print $2}')
if [[ "$swap_lines" != 1 || "$swap_name" != "$HOST_SWAP_FILE" || ! "$swap_bytes" =~ ^[0-9]+$ ]]; then
  complete STOP_SWAP swap-layout-mismatch "$EXIT_PRECONDITION" NONE
fi
# HOST_SWAP_*_BYTES 由 lib/host-config.sh 限定为 ^[1-9][0-9]{0,17}$，裸算术因此无注入与溢出风险。
if (( swap_bytes < HOST_SWAP_MIN_BYTES || swap_bytes > HOST_SWAP_MAX_BYTES )); then
  complete STOP_SWAP swap-size-mismatch "$EXIT_PRECONDITION" NONE
fi
log_evidence "SWAP=${HOST_SWAP_FILE}"
log_evidence "SWAP_BYTES=${swap_bytes}"

for service in chrony systemd-networkd systemd-resolved ssh; do
  service_state=$(systemctl is-active "$service" 2>/dev/null) || complete STOP_HOST_HEALTH "service-${service}-inactive" "$EXIT_PRECONDITION" NONE
  if [[ "$service_state" != active ]]; then
    complete STOP_HOST_HEALTH "service-${service}-not-active" "$EXIT_PRECONDITION" NONE
  fi
done
log_evidence "BASE_SERVICES=active"

cleanup_evidence=$(host_path /root/dev-infra-evidence/06-host-workflow-cleanup-20260810T033358Z.txt)
if [[ ! -f "$cleanup_evidence" || -L "$cleanup_evidence" ]]; then
  complete STOP_CLEANUP_EVIDENCE cleanup-evidence-missing "$EXIT_PRECONDITION" NONE
fi
cleanup_digest=$(sha256_file "$cleanup_evidence") || complete STOP_CLEANUP_EVIDENCE cleanup-evidence-unreadable "$EXIT_PRECONDITION" NONE
if [[ "$cleanup_digest" != "$CLEANUP_EVIDENCE_SHA256" ]]; then
  complete STOP_CLEANUP_EVIDENCE cleanup-evidence-digest-mismatch "$EXIT_PRECONDITION" NONE
fi
log_evidence "CLEANUP_EVIDENCE_SHA256=${cleanup_digest}"

for binary in caddy docker dockerd node npm npx pnpm; do
  if command -v "$binary" >/dev/null 2>&1; then
    complete STOP_OLD_RUNTIME "unexpected-binary-${binary}" "$EXIT_UNKNOWN_STATE" NONE
  fi
done

for package in caddy containerd.io docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras; do
  if dpkg-query -W -f='${Status}\n' "$package" 2>/dev/null | grep -Fxq 'install ok installed'; then
    complete STOP_OLD_RUNTIME "unexpected-package-${package}" "$EXIT_UNKNOWN_STATE" NONE
  fi
done

for path in /data/workflow /etc/caddy /etc/docker /usr/local/lib/node-v24.18.0 /var/lib/docker; do
  resolved=$(host_path "$path")
  if [[ -e "$resolved" || -L "$resolved" ]]; then
    complete STOP_OLD_RUNTIME "unexpected-path-${path}" "$EXIT_UNKNOWN_STATE" NONE
  fi
done

unit_files=$(systemctl list-unit-files caddy.service docker.service docker.socket 2>/dev/null || true)
if printf '%s\n' "$unit_files" | grep -Eq '^(caddy|docker)\.(service|socket)[[:space:]]'; then
  complete STOP_OLD_RUNTIME unexpected-old-unit "$EXIT_UNKNOWN_STATE" NONE
fi

port_3001=$(ss -H -ltn 'sport = :3001' 2>/dev/null || true)
if [[ -n "$port_3001" ]]; then
  complete STOP_OLD_RUNTIME port-3001-listening "$EXIT_UNKNOWN_STATE" NONE
fi
log_evidence "OLD_RUNTIME=absent"
log_evidence "PORT_3001=closed"

cidr_arguments=(
  --service-cidr "$HOST_SERVICE_CIDR"
  --pod-cidr "$HOST_POD_CIDR"
)
for cni_device in "${CNI_HOST_DEVICES[@]}"; do
  cidr_arguments+=(--cni-device "$cni_device")
done
# 地址/路由带上网卡名（前缀@网卡），让 CIDR 检查能识别 CNI 自建条目。
while IFS= read -r address; do
  [[ -n "$address" ]] && cidr_arguments+=(--address "$address")
done < <(printf '%s\n' "$address_output" | awk 'NF >= 4 {print $4 "@" $2}')

route_output=$(ip -o -4 route show table all 2>/dev/null) || complete STOP_NETWORK ip-route-unreadable "$EXIT_PRECONDITION" NONE
while IFS= read -r route; do
  [[ -n "$route" && "$route" != default ]] && cidr_arguments+=(--route "$route")
done < <(printf '%s\n' "$route_output" | awk '$1 != "default" && $1 ~ /\// {
  device = ""
  for (i = 1; i <= NF; i++) if ($i == "dev") device = $(i + 1)
  print (device != "" ? $1 "@" device : $1)
}')

set +e
cidr_output=$(python3 "${script_dir}/check_cidrs.py" "${cidr_arguments[@]}" 2>/dev/null)
cidr_exit=$?
set -e
if [[ "$cidr_exit" -ne 0 ]]; then
  cidr_result=$(printf '%s\n' "$cidr_output" | awk -F= '$1 == "RESULT" {print $2}')
  complete "${cidr_result:-STOP_CIDR_INVALID}" cidr-overlap-or-invalid "$EXIT_PRECONDITION" NONE
fi
log_evidence "SERVICE_CIDR=${HOST_SERVICE_CIDR}"
log_evidence "POD_CIDR=${HOST_POD_CIDR}"
log_evidence "CIDR_SCOPE=SERVER_LOCAL_SCOPE_ONLY"
log_evidence "REPO_ROOT=${repo_root}"

complete PASS_PREFLIGHT server-local-preflight-passed 0 '10-stage-artifacts.sh --check'
