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
repo_root=$(cd "${script_dir}/../.." && pwd -P)
# shellcheck disable=SC1091
source "${script_dir}/lib/common.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/path-facts.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/archive.sh"

# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=containerd
readonly ARTIFACT_SET=pcs-2026-08-10.1
readonly APPROVED_RECORD_COUNT=6
readonly CRI_ENDPOINT=unix:///run/containerd/containerd.sock

host_path() {
  local absolute=$1
  if [[ "${BOOTSTRAP_TEST_MODE:-0}" == 1 ]]; then
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

stream_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

archive_member_sha256() {
  local archive=$1
  local member=$2
  tar -xOzf "$archive" "$member" 2>/dev/null | stream_sha256
}

private_staging_directory() {
  local directory=$1
  [[ -d "$directory" && ! -L "$directory" && "$(path_mode "$directory")" == 700 ]] && owned_by_expected "$directory"
}

staged_file_state() {
  local path=$1
  local expected_digest=$2
  local actual_digest
  if [[ -L "$path" || ! -f "$path" || "$(path_mode "$path")" != 600 ]] || ! owned_by_expected "$path"; then
    printf 'UNSAFE\n'
    return 0
  fi
  actual_digest=$(sha256_file "$path") || return "$?"
  if [[ "$actual_digest" == "$expected_digest" ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'DRIFT\n'
  fi
}

target_file_state() {
  local path=$1
  local expected_digest=$2
  local expected_mode=$3
  local actual_digest
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    printf 'MISSING\n'
    return 0
  fi
  if [[ -L "$path" || ! -f "$path" || "$(path_mode "$path")" != "$expected_mode" ]] || ! owned_by_expected "$path"; then
    printf 'UNKNOWN\n'
    return 0
  fi
  actual_digest=$(sha256_file "$path") || {
    printf 'UNKNOWN\n'
    return 0
  }
  if [[ "$actual_digest" == "$expected_digest" ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

directory_state() {
  local directory=$1
  if [[ ! -e "$directory" && ! -L "$directory" ]]; then
    printf 'MISSING\n'
  elif [[ -d "$directory" && ! -L "$directory" && "$(path_mode "$directory")" == 755 ]] && owned_by_expected "$directory"; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

data_root_safe() {
  local data_root=$1
  local entries
  if [[ ! -e "$data_root" && ! -L "$data_root" ]]; then
    return 0
  fi
  [[ -d "$data_root" && ! -L "$data_root" && "$(path_mode "$data_root")" == 700 ]] || return 2
  owned_by_expected "$data_root" || return 2
  shopt -s dotglob nullglob
  entries=("$data_root"/*)
  shopt -u dotglob nullglob
  (( ${#entries[@]} == 0 )) && return 0
  return 1
}

runtime_directory_state() {
  local run_dir=$1
  if [[ ! -e "$run_dir" && ! -L "$run_dir" ]]; then
    printf 'MISSING\n'
  elif [[ -d "$run_dir" && ! -L "$run_dir" && "$(path_mode "$run_dir")" == 711 ]] && owned_by_expected "$run_dir"; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

private_extract_directory() {
  local directory=$1
  local parent=$2
  [[ "${directory%/*}" == "$parent" ]] || return 1
  [[ "$(directory_state "$parent")" == COMPLIANT ]] || return 1
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  [[ "$(path_mode "$directory")" == 700 ]] && owned_by_expected "$directory"
}

atomic_publish() {
  local source=$1
  local target=$2
  local mode=$3
  local temporary
  local parent=${target%/*}
  [[ "$(directory_state "$parent")" == COMPLIANT ]] || return "$EXIT_UNKNOWN_STATE"
  temporary=$(mktemp "${target}.tmp.XXXXXX") || return "$EXIT_APPLY_FAILED"
  if [[ "$(directory_state "$parent")" != COMPLIANT ]] || ! owned_by_expected "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  [[ "$(directory_state "$parent")" == COMPLIANT ]] || { rm -f -- "$temporary"; return "$EXIT_UNKNOWN_STATE"; }
  if ! install -m "$mode" "$source" "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if [[ ! -f "$temporary" || -L "$temporary" || "$(path_mode "$temporary")" != "$mode" ]] || ! owned_by_expected "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_UNKNOWN_STATE"
  fi
  if ! sync "$temporary"; then
    rm -f -- "$temporary"
    return "$EXIT_APPLY_FAILED"
  fi
  if [[ "$(directory_state "$parent")" != COMPLIANT ]]; then
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

verify_health() {
  local containerd_path=$1 runc_path=$2 ctr_path=$3 crictl_path=$4
  local output first_line marker
  output=$("$containerd_path" --version 2>/dev/null) || return 1
  [[ "$output" =~ ^containerd\ github.com/containerd/containerd/v2\ v2\.3\.1\ [^[:space:]]+$ ]] || return 1
  output=$("$runc_path" --version 2>/dev/null) || return 1
  IFS= read -r first_line <<<"$output"
  [[ "$first_line" == 'runc version 1.3.6' ]] || return 1
  output=$("$crictl_path" --version 2>/dev/null) || return 1
  [[ "$output" == 'crictl version v1.36.0' ]] || return 1
  output=$("$ctr_path" plugins ls 2>/dev/null) || return 1
  awk '
    $1 == "io.containerd.snapshotter.v1" && $2 == "overlayfs" && $4 == "ok" { overlay++ }
    $1 == "io.containerd.cri.v1" && $2 == "images" && $4 == "ok" { images++ }
    $1 == "io.containerd.cri.v1" && $2 == "runtime" && $4 == "ok" { runtime++ }
    END { exit !(overlay == 1 && images == 1 && runtime == 1) }
  ' <<<"$output" || return 1
  marker=$(
    "$crictl_path" \
      --runtime-endpoint "$CRI_ENDPOINT" \
      --image-endpoint "$CRI_ENDPOINT" \
      info --output json 2>/dev/null |
      python3 -c '
import json
import sys
try:
    value = json.load(sys.stdin)
    conditions = value["status"]["conditions"]
    ready = [item for item in conditions if isinstance(item, dict) and item.get("type") == "RuntimeReady"]
    runtime = value["config"]["containerd"]
    runc = runtime["runtimes"]["runc"]
    valid = (
        len(ready) == 1
        and ready[0].get("status") is True
        and runtime.get("defaultRuntimeName") == "runc"
        and runc.get("runtimeType") == "io.containerd.runc.v2"
        and runc.get("options", {}).get("SystemdCgroup") is True
    )
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    valid = False
if not valid:
    raise SystemExit(1)
print("CRI_RUNTIME_READY=true")
' 2>/dev/null
  ) || return 1
  [[ "$marker" == CRI_RUNTIME_READY=true ]]
}

unit_contract_state() {
  local unit_target=$1
  local properties line
  local load_state='' fragment_path='' drop_in_paths=''
  local load_seen=0 fragment_seen=0 drop_in_seen=0
  properties=$(systemctl show --all \
    --property=LoadState \
    --property=FragmentPath \
    --property=DropInPaths \
    containerd.service 2>/dev/null) || {
      printf 'UNKNOWN\n'
      return 0
    }
  while IFS= read -r line; do
    case "$line" in
      LoadState=*)
        (( load_seen == 0 )) || { printf 'UNKNOWN\n'; return 0; }
        load_state=${line#LoadState=}
        load_seen=1
        ;;
      FragmentPath=*)
        (( fragment_seen == 0 )) || { printf 'UNKNOWN\n'; return 0; }
        fragment_path=${line#FragmentPath=}
        fragment_seen=1
        ;;
      DropInPaths=*)
        (( drop_in_seen == 0 )) || { printf 'UNKNOWN\n'; return 0; }
        drop_in_paths=${line#DropInPaths=}
        drop_in_seen=1
        ;;
      *) printf 'UNKNOWN\n'; return 0 ;;
    esac
  done <<<"$properties"
  if (( load_seen != 1 || fragment_seen != 1 || drop_in_seen != 1 )); then
    printf 'UNKNOWN\n'
  elif [[ "$load_state" == not-found && -z "$fragment_path" && -z "$drop_in_paths" ]]; then
    printf 'MISSING\n'
  elif [[ "$load_state" == loaded && "$fragment_path" == "$unit_target" && -z "$drop_in_paths" ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'UNKNOWN\n'
  fi
}

service_contract_compliant() {
  local unit_target=$1
  local socket_target=$2
  local data_root=$3
  local data_result=0
  [[ "$(unit_contract_state "$unit_target")" == COMPLIANT ]] || return 1
  [[ "$(runtime_directory_state "${socket_target%/*}")" == COMPLIANT ]] || return 1
  [[ -S "$socket_target" && ! -L "$socket_target" ]] || return 1
  [[ "$(path_mode "$socket_target")" == 660 ]] && owned_by_expected "$socket_target" || return 1
  [[ -d "$data_root" && ! -L "$data_root" ]] || return 1
  data_root_safe "$data_root" || data_result=$?
  (( data_result == 0 || data_result == 1 ))
}

parse_mode "$@" || exit "$?"
require_root || complete STOP_PRECONDITION not-root "$EXIT_PRECONDITION" NONE
for required_command in awk chmod cmp date grep id install mktemp mv python3 rm stat sync systemctl tar; do
  require_command "$required_command" || complete STOP_PRECONDITION "missing-command-${required_command}" "$EXIT_PRECONDITION" NONE
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  complete STOP_PRECONDITION missing-command-sha256 "$EXIT_PRECONDITION" NONE
fi
lock_file=${BOOTSTRAP_TEST_LOCK_FILE:-"${repo_root}/bootstrap/artifacts.lock.tsv"}
[[ -f "$lock_file" && ! -L "$lock_file" ]] || complete STOP_SUPPLY_CHAIN_MISMATCH lock-file-missing-or-unsafe "$EXIT_SUPPLY_CHAIN" NONE
declare -a names=() urls=() digests=() basenames=()
while IFS=$'\t' read -r name version url digest target extra; do
  [[ -n "$name" && -n "$version" && -n "$url" && -n "$digest" && -n "$target" && -z "$extra" ]] || complete STOP_SUPPLY_CHAIN_MISMATCH lock-record-invalid "$EXIT_SUPPLY_CHAIN" NONE
  expected_record=$(approved_record "$name") || complete STOP_SUPPLY_CHAIN_MISMATCH lock-name-unapproved "$EXIT_SUPPLY_CHAIN" NONE
  array_contains "$name" "${names[@]-}" && complete STOP_SUPPLY_CHAIN_MISMATCH lock-name-duplicate "$EXIT_SUPPLY_CHAIN" NONE
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || complete STOP_SUPPLY_CHAIN_MISMATCH lock-digest-invalid "$EXIT_SUPPLY_CHAIN" NONE
  IFS=$'\t' read -r expected_version expected_url expected_digest expected_target <<<"$expected_record"
  [[ "$version" == "$expected_version" && "$url" == "$expected_url" && "$digest" == "$expected_digest" && "$target" == "$expected_target" ]] || complete STOP_SUPPLY_CHAIN_MISMATCH lock-schema-drift "$EXIT_SUPPLY_CHAIN" NONE
  basename=${url##*/}
  [[ -n "$basename" ]] || complete STOP_SUPPLY_CHAIN_MISMATCH lock-basename-invalid "$EXIT_SUPPLY_CHAIN" NONE
  array_contains "$basename" "${basenames[@]-}" && complete STOP_SUPPLY_CHAIN_MISMATCH lock-basename-duplicate "$EXIT_SUPPLY_CHAIN" NONE
  names+=("$name") urls+=("$url") digests+=("$digest") basenames+=("$basename")
done <"$lock_file"
(( ${#names[@]} == APPROVED_RECORD_COUNT )) || complete STOP_SUPPLY_CHAIN_MISMATCH lock-record-count-invalid "$EXIT_SUPPLY_CHAIN" NONE

artifact_root=$(host_path /root/dev-infra-artifacts)
artifact_dir="${artifact_root}/${ARTIFACT_SET}"
private_staging_directory "$artifact_root" || complete STOP_UNKNOWN_STATE artifact-root-unsafe "$EXIT_UNKNOWN_STATE" NONE
private_staging_directory "$artifact_dir" || complete STOP_UNKNOWN_STATE artifact-directory-unsafe "$EXIT_UNKNOWN_STATE" NONE
declare -a staged_paths=()
for index in "${!names[@]}"; do
  path="${artifact_dir}/${basenames[index]}"
  state=$(staged_file_state "$path" "${digests[index]}") || complete STOP_UNKNOWN_STATE artifact-state-unreadable "$EXIT_UNKNOWN_STATE" NONE
  case "$state" in
    COMPLIANT) staged_paths[index]=$path ;;
    DRIFT) complete STOP_SUPPLY_CHAIN_MISMATCH "artifact-digest-drift-${basenames[index]}" "$EXIT_SUPPLY_CHAIN" NONE ;;
    *) complete STOP_UNKNOWN_STATE "artifact-file-unsafe-${basenames[index]}" "$EXIT_UNKNOWN_STATE" NONE ;;
  esac
done
shopt -s dotglob nullglob
for path in "$artifact_dir"/*; do
  array_contains "${path##*/}" "${basenames[@]}" || complete STOP_UNKNOWN_STATE artifact-entry-unapproved "$EXIT_UNKNOWN_STATE" NONE
done
shopt -u dotglob nullglob

for index in "${!names[@]}"; do
  case "${names[index]}" in
    containerd) containerd_artifact=${staged_paths[index]} ;;
    runc) runc_artifact=${staged_paths[index]}; runc_digest=${digests[index]} ;;
    crictl) crictl_artifact=${staged_paths[index]} ;;
  esac
done
[[ -n "${containerd_artifact:-}" && -n "${runc_artifact:-}" && -n "${crictl_artifact:-}" ]] || complete STOP_SUPPLY_CHAIN_MISMATCH required-artifact-missing "$EXIT_SUPPLY_CHAIN" NONE

validate_archive containerd "$containerd_artifact" || complete STOP_ARCHIVE_UNSAFE archive-validation-failed-containerd "$EXIT_SUPPLY_CHAIN" NONE
validate_archive crictl "$crictl_artifact" || complete STOP_ARCHIVE_UNSAFE archive-validation-failed-crictl "$EXIT_SUPPLY_CHAIN" NONE

declare -a directory_paths=(
  /usr /usr/local /usr/local/bin /usr/local/sbin /usr/local/lib
  /usr/local/lib/systemd /usr/local/lib/systemd/system
  /etc /etc/containerd /var /var/lib
)
declare -a missing_directories=()
for absolute in "${directory_paths[@]}"; do
  directory=$(host_path "$absolute")
  state=$(directory_state "$directory")
  case "$state" in
    COMPLIANT) ;;
    MISSING) missing_directories+=("$directory") ;;
    *) complete STOP_UNKNOWN_STATE "target-directory-unsafe-${absolute//\//-}" "$EXIT_UNKNOWN_STATE" NONE ;;
  esac
done
data_root=$(host_path /var/lib/containerd)
run_parent=$(host_path /run)
run_dir=$(host_path /run/containerd)
socket_target=$(host_path /run/containerd/containerd.sock)
[[ "$(directory_state "$run_parent")" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE run-parent-unsafe "$EXIT_UNKNOWN_STATE" NONE
[[ "$(runtime_directory_state "$run_dir")" != UNKNOWN ]] || complete STOP_UNKNOWN_STATE containerd-run-directory-unsafe "$EXIT_UNKNOWN_STATE" NONE

containerd_target=$(host_path /usr/local/bin/containerd)
ctr_target=$(host_path /usr/local/bin/ctr)
shim_target=$(host_path /usr/local/bin/containerd-shim-runc-v2)
runc_target=$(host_path /usr/local/sbin/runc)
crictl_target=$(host_path /usr/local/bin/crictl)
config_target=$(host_path /etc/containerd/config.toml)
unit_target=$(host_path /usr/local/lib/systemd/system/containerd.service)
config_source="${repo_root}/bootstrap/containerd/config.toml"
unit_source="${repo_root}/bootstrap/containerd/containerd.service"
[[ -f "$config_source" && ! -L "$config_source" && -f "$unit_source" && ! -L "$unit_source" ]] || complete STOP_SUPPLY_CHAIN_MISMATCH repository-contract-unsafe "$EXIT_SUPPLY_CHAIN" NONE

declare -a targets=("$containerd_target" "$ctr_target" "$shim_target" "$runc_target" "$crictl_target" "$config_target" "$unit_target")
declare -a target_modes=(755 755 755 755 755 644 644)
declare -a target_digests=(
  "$(archive_member_sha256 "$containerd_artifact" bin/containerd)"
  "$(archive_member_sha256 "$containerd_artifact" bin/ctr)"
  "$(archive_member_sha256 "$containerd_artifact" bin/containerd-shim-runc-v2)"
  "$runc_digest"
  "$(archive_member_sha256 "$crictl_artifact" crictl)"
  "$(sha256_file "$config_source")"
  "$(sha256_file "$unit_source")"
)
missing_count=0
compliant_count=0
for index in "${!targets[@]}"; do
  state=$(target_file_state "${targets[index]}" "${target_digests[index]}" "${target_modes[index]}")
  case "$state" in
    MISSING) ((missing_count += 1)) ;;
    COMPLIANT) ((compliant_count += 1)) ;;
    *) complete STOP_UNKNOWN_STATE "managed-target-drift-${targets[index]##*/}" "$EXIT_UNKNOWN_STATE" NONE ;;
  esac
done
if (( missing_count > 0 && compliant_count > 0 )); then
  complete STOP_UNKNOWN_STATE partial-containerd-installation "$EXIT_UNKNOWN_STATE" NONE
fi
if (( compliant_count != ${#targets[@]} )) && [[ -e "$socket_target" || -L "$socket_target" ]]; then
  complete STOP_UNKNOWN_STATE orphan-containerd-socket "$EXIT_UNKNOWN_STATE" NONE
fi
unit_state=$(unit_contract_state "$unit_target")
if (( compliant_count != ${#targets[@]} )) && [[ "$unit_state" != MISSING ]]; then
  complete STOP_UNKNOWN_STATE partial-containerd-unit-state "$EXIT_UNKNOWN_STATE" NONE
fi
data_root_result=0
data_root_safe "$data_root" || data_root_result=$?
if (( data_root_result == 2 || (data_root_result == 1 && compliant_count != ${#targets[@]}) )); then
  complete STOP_UNKNOWN_STATE containerd-data-root-unsafe "$EXIT_UNKNOWN_STATE" NONE
fi

service_enabled=false
service_active=false
systemctl is-enabled containerd.service >/dev/null 2>&1 && service_enabled=true
systemctl is-active containerd.service >/dev/null 2>&1 && service_active=true
if (( compliant_count == ${#targets[@]} )); then
  [[ "$service_enabled" == true && "$service_active" == true ]] || complete STOP_UNKNOWN_STATE containerd-service-state-drift "$EXIT_UNKNOWN_STATE" NONE
  service_contract_compliant "$unit_target" "$socket_target" "$data_root" || complete STOP_UNKNOWN_STATE containerd-service-contract-drift "$EXIT_UNKNOWN_STATE" NONE
  verify_health "$containerd_target" "$runc_target" "$ctr_target" "$crictl_target" || complete STOP_VERIFY_FAILED containerd-health-verification-failed "$EXIT_VERIFY_FAILED" NONE
  complete ALREADY_COMPLIANT containerd-ready 0 40-install-kubernetes
fi
[[ "$service_enabled" == false && "$service_active" == false ]] || complete STOP_UNKNOWN_STATE partial-containerd-service-state "$EXIT_UNKNOWN_STATE" NONE

# MODE 由公共 parse_mode helper 赋值。
# shellcheck disable=SC2153
if [[ "$MODE" == CHECK ]]; then
  complete PASS_CONTAINERD_CHECK apply-required 0 30-install-containerd--apply
fi

evidence_dir=$(host_path /root/dev-infra-evidence)
open_evidence 10-containerd "$evidence_dir" || complete STOP_EVIDENCE evidence-open-failed "$EXIT_UNKNOWN_STATE" NONE
for directory in "${missing_directories[@]-}"; do
  [[ -n "$directory" ]] || continue
  [[ "$(directory_state "${directory%/*}")" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE target-directory-parent-raced "$EXIT_UNKNOWN_STATE" NONE
  install -d -m 0755 "$directory" || complete STOP_APPLY_FAILED target-directory-create-failed "$EXIT_APPLY_FAILED" NONE
  [[ "$(directory_state "$directory")" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE target-directory-post-create-drift "$EXIT_UNKNOWN_STATE" NONE
done

[[ "$(directory_state "$(host_path /usr/local/bin)")" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE containerd-extract-parent-raced "$EXIT_UNKNOWN_STATE" NONE
bin_parent=$(host_path /usr/local/bin)
containerd_extract=$(mktemp -d "${bin_parent}/.containerd.extract.XXXXXX") || complete STOP_APPLY_FAILED containerd-extract-create-failed "$EXIT_APPLY_FAILED" NONE
private_extract_directory "$containerd_extract" "$bin_parent" || complete STOP_UNKNOWN_STATE containerd-extract-state-raced "$EXIT_UNKNOWN_STATE" NONE
[[ "$(directory_state "$bin_parent")" == COMPLIANT ]] || complete STOP_UNKNOWN_STATE crictl-extract-parent-raced "$EXIT_UNKNOWN_STATE" NONE
crictl_extract=$(mktemp -d "${bin_parent}/.crictl.extract.XXXXXX") || { rm -r -- "$containerd_extract"; complete STOP_APPLY_FAILED crictl-extract-create-failed "$EXIT_APPLY_FAILED" NONE; }
private_extract_directory "$crictl_extract" "$bin_parent" || complete STOP_UNKNOWN_STATE crictl-extract-state-raced "$EXIT_UNKNOWN_STATE" NONE
private_extract_directory "$containerd_extract" "$bin_parent" || complete STOP_UNKNOWN_STATE containerd-extract-pre-tar-raced "$EXIT_UNKNOWN_STATE" NONE
if ! tar -xzf "$containerd_artifact" -C "$containerd_extract" -- bin/containerd bin/ctr bin/containerd-shim-runc-v2; then
  rm -r -- "$containerd_extract" "$crictl_extract"
  complete STOP_ARCHIVE_UNSAFE containerd-extract-failed "$EXIT_SUPPLY_CHAIN" NONE
fi
private_extract_directory "$crictl_extract" "$bin_parent" || complete STOP_UNKNOWN_STATE crictl-extract-pre-tar-raced "$EXIT_UNKNOWN_STATE" NONE
if ! tar -xzf "$crictl_artifact" -C "$crictl_extract" -- crictl; then
  rm -r -- "$containerd_extract" "$crictl_extract"
  complete STOP_ARCHIVE_UNSAFE crictl-extract-failed "$EXIT_SUPPLY_CHAIN" NONE
fi

declare -a sources=(
  "$containerd_extract/bin/containerd" "$containerd_extract/bin/ctr"
  "$containerd_extract/bin/containerd-shim-runc-v2" "$runc_artifact"
  "$crictl_extract/crictl" "$config_source" "$unit_source"
)
for index in "${!sources[@]}"; do
  source_path=${sources[index]}
  [[ -f "$source_path" && ! -L "$source_path" ]] || { rm -r -- "$containerd_extract" "$crictl_extract"; complete STOP_ARCHIVE_UNSAFE extracted-member-unsafe "$EXIT_SUPPLY_CHAIN" NONE; }
  if (( index < 5 )); then
    [[ -x "$source_path" || "$source_path" == "$runc_artifact" ]] || { rm -r -- "$containerd_extract" "$crictl_extract"; complete STOP_ARCHIVE_UNSAFE extracted-member-not-executable "$EXIT_SUPPLY_CHAIN" NONE; }
  fi
  case "$source_path" in
    "$containerd_extract"/*) private_extract_directory "$containerd_extract" "$bin_parent" || complete STOP_UNKNOWN_STATE containerd-extract-pre-publish-raced "$EXIT_UNKNOWN_STATE" NONE ;;
    "$crictl_extract"/*) private_extract_directory "$crictl_extract" "$bin_parent" || complete STOP_UNKNOWN_STATE crictl-extract-pre-publish-raced "$EXIT_UNKNOWN_STATE" NONE ;;
  esac
  publish_result=0
  atomic_publish "$source_path" "${targets[index]}" "${target_modes[index]}" || publish_result=$?
  if (( publish_result != 0 )); then
    rm -r -- "$containerd_extract" "$crictl_extract"
    if (( publish_result == EXIT_UNKNOWN_STATE )); then
      complete STOP_UNKNOWN_STATE "target-appeared-${targets[index]##*/}" "$EXIT_UNKNOWN_STATE" NONE
    fi
    complete STOP_APPLY_FAILED "target-publish-failed-${targets[index]##*/}" "$EXIT_APPLY_FAILED" NONE
  fi
  [[ "$(target_file_state "${targets[index]}" "${target_digests[index]}" "${target_modes[index]}")" == COMPLIANT ]] || { rm -r -- "$containerd_extract" "$crictl_extract"; complete STOP_UNKNOWN_STATE "target-post-publish-drift-${targets[index]##*/}" "$EXIT_UNKNOWN_STATE" NONE; }
done
rm -r -- "$containerd_extract" "$crictl_extract"

systemctl daemon-reload >/dev/null 2>&1 || complete STOP_APPLY_FAILED systemd-daemon-reload-failed "$EXIT_APPLY_FAILED" NONE
systemctl enable containerd.service >/dev/null 2>&1 || complete STOP_APPLY_FAILED containerd-enable-failed "$EXIT_APPLY_FAILED" NONE
systemctl start containerd.service >/dev/null 2>&1 || complete STOP_APPLY_FAILED containerd-start-failed "$EXIT_APPLY_FAILED" NONE
systemctl is-enabled containerd.service >/dev/null 2>&1 || complete STOP_VERIFY_FAILED containerd-not-enabled "$EXIT_VERIFY_FAILED" NONE
systemctl is-active containerd.service >/dev/null 2>&1 || complete STOP_VERIFY_FAILED containerd-not-active "$EXIT_VERIFY_FAILED" NONE
service_contract_compliant "$unit_target" "$socket_target" "$data_root" || complete STOP_VERIFY_FAILED containerd-service-contract-verification-failed "$EXIT_VERIFY_FAILED" NONE
verify_health "$containerd_target" "$runc_target" "$ctr_target" "$crictl_target" || complete STOP_VERIFY_FAILED containerd-health-verification-failed "$EXIT_VERIFY_FAILED" NONE

log_evidence ARTIFACT_SET="$ARTIFACT_SET"
log_evidence CONTAINERD_VERSION=2.3.1
log_evidence RUNC_VERSION=1.3.6
log_evidence CRICTL_VERSION=1.36.0
log_evidence CRI_RUNTIME_READY=true
log_evidence SNAPSHOTTER=overlayfs
log_evidence RUNTIME_NAME=runc
log_evidence RUNTIME_TYPE=io.containerd.runc.v2
log_evidence SYSTEMD_CGROUP=true
log_evidence SERVICE_ACTIVE=active
log_evidence SERVICE_ENABLED=enabled
log_evidence CRI_SOCKET=ready
complete PASS_CONTAINERD_INSTALLED containerd-ready 0 40-install-kubernetes
