#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "${script_dir}/../.." && pwd -P)
# shellcheck disable=SC1091
source "${script_dir}/lib/common.sh"
# shellcheck disable=SC1091
source "${script_dir}/lib/archive.sh"

readonly ARTIFACT_SET=pcs-2026-08-10.1
readonly MINIMUM_AVAILABLE_KIB=1048576
readonly APPROVED_RECORD_COUNT=6
# PHASE 由公共 evidence helper 间接读取。
# shellcheck disable=SC2034
readonly PHASE=stage-artifacts

is_official_url() {
  local url=$1
  local host

  if [[ ! "$url" =~ ^https://([^/:?#]+)(/[^?#]*)?$ ]]; then
    return 1
  fi
  host=${BASH_REMATCH[1]}
  case "$host" in
    github.com|get.helm.sh|helm.cilium.io)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

artifact_basename() {
  local url=$1
  local path=${url#https://*/}
  local base=${path##*/}
  [[ -n "$base" && "$base" != . && "$base" != .. && "$base" != *$'\n'* ]] || return 1
  printf '%s\n' "$base"
}

artifact_state() {
  local target=$1
  local expected_digest=$2
  local actual_digest

  if [[ ! -e "$target" && ! -L "$target" ]]; then
    printf 'MISSING\n'
    return 0
  fi
  if [[ -L "$target" || ! -f "$target" ]]; then
    printf 'DRIFT\n'
    return 0
  fi
  actual_digest=$(sha256_file "$target") || return "$?"
  if [[ "$actual_digest" == "$expected_digest" ]]; then
    printf 'COMPLIANT\n'
  else
    printf 'DRIFT\n'
  fi
}

private_directory() {
  local directory=$1
  local mode

  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  if mode=$(stat -f '%Lp' "$directory" 2>/dev/null); then
    :
  else
    mode=$(stat -c '%a' "$directory" 2>/dev/null) || return 1
  fi
  [[ "$mode" =~ ^0?[0-7]{3}$ ]] || return 1
  [[ "$mode" == 700 || "$mode" == 0700 ]]
}

parse_mode "$@" || exit "$?"

for required_command in curl df grep mktemp mv rm stat tar; do
  require_command "$required_command" || complete STOP_PRECONDITION "missing-command-${required_command}" "$EXIT_PRECONDITION"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  complete STOP_PRECONDITION missing-command-sha256 "$EXIT_PRECONDITION"
fi
require_root || complete STOP_PRECONDITION not-root "$EXIT_PRECONDITION"

lock_file=${BOOTSTRAP_TEST_LOCK_FILE:-"${repo_root}/bootstrap/artifacts.lock.tsv"}
[[ -f "$lock_file" && ! -L "$lock_file" ]] || complete STOP_SUPPLY_CHAIN_MISMATCH lock-file-missing-or-unsafe "$EXIT_SUPPLY_CHAIN"

artifact_root=$(host_path /root/dev-infra-artifacts)
artifact_dir="${artifact_root}/${ARTIFACT_SET}"
artifact_parent=$(dirname "$artifact_root")
[[ -d "$artifact_parent" && ! -L "$artifact_parent" ]] || complete STOP_UNKNOWN_STATE artifact-parent-missing-or-unsafe "$EXIT_UNKNOWN_STATE"

available_kib=$(df -Pk "$artifact_parent" 2>/dev/null | awk 'NR == 2 {print $4}') || complete STOP_PRECONDITION disk-space-unreadable "$EXIT_PRECONDITION"
[[ "$available_kib" =~ ^[0-9]+$ ]] || complete STOP_PRECONDITION disk-space-invalid "$EXIT_PRECONDITION"
(( available_kib >= MINIMUM_AVAILABLE_KIB )) || complete STOP_PRECONDITION disk-space-below-1-gib "$EXIT_PRECONDITION"

declare -a names=() urls=() digests=() basenames=()
while IFS=$'\t' read -r name version url digest target extra; do
  [[ -z "$name" && -z "$version" && -z "$url" && -z "$digest" && -z "$target" && -z "$extra" ]] && continue
  [[ -n "$name" && -n "$version" && -n "$target" && -z "$extra" ]] || complete STOP_SUPPLY_CHAIN_MISMATCH lock-record-invalid "$EXIT_SUPPLY_CHAIN"
  expected_record=$(approved_record "$name") || complete STOP_SUPPLY_CHAIN_MISMATCH lock-name-unapproved "$EXIT_SUPPLY_CHAIN"
  if array_contains "$name" "${names[@]-}"; then
    complete STOP_SUPPLY_CHAIN_MISMATCH lock-name-duplicate "$EXIT_SUPPLY_CHAIN"
  fi
  is_official_url "$url" || complete STOP_SUPPLY_CHAIN_MISMATCH url-not-official-https "$EXIT_SUPPLY_CHAIN"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || complete STOP_SUPPLY_CHAIN_MISMATCH lock-digest-invalid "$EXIT_SUPPLY_CHAIN"
  base=$(artifact_basename "$url") || complete STOP_SUPPLY_CHAIN_MISMATCH url-basename-invalid "$EXIT_SUPPLY_CHAIN"
  if array_contains "$base" "${basenames[@]-}"; then
    complete STOP_SUPPLY_CHAIN_MISMATCH lock-basename-duplicate "$EXIT_SUPPLY_CHAIN"
  fi
  IFS=$'\t' read -r expected_version expected_url expected_digest expected_target <<<"$expected_record"
  [[ "$version" == "$expected_version" && "$url" == "$expected_url" && "$digest" == "$expected_digest" && "$target" == "$expected_target" ]] || complete STOP_SUPPLY_CHAIN_MISMATCH lock-schema-drift "$EXIT_SUPPLY_CHAIN"
  names+=("$name")
  urls+=("$url")
  digests+=("$digest")
  basenames+=("$base")
done <"$lock_file"

(( ${#names[@]} == APPROVED_RECORD_COUNT )) || complete STOP_SUPPLY_CHAIN_MISMATCH lock-record-count-invalid "$EXIT_SUPPLY_CHAIN"

if [[ -e "$artifact_root" || -L "$artifact_root" ]]; then
  private_directory "$artifact_root" || complete STOP_UNKNOWN_STATE artifact-root-unsafe "$EXIT_UNKNOWN_STATE"
fi
if [[ -e "$artifact_dir" || -L "$artifact_dir" ]]; then
  private_directory "$artifact_dir" || complete STOP_UNKNOWN_STATE artifact-directory-unsafe "$EXIT_UNKNOWN_STATE"
fi

all_compliant=true
for index in "${!names[@]}"; do
  target_path="${artifact_dir}/${basenames[index]}"
  state=$(artifact_state "$target_path" "${digests[index]}") || complete STOP_UNKNOWN_STATE artifact-state-unreadable "$EXIT_UNKNOWN_STATE"
  case "$state" in
    COMPLIANT)
      ;;
    MISSING)
      all_compliant=false
      ;;
    DRIFT)
      complete STOP_SUPPLY_CHAIN_MISMATCH "artifact-digest-drift-${basenames[index]}" "$EXIT_SUPPLY_CHAIN"
      ;;
    *)
      complete STOP_UNKNOWN_STATE artifact-state-invalid "$EXIT_UNKNOWN_STATE"
      ;;
  esac
done

if [[ -d "$artifact_dir" && ! -L "$artifact_dir" ]]; then
  shopt -s dotglob nullglob
  for entry in "$artifact_dir"/*; do
    entry_name=${entry##*/}
    array_contains "$entry_name" "${basenames[@]}" || complete STOP_UNKNOWN_STATE "artifact-entry-unapproved-${entry_name}" "$EXIT_UNKNOWN_STATE"
  done
fi

if [[ "$all_compliant" == true ]]; then
  complete ALREADY_COMPLIANT artifacts-ready 0 \
    '20-prepare-kernel.sh --check'
fi

# parse_mode 在公共库中赋值。
# shellcheck disable=SC2153
if [[ "$MODE" == CHECK ]]; then
  complete PASS_ARTIFACTS_CHECK apply-required 0 \
    '10-stage-artifacts.sh --apply'
fi

if [[ -e "$artifact_root" || -L "$artifact_root" ]]; then
  private_directory "$artifact_root" || complete STOP_UNKNOWN_STATE artifact-root-unsafe "$EXIT_UNKNOWN_STATE"
else
  mkdir -p -- "$artifact_root" || complete STOP_APPLY_FAILED artifact-root-create-failed "$EXIT_APPLY_FAILED"
  chmod 700 "$artifact_root" || complete STOP_APPLY_FAILED artifact-root-mode-failed "$EXIT_APPLY_FAILED"
fi
if [[ -e "$artifact_dir" || -L "$artifact_dir" ]]; then
  private_directory "$artifact_dir" || complete STOP_UNKNOWN_STATE artifact-directory-unsafe "$EXIT_UNKNOWN_STATE"
else
  mkdir -- "$artifact_dir" || complete STOP_APPLY_FAILED artifact-directory-create-failed "$EXIT_APPLY_FAILED"
  chmod 700 "$artifact_dir" || complete STOP_APPLY_FAILED artifact-directory-mode-failed "$EXIT_APPLY_FAILED"
fi

for index in "${!names[@]}"; do
  target_path="${artifact_dir}/${basenames[index]}"
  state=$(artifact_state "$target_path" "${digests[index]}") || complete STOP_UNKNOWN_STATE artifact-state-unreadable "$EXIT_UNKNOWN_STATE"
  [[ "$state" == MISSING ]] || complete STOP_UNKNOWN_STATE "artifact-state-changed-${basenames[index]}" "$EXIT_UNKNOWN_STATE"

  temporary=$(mktemp "${artifact_dir}/.${basenames[index]}.tmp.XXXXXX") || complete STOP_APPLY_FAILED artifact-temp-create-failed "$EXIT_APPLY_FAILED"
  if ! curl --fail --location --proto '=https' --tlsv1.2 --output "$temporary" "${urls[index]}"; then
    rm -f -- "$temporary"
    complete STOP_APPLY_FAILED "download-failed-${basenames[index]}" "$EXIT_APPLY_FAILED"
  fi
  actual_digest=$(sha256_file "$temporary") || {
    rm -f -- "$temporary"
    complete STOP_APPLY_FAILED "download-digest-unreadable-${basenames[index]}" "$EXIT_APPLY_FAILED"
  }
  if [[ "$actual_digest" != "${digests[index]}" ]]; then
    rm -f -- "$temporary"
    complete STOP_SUPPLY_CHAIN_MISMATCH "download-digest-mismatch-${basenames[index]}" "$EXIT_SUPPLY_CHAIN"
  fi
  case "${names[index]}" in
    containerd|crictl|helm)
      if ! validate_archive "${names[index]}" "$temporary"; then
        rm -f -- "$temporary"
        complete STOP_ARCHIVE_UNSAFE "archive-validation-failed-${basenames[index]}" "$EXIT_SUPPLY_CHAIN"
      fi
      ;;
  esac
  if ! mv -n "$temporary" "$target_path" || [[ -e "$temporary" || -L "$temporary" ]]; then
    rm -f -- "$temporary"
    complete STOP_UNKNOWN_STATE "artifact-target-appeared-${basenames[index]}" "$EXIT_UNKNOWN_STATE"
  fi
  rm -f -- "$temporary"
  size=$(wc -c <"$target_path") || complete STOP_VERIFY_FAILED "artifact-size-unreadable-${basenames[index]}" "$EXIT_VERIFY_FAILED"
  printf 'URL=%s\nFILE=%s\nSIZE=%s\nARTIFACT_SHA256=%s\n' \
    "${urls[index]}" "${basenames[index]}" "$size" "$actual_digest"
done

complete PASS_ARTIFACTS_STAGED artifacts-staged 0 \
  '20-prepare-kernel.sh --check'
