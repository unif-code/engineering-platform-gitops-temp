#!/bin/bash -p
set -Eeuo pipefail
export LC_ALL=C
umask 077
IFS=$' \t\n'

readonly -a STAGES=(00 10 20 30 40 50 60 90)
readonly -a MUTATING_STAGES=(10 20 30 40 50 60)

declare -a SUMMARY_STAGE=()
declare -a SUMMARY_RESULT=()
declare -a SUMMARY_EVIDENCE=()
declare -a SUMMARY_SHA256=()
SUMMARY_COUNT=0
git_commit=NONE
test_mode=false
stage_index=0
stage_started=0
progress_heartbeat_pid=
readonly PROGRESS_HEARTBEAT_DEFAULT=15
heartbeat_seconds=$PROGRESS_HEARTBEAT_DEFAULT

case "$#:${1:-}" in
  1:--check) MODE=CHECK ;;
  1:--apply) MODE=APPLY ;;
  *)
    printf 'RESULT=STOP_MODE\nREASON=expected-check-or-apply\n' >&2
    exit 10
    ;;
esac
readonly MODE

script_source=${BASH_SOURCE[0]}
case "$script_source" in
  /*) ;;
  *) script_source="$PWD/$script_source" ;;
esac
script_dir=$(cd "${script_source%/*}" && pwd -P)
repo_root=$(cd "${script_dir}/../.." && pwd -P)

finish_orchestrator() {
  local result=$1 reason=$2 code=$3 next_stage=$4
  local index summary_stage

  for ((index = 0; index < SUMMARY_COUNT; index++)); do
    summary_stage=${SUMMARY_STAGE[index]}
    printf 'STAGE_%s_RESULT=%s\n' \
      "$summary_stage" "${SUMMARY_RESULT[index]}"
    printf 'STAGE_%s_EVIDENCE=%s\n' \
      "$summary_stage" "${SUMMARY_EVIDENCE[index]}"
    printf 'STAGE_%s_SHA256=%s\n' \
      "$summary_stage" "${SUMMARY_SHA256[index]}"
  done
  printf 'PHASE=bootstrap-all\nMODE=%s\nRESULT=%s\nREASON=%s\n' \
    "$MODE" "$result" "$reason"
  printf 'GIT_COMMIT=%s\nNEXT_STAGE=%s\nEXIT_CODE=%s\n' \
    "$git_commit" "$next_stage" "$code"
  exit "$code"
}

stop_orchestrator() {
  finish_orchestrator STOP_ORCHESTRATOR "$1" "$2" NONE
}

path_owner_uid() {
  local owner

  owner=$(/usr/bin/stat -f '%u' "$1" 2>/dev/null) || owner=
  if [[ "$owner" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$owner"
    return 0
  fi
  owner=$(/usr/bin/stat -c '%u' "$1" 2>/dev/null) || return 1
  [[ "$owner" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$owner"
}

path_mode() {
  local mode

  mode=$(/usr/bin/stat -f '%Lp' "$1" 2>/dev/null) || mode=
  if [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
    printf '%s\n' "$mode"
    return 0
  fi
  mode=$(/usr/bin/stat -c '%a' "$1" 2>/dev/null) || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  printf '%s\n' "$mode"
}

lock_parent_mode() {
  local mode

  mode=$(/usr/bin/stat -f '%Mp%Lp' "$1" 2>/dev/null) || mode=
  if [[ "$mode" =~ ^[0-7]{4}$ ]]; then
    printf '%s\n' "$mode"
    return 0
  fi
  /usr/bin/stat -c '%a' "$1" 2>/dev/null
}

safe_owned_directory() {
  local directory=$1 expected_uid=$2 canonical mode

  [[ "$directory" == /* && "$directory" != / &&
     -d "$directory" && ! -L "$directory" ]] || return 1
  canonical=$(cd "$directory" 2>/dev/null && pwd -P) || return 1
  [[ "$canonical" == "$directory" ]] || return 1
  [[ "$(path_owner_uid "$directory")" == "$expected_uid" ]] || return 1
  mode=$(path_mode "$directory") || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 0022) == 0 ))
}

safe_owned_file() {
  local file=$1 expected_uid=$2 mode

  [[ "$file" == /* && -f "$file" && ! -L "$file" ]] || return 1
  [[ "$(path_owner_uid "$file")" == "$expected_uid" ]] || return 1
  mode=$(path_mode "$file") || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 0022) == 0 ))
}

safe_directory_ancestry() {
  local directory=$1 expected_uid=$2 canonical owner mode parent

  [[ "$directory" == /* && -d "$directory" && ! -L "$directory" ]] ||
    return 1
  canonical=$(cd "$directory" 2>/dev/null && pwd -P) || return 1
  [[ "$canonical" == "$directory" ]] || return 1
  while :; do
    [[ -d "$directory" && ! -L "$directory" ]] || return 1
    owner=$(path_owner_uid "$directory") || return 1
    [[ "$owner" == 0 || "$owner" == "$expected_uid" ]] || return 1
    mode=$(path_mode "$directory") || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    if (( (8#$mode & 0022) != 0 )); then
      [[ "$owner" == 0 ]] && (( (8#$mode & 01000) != 0 )) || return 1
    fi
    [[ "$directory" != / ]] || break
    parent=${directory%/*}
    [[ -n "$parent" ]] || parent=/
    directory=$parent
  done
}

safe_lock_parent() {
  local directory=$1 expected_uid=$2 canonical mode parent

  [[ "$directory" == /* && "$directory" != / &&
     -d "$directory" && ! -L "$directory" ]] || return 1
  canonical=$(cd "$directory" 2>/dev/null && pwd -P) || return 1
  [[ "$canonical" == "$directory" ]] || return 1
  [[ "$(path_owner_uid "$directory")" == "$expected_uid" ]] || return 1
  mode=$(lock_parent_mode "$directory") || return 1
  [[ "$mode" == 1777 ]] || return 1
  parent=${directory%/*}
  [[ -n "$parent" ]] || parent=/
  safe_directory_ancestry "$parent" "$expected_uid"
}

acquire_lock() {
  local expected_uid=$1 lock_parent snapshot_dir snapshot_file create_rc

  lock_parent=${lock_file%/*}
  safe_lock_parent "$lock_parent" "$expected_uid" ||
    stop_orchestrator unsafe-lock-parent 30

  if [[ ! -e "$lock_file" && ! -L "$lock_file" ]]; then
    set +e
    (set -o noclobber; : >"$lock_file") 2>/dev/null
    create_rc=$?
    set -e
    if (( create_rc != 0 )) &&
       [[ ! -e "$lock_file" && ! -L "$lock_file" ]]; then
      stop_orchestrator lock-create-failed 30
    fi
  fi
  safe_owned_file "$lock_file" "$expected_uid" ||
    stop_orchestrator unsafe-lock-target 30

  snapshot_dir=$(
    /usr/bin/mktemp -d \
      "${lock_parent}/.engineering-platform-bootstrap-lock.XXXXXX"
  ) || stop_orchestrator lock-snapshot-create-failed 30
  if ! safe_owned_directory "$snapshot_dir" "$expected_uid"; then
    /bin/rmdir -- "$snapshot_dir" 2>/dev/null || true
    stop_orchestrator unsafe-lock-snapshot 30
  fi
  snapshot_file=${snapshot_dir}/lock
  if ! /bin/ln -- "$lock_file" "$snapshot_file" 2>/dev/null ||
     ! safe_owned_file "$snapshot_file" "$expected_uid"; then
    /bin/rm -f -- "$snapshot_file" 2>/dev/null || true
    /bin/rmdir -- "$snapshot_dir" 2>/dev/null || true
    stop_orchestrator unsafe-lock-target 30
  fi
  exec 9<>"$snapshot_file"
  /bin/rm -- "$snapshot_file" || stop_orchestrator lock-snapshot-cleanup-failed 30
  /bin/rmdir -- "$snapshot_dir" || stop_orchestrator lock-snapshot-cleanup-failed 30
  "$flock_binary" -n 9 || stop_orchestrator concurrent-run 30
}

if [[ "${BOOTSTRAP_ORCHESTRATOR_TEST_MODE:-}" == 1 ]]; then
  test_mode=true
  git_binary=git
  [[ "$EUID" -ne 0 ]] || {
    printf 'RESULT=STOP_TEST_MODE\nREASON=test-mode-is-for-unprivileged-tests-only\n' >&2
    exit 10
  }
  for test_override in "${!BOOTSTRAP_ORCHESTRATOR_TEST_@}"; do
    case "$test_override" in
      BOOTSTRAP_ORCHESTRATOR_TEST_MODE|\
      BOOTSTRAP_ORCHESTRATOR_TEST_STAGE_DIR|\
      BOOTSTRAP_ORCHESTRATOR_TEST_HEARTBEAT_SECONDS|\
      BOOTSTRAP_ORCHESTRATOR_TEST_LOCK_FILE) ;;
      *) stop_orchestrator test-override-unapproved 10 ;;
    esac
  done
  stage_dir=${BOOTSTRAP_ORCHESTRATOR_TEST_STAGE_DIR:-}
  lock_file=${BOOTSTRAP_ORCHESTRATOR_TEST_LOCK_FILE:-}
  state_dir=${ORCHESTRATOR_STATE_DIR:-}
  lock_parent=${lock_file%/*}
  if ! safe_directory_ancestry "$repo_root" "$EUID"; then
    stop_orchestrator unsafe-repository-path 10
  fi
  if ! safe_directory_ancestry "$stage_dir" "$EUID" ||
     ! safe_owned_directory "$state_dir" "$EUID" ||
     ! safe_lock_parent "$lock_parent" "$EUID"; then
    stop_orchestrator unsafe-test-path 10
  fi
  if [[ -e "$lock_file" || -L "$lock_file" ]]; then
    safe_owned_file "$lock_file" "$EUID" ||
      stop_orchestrator unsafe-lock-target 10
  fi
  flock_binary=flock
  if [[ -n "${BOOTSTRAP_ORCHESTRATOR_TEST_HEARTBEAT_SECONDS:-}" ]]; then
    # 值进了 sleep 与算术，必须先钉死形状，不能直接展开。
    [[ "$BOOTSTRAP_ORCHESTRATOR_TEST_HEARTBEAT_SECONDS" =~ ^[1-9][0-9]{0,3}$ ]] ||
      stop_orchestrator invalid-test-heartbeat 10
    heartbeat_seconds=$BOOTSTRAP_ORCHESTRATOR_TEST_HEARTBEAT_SECONDS
  fi
else
  for test_override in "${!BOOTSTRAP_ORCHESTRATOR_TEST_@}"; do
    : "$test_override"
    printf 'RESULT=STOP_TEST_OVERRIDE\nREASON=test-override-in-production\n' >&2
    exit 10
  done
  for git_override in "${!GIT_@}"; do
    : "$git_override"
    printf 'RESULT=STOP_PRECONDITION\nREASON=untrusted-git-environment\n' >&2
    exit 10
  done
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin
  git_binary=/usr/bin/git
  flock_binary=/usr/bin/flock
  stage_dir=$script_dir
  lock_file=/run/lock/engineering-platform-bootstrap.lock
  [[ "$MODE" != APPLY || "$EUID" -eq 0 ]] ||
    stop_orchestrator not-root 10
  safe_directory_ancestry "$repo_root" 0 ||
    stop_orchestrator unsafe-repository-path 30
  safe_directory_ancestry "$stage_dir" 0 ||
    stop_orchestrator unsafe-stage-directory 30
fi
readonly stage_dir lock_file git_binary flock_binary

stage_path() {
  case "$1" in
    00) printf '%s/stages/00-preflight/run.sh\n' "$stage_dir" ;;
    10) printf '%s/stages/10-stage-artifacts/run.sh\n' "$stage_dir" ;;
    20) printf '%s/stages/20-prepare-kernel/run.sh\n' "$stage_dir" ;;
    30) printf '%s/stages/30-install-containerd/run.sh\n' "$stage_dir" ;;
    40) printf '%s/stages/40-install-kubernetes/run.sh\n' "$stage_dir" ;;
    50) printf '%s/stages/50-kubeadm-init/run.sh\n' "$stage_dir" ;;
    60) printf '%s/stages/60-install-cilium/run.sh\n' "$stage_dir" ;;
    90) printf '%s/stages/90-verify/run.sh\n' "$stage_dir" ;;
    *) return 30 ;;
  esac
}

check_result_is_complete() {
  case "$1:$2" in
    00:PASS_PREFLIGHT|10:ALREADY_COMPLIANT|20:ALREADY_COMPLIANT|\
    30:ALREADY_COMPLIANT|40:ALREADY_COMPLIANT|50:ALREADY_COMPLIANT|\
    60:ALREADY_COMPLIANT|90:PASS_BOOTSTRAP_VERIFIED) return 0 ;;
    *) return 1 ;;
  esac
}

check_result_requires_apply() {
  case "$1:$2" in
    10:PASS_ARTIFACTS_CHECK|20:PASS_KERNEL_CHECK|\
    30:PASS_CONTAINERD_CHECK|40:PASS_KUBERNETES_CHECK|\
    50:PASS_KUBEADM_CHECK|60:PASS_CILIUM_CHECK) return 0 ;;
    *) return 1 ;;
  esac
}

apply_result_is_success() {
  case "$1:$2" in
    10:PASS_ARTIFACTS_STAGED|20:PASS_KERNEL_PREPARED|\
    30:PASS_CONTAINERD_INSTALLED|40:PASS_KUBERNETES_INSTALLED|\
    50:PASS_KUBEADM_INITIALIZED|60:PASS_CILIUM_INSTALLED|\
    10:ALREADY_COMPLIANT|20:ALREADY_COMPLIANT|30:ALREADY_COMPLIANT|\
    40:ALREADY_COMPLIANT|50:ALREADY_COMPLIANT|60:ALREADY_COMPLIANT) return 0 ;;
    *) return 1 ;;
  esac
}

stage_is_mutating() {
  local expected
  for expected in "${MUTATING_STAGES[@]}"; do
    [[ "$1" != "$expected" ]] || return 0
  done
  return 1
}

# 进度写 stderr。stdout 是逐字节的机器契约（STAGE_*_RESULT / PHASE= / RESULT= …），
# 掺进人看的行会破坏既有断言与下游解析；stderr 则本来就用于诊断。
# 刻意不使用 STAGE_NN_ 前缀：那是摘要字段的命名空间，混用会让
# 「失败的 stage 不得出现摘要行」这类断言失去意义。
report_progress() {
  local stage=$1 operation=$2 phase=$3 result=$4
  if [[ "$phase" == begin ]]; then
    stage_started=$SECONDS
    printf '[%s/%s] stage %s %s ...\n' \
      "$stage_index" "${#STAGES[@]}" "$stage" "$operation" >&2
    return
  fi
  printf '[%s/%s] stage %s %s -> %s (%ss)\n' \
    "$stage_index" "${#STAGES[@]}" "$stage" "$operation" "$result" \
    "$(( SECONDS - stage_started ))" >&2
}

# stage 的输出是被 run_stage 整体捕获后再校验的，运行期间一个字节都不会流出来。
# 装 kubernetes 这类 stage 要跑几分钟，期间终端全静默——运维分不清「在装」还是
# 「卡死」。心跳是唯一能在不破坏「捕获后校验」契约的前提下给出存活信号的办法。
# 每次一整行而不是原地刷新：日志要能 grep，进度条会毁掉这一点。
start_progress_heartbeat() {
  local stage=$1 operation=$2
  (
    elapsed=0
    while :; do
      /bin/sleep "$heartbeat_seconds"
      elapsed=$(( elapsed + heartbeat_seconds ))
      printf '[%s/%s] stage %s %s ... %ss elapsed\n' \
        "$stage_index" "${#STAGES[@]}" "$stage" "$operation" "$elapsed" >&2
    done
  ) &
  progress_heartbeat_pid=$!
}

# kill/wait 对已退出的子进程都会返回非零；这里全部吞掉，心跳的死活不能影响判定。
stop_progress_heartbeat() {
  [[ -n "$progress_heartbeat_pid" ]] || return 0
  kill "$progress_heartbeat_pid" 2>/dev/null || :
  wait "$progress_heartbeat_pid" 2>/dev/null || :
  progress_heartbeat_pid=
}

record_stage_summary() {
  SUMMARY_STAGE[SUMMARY_COUNT]=$1
  SUMMARY_RESULT[SUMMARY_COUNT]=$STAGE_RESULT
  SUMMARY_EVIDENCE[SUMMARY_COUNT]=$STAGE_EVIDENCE
  SUMMARY_SHA256[SUMMARY_COUNT]=$STAGE_SHA256
  SUMMARY_COUNT=$((SUMMARY_COUNT + 1))
}

run_stage() {
  local stage=$1 operation=$2 script captured rc result_count exit_count
  local valid_exit_count evidence_count sha_count expected_uid

  script=$(stage_path "$stage") || return 30
  expected_uid=0
  [[ "$test_mode" != true ]] || expected_uid=$EUID
  if ! safe_owned_file "$script" "$expected_uid" || [[ ! -x "$script" ]]; then
    stop_orchestrator unsafe-stage-file 30
  fi

  set +e
  if [[ "$test_mode" == true ]]; then
    captured=$(/usr/bin/env -u BASH_ENV -u ENV \
      /bin/bash -p "$script" "--${operation}" 2>&1)
  else
    captured=$(/usr/bin/env -u BASH_ENV -u ENV -u ORCHESTRATOR_STATE_DIR \
      /bin/bash -p "$script" "--${operation}" 2>&1)
  fi
  rc=$?
  set -e
  if (( rc != 0 )); then
    printf '%s\n' "$captured"
    return "$rc"
  fi

  result_count=$(printf '%s\n' "$captured" |
    awk -F= '$1=="RESULT" {count++} END {print count+0}')
  exit_count=$(printf '%s\n' "$captured" |
    awk -F= '$1=="EXIT_CODE" {count++} END {print count+0}')
  valid_exit_count=$(printf '%s\n' "$captured" |
    awk '$0=="EXIT_CODE=0" {count++} END {print count+0}')
  evidence_count=$(printf '%s\n' "$captured" |
    awk -F= '$1=="EVIDENCE" {count++} END {print count+0}')
  sha_count=$(printf '%s\n' "$captured" |
    awk -F= '$1=="SHA256" {count++} END {print count+0}')
  if [[ "$result_count" != 1 || "$exit_count" != 1 ||
        "$valid_exit_count" != 1 ||
        "$evidence_count" != 1 || "$sha_count" != 1 ]]; then
    stop_orchestrator invalid-stage-output 30
  fi

  STAGE_RESULT=$(printf '%s\n' "$captured" |
    awk -F= '$1=="RESULT" {print substr($0,8)}')
  STAGE_EVIDENCE=$(printf '%s\n' "$captured" |
    awk -F= '$1=="EVIDENCE" {print substr($0,10)}')
  STAGE_SHA256=$(printf '%s\n' "$captured" |
    awk -F= '$1=="SHA256" {print substr($0,8)}')

  case "$STAGE_EVIDENCE" in
    NONE) ;;
    /*)
      [[ ! "$STAGE_EVIDENCE" =~ [[:cntrl:]] ]] ||
        stop_orchestrator invalid-stage-output 30
      ;;
    *) stop_orchestrator invalid-stage-output 30 ;;
  esac
  [[ "$STAGE_SHA256" == NONE ||
     "$STAGE_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    stop_orchestrator invalid-stage-output 30
}

if [[ "$test_mode" == true ]]; then
  expected_stage_uid=$EUID
else
  expected_stage_uid=0
  safe_owned_directory "$stage_dir" 0 ||
    stop_orchestrator unsafe-stage-directory 30
fi
readonly expected_stage_uid

# 每个 stage 都以 root source lib/*.sh，这些文件与 stage 脚本同属供应链，
# 必须在任何 stage 启动前完成属主与权限校验。目录内的每一个条目都要过门禁：
# dotglob 让点文件无法绕过通配，nullglob 让空目录退化为计数 0 而不是字面量。
library_dir="${stage_dir}/lib"
safe_owned_directory "$library_dir" "$expected_stage_uid" ||
  stop_orchestrator unsafe-library-file 30
library_file_count=0
shopt -s dotglob nullglob
for library_file in "$library_dir"/*; do
  library_file_count=$((library_file_count + 1))
  safe_owned_file "$library_file" "$expected_stage_uid" ||
    stop_orchestrator unsafe-library-file 30
done
shopt -u dotglob nullglob
(( library_file_count > 0 )) || stop_orchestrator unsafe-library-file 30
readonly library_dir

# stage 迁进 stages/<NN-name>/ 后，被 root 执行的东西不再只有一个文件：stages/ 本身、
# 每个 stage 目录，以及目录里的每个条目（run.sh、gates.sh、README.md 及任何新增文件）
# 都在 root 的读写路径上。按 lib/ 门禁的同一原则——覆盖**每个条目**而不只是 *.sh，
# 否则 .hidden.sh 之类的点文件可以绕过。
stages_root="${stage_dir}/stages"
safe_owned_directory "$stages_root" "$expected_stage_uid" ||
  stop_orchestrator unsafe-stage-file 30
readonly stages_root

# check_cidrs.py 由 stage 00 与 50 以 root 执行，逃逸面与被 source 的库同级。
cidr_script="${stage_dir}/check_cidrs.py"
safe_owned_file "$cidr_script" "$expected_stage_uid" ||
  stop_orchestrator unsafe-executed-file 30
readonly cidr_script

for stage in "${STAGES[@]}"; do
  stage_script=$(stage_path "$stage") || stop_orchestrator invalid-stage-map 30
  stage_home=${stage_script%/*}
  safe_owned_directory "$stage_home" "$expected_stage_uid" ||
    stop_orchestrator unsafe-stage-file 30
  stage_entry_count=0
  shopt -s dotglob nullglob
  for stage_entry in "$stage_home"/*; do
    stage_entry_count=$((stage_entry_count + 1))
    safe_owned_file "$stage_entry" "$expected_stage_uid" ||
      stop_orchestrator unsafe-stage-file 30
  done
  shopt -u dotglob nullglob
  (( stage_entry_count > 0 )) || stop_orchestrator unsafe-stage-file 30
  [[ -x "$stage_script" ]] || stop_orchestrator unsafe-stage-file 30
done

git_commit=$("$git_binary" -C "$repo_root" rev-parse HEAD 2>/dev/null) ||
  stop_orchestrator git-commit-unreadable 30
[[ "$git_commit" =~ ^[0-9a-f]{40}$ ]] ||
  stop_orchestrator git-commit-invalid 30
readonly git_commit

if [[ "$MODE" == APPLY ]]; then
  [[ "$test_mode" == true || "$EUID" -eq 0 ]] ||
    stop_orchestrator not-root 10
  [[ "$("$git_binary" -C "$repo_root" branch --show-current 2>/dev/null)" == main ]] ||
    stop_orchestrator current-branch-not-main 30
  if ! worktree_status=$(
    "$git_binary" -C "$repo_root" status --porcelain=v1 --untracked-files=all 2>/dev/null
  ); then
    stop_orchestrator worktree-state-unreadable 30
  fi
  [[ -z "$worktree_status" ]] ||
    stop_orchestrator worktree-not-clean 30

  lock_uid=0
  [[ "$test_mode" != true ]] || lock_uid=$EUID
  acquire_lock "$lock_uid"
fi

# run_stage 内的 stop_orchestrator 会直接 exit，信号也可能在任意点打断；
# 心跳进程不能因此变成孤儿。
trap stop_progress_heartbeat EXIT

for stage in "${STAGES[@]}"; do
  stage_index=$((stage_index + 1))
  report_progress "$stage" check begin ''
  rc=0
  start_progress_heartbeat "$stage" check
  run_stage "$stage" check || rc=$?
  stop_progress_heartbeat
  (( rc == 0 )) ||
    finish_orchestrator STOP_STAGE "stage-${stage}-check-stopped" "$rc" "$stage"

  if check_result_is_complete "$stage" "$STAGE_RESULT"; then
    report_progress "$stage" check end "$STAGE_RESULT"
    record_stage_summary "$stage"
    continue
  fi
  if [[ "$MODE" == CHECK ]] &&
     check_result_requires_apply "$stage" "$STAGE_RESULT"; then
    report_progress "$stage" check end "$STAGE_RESULT"
    record_stage_summary "$stage"
    finish_orchestrator PASS_BOOTSTRAP_CHECK apply-required 0 "$stage"
  fi
  if [[ "$MODE" == APPLY ]] &&
     check_result_requires_apply "$stage" "$STAGE_RESULT"; then
    report_progress "$stage" check end "$STAGE_RESULT"
    record_stage_summary "$stage"
    stage_is_mutating "$stage" || stop_orchestrator invalid-stage-result 30
    report_progress "$stage" apply begin ''
    rc=0
    start_progress_heartbeat "$stage" apply
    run_stage "$stage" apply || rc=$?
    stop_progress_heartbeat
    (( rc == 0 )) ||
      finish_orchestrator STOP_STAGE "stage-${stage}-apply-stopped" "$rc" "$stage"
    apply_result_is_success "$stage" "$STAGE_RESULT" ||
      stop_orchestrator invalid-apply-result 30
    report_progress "$stage" apply end "$STAGE_RESULT"
    record_stage_summary "$stage"

    report_progress "$stage" postcheck begin ''
    rc=0
    start_progress_heartbeat "$stage" postcheck
    run_stage "$stage" check || rc=$?
    stop_progress_heartbeat
    (( rc == 0 )) ||
      finish_orchestrator STOP_STAGE "stage-${stage}-postcheck-stopped" "$rc" "$stage"
    [[ "$STAGE_RESULT" == ALREADY_COMPLIANT ]] ||
      stop_orchestrator post-apply-check-not-compliant 30
    report_progress "$stage" postcheck end "$STAGE_RESULT"
    record_stage_summary "$stage"
    continue
  fi
  stop_orchestrator invalid-stage-result 30
done

if [[ "$MODE" == CHECK ]]; then
  finish_orchestrator PASS_BOOTSTRAP_ALL_CHECK \
    bootstrap-check-complete 0 NONE
fi
finish_orchestrator PASS_BOOTSTRAP_ALL bootstrap-complete 0 NONE
