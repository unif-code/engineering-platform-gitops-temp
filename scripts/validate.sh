#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

# 字节码写入用 -B 关掉，不用 PYTHONDONTWRITEBYTECODE：前缀赋值会把变量导出，
# 一路继承进用例派生的 stage 子进程，撞上 stage 60/90 的 ${!PYTHON@} 不可信环境
# 守卫（它排在测试变量守卫之前），本地恒红而 CI 全绿。-B 只作用于本进程。
python3 -B "$repo_root/scripts/run_validation.py" --profile full
"$repo_root/scripts/validate-static.sh"
