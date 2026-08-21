#!/bin/bash
# 重算并原子写入 bootstrap/hosts/<hostname>/pins.sha256；只写这一个文件。
set -Eeuo pipefail
export LC_ALL=C
umask 022

if [[ $# -ne 1 ]]; then
  printf 'usage: %s bootstrap/hosts/<hostname>\n' "${0##*/}" >&2
  exit 2
fi
host_dir=$1
if [[ ! -d "$host_dir" || -L "$host_dir" ]]; then
  printf 'not a host directory: %s\n' "$host_dir" >&2
  exit 2
fi
for name in kubeadm-init.yaml cilium-values.yaml; do
  if [[ ! -f "${host_dir}/${name}" || -L "${host_dir}/${name}" ]]; then
    printf 'missing regular file: %s\n' "${host_dir}/${name}" >&2
    exit 2
  fi
done

digest_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi | awk '{print $1}'
}

# 先落到局部变量：digest_of 失败时由 set -e 中止，避免写入空 digest。
kubeadm_digest=$(digest_of "${host_dir}/kubeadm-init.yaml")
cilium_digest=$(digest_of "${host_dir}/cilium-values.yaml")
temporary=$(mktemp "${host_dir}/.pins.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
{
  printf '%s  kubeadm-init.yaml\n' "$kubeadm_digest"
  printf '%s  cilium-values.yaml\n' "$cilium_digest"
} >"$temporary"
chmod 0644 "$temporary"
mv -f -- "$temporary" "${host_dir}/pins.sha256"
trap - EXIT
cat "${host_dir}/pins.sha256"
