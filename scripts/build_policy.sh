#!/usr/bin/env bash
set -ex

CDIR=$(dirname $(readlink -f "$0"))
RDIR=$(readlink -f "${CDIR}/../../../../")

{
  binary_dir="${RDIR}/out/ohos-arm-release/clang_x64/security/selinux/"
  sepolicy_dir=$(readlink -f "${CDIR}/../sepolicy")

  for product in 3516
  do
    command "${binary_dir}/checkpolicy" \
      "${sepolicy_dir}/sepolicy.default.${product}.conf" \
      -M -C -c 30 \
      -o "${sepolicy_dir}/sepolicy.${product}.cil"

    command "${binary_dir}/secilc" \
      "${sepolicy_dir}/sepolicy.${product}.cil" \
      -m -M true -G -c 30 -N \
      -f /dev/null \
      -o "${sepolicy_dir}/policy.${product}.31"
  done

  mv "${sepolicy_dir}/policy."{${product},}".31"
}

