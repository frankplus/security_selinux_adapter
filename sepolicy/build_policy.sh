#!/usr/bin/env bash
set -ex

CDIR=$(dirname $(readlink -f "$0"))
RDIR=$(readlink -f "${CDIR}/../../../")

{
  command "${RDIR}/out/ohos-arm-release/clang_x64/security/selinux/checkpolicy" \
    -M -C -c 30 \
    -o "${RDIR}/third_party/selinux/demo/test.cil" \
    "${RDIR}/third_party/selinux/demo/sepolicy.default.3516.conf"

  command "${RDIR}/out/ohos-arm-release/clang_x64/security/selinux/secilc" \
    -m -M true -G -c 30 -N \
    -f /dev/null \
    -o "${RDIR}/third_party/selinux/demo/policy.31" \
    "${RDIR}/third_party/selinux/demo/test.cil"
}

