#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_KO" >&2
  exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=$1
release='6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k'
expected_hash='e947f91c986e6594b965c7e65871bf8287542198484334945fe461d886a701c7'
kernelsu_commit='b0bc817b4e966aa6aa830834eaf6ef765d821d40'
rmg_commit='6e3223e689688540060ddd97a0927e927bfed207'

: "${KDIR:?KDIR must point to the pinned android16-6.12 DDK tree}"
command -v clang >/dev/null
command -v llvm-strip >/dev/null
command -v readelf >/dev/null
command -v modinfo >/dev/null

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

ksu="$work/KernelSU"
rmg="$work/rmg"
git clone -q https://github.com/tiann/KernelSU.git "$ksu"
git -C "$ksu" checkout -q --detach "$kernelsu_commit"
git clone -q https://github.com/BuSung-dev/Root-My-Galaxy-Payloads.git "$rmg"
git -C "$rmg" checkout -q --detach "$rmg_commit"
git -C "$ksu" apply \
  "$rmg/kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch"
python3 "$repo_root/tools/apply_m3q_kdp_compat.py" \
  "$ksu/kernel/compat/samsung_kdp.c"
git -C "$ksu" diff --check

old=$(cat "$KDIR/include/config/kernel.release")
printf '%s\n' "$release" > "$KDIR/include/config/kernel.release"
sed -i "s|$old|$release|g" "$KDIR/include/generated/utsrelease.h"
test "$(cat "$KDIR/include/config/kernel.release")" = "$release"
grep -Fqx "#define UTS_RELEASE \"$release\"" \
  "$KDIR/include/generated/utsrelease.h"

cd "$ksu/kernel"
make -C "$KDIR" M="$PWD" src="$PWD" clean
rm -f check_symbol
CONFIG_KSU=m \
CONFIG_KSU_SAMSUNG_KDP=y \
CONFIG_KSU_SAMSUNG_RKP=y \
CONFIG_KSU_SAMSUNG_DEFEX=y \
CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y \
CC=clang make -j"$(nproc)"
module="$PWD/kernelsu.ko"

vermagic=$(modinfo -F vermagic "$module")
test "$vermagic" = "$release SMP preempt mod_unload modversions aarch64"
versions_size=$(readelf -SW "$module" | awk '$2 == "__versions" {print $6}')
test "$versions_size" = "000000"
imports="$work/imports.txt"
readelf -Ws "$module" \
  | awk '$7 == "UND" && $8 != "" {print $8}' \
  | sort -u > "$imports"
test "$(wc -l < "$imports")" -eq 214
test -z "$(grep -E \
  '^(stop_machine|aarch64_insn_patch_text|patch_text|__aarch64_insn_write)' \
  "$imports" || true)"
strings -a "$module" | grep -x 'kdp_usecount_sub_and_test' >/dev/null
strings -a "$module" | grep -x 'kdp_usecount_dec_and_test' >/dev/null

symbol_size() {
  readelf -Ws "$module" \
    | awk -v name="$1" '$8 == name {print $3; found=1} END {if (!found) exit 1}'
}
test "$(symbol_size ksu_samsung_kdp_put_cred)" -eq 148
test "$(symbol_size samsung_kdp_put_cred_many)" -eq 188
test "$(symbol_size ksu_samsung_kdp_init)" -eq 272
test "$(symbol_size samsung_kdp_commit_worker)" -eq 488

llvm-strip -d "$module"
actual_hash=$(sha256sum "$module" | awk '{print $1}')
test "$actual_hash" = "$expected_hash"
mkdir -p "$(dirname -- "$out")"
cp "$module" "$out"

printf '%s\n' \
  "KERNELSU_COMMIT=$kernelsu_commit" \
  "RMG_COMMIT=$rmg_commit" \
  "AZHJ_RELEASE=$release" \
  "AZHJ_KSU_SHA256=$actual_hash" \
  "AZHJ_KSU_IMPORTS=214" \
  "AZHJ_KSU_TEXT_PATCH_IMPORTS=0" \
  "AZHJ_KSU_BUILD_GATE=PASS"
