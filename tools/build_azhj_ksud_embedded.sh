#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 EXACT_AZHJ_KO OUTPUT_KSUD" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ko=$(realpath "$1")
out=$(realpath -m "$2")
expected_ko='e947f91c986e6594b965c7e65871bf8287542198484334945fe461d886a701c7'
kernelsu_commit='b0bc817b4e966aa6aa830834eaf6ef765d821d40'
rust_toolchain='1.96.0'
target='aarch64-linux-android'
android_api='26'
expected_ndk_revision='29.0.14206865'

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to Android NDK 29.0.14206865}"
command -v git >/dev/null
command -v rustup >/dev/null
command -v cargo >/dev/null
command -v sha256sum >/dev/null
command -v python3 >/dev/null

source_properties="$ANDROID_NDK_HOME/source.properties"
test -f "$source_properties"
ndk_revision=$(sed -n 's/^Pkg.Revision[[:space:]]*=[[:space:]]*//p' "$source_properties" | head -n1)
echo "AZHJ_KSUD_NDK_REVISION=$ndk_revision"
test "$ndk_revision" = "$expected_ndk_revision"

actual_ko=$(sha256sum "$ko" | awk '{print $1}')
echo "AZHJ_KSUD_EMBED_INPUT_KO_SHA256=$actual_ko"
test "$actual_ko" = "$expected_ko"

if [ -n "${M3Q_KSUD_BUILD_ROOT:-}" ]; then
  work=$(realpath -m "$M3Q_KSUD_BUILD_ROOT")
  rm -rf -- "$work"
  mkdir -p -- "$work"
  cleanup_work=0
else
  work=$(mktemp -d)
  cleanup_work=1
fi
ksu="$work/KernelSU"
cleanup() {
  if [ "$cleanup_work" -eq 1 ]; then
    rm -rf -- "$work"
  fi
}
trap cleanup EXIT HUP INT TERM

git clone -q https://github.com/tiann/KernelSU.git "$ksu"
git -C "$ksu" checkout -q --detach "$kernelsu_commit"
test "$(git -C "$ksu" rev-parse HEAD)" = "$kernelsu_commit"
test -z "$(git -C "$ksu" status --porcelain)"

# Add only the M3Q completion-barrier flag. The patcher verifies the exact
# upstream blob identities and exact replacement cardinalities before editing.
python3 "$script_dir/patch_azhj_ksud_foreground.py" "$ksu"
git -C "$ksu" diff --check
patched_files=$(git -C "$ksu" diff --name-only | sort)
printf '%s\n' "$patched_files"
test "$patched_files" = $'userspace/ksud/src/cli.rs\nuserspace/ksud/src/late_load.rs'

asset="$ksu/userspace/ksud/bin/aarch64/android16-6.12_kernelsu.ko"
cp "$ko" "$asset"
test "$(sha256sum "$asset" | awk '{print $1}')" = "$expected_ko"

echo "KERNELSU_USERSPACE_COMMIT=$kernelsu_commit"
echo "AZHJ_KSUD_RUST_TOOLCHAIN=$rust_toolchain"
echo "AZHJ_KSUD_TARGET=$target"
echo "AZHJ_KSUD_ANDROID_API=$android_api"

rustup toolchain install "$rust_toolchain" --profile minimal --no-self-update >/dev/null
rustup target add --toolchain "$rust_toolchain" "$target" >/dev/null

llvm_path="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
llvm_bin="$llvm_path/bin"
clang_path="$llvm_bin/${target}${android_api}-clang"
test -x "$clang_path"

utriple=${target//-/_}
uutriple=$(printf '%s' "$utriple" | tr '[:lower:]' '[:upper:]')
export "CC_${target//-/_}=$clang_path"
export "CXX_${target//-/_}=${clang_path}++"
export "AR_${target//-/_}=$llvm_bin/llvm-ar"
export "CARGO_TARGET_${uutriple}_LINKER=$clang_path"
export "BINDGEN_EXTRA_CLANG_ARGS_${target//-/_}=--sysroot=$llvm_path/sysroot -I$llvm_path/sysroot/usr/include/$target"

# Normalize every build-root-dependent input that can reach rustc/linker output.
# The adversarial CI builds from two deliberately different absolute roots and
# requires byte-for-byte identity, so this remap must remain effective rather
# than replacing that gate with a fixed checkout path.
source_date_epoch=$(git -C "$ksu" show -s --format=%ct "$kernelsu_commit")
export SOURCE_DATE_EPOCH="$source_date_epoch"
export TZ=UTC
export LC_ALL=C
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$work=/m3q/ksud-build"
echo "AZHJ_KSUD_SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "AZHJ_KSUD_PATH_REMAP=$work=/m3q/ksud-build"

# Cargo.lock pins registry/git dependency revisions. Rust, NDK, target and API
# are pinned above. M3Q_KSUD_BUILD_ROOT lets CI prove the output is independent
# of the absolute checkout/target path by building in two distinct roots.
CARGO_TARGET_DIR="$work/target" \
  cargo "+$rust_toolchain" build \
  --locked \
  --target "$target" \
  --release \
  --manifest-path "$ksu/userspace/ksud/Cargo.toml"

built="$work/target/$target/release/ksud"
test -f "$built"
mkdir -p "$(dirname -- "$out")"
cp "$built" "$out"

actual_ksud=$(sha256sum "$out" | awk '{print $1}')
size=$(wc -c < "$out")
printf '%s\n' \
  "AZHJ_KSUD_EMBEDDED_SHA256=$actual_ksud" \
  "AZHJ_KSUD_EMBEDDED_SIZE=$size" \
  "AZHJ_KSUD_EMBEDDED_BUILD=PASS"
