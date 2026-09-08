#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 KERNELSU_AZHJ_KO" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
ko=$(realpath "$1")
engine="$script_dir/app/src/main/java/dev/indevelopment/m3qroot/M3qRootEngine.java"
gradle_file="$script_dir/app/build.gradle"
preloader_template="$script_dir/azhj/AzhjKernelSuPreloader.java"
preloader_dest="$script_dir/app/src/main/java/dev/indevelopment/m3qroot/AzhjKernelSuPreloader.java"
jni_dir="$script_dir/app/src/main/jniLibs/arm64-v8a"
asset_dir="$script_dir/app/src/main/assets/azhj"
asset_ko="$asset_dir/kernelsu-azhj-kdp-m3q-compat.ko"
native_bin="$repo_root/exploit/build/m3q-BP4A.251205.006-AZHJ/bin"
ksud="$script_dir/prebuilt/ksud-m3q-S948NKSS4AZG3-kdp"
output_dir="$script_dir/app/build/outputs/apk/azhj"
review_head=${M3Q_REVIEW_HEAD_SHA:?M3Q_REVIEW_HEAD_SHA is required}
actual_head=$(git -C "$repo_root" rev-parse HEAD)
if [ "$actual_head" != "$review_head" ]; then
  echo "FAIL: checkout HEAD $actual_head != review HEAD $review_head" >&2
  exit 125
fi

expected_ko='e947f91c986e6594b965c7e65871bf8287542198484334945fe461d886a701c7'
expected_ksud='3ce5753203c93f4d733fbc10eebd7a69152189afb1d2a15bfd855bd6b5d4f622'
expected_helper='a3bc95af6b31a988da0f19b4285c20af31735569dd0c9abd64752e26622bc08f'
expected_oracle='00c1d4d577f013e3823cb33998576e17bbb9e2697cc0787efe3a7a95f10f45af'
expected_payload='d34568842ca0664ab8f25984620504922cdb3bfe17b380ac8a28e40d099b1c95'

hash_of() { sha256sum "$1" | awk '{print $1}'; }
assert_hash() {
  local path=$1 expected=$2 label=$3
  local actual
  actual=$(hash_of "$path")
  if [ "$actual" != "$expected" ]; then
    echo "FAIL: $label hash $actual != $expected" >&2
    exit 125
  fi
  echo "$label=$actual"
}

assert_hash "$ko" "$expected_ko" AZHJ_KSU_INPUT_SHA256
assert_hash "$ksud" "$expected_ksud" KSUD_SHA256

work=$(mktemp -d)
engine_backup="$work/M3qRootEngine.java"
gradle_backup="$work/build.gradle"
cp "$engine" "$engine_backup"
cp "$gradle_file" "$gradle_backup"
if [ -e "$preloader_dest" ]; then
  echo "FAIL: AZHJ overlay destination already exists: $preloader_dest" >&2
  exit 125
fi
if [ -d "$jni_dir" ]; then
  cp -a "$jni_dir" "$work/jni-backup"
fi
if [ -e "$script_dir/app/src/main/assets" ]; then
  cp -a "$script_dir/app/src/main/assets" "$work/assets-backup"
fi

cleanup() {
  cp "$engine_backup" "$engine"
  cp "$gradle_backup" "$gradle_file"
  rm -f "$preloader_dest"
  rm -rf "$jni_dir"
  if [ -d "$work/jni-backup" ]; then
    mkdir -p "$(dirname -- "$jni_dir")"
    cp -a "$work/jni-backup" "$jni_dir"
  fi
  rm -rf "$script_dir/app/src/main/assets"
  if [ -d "$work/assets-backup" ]; then
    cp -a "$work/assets-backup" "$script_dir/app/src/main/assets"
  fi
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

"$script_dir/build-native-azhj.sh"
assert_hash "$native_bin/su_daemon_aarch64_pie.app" "$expected_helper" AZHJ_HELPER_SHA256
assert_hash "$native_bin/slide_oracle.app.so" "$expected_oracle" AZHJ_ORACLE_SHA256
assert_hash "$native_bin/preload.app.so" "$expected_payload" AZHJ_PAYLOAD_SHA256

python3 "$repo_root/tools/prepare_azhj_app.py" "$engine" "$gradle_file"
cp "$preloader_template" "$preloader_dest"

rm -rf "$jni_dir"
mkdir -p "$jni_dir"
cp "$native_bin/su_daemon_aarch64_pie.app" "$jni_dir/libm3qroot.so"
cp "$native_bin/slide_oracle.app.so" "$jni_dir/libm3qoracle.so"
cp "$native_bin/preload.app.so" "$jni_dir/libm3qpayload.so"
cp "$ksud" "$jni_dir/libm3qksud.so"
mkdir -p "$asset_dir"
cp "$ko" "$asset_ko"
assert_hash "$asset_ko" "$expected_ko" AZHJ_ASSET_KSU_SHA256

cd "$script_dir"
./gradlew clean :app:assembleRelease -x prepareM3qPayloads
apk="$script_dir/app/build/outputs/apk/release/app-release.apk"
test -f "$apk"

rm -rf "$output_dir"
mkdir -p "$output_dir"
final_apk="$output_dir/m3q-root-S948NKSU4AZHJ-preflight-unverified.apk"
cp "$apk" "$final_apk"

extract="$work/apk"
mkdir -p "$extract"
unzip -q "$final_apk" -d "$extract"
libdir="$extract/lib/arm64-v8a"
assert_hash "$libdir/libm3qroot.so" "$expected_helper" APK_HELPER_SHA256
assert_hash "$libdir/libm3qoracle.so" "$expected_oracle" APK_ORACLE_SHA256
assert_hash "$libdir/libm3qpayload.so" "$expected_payload" APK_PAYLOAD_SHA256
assert_hash "$libdir/libm3qksud.so" "$expected_ksud" APK_KSUD_SHA256
apk_asset="$extract/assets/azhj/kernelsu-azhj-kdp-m3q-compat.ko"
assert_hash "$apk_asset" "$expected_ko" APK_KSU_ASSET_SHA256

grep -aFq \
  'vermagic=6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k SMP preempt mod_unload modversions aarch64' \
  "$apk_asset"
grep -aFq 'S948NKSU4AZHJ_OKR4AZHJ:user/release-keys' "$extract"/classes*.dex
if grep -aFq 'S948NKSS4AZG3_OKR4AZG3:user/release-keys' "$extract"/classes*.dex; then
  echo 'FAIL: AZG3 exact fingerprint remains in AZHJ classes.dex' >&2
  exit 125
fi
grep -aFq 'M3Q_AZHJ_KSU_MODULE_OK:' "$extract"/classes*.dex

apksigner=$(find "${ANDROID_HOME:-$HOME/Android/Sdk}/build-tools" \
  -type f -name apksigner 2>/dev/null | sort -V | tail -n1 || true)
if [ -z "$apksigner" ]; then
  echo 'FAIL: apksigner not found' >&2
  exit 125
fi
aapt=$(find "${ANDROID_HOME:-$HOME/Android/Sdk}/build-tools" \
  -type f -name aapt 2>/dev/null | sort -V | tail -n1 || true)
if [ -z "$aapt" ]; then
  echo 'FAIL: aapt not found' >&2
  exit 125
fi
badging="$work/apk-badging.txt"
"$aapt" dump badging "$final_apk" > "$badging"
grep -Fq "package: name='dev.indevelopment.m3qroot.hardened.azhjpreflight'" "$badging"
"$apksigner" verify --verbose "$final_apk"

apk_hash=$(hash_of "$final_apk")
cat > "$output_dir/AZHJ-BUILD-EVIDENCE.txt" <<EVIDENCE
REVIEW_HEAD_SHA=$review_head
TARGET_MODEL=SM-S948N
TARGET_FIRMWARE=S948NKSU4AZHJ
TARGET_FINGERPRINT=samsung/m3qksx/m3q:16/BP4A.251205.006/S948NKSU4AZHJ_OKR4AZHJ:user/release-keys
TARGET_KERNEL=6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k
APK_APPLICATION_ID=dev.indevelopment.m3qroot.hardened.azhjpreflight
AZHJ_HELPER_SHA256=$expected_helper
AZHJ_ORACLE_SHA256=$expected_oracle
AZHJ_PAYLOAD_SHA256=$expected_payload
KSUD_SHA256=$expected_ksud
AZHJ_KSU_SHA256=$expected_ko
APK_SHA256=$apk_hash
APK_SIGNATURE_GATE=PASS
APK_EMBEDDED_HASH_GATE=PASS
AZHJ_IDENTITY_OVERLAY_GATE=PASS
AZHJ_RUNTIME_KERNEL_WRITE=UNVERIFIED_FAIL
EVIDENCE
sha256sum "$final_apk" > "$output_dir/SHA256SUMS"
cat "$output_dir/AZHJ-BUILD-EVIDENCE.txt"
cat "$output_dir/SHA256SUMS"
echo "AZHJ_APK=$final_apk"
echo 'AZHJ_APK_BUILD_GATE=PASS'
