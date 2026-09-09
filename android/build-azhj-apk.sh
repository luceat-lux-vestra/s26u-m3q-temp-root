#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 KERNELSU_AZHJ_KO AZHJ_FOREGROUND_KSUD" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
ko=$(realpath "$1")
ksud=$(realpath "$2")
engine="$script_dir/app/src/main/java/dev/indevelopment/m3qroot/M3qRootEngine.java"
activity="$script_dir/app/src/main/java/dev/indevelopment/m3qroot/MainActivity.java"
strings_file="$script_dir/app/src/main/res/values/strings.xml"
gradle_file="$script_dir/app/build.gradle"
preloader_template="$script_dir/azhj/AzhjKernelSuPreloader.java"
preloader_dest="$script_dir/app/src/main/java/dev/indevelopment/m3qroot/AzhjKernelSuPreloader.java"
jni_dir="$script_dir/app/src/main/jniLibs/arm64-v8a"
native_ko="$jni_dir/libm3qksumodule.so"
native_bin="$repo_root/exploit/build/m3q-BP4A.251205.006-AZHJ/bin"
output_dir="$script_dir/app/build/outputs/apk/azhj"
review_head=${M3Q_REVIEW_HEAD_SHA:?M3Q_REVIEW_HEAD_SHA is required}
actual_head=$(git -C "$repo_root" rev-parse HEAD)
if [ "$actual_head" != "$review_head" ]; then
  echo "FAIL: checkout HEAD $actual_head != review HEAD $review_head" >&2
  exit 125
fi

expected_ko='e947f91c986e6594b965c7e65871bf8287542198484334945fe461d886a701c7'
expected_ksud='83c754dcbacf1c5bd96836cc52380dcd5b5c9273e1f6a8bedfde2ddc0b7f3ab4'
expected_helper='f13f2a19d4b6b3154af68a42f8bdbc085e5295cc3700d48b25d514f51f074139'
expected_oracle='00c1d4d577f013e3823cb33998576e17bbb9e2697cc0787efe3a7a95f10f45af'
expected_payload='0f873301def6b8c834942565e70b0a01f88270e74190dbfd596881c5e6944106'
expected_activity_blob='b7b19c2669408a9de125237fe491928fdc9850db'
expected_strings_blob='a70879c89ddaaf35ac77a18eb0d091ae7d16d967'

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
assert_git_blob() {
  local path=$1 expected=$2 label=$3
  local actual
  actual=$(git -C "$repo_root" hash-object -- "$path")
  if [ "$actual" != "$expected" ]; then
    echo "FAIL: $label git blob $actual != $expected" >&2
    exit 125
  fi
  echo "$label=$actual"
}

assert_hash "$ko" "$expected_ko" AZHJ_KSU_INPUT_SHA256
assert_hash "$ksud" "$expected_ksud" AZHJ_FOREGROUND_KSUD_INPUT_SHA256
python3 "$repo_root/tools/audit_azhj_ksud.py" --ksud "$ksud"
assert_git_blob "$activity" "$expected_activity_blob" MAIN_ACTIVITY_SOURCE_GIT_BLOB_SHA1
assert_git_blob "$strings_file" "$expected_strings_blob" STRINGS_SOURCE_GIT_BLOB_SHA1

work=$(mktemp -d)
engine_backup="$work/M3qRootEngine.java"
activity_backup="$work/MainActivity.java"
strings_backup="$work/strings.xml"
gradle_backup="$work/build.gradle"
cp "$engine" "$engine_backup"
cp "$activity" "$activity_backup"
cp "$strings_file" "$strings_backup"
cp "$gradle_file" "$gradle_backup"
if [ -e "$preloader_dest" ]; then
  echo "FAIL: AZHJ overlay destination already exists: $preloader_dest" >&2
  exit 125
fi
if [ -e "$native_ko" ]; then
  echo "FAIL: stale AZHJ KernelSU native module witness already exists: $native_ko" >&2
  exit 125
fi
if [ -d "$jni_dir" ]; then
  cp -a "$jni_dir" "$work/jni-backup"
fi

cleanup() {
  cp "$engine_backup" "$engine"
  cp "$activity_backup" "$activity"
  cp "$strings_backup" "$strings_file"
  cp "$gradle_backup" "$gradle_file"
  rm -f "$preloader_dest"
  rm -rf "$jni_dir"
  if [ -d "$work/jni-backup" ]; then
    mkdir -p "$(dirname -- "$jni_dir")"
    cp -a "$work/jni-backup" "$jni_dir"
  fi
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

"$script_dir/build-native-azhj.sh"
assert_hash "$native_bin/su_daemon_aarch64_pie.app" "$expected_helper" AZHJ_HELPER_SHA256
assert_hash "$native_bin/slide_oracle.app.so" "$expected_oracle" AZHJ_ORACLE_SHA256
assert_hash "$native_bin/preload.app.so" "$expected_payload" AZHJ_PAYLOAD_SHA256

python3 "$repo_root/tools/prepare_azhj_app.py" "$engine" "$gradle_file"
python3 - "$activity" "$strings_file" <<'PY'
from pathlib import Path
import sys

activity = Path(sys.argv[1])
strings = Path(sys.argv[2])

def replace_exact(path: Path, replacements: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for old, new in replacements:
        count = text.count(old)
        if count != 1:
            raise SystemExit(
                f"FAIL: {path} expected exactly one occurrence of {old!r}, found {count}"
            )
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")

replace_exact(
    activity,
    [
        (
            "이 앱은 SM-S948N AZG3 펌웨어에서만 실행할 수 있습니다.",
            "이 앱은 SM-S948N AZHJ 펌웨어에서만 실행할 수 있습니다.",
        ),
        (
            "정확한 SM-S948N AZG3 빌드에서만 실행할 수 있습니다.",
            "정확한 SM-S948N AZHJ 빌드에서만 실행할 수 있습니다.",
        ),
    ],
)
replace_exact(
    strings,
    [
        (
            "Galaxy S26 Ultra · AZG3 전용 · 재부팅 시 해제",
            "Galaxy S26 Ultra · AZHJ 전용 · 재부팅 시 해제",
        ),
        (
            "SM-S948N AZG3 전용 RAM-only 방식입니다.",
            "SM-S948N AZHJ 전용 RAM-only 방식입니다.",
        ),
    ],
)

activity_text = activity.read_text(encoding="utf-8")
strings_text = strings.read_text(encoding="utf-8")
if "AZG3" in activity_text:
    raise SystemExit("FAIL: stale AZG3 UI text remains in transformed MainActivity")
if "AZG3 전용" in strings_text:
    raise SystemExit("FAIL: stale AZG3-only UI text remains in transformed strings")
print("AZHJ_UI_SOURCE_OVERLAY=PASS")
PY
cp "$preloader_template" "$preloader_dest"

rm -rf "$jni_dir"
mkdir -p "$jni_dir"
cp "$native_bin/su_daemon_aarch64_pie.app" "$jni_dir/libm3qroot.so"
cp "$native_bin/slide_oracle.app.so" "$jni_dir/libm3qoracle.so"
cp "$native_bin/preload.app.so" "$jni_dir/libm3qpayload.so"
cp "$ksud" "$jni_dir/libm3qksud.so"
# Retain the independently audited KO only as a byte-for-byte witness. Runtime
# never insmods this standalone file; the custom ksud loads its embedded copy.
cp "$ko" "$native_ko"
assert_hash "$native_ko" "$expected_ko" AZHJ_NATIVE_KSU_WITNESS_SHA256

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
python3 "$repo_root/tools/audit_azhj_ksud.py" --ksud "$libdir/libm3qksud.so"
apk_module="$libdir/libm3qksumodule.so"
assert_hash "$apk_module" "$expected_ko" APK_KSU_WITNESS_SHA256

grep -aFq \
  'vermagic=6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k SMP preempt mod_unload modversions aarch64' \
  "$apk_module"
grep -aFq 'S948NKSU4AZHJ_OKR4AZHJ:user/release-keys' "$extract"/classes*.dex
if grep -aFq 'S948NKSS4AZG3_OKR4AZG3:user/release-keys' "$extract"/classes*.dex; then
  echo 'FAIL: AZG3 exact fingerprint remains in AZHJ classes.dex' >&2
  exit 125
fi

for marker in \
  'SCHEMA=2' \
  'M3Q_AZHJ_KSU_BOOTSTRAP_STAGE_OK:' \
  'M3Q_AZHJ_DAEMON_KSU_CONTROL_OK' \
  'M3Q_AZHJ_DAEMON_KSU_CONTROL_FAIL:' \
  'KernelSU control verified version=32525 flags=0x5 uapi=2 features=0x5' \
  'M3Q_AZHJ_EMBEDDED_MODULE_VERIFIED:' \
  'M3Q_AZHJ_PHASE_RECORDED:' \
  'PRE_LATE_LOAD_CONTROL_PROBE' \
  'KSU_ABSENT_PROVEN' \
  'EMBEDDED_MODULE_VERIFIED' \
  'PRE_LATE_LOAD' \
  'M3Q_AZHJ_KSU_FOREGROUND_LATE_LOAD_OK' \
  'M3Q_AZHJ_KSU_READY:' \
  'KernelSU 3.2.5 LKM foreground late-load 검증 완료'
do
  if ! grep -aFq "$marker" "$extract"/classes*.dex; then
    echo "FAIL: AZHJ foreground handoff artifact marker missing: $marker" >&2
    exit 125
  fi
done

for stale in \
  'PRE_INSMOD_CONTROL_PROBE' \
  'KSU_READY_AFTER_STAGE' \
  'PRE_INSMOD' \
  'MODULE_ALIAS_OK' \
  'INSMOD_CALL_BEGIN' \
  'INSMOD_RETURNED' \
  'INSMOD_RECEIPT_OK' \
  'POST_INSMOD_CONTROL_PROBE' \
  'POST_INSMOD_CONTROL_READY' \
  'M3Q_AZHJ_KSU_MODULE_ALIAS_OK:' \
  'M3Q_AZHJ_KSU_BIND_EXEC_OK' \
  'M3Q_AZHJ_KSU_MODULE_OK:' \
  'M3Q_AZHJ_KSU_ALREADY_LOADED'
do
  if grep -aFq "$stale" "$extract"/classes*.dex; then
    echo "FAIL: stale manual-insmod artifact marker remains: $stale" >&2
    exit 125
  fi
done
if grep -aFq 'AZHJ KernelSU module insmod 후 control 검증 실패' "$extract"/classes*.dex; then
  echo 'FAIL: stale post-insmod Shizuku control gate remains in AZHJ classes.dex' >&2
  exit 125
fi
echo 'AZHJ_FOREGROUND_HANDOFF_ARTIFACT_GATE=PASS'

grep -aFq '이 앱은 SM-S948N AZHJ 펌웨어에서만 실행할 수 있습니다.' "$extract"/classes*.dex
grep -aFq '정확한 SM-S948N AZHJ 빌드에서만 실행할 수 있습니다.' "$extract"/classes*.dex
if grep -aFq '이 앱은 SM-S948N AZG3 펌웨어에서만 실행할 수 있습니다.' "$extract"/classes*.dex; then
  echo 'FAIL: stale AZG3 MainActivity UI remains in AZHJ classes.dex' >&2
  exit 125
fi

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
resources="$work/apk-resources.txt"
"$aapt" dump --values resources "$final_apk" > "$resources"
grep -Fq 'Galaxy S26 Ultra · AZHJ 전용 · 재부팅 시 해제' "$resources"
grep -Fq 'SM-S948N AZHJ 전용 RAM-only 방식입니다.' "$resources"
if grep -Fq 'AZG3 전용' "$resources"; then
  echo 'FAIL: stale AZG3-only resource text remains in AZHJ APK' >&2
  exit 125
fi
echo 'AZHJ_UI_ARTIFACT_GATE=PASS'
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
AZHJ_FOREGROUND_KSUD_SHA256=$expected_ksud
AZHJ_KSU_WITNESS_SHA256=$expected_ko
AZHJ_KSU_WITNESS_LIBRARY_GATE=PASS
AZHJ_FOREGROUND_KSUD_AUDIT_GATE=PASS
AZHJ_FOREGROUND_HANDOFF_ARTIFACT_GATE=PASS
APK_SHA256=$apk_hash
APK_SIGNATURE_GATE=PASS
APK_EMBEDDED_HASH_GATE=PASS
AZHJ_IDENTITY_OVERLAY_GATE=PASS
AZHJ_UI_OVERLAY_GATE=PASS
AZHJ_RUNTIME_KERNEL_WRITE=UNVERIFIED_FAIL
EVIDENCE
(
  cd "$output_dir"
  sha256sum "$(basename "$final_apk")" > SHA256SUMS
  sha256sum -c SHA256SUMS
)
cat "$output_dir/AZHJ-BUILD-EVIDENCE.txt"
cat "$output_dir/SHA256SUMS"
echo "AZHJ_APK=$final_apk"
echo 'AZHJ_APK_BUILD_GATE=PASS'
