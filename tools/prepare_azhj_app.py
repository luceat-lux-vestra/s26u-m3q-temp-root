#!/usr/bin/env python3
"""Fail-closed, build-time AZHJ overlay for the unchanged AZG3 app source."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

EXPECTED_ENGINE_BLOB_SHA1 = "76516319bfd3d3a7a03ed308f2dfb791db715f25"
EXPECTED_GRADLE_BLOB_SHA1 = "f554159032883d83216de48765b3afa713ff4839"
AZG3_KERNEL = "6.12.30-android16-5-pd30ff70-abogkiS948NKSS4AZG3-4k"
AZHJ_KERNEL = "6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k"
AZG3_FIRMWARE = "S948NKSS4AZG3_OKR4AZG3"
AZHJ_FIRMWARE = "S948NKSU4AZHJ_OKR4AZHJ"
ACTIVATE_METHOD_START = "    private int activateKernelSu(File helper, File ksud) {"
ACTIVATE_METHOD_END = "    private void appendKernelSuLog(File helper) {"
KSU_READY_ANCHOR = '''        if (kernelSu) {
            markKernelSuVerifiedForThisBoot();
            return new RootState(true, false, false, ksuOutput);
        }'''
KSU_READY_OVERLAY = '''        if (kernelSu && hasVerifiedKernelSuThisBoot()) {
            return new RootState(true, false, false, ksuOutput);
        }
        if (kernelSu && verbose) {
            log("AZHJ KernelSU control detected without late-load receipt; "
                    + "recover with KernelSU activation only");
        }'''
GRADLE_RELEASE_ANCHOR = '''        release {
            minifyEnabled false
            signingConfig = signingConfigs.debug
        }'''
GRADLE_RELEASE_OVERLAY = '''        release {
            applicationIdSuffix '.azhjpreflight'
            versionNameSuffix '-azhj-preflight'
            minifyEnabled false
            signingConfig = signingConfigs.debug
        }'''

AZHJ_ACTIVATE_METHOD = '''    private int activateKernelSu(File helper, File ksud) {
        if (!helper.isFile() || !ksud.isFile()) {
            log("KernelSU loader를 APK에서 찾지 못했습니다.");
            return 126;
        }

        status("KernelSU 활성화 중", STATUS_WORKING);
        int code = AzhjKernelSuPreloader.activate(context, helper, ksud);
        if (code == EXIT_TERMINATION_UNCONFIRMED) {
            log("AZHJ KernelSU daemon handoff 종료 상태를 확인하지 못했습니다.");
            return code;
        }
        if (code != 0) {
            log("AZHJ KernelSU daemon handoff 실패 code=" + code);
            appendKernelSuLog(helper);
            return code;
        }

        /* AzhjKernelSuPreloader returns 0 only after the bootstrap daemon's
         * --late-load path has completed and daemon-side exact v32525 control
         * verification has passed. Only then issue this-boot ready receipt. */
        if (!markKernelSuVerifiedForThisBoot()) {
            log("KernelSU는 daemon 검증됐지만 이 boot ID의 영수증을 저장하지 못했습니다.");
            return 123;
        }
        log("KernelSU 3.2.5 LKM late-load daemon 검증 완료");
        return 0;
    }'''


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def replace_exact(text: str, old: str, new: str, expected_count: int = 1) -> str:
    count = text.count(old)
    if count != expected_count:
        raise SystemExit(
            f"FAIL: expected {expected_count} occurrence(s) of {old!r}, found {count}"
        )
    return text.replace(old, new)


def replace_region_exact(text: str, start: str, end: str, replacement: str) -> str:
    if text.count(start) != 1:
        raise SystemExit(f"FAIL: activation method start cardinality={text.count(start)}")
    if text.count(end) != 1:
        raise SystemExit(f"FAIL: activation method end cardinality={text.count(end)}")
    begin = text.index(start)
    finish = text.index(end, begin)
    if finish <= begin:
        raise SystemExit("FAIL: activation method boundary order invalid")
    return text[:begin] + replacement + "\n\n" + text[finish:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("engine", type=Path)
    parser.add_argument("gradle", type=Path)
    args = parser.parse_args()

    raw = args.engine.read_bytes()
    blob = git_blob_sha1(raw)
    print(f"ENGINE_SOURCE_GIT_BLOB_SHA1={blob}")
    if blob != EXPECTED_ENGINE_BLOB_SHA1:
        raise SystemExit(
            "FAIL: M3qRootEngine.java source changed; re-audit the overlay before building AZHJ"
        )

    text = raw.decode("utf-8")
    text = replace_exact(text, AZG3_KERNEL, AZHJ_KERNEL)
    text = replace_exact(text, AZG3_FIRMWARE, AZHJ_FIRMWARE)
    text = replace_exact(text, "AZG3 root-single", "AZHJ root-single", expected_count=2)
    text = replace_exact(text, KSU_READY_ANCHOR, KSU_READY_OVERLAY)
    text = replace_region_exact(
        text, ACTIVATE_METHOD_START, ACTIVATE_METHOD_END, AZHJ_ACTIVATE_METHOD
    )

    if AZG3_KERNEL in text or AZG3_FIRMWARE in text:
        raise SystemExit("FAIL: stale AZG3 identity remains in transformed engine")
    if text.count("AzhjKernelSuPreloader.activate(context, helper, ksud)") != 1:
        raise SystemExit("FAIL: AZHJ daemon handoff hook cardinality mismatch")
    if text.count("AZHJ KernelSU control detected without late-load receipt") != 1:
        raise SystemExit("FAIL: AZHJ KernelSU recovery-state overlay cardinality mismatch")
    if text.count("KernelSU 3.2.5 LKM late-load daemon 검증 완료") != 1:
        raise SystemExit("FAIL: AZHJ daemon-authoritative ready receipt missing")
    if "AzhjKernelSuPreloader.ensureLoaded(" in text:
        raise SystemExit("FAIL: stale AZHJ preloader sequencing remains")
    if "KernelSU module insmod 후 control 검증 실패" in text:
        raise SystemExit("FAIL: stale post-insmod Shizuku control gate remains")
    if "private int activateKernelSu(File helper, File ksud)" not in text:
        raise SystemExit("FAIL: transformed activation method missing")
    if "markKernelSuVerifiedForThisBoot();\n            return new RootState(true" in text:
        raise SystemExit("FAIL: AZHJ checkRoot still self-issues a KernelSU ready receipt")
    if AZHJ_KERNEL not in text or AZHJ_FIRMWARE not in text:
        raise SystemExit("FAIL: exact AZHJ identity missing after transform")

    encoded = text.encode("utf-8")
    args.engine.write_bytes(encoded)
    print(f"ENGINE_AZHJ_SHA256={hashlib.sha256(encoded).hexdigest()}")

    gradle_raw = args.gradle.read_bytes()
    gradle_blob = git_blob_sha1(gradle_raw)
    print(f"GRADLE_SOURCE_GIT_BLOB_SHA1={gradle_blob}")
    if gradle_blob != EXPECTED_GRADLE_BLOB_SHA1:
        raise SystemExit(
            "FAIL: app/build.gradle source changed; re-audit the AZHJ overlay before building"
        )
    gradle_text = gradle_raw.decode("utf-8")
    gradle_text = replace_exact(
        gradle_text, GRADLE_RELEASE_ANCHOR, GRADLE_RELEASE_OVERLAY
    )
    if gradle_text.count("applicationIdSuffix '.azhjpreflight'") != 1:
        raise SystemExit("FAIL: AZHJ applicationIdSuffix overlay cardinality mismatch")
    gradle_encoded = gradle_text.encode("utf-8")
    args.gradle.write_bytes(gradle_encoded)
    print(f"GRADLE_AZHJ_SHA256={hashlib.sha256(gradle_encoded).hexdigest()}")
    print("AZHJ_APP_SOURCE_OVERLAY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
