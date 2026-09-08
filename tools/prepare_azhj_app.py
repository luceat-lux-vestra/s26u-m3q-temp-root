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
ACTIVATE_ANCHOR = '        status("KernelSU 구성 확인 중", STATUS_WORKING);'
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

ACTIVATE_OVERLAY = '''        int moduleCode = AzhjKernelSuPreloader.ensureLoaded(context, helper, ksud);
        if (moduleCode != 0) {
            log("AZHJ KernelSU module pre-load 실패 code=" + moduleCode);
            return moduleCode;
        }

        status("KernelSU 구성 확인 중", STATUS_WORKING);'''


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
    text = replace_exact(text, ACTIVATE_ANCHOR, ACTIVATE_OVERLAY)

    if AZG3_KERNEL in text or AZG3_FIRMWARE in text:
        raise SystemExit("FAIL: stale AZG3 identity remains in transformed engine")
    if text.count("AzhjKernelSuPreloader.ensureLoaded(context, helper, ksud)") != 1:
        raise SystemExit("FAIL: AZHJ KernelSU preload hook cardinality mismatch")
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
