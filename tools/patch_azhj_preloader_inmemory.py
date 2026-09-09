#!/usr/bin/env python3
"""Fail-closed build overlay for the AZHJ KernelSU preloader.

The reviewed 406 runtime proved that the separate `ksud debug extract-binary`
probe can fail before the authorized KernelSU write even when the embedded KO
is correct. The foreground ksud now verifies the exact in-memory bytes passed
to `load_module()`, so remove the redundant filesystem extraction path from the
APK build and bind the Java preloader to the exact reviewed foreground ksud.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

EXPECTED_PRELOADER_BLOB_SHA1 = "579980e209da724c0fba049f608fd9a884df9377"
OLD_KSUD_SHA256 = "83c754dcbacf1c5bd96836cc52380dcd5b5c9273e1f6a8bedfde2ddc0b7f3ab4"
EXPECTED_MODULE_SHA256 = "e947f91c986e6594b965c7e65871bf8287542198484334945fe461d886a701c7"


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def replace_exact(text: str, old: str, new: str, label: str, count: int = 1) -> str:
    actual = text.count(old)
    if actual != count:
        raise SystemExit(f"FAIL: {label} cardinality={actual}, expected {count}")
    return text.replace(old, new)


def remove_region(text: str, start: str, end: str, label: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit(
            f"FAIL: {label} boundary cardinality start={text.count(start)} end={text.count(end)}"
        )
    begin = text.index(start)
    finish = text.index(end, begin)
    if finish <= begin:
        raise SystemExit(f"FAIL: {label} boundary ordering")
    return text[:begin] + text[finish:]


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} PRELOADER_JAVA EXPECTED_FOREGROUND_KSUD_SHA256")

    path = Path(sys.argv[1]).resolve()
    expected_ksud = sys.argv[2].strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_ksud):
        raise SystemExit("FAIL: foreground ksud SHA-256 must be 64 lowercase hex chars")
    if expected_ksud == OLD_KSUD_SHA256:
        raise SystemExit("FAIL: refusing stale 406 foreground ksud hash")

    raw = path.read_bytes()
    source_blob = git_blob_sha1(raw)
    print(f"AZHJ_PRELOADER_PATCH_SOURCE_BLOB={source_blob}")
    if source_blob != EXPECTED_PRELOADER_BLOB_SHA1:
        raise SystemExit(
            f"FAIL: unexpected AZHJ preloader source blob {source_blob} != {EXPECTED_PRELOADER_BLOB_SHA1}"
        )

    text = raw.decode("utf-8")

    text = replace_exact(
        text,
        OLD_KSUD_SHA256,
        expected_ksud,
        "foreground ksud runtime hash",
    )

    text = replace_exact(
        text,
        '''    private static final String EMBEDDED_RECEIPT_PREFIX =\n            "M3Q_AZHJ_EMBEDDED_MODULE_VERIFIED:";\n''',
        "",
        "obsolete Java embedded receipt constant",
    )

    text = replace_exact(
        text,
        '''        code = recordPhase(context, helper, "KSU_ABSENT_PROVEN");\n        if (code != 0) return code;\n        code = verifyEmbeddedModule(context, helper);\n        if (code != 0) return code;\n        code = recordPhase(context, helper, "EMBEDDED_MODULE_VERIFIED");\n        if (code != 0) return code;\n        code = recordPhase(context, helper, "PRE_LATE_LOAD");\n''',
        '''        code = recordPhase(context, helper, "KSU_ABSENT_PROVEN");\n        if (code != 0) return code;\n        code = recordPhase(context, helper, "PRE_LATE_LOAD");\n''',
        "activation phase transition",
    )

    text = replace_exact(
        text,
        '''        /* This is the single authorized KernelSU kernel-write entry. The native\n         * helper's K protocol returns status 0 only after the custom foreground\n         * ksud has completed embedded-KO late-load and the root-context worker\n         * independently verifies exact KernelSU v32525 control. The successful\n         * K response also causes the bootstrap daemon to unlink its socket and\n         * terminate. Do not issue any post-write bootstrap-daemon command and\n         * do not invoke --ksu-info from the app UID. */\n''',
        '''        /* This is the single authorized KernelSU kernel-write entry. The custom\n         * foreground ksud first hashes the exact in-memory KO byte slice that is\n         * passed directly to load_module(), and aborts before that write unless\n         * it is the exact audited AZHJ module. The native helper's K protocol then\n         * returns status 0 only after foreground late-load completes and its\n         * root-context worker independently verifies exact KernelSU v32525 control.\n         * The successful K response also causes the bootstrap daemon to unlink its\n         * socket and terminate. Do not issue any post-write bootstrap-daemon command\n         * and do not invoke --ksu-info from the app UID. */\n''',
        "single-write contract comment",
    )

    text = remove_region(
        text,
        "    private static int verifyEmbeddedModule(Context context, File helper) {",
        "    private static int recordPhase(Context context, File helper, String phase) {",
        "obsolete filesystem embedded-module verifier",
    )

    # The old probe path is retained only so a successful fresh staging pass can
    # clean up evidence from earlier 406 runs. It is never created or read by the
    # new activation path.
    text = replace_exact(
        text,
        "EMBEDDED_PROBE_STAGE",
        "LEGACY_EMBEDDED_PROBE_STAGE",
        "legacy probe cleanup symbol",
        count=2,
    )
    text = replace_exact(
        text,
        '''    private static final String LEGACY_EMBEDDED_PROBE_STAGE =\n            "/data/local/tmp/.m3q-azhj-embedded-kernelsu.ko";\n''',
        '''    /* Cleanup-only path from the superseded 406 filesystem probe. */\n    private static final String LEGACY_EMBEDDED_PROBE_STAGE =\n            "/data/local/tmp/.m3q-azhj-embedded-kernelsu.ko";\n''',
        "legacy probe cleanup comment",
    )
    text = replace_exact(
        text,
        '                + "probe_stage=" + shellQuote(LEGACY_EMBEDDED_PROBE_STAGE) + "\\n"\n',
        '                + "legacy_probe_stage=" + shellQuote(LEGACY_EMBEDDED_PROBE_STAGE) + "\\n"\n',
        "legacy probe shell variable",
    )
    text = replace_exact(
        text,
        '+ "\\\"$probe_stage\\\" \\\"$late_log\\\" \\\"$journal\\\"\\n"',
        '+ "\\\"$legacy_probe_stage\\\" \\\"$late_log\\\" \\\"$journal\\\"\\n"',
        "legacy probe cleanup shell reference",
    )

    # Semantic fail-closed audit of the transformed source.
    forbidden = [
        "verifyEmbeddedModule(",
        "debug extract-binary",
        "EMBEDDED_MODULE_VERIFIED",
        "EMBEDDED_RECEIPT_PREFIX",
        "M3Q_AZHJ_EMBEDDED_MODULE_HASH_MISMATCH",
    ]
    for token in forbidden:
        if token in text:
            raise SystemExit(f"FAIL: stale Java filesystem module-proof token remains: {token}")

    required = [
        expected_ksud,
        EXPECTED_MODULE_SHA256,
        "KSU_ABSENT_PROVEN",
        "PRE_LATE_LOAD",
        "ROUTE=FOREGROUND_EMBEDDED_LATE_LOAD",
        "LEGACY_EMBEDDED_PROBE_STAGE",
        "--late-load",
    ]
    for token in required:
        if token not in text:
            raise SystemExit(f"FAIL: required transformed preloader token missing: {token}")

    if text.index('recordPhase(context, helper, "KSU_ABSENT_PROVEN")') > text.index(
        'recordPhase(context, helper, "PRE_LATE_LOAD")'
    ):
        raise SystemExit("FAIL: KSU absence proof must precede PRE_LATE_LOAD")
    if text.index('recordPhase(context, helper, "PRE_LATE_LOAD")') > text.index(
        'new String[]{helper.getAbsolutePath(), "--late-load"}'
    ):
        raise SystemExit("FAIL: PRE_LATE_LOAD must precede the single late-load entry")

    path.write_text(text, encoding="utf-8")
    print(f"AZHJ_PRELOADER_PATCHED_SHA256={hashlib.sha256(path.read_bytes()).hexdigest()}")
    print(f"AZHJ_PRELOADER_EXPECTED_KSUD_SHA256={expected_ksud}")
    print("AZHJ_PRELOADER_FILESYSTEM_EXTRACT_REMOVED=PASS")
    print("AZHJ_PRELOADER_IN_MEMORY_HANDOFF_CONTRACT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
