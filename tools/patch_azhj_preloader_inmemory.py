#!/usr/bin/env python3
'''Fail-closed build overlay for the AZHJ KernelSU preloader.

The reviewed 406 runtime proved that the separate `ksud debug extract-binary`
probe can fail before the authorized KernelSU write even when the embedded KO
is correct. The foreground ksud now verifies the exact in-memory bytes passed
to `load_module()`, so remove the redundant filesystem extraction path from the
APK build and bind the Java preloader to the exact reviewed foreground ksud.
'''

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
        '''    private static final String EMBEDDED_PROBE_STAGE =
            "/data/local/tmp/.m3q-azhj-embedded-kernelsu.ko";
''',
        "",
        "obsolete filesystem probe path",
    )

    text = replace_exact(
        text,
        '''    private static final String EMBEDDED_RECEIPT_PREFIX =
            "M3Q_AZHJ_EMBEDDED_MODULE_VERIFIED:";
''',
        "",
        "obsolete Java embedded receipt constant",
    )

    text = replace_exact(
        text,
        '''        code = recordPhase(context, helper, "KSU_ABSENT_PROVEN");
        if (code != 0) return code;
        code = verifyEmbeddedModule(context, helper);
        if (code != 0) return code;
        code = recordPhase(context, helper, "EMBEDDED_MODULE_VERIFIED");
        if (code != 0) return code;
        code = recordPhase(context, helper, "PRE_LATE_LOAD");
''',
        '''        code = recordPhase(context, helper, "KSU_ABSENT_PROVEN");
        if (code != 0) return code;
        code = recordPhase(context, helper, "PRE_LATE_LOAD");
''',
        "activation phase transition",
    )

    text = replace_exact(
        text,
        '''        /* This is the single authorized KernelSU kernel-write entry. The native
         * helper's K protocol returns status 0 only after the custom foreground
         * ksud has completed embedded-KO late-load and the root-context worker
         * independently verifies exact KernelSU v32525 control. The successful
         * K response also causes the bootstrap daemon to unlink its socket and
         * terminate. Do not issue any post-write bootstrap-daemon command and
         * do not invoke --ksu-info from the app UID. */
''',
        '''        /* This is the single authorized KernelSU kernel-write entry. The custom
         * foreground ksud first hashes the exact in-memory KO byte slice that is
         * passed directly to load_module(), and aborts before that write unless
         * it is the exact audited AZHJ module. The native helper's K protocol then
         * returns status 0 only after foreground late-load completes and its
         * root-context worker independently verifies exact KernelSU v32525 control.
         * The successful K response also causes the bootstrap daemon to unlink its
         * socket and terminate. Do not issue any post-write bootstrap-daemon command
         * and do not invoke --ksu-info from the app UID. */
''',
        "single-write contract comment",
    )

    text = remove_region(
        text,
        "    private static int verifyEmbeddedModule(Context context, File helper) {",
        "    private static int recordPhase(Context context, File helper, String phase) {",
        "obsolete filesystem embedded-module verifier",
    )
    text = replace_exact(
        text,
        '                + "probe_stage=" + shellQuote(EMBEDDED_PROBE_STAGE) + "\\n"\n',
        "",
        "obsolete filesystem probe shell variable",
    )
    text = replace_exact(
        text,
        '+ "\\\"$probe_stage\\\" \\\"$late_log\\\" \\\"$journal\\\"\\n"',
        '+ "\\\"$late_log\\\" \\\"$journal\\\"\\n"',
        "obsolete filesystem probe cleanup reference",
    )

    text = replace_exact(
        text,
        '''        if (result.output.contains(CONTROL_OK_MARKER)
                && result.output.contains(CONTROL_EXACT_LINE)) {
            return new ProbeResult(ProbeKind.READY, 0, result.output);
        }
        if (result.output.contains(CONTROL_FAIL_PREFIX + "13")
                && result.output.contains("KernelSU driver fd unavailable")) {
            return new ProbeResult(ProbeKind.ABSENT, 13, result.output);
        }
        return new ProbeResult(ProbeKind.FAIL, 125, result.output);
''',
        '''        int okMarkers = 0;
        int failMarkers = 0;
        int fail13Markers = 0;
        int exactReadyLines = 0;
        int readyFamilyLines = 0;
        int exactAbsentLines = 0;
        int absentFamilyLines = 0;
        int controlFailLines = 0;
        for (String line : result.output.split("\\\\R")) {
            if (CONTROL_OK_MARKER.equals(line)) okMarkers++;
            if (line.startsWith(CONTROL_FAIL_PREFIX)) failMarkers++;
            if ((CONTROL_FAIL_PREFIX + "13").equals(line)) fail13Markers++;
            if (line.startsWith("KernelSU control verified ")) readyFamilyLines++;
            if (CONTROL_EXACT_LINE.equals(line)) exactReadyLines++;
            if (line.startsWith("KernelSU driver fd unavailable")) absentFamilyLines++;
            if ("KernelSU driver fd unavailable".equals(line)) exactAbsentLines++;
            if (line.startsWith("KernelSU control failed ")) controlFailLines++;
        }
        if (okMarkers == 1
                && failMarkers == 0
                && exactReadyLines == 1
                && readyFamilyLines == 1
                && exactAbsentLines == 0
                && absentFamilyLines == 0
                && controlFailLines == 0) {
            return new ProbeResult(ProbeKind.READY, 0, result.output);
        }
        if (okMarkers == 0
                && failMarkers == 1
                && fail13Markers == 1
                && exactReadyLines == 0
                && readyFamilyLines == 0
                && exactAbsentLines == 1
                && absentFamilyLines == 1
                && controlFailLines == 0) {
            return new ProbeResult(ProbeKind.ABSENT, 13, result.output);
        }
        return new ProbeResult(ProbeKind.FAIL, 125, result.output);
''',
        "daemon KernelSU exact receipt classification",
    )

    # Semantic fail-closed audit of the transformed source. The historical
    # extraction path must be absent from DEX, not merely dormant.
    forbidden = [
        "verifyEmbeddedModule(",
        "debug extract-binary",
        "extract-binary",
        "EMBEDDED_MODULE_VERIFIED",
        "EMBEDDED_RECEIPT_PREFIX",
        "EMBEDDED_PROBE_STAGE",
        ".m3q-azhj-embedded-kernelsu.ko",
        "M3Q_AZHJ_EMBEDDED_MODULE_HASH_MISMATCH",
        "result.output.contains(CONTROL_OK_MARKER)",
        'result.output.contains(CONTROL_FAIL_PREFIX + "13")',
    ]
    for token in forbidden:
        if token in text:
            raise SystemExit(f"FAIL: stale Java filesystem/probe token remains: {token}")

    required = [
        expected_ksud,
        EXPECTED_MODULE_SHA256,
        "KSU_ABSENT_PROVEN",
        "PRE_LATE_LOAD",
        "ROUTE=FOREGROUND_EMBEDDED_LATE_LOAD",
        "--late-load",
        'result.output.split("\\\\R")',
        "int exactReadyLines = 0;",
        "int exactAbsentLines = 0;",
        "int readyFamilyLines = 0;",
        "int absentFamilyLines = 0;",
        "int fail13Markers = 0;",
        '"KernelSU driver fd unavailable".equals(line)',
        'line.startsWith("KernelSU control failed ")',
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
    if text.count("okMarkers == 1") != 1 or text.count("fail13Markers == 1") != 1:
        raise SystemExit("FAIL: daemon KernelSU exact terminal-cardinality gate mismatch")
    if text.count("readyFamilyLines == 1") != 1 or text.count("absentFamilyLines == 1") != 1:
        raise SystemExit("FAIL: daemon KernelSU terminal-family cardinality gate mismatch")

    path.write_text(text, encoding="utf-8")
    print(f"AZHJ_PRELOADER_PATCHED_SHA256={hashlib.sha256(path.read_bytes()).hexdigest()}")
    print(f"AZHJ_PRELOADER_EXPECTED_KSUD_SHA256={expected_ksud}")
    print("AZHJ_PRELOADER_FILESYSTEM_EXTRACT_REMOVED=PASS")
    print("AZHJ_PRELOADER_IN_MEMORY_HANDOFF_CONTRACT=PASS")
    print("AZHJ_PRELOADER_STRICT_DAEMON_KSU_PROBE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
