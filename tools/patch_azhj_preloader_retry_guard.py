#!/usr/bin/env python3
"""Apply the fail-closed same-boot retry guard to the copied AZHJ preloader.

The tracked preloader template is exact-blob pinned.  The APK build copies that
file into the app source tree and this overlay then prevents bootstrap-only
KernelSU activation from erasing a phase journal created earlier in the same
boot.  A journal with ambiguous provenance is preserved and rejected as well.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

EXPECTED_PRELOADER_BLOB = "9a8019c5a7d5783936e5dee90512d2b3135d2364"


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"FAIL: {label} anchor cardinality={count}, expected 1")
    return text.replace(old, new)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} COPIED_AZHJ_PRELOADER")

    path = Path(sys.argv[1])
    raw = path.read_bytes()
    blob = git_blob_sha1(raw)
    print(f"AZHJ_PRELOADER_RETRY_GUARD_SOURCE_BLOB={blob}")
    if blob != EXPECTED_PRELOADER_BLOB:
        raise SystemExit(
            f"FAIL: preloader template changed; re-audit retry guard {blob} != {EXPECTED_PRELOADER_BLOB}"
        )

    text = raw.decode("utf-8")
    text = replace_once(
        text,
        '''                + "mkdir -p /data/adb\\n"\n                + "rm -f -- \\"$helper_stage\\" \\"$loader_stage\\" \\"$module_stage\\" "\n                + "\\"$probe_stage\\" \\"$late_log\\" \\"$journal\\"\\n"\n                + "boot_id=$(cat /proc/sys/kernel/random/boot_id)\\n"\n''',
        '''                + "mkdir -p /data/adb\\n"\n                + "boot_id=$(cat /proc/sys/kernel/random/boot_id)\\n"\n                + "if [ -e \\"$journal\\" ]; then\\n"\n                + "  count=$(grep -c '^BOOT_ID=' \\"$journal\\" 2>/dev/null || true)\\n"\n                + "  if [ \\"$count\\" -ne 1 ]; then\\n"\n                + "    echo M3Q_AZHJ_PHASE_JOURNAL_PROVENANCE_INVALID\\n"\n                + "    exit 0\\n"\n                + "  fi\\n"\n                + "  old_boot=$(sed -n 's/^BOOT_ID=//p' \\"$journal\\")\\n"\n                + "  if [ \\"$old_boot\\" = \\"$boot_id\\" ]; then\\n"\n                + "    echo M3Q_AZHJ_SAME_BOOT_ACTIVATION_EXISTS:$boot_id\\n"\n                + "    exit 0\\n"\n                + "  fi\\n"\n                + "fi\\n"\n                + "rm -f -- \\"$helper_stage\\" \\"$loader_stage\\" \\"$module_stage\\" "\n                + "\\"$probe_stage\\" \\"$late_log\\" \\"$journal\\"\\n"\n''',
        "same-boot journal preservation",
    )
    text = replace_once(
        text,
        '''        Log.i(TAG, "AZHJ bootstrap stage code=" + result.code + " output=" + result.output);\n        String receipt = "M3Q_AZHJ_KSU_BOOTSTRAP_STAGE_OK:"\n''',
        '''        Log.i(TAG, "AZHJ bootstrap stage code=" + result.code + " output=" + result.output);\n        if (result.output.contains("M3Q_AZHJ_SAME_BOOT_ACTIVATION_EXISTS:")) {\n            Log.e(TAG, "AZHJ KernelSU activation already attempted on this boot; reboot required");\n            return EXIT_REBOOT_REQUIRED;\n        }\n        if (result.output.contains("M3Q_AZHJ_PHASE_JOURNAL_PROVENANCE_INVALID")) {\n            Log.e(TAG, "AZHJ phase journal provenance is invalid; refusing to overwrite evidence");\n            return 125;\n        }\n        String receipt = "M3Q_AZHJ_KSU_BOOTSTRAP_STAGE_OK:"\n''',
        "retry guard result classification",
    )

    requirements = {
        "same-boot marker": text.count("M3Q_AZHJ_SAME_BOOT_ACTIVATION_EXISTS") == 2,
        "provenance marker": text.count("M3Q_AZHJ_PHASE_JOURNAL_PROVENANCE_INVALID") == 2,
        "single journal delete": text.count('"$probe_stage" "$late_log" "$journal"') == 1,
        "schema 2": "SCHEMA=2" in text,
        "foreground route": "ROUTE=FOREGROUND_EMBEDDED_LATE_LOAD" in text,
        "manual insmod absent": "runInsmod" not in text and "PRE_INSMOD" not in text,
    }
    for label, ok in requirements.items():
        if not ok:
            raise SystemExit(f"FAIL: retry-guard invariant missing: {label}")

    encoded = text.encode("utf-8")
    path.write_bytes(encoded)
    print(f"AZHJ_PRELOADER_RETRY_GUARD_SHA256={hashlib.sha256(encoded).hexdigest()}")
    print("AZHJ_PRELOADER_SAME_BOOT_RETRY_GUARD=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
