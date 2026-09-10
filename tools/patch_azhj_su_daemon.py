#!/usr/bin/env python3
"""Build-time AZHJ overlay for the bootstrap helper's KernelSU late-load path."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

EXPECTED_SOURCE_BLOB = "a506c46e65689a016a67abc9ed8860b704e405d8"


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"FAIL: {label} anchor cardinality={count}, expected 1")
    return text.replace(old, new)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} INPUT_SU_DAEMON_C OUTPUT_SU_DAEMON_C")

    src = Path(sys.argv[1])
    out = Path(sys.argv[2])
    raw = src.read_bytes()
    blob = git_blob_sha1(raw)
    print(f"AZHJ_SU_DAEMON_SOURCE_GIT_BLOB_SHA1={blob}")
    if blob != EXPECTED_SOURCE_BLOB:
        raise SystemExit(
            f"FAIL: su_daemon.c source changed; re-audit AZHJ overlay {blob} != {EXPECTED_SOURCE_BLOB}"
        )

    text = raw.decode("utf-8")
    text = replace_once(
        text,
        '''      execl(LOGCAT_PATH, "logcat", "late-load", "--kmi", "android16-6.12",\n            "--package-name", "me.weishu.kernelsu", (char *)NULL);\n''',
        '''      execl(LOGCAT_PATH, "logcat", "late-load", "--m3q-foreground",\n            "--kmi", "android16-6.12", "--package-name",\n            "me.weishu.kernelsu", (char *)NULL);\n''',
        "foreground late-load exec",
    )
    text = replace_once(
        text,
        '''    int status = wait_status(loader);\n    if (status != 0) _exit(status);\n    _exit(verify_kernelsu_control());\n''',
        '''    int status = wait_status(loader);\n    if (status != 0) _exit(status);\n    dprintf(STDOUT_FILENO, "M3Q_AZHJ_KSU_LATE_LOAD_FOREGROUND_RETURNED\\n");\n    int control_status = verify_kernelsu_control();\n    if (control_status == 0) {\n      dprintf(STDOUT_FILENO, "M3Q_AZHJ_KSU_LATE_LOAD_CONTROL_OK\\n");\n    }\n    _exit(control_status);\n''',
        "foreground completion receipt",
    )

    checks = {
        "foreground flag": text.count('"--m3q-foreground"') == 1,
        "foreground returned receipt": text.count("M3Q_AZHJ_KSU_LATE_LOAD_FOREGROUND_RETURNED") == 1,
        "control receipt": text.count("M3Q_AZHJ_KSU_LATE_LOAD_CONTROL_OK") == 1,
        "single post-loader control": text.count("int control_status = verify_kernelsu_control();") == 1,
    }
    for label, ok in checks.items():
        if not ok:
            raise SystemExit(f"FAIL: patched helper invariant missing: {label}")

    out.parent.mkdir(parents=True, exist_ok=True)
    encoded = text.encode("utf-8")
    out.write_bytes(encoded)
    print(f"AZHJ_SU_DAEMON_PATCHED_SHA256={hashlib.sha256(encoded).hexdigest()}")
    print("AZHJ_SU_DAEMON_FOREGROUND_PATCH=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
