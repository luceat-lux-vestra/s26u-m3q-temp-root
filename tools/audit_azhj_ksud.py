#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
EM_AARCH64 = 183
ET_DYN = 3
LEGACY_KSUD_SHA256 = "3ce5753203c93f4d733fbc10eebd7a69152189afb1d2a15bfd855bd6b5d4f622"
FOREGROUND_KSUD_SHA256 = "83c754dcbacf1c5bd96836cc52380dcd5b5c9273e1f6a8bedfde2ddc0b7f3ab4"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def count_and_require(data: bytes, needle: bytes, label: str, minimum: int = 1) -> int:
    count = data.count(needle)
    print(f"{label}_occurrences={count}")
    if count < minimum:
        raise SystemExit(f"required marker {label!r} is absent")
    return count


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ksud", required=True, type=Path)
    args = ap.parse_args()

    data = args.ksud.read_bytes()
    digest = sha256(data)
    print(f"ksud_size={len(data)}")
    print(f"ksud_sha256={digest}")

    if digest == LEGACY_KSUD_SHA256:
        mode = "legacy-prebuilt"
    elif digest == FOREGROUND_KSUD_SHA256:
        mode = "azhj-foreground"
    else:
        raise SystemExit(f"unrecognized ksud sha256: {digest}")
    print(f"ksud_audit_mode={mode}")

    if len(data) < 64 or data[:4] != ELF_MAGIC:
        raise SystemExit("ksud is not ELF64")
    ident = data[:16]
    if ident[4] != 2 or ident[5] != 1:
        raise SystemExit("ksud is not ELF64 little-endian")
    e_type, machine = struct.unpack_from("<HH", data, 16)
    print(f"elf_type={e_type}")
    print(f"elf_machine={machine}")
    if e_type != ET_DYN or machine != EM_AARCH64:
        raise SystemExit("ksud is not AArch64 PIE/ET_DYN")

    # Both explicitly allowed binaries use KernelSU's compressed embedded asset
    # container and expose the extraction/late-load commands. The AZHJ custom
    # binary is additionally required to expose the hidden synchronous barrier.
    count_and_require(data, b"android16-6.12_kernelsu.ko", "kmi_asset_name")
    count_and_require(data, b"extract-binary", "extract_binary_cli")
    count_and_require(data, b"late-load", "late_load_cli")

    if mode == "azhj-foreground":
        count_and_require(data, b"m3q-foreground", "m3q_foreground_cli")
        count_and_require(
            data,
            b"M3Q_AZHJ_KSUD_FOREGROUND_LATE_LOAD",
            "m3q_foreground_runtime_marker",
        )
        print("foreground_completion_barrier=PASS")
    else:
        if b"m3q-foreground" in data or b"M3Q_AZHJ_KSUD_FOREGROUND_LATE_LOAD" in data:
            raise SystemExit("legacy prebuilt unexpectedly contains AZHJ foreground markers")
        print("legacy_prebuilt_container=PASS")

    old_release = b"6.12.30-android16-5-pd30ff70-abogkiS948NKSS4AZG3-4k"
    old_release_count = data.count(old_release)
    print(f"old_release_plaintext_occurrences={old_release_count}")
    if old_release_count != 0:
        raise SystemExit("unexpected plaintext embedded module release; audit assumptions changed")

    child_elfs = []
    p = 1
    while True:
        p = data.find(ELF_MAGIC, p)
        if p < 0:
            break
        child_elfs.append(p)
        p += 4
    print("child_elf_offsets=" + ",".join(f"0x{x:x}" for x in child_elfs))
    if child_elfs:
        raise SystemExit("unexpected raw child ELF; rust-embed compression assumptions changed")

    print("asset_container=rust-embed-compressed")
    print("module_extraction=ksud_debug_extract-binary_required")
    if mode == "azhj-foreground":
        print("embedded_module_late_load=PASS")
    print("AZHJ_KSUD_EXACT_HASH_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
