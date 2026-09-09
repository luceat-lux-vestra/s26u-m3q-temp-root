#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
EM_AARCH64 = 183
ET_DYN = 3


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
    print(f"ksud_size={len(data)}")
    print(f"ksud_sha256={sha256(data)}")

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

    # KernelSU embeds assets with rust-embed's compression feature. The asset
    # name remains directly discoverable while the module bytes themselves are
    # compressed. Device preflight therefore materializes this exact asset via
    # `debug extract-binary` and hashes it before the single late-load write.
    count_and_require(data, b"android16-6.12_kernelsu.ko", "kmi_asset_name")
    count_and_require(data, b"extract-binary", "extract_binary_cli")
    count_and_require(data, b"late-load", "late_load_cli")

    # The AZHJ custom userspace build adds only a hidden foreground switch.
    # It keeps stock late-load behavior when the switch is absent, while the
    # M3Q helper uses foreground mode as a real completion barrier around
    # embedded module load + userspace late-load.
    count_and_require(data, b"m3q-foreground", "m3q_foreground_cli")
    count_and_require(
        data,
        b"M3Q_AZHJ_KSUD_FOREGROUND_LATE_LOAD",
        "m3q_foreground_runtime_marker",
    )

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
    print("embedded_module_late_load=PASS")
    print("foreground_completion_barrier=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
