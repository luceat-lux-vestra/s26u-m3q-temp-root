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

    # KernelSU embeds assets with rust-embed's `compression` feature. The
    # filenames remain part of Asset::iter()/lookup metadata, while file data
    # is DEFLATE-compressed by include-flate. Therefore a raw child-ELF scan
    # is deliberately not used as an extraction mechanism.
    count_and_require(data, b"android16-6.12_kernelsu.ko", "kmi_asset_name")
    count_and_require(data, b"extract-binary", "extract_binary_cli")

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
