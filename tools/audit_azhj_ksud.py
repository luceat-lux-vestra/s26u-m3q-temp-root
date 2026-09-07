#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
EM_AARCH64 = 183
ET_REL = 1
SHT_NOBITS = 8
SHN_UNDEF = 0


@dataclass
class Section:
    name: str
    sh_type: int
    offset: int
    size: int
    link: int
    entsize: int


@dataclass
class ElfImage:
    offset: int
    end: int
    e_type: int
    machine: int
    sections: list[Section]

    def section(self, name: str) -> Section:
        matches = [s for s in self.sections if s.name == name]
        if len(matches) != 1:
            raise RuntimeError(f"ELF@0x{self.offset:x}: section {name!r} count={len(matches)}")
        return matches[0]


def cstr(data: bytes, start: int, limit: int) -> str:
    end = data.find(b"\0", start, limit)
    if end < 0:
        raise RuntimeError("unterminated ELF string")
    return data[start:end].decode("ascii", errors="strict")


def parse_elf(data: bytes, base: int) -> ElfImage | None:
    if data[base:base + 4] != ELF_MAGIC or base + 64 > len(data):
        return None
    ident = data[base:base + 16]
    if ident[4] != 2 or ident[5] != 1:  # ELF64 little endian
        return None
    try:
        (
            e_type, machine, _version, _entry, _phoff, shoff, _flags,
            ehsize, _phentsize, _phnum, shentsize, shnum, shstrndx,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", data, base + 16)
    except struct.error:
        return None
    if machine != EM_AARCH64 or ehsize != 64 or shentsize != 64:
        return None
    if shnum == 0 or shstrndx >= shnum:
        return None
    sht_end = base + shoff + shentsize * shnum
    if shoff == 0 or sht_end > len(data):
        return None

    raw = []
    for i in range(shnum):
        p = base + shoff + i * shentsize
        try:
            raw.append(struct.unpack_from("<IIQQQQIIQQ", data, p))
        except struct.error:
            return None

    shstr = raw[shstrndx]
    shstr_off = base + shstr[4]
    shstr_end = shstr_off + shstr[5]
    if shstr_end > len(data):
        return None

    sections: list[Section] = []
    image_end = max(base + ehsize, sht_end)
    for row in raw:
        name_off, sh_type, _flags, _addr, sec_off, sec_size, link, _info, _align, entsize = row
        if name_off >= shstr[5]:
            return None
        try:
            name = cstr(data, shstr_off + name_off, shstr_end)
        except (RuntimeError, UnicodeDecodeError):
            return None
        if sh_type != SHT_NOBITS:
            sec_end = base + sec_off + sec_size
            if sec_end > len(data):
                return None
            image_end = max(image_end, sec_end)
        sections.append(Section(name, sh_type, sec_off, sec_size, link, entsize))
    return ElfImage(base, image_end, e_type, machine, sections)


def section_bytes(data: bytes, elf: ElfImage, section: Section) -> bytes:
    start = elf.offset + section.offset
    return data[start:start + section.size]


def undefined_symbols(data: bytes, elf: ElfImage) -> list[str]:
    symtab = elf.section(".symtab")
    if not symtab.entsize:
        raise RuntimeError(".symtab has zero entsize")
    if symtab.link >= len(elf.sections):
        raise RuntimeError(".symtab link out of range")
    strtab = elf.sections[symtab.link]
    strings = section_bytes(data, elf, strtab)
    symbols = section_bytes(data, elf, symtab)
    result = set()
    for p in range(0, len(symbols) - symtab.entsize + 1, symtab.entsize):
        if symtab.entsize < 24:
            raise RuntimeError("unexpected ELF64 symbol size")
        st_name, _info, _other, st_shndx, _value, _size = struct.unpack_from("<IBBHQQ", symbols, p)
        if st_shndx != SHN_UNDEF or st_name == 0 or st_name >= len(strings):
            continue
        try:
            name = cstr(strings, st_name, len(strings))
        except RuntimeError:
            continue
        if name:
            result.add(name)
    return sorted(result)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ksud", required=True, type=Path)
    ap.add_argument("--old-release", required=True)
    ap.add_argument("--new-release", required=True)
    ap.add_argument("--patched-ksud", type=Path)
    ap.add_argument("--patched-module", type=Path)
    ap.add_argument("--imports", type=Path)
    args = ap.parse_args()

    old = args.old_release.encode("ascii")
    new = args.new_release.encode("ascii")
    if len(old) != len(new):
        raise SystemExit("refusing in-place vermagic patch: release lengths differ")

    data = args.ksud.read_bytes()
    print(f"ksud_size={len(data)}")
    print(f"ksud_sha256={sha256(data)}")
    print(f"old_release_occurrences={data.count(old)}")
    print(f"new_release_occurrences_before={data.count(new)}")

    offsets = []
    pos = 0
    while True:
        pos = data.find(ELF_MAGIC, pos)
        if pos < 0:
            break
        offsets.append(pos)
        pos += 4

    parsed = [e for off in offsets if (e := parse_elf(data, off)) is not None]
    print("elf_candidates=" + ",".join(
        f"0x{e.offset:x}:type={e.e_type}:end=0x{e.end:x}" for e in parsed
    ))

    modules = []
    for elf in parsed:
        if elf.e_type != ET_REL:
            continue
        try:
            modinfo = section_bytes(data, elf, elf.section(".modinfo"))
        except RuntimeError:
            continue
        if old in modinfo or new in modinfo:
            modules.append((elf, modinfo))
    if len(modules) != 1:
        raise SystemExit(f"expected exactly one embedded KernelSU module, found {len(modules)}")

    elf, modinfo = modules[0]
    print(f"embedded_module_offset=0x{elf.offset:x}")
    print(f"embedded_module_size={elf.end - elf.offset}")
    print(f"embedded_module_sha256={sha256(data[elf.offset:elf.end])}")
    for item in modinfo.split(b"\0"):
        if item.startswith((b"vermagic=", b"name=", b"license=", b"depends=")):
            print("modinfo=" + item.decode("ascii", errors="replace"))

    imports = undefined_symbols(data, elf)
    print(f"undefined_import_count={len(imports)}")
    for name in imports:
        print(f"undefined={name}")
    if args.imports:
        args.imports.write_text("\n".join(imports) + "\n", encoding="utf-8")

    old_positions = []
    p = 0
    while True:
        p = data.find(old, p)
        if p < 0:
            break
        old_positions.append(p)
        p += len(old)
    if not old_positions:
        raise SystemExit("old release string is absent; refusing patch")
    if any(not (elf.offset <= p < elf.end) for p in old_positions):
        raise SystemExit("old release string occurs outside embedded module; refusing patch")

    patched = bytearray(data)
    for p in old_positions:
        patched[p:p + len(old)] = new
    patched = bytes(patched)
    if patched.count(old) != 0 or patched.count(new) < len(old_positions):
        raise SystemExit("release patch verification failed")
    diff = [i for i, (a, b) in enumerate(zip(data, patched)) if a != b]
    expected_diff = sum(a != b for a, b in zip(old, new)) * len(old_positions)
    if len(diff) != expected_diff:
        raise SystemExit(f"unexpected patch diff bytes: {len(diff)} != {expected_diff}")
    print(f"patched_diff_bytes={len(diff)}")
    print(f"patched_ksud_sha256={sha256(patched)}")

    patched_elf = parse_elf(patched, elf.offset)
    if patched_elf is None:
        raise SystemExit("patched embedded module no longer parses as ELF")
    patched_modinfo = section_bytes(patched, patched_elf, patched_elf.section(".modinfo"))
    if old in patched_modinfo or new not in patched_modinfo:
        raise SystemExit("patched .modinfo vermagic verification failed")

    if args.patched_ksud:
        args.patched_ksud.write_bytes(patched)
    if args.patched_module:
        args.patched_module.write_bytes(patched[patched_elf.offset:patched_elf.end])
        print(f"patched_module_sha256={sha256(patched[patched_elf.offset:patched_elf.end])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
