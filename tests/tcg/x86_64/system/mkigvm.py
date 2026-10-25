#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2026 The ASTERISC Research Lab
#
# mkigvm.py: wrap a flat x86_64 ELF test (tests/tcg/x86_64/system) into an
# IGVM file for the emulated SEV-ES guest of QEMU TCG: the PT_LOAD pages at
# their physical addresses and one VP context (VMSA) that enters the ELF's
# entry point in 32-bit protected mode with flat segments, as the PVH entry
# of boot.S expects. Only the Python standard library is used; the layout
# follows the IGVM specification (github.com/microsoft/igvm).
#
# Usage: mkigvm.py [--platform sev-es|sev|snp] <elf> <output.igvm>

import argparse
import struct
import zlib

PAGE = 4096
IGVM_MAGIC = 0x4D564749
VHT_SUPPORTED_PLATFORM = 0x1
VHT_PAGE_DATA = 0x302
VHT_VP_CONTEXT = 0x304
PLATFORM = {'sev': 4, 'sev-es': 5, 'snp': 2}
VMSA_GPA = 0xFFFFFFFFF000
# the SNP secrets and CPUID pages, above the test image (sev-es.c reads them)
SNP_SECRETS_GPA = 0x3fe000
SNP_CPUID_GPA = 0x3ff000
PAGE_DATA_SECRETS = 1
PAGE_DATA_CPUID = 2


def symbol(data, shoff, shentsize, shnum, name):
    """The value of `name` in the ELF's symbol table, or None."""
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize)
                for i in range(shnum)]
    for sh in sections:
        sh_type, sh_offset, sh_size, sh_link, sh_entsize = sh[1], sh[4], sh[5], sh[6], sh[9]
        if sh_type != 2:    # SHT_SYMTAB
            continue
        strtab = sections[sh_link]
        for j in range(sh_size // sh_entsize):
            st_name, _info, _other, _shndx, st_value, _size = \
                struct.unpack_from('<IBBHQQ', data, sh_offset + j * sh_entsize)
            end = data.index(b'\0', strtab[4] + st_name)
            if data[strtab[4] + st_name:end] == name.encode():
                return st_value
    return None


def elf_pages(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] != b'\x7fELF' or data[4] != 2:
        raise SystemExit(f'{path}: not an ELF64 file')
    e_entry, e_phoff, e_shoff = struct.unpack_from('<QQQ', data, 0x18)
    e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
        struct.unpack_from('<HHHHH', data, 0x36)
    # the tests enter through _start (the PVH note's entry), not through e_entry
    e_entry = symbol(data, e_shoff, e_shentsize, e_shnum, '_start') or e_entry
    pages = {}
    for i in range(e_phnum):
        p_type, _flags, p_offset, _vaddr, p_paddr, p_filesz, p_memsz, _align = \
            struct.unpack_from('<IIQQQQQQ', data, e_phoff + i * e_phentsize)
        if p_type != 1 or not p_memsz:
            continue
        seg = data[p_offset:p_offset + p_filesz] + bytes(p_memsz - p_filesz)
        start = p_paddr & ~(PAGE - 1)
        end = (p_paddr + p_memsz + PAGE - 1) & ~(PAGE - 1)
        for gpa in range(start, end, PAGE):
            page = pages.setdefault(gpa, bytearray(PAGE))
            lo, hi = max(gpa, p_paddr), min(gpa + PAGE, p_paddr + p_memsz)
            page[lo - gpa:hi - gpa] = seg[lo - p_paddr:hi - p_paddr]
    return pages, e_entry


def vmsa(entry, snp):
    v = bytearray(PAGE)

    def seg(off, selector, attrib, limit, base):
        struct.pack_into('<HHIQ', v, off, selector, attrib, limit, base)

    for off in (0x00, 0x20, 0x30, 0x40, 0x50):              # es, ss, ds, fs, gs
        seg(off, 0x10, 0xc93, 0xffffffff, 0)
    seg(0x10, 0x08, 0xc9b, 0xffffffff, 0)                   # cs: 32-bit code
    seg(0x70, 0, 0x82, 0xffff, 0)                            # ldtr
    seg(0x90, 0, 0x8b, 0xffff, 0)                            # tr
    struct.pack_into('<Q', v, 0xd0, 0x1000)                 # efer: SVME
    struct.pack_into('<Q', v, 0x158, 0x11)                  # cr0: PE, ET
    struct.pack_into('<Q', v, 0x160, 0x400)                 # dr7
    struct.pack_into('<Q', v, 0x168, 0xffff0ff0)            # dr6
    struct.pack_into('<Q', v, 0x170, 0x2)                   # rflags
    struct.pack_into('<Q', v, 0x178, entry)                 # rip
    struct.pack_into('<Q', v, 0x268, 0x0007040600070406)    # g_pat
    struct.pack_into('<Q', v, 0x3b0, 1 if snp else 0)       # sev_features
    struct.pack_into('<Q', v, 0x3e8, 0x1)                   # xcr0
    struct.pack_into('<I', v, 0x408, 0x1f80)                # mxcsr
    struct.pack_into('<H', v, 0x410, 0x37f)                 # x87 fcw
    return bytes(v)


def vheader(typ, payload):
    hdr = struct.pack('<II', typ, len(payload)) + payload
    return hdr + bytes(-len(hdr) % 8)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--platform', choices=PLATFORM, default='sev-es')
    ap.add_argument('elf')
    ap.add_argument('output')
    args = ap.parse_args()

    pages, entry = elf_pages(args.elf)
    mask = 1
    headers = vheader(VHT_SUPPORTED_PLATFORM,
                      struct.pack('<IBBHQ', mask, 0, PLATFORM[args.platform], 1, 0))
    page_hdr = len(vheader(VHT_PAGE_DATA, bytes(24)))
    vp_hdr = len(vheader(VHT_VP_CONTEXT, bytes(20)))
    with_vmsa = args.platform != 'sev'
    extra = 2 if args.platform == 'snp' else 0
    data_start = 24 + len(headers) + (len(pages) + extra) * page_hdr + (vp_hdr if with_vmsa else 0)
    file_data = bytearray()
    for gpa in sorted(pages):
        page = bytes(pages[gpa])
        if any(page):
            off = data_start + len(file_data)
            file_data += page
        else:
            off = 0
        headers += vheader(VHT_PAGE_DATA, struct.pack('<QIIIHH', gpa, mask, off, 0, 0, 0))
    if args.platform == 'snp':
        for gpa, typ in ((SNP_SECRETS_GPA, PAGE_DATA_SECRETS), (SNP_CPUID_GPA, PAGE_DATA_CPUID)):
            headers += vheader(VHT_PAGE_DATA, struct.pack('<QIIIHH', gpa, mask, 0, 0, typ, 0))
    if with_vmsa:
        off = data_start + len(file_data)
        file_data += vmsa(entry, args.platform == 'snp')
        headers += vheader(VHT_VP_CONTEXT, struct.pack('<QIIHH', VMSA_GPA, mask, off, 0, 0))
    total = data_start + len(file_data)
    fixed = struct.pack('<IIIIII', IGVM_MAGIC, 1, 24, len(headers), total, 0)
    checksum = zlib.crc32(fixed + headers) & 0xffffffff
    fixed = struct.pack('<IIIIII', IGVM_MAGIC, 1, 24, len(headers), total, checksum)
    with open(args.output, 'wb') as f:
        f.write(fixed + headers + file_data)


if __name__ == '__main__':
    main()
