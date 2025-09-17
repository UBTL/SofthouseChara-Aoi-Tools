#!/usr/bin/env python3
"""
AOI VFS Repacker (v1 & v2) — aoi_vfs_cli.py

Features
- vfs-list:     list entries
- vfs-extract:  extract one or many entries
- vfs-replace:  replace one entry and rebuild the VFS (size can change)
- vfs-replace-many: replace multiple entries from a TSV manifest
- Options: --align for payload alignment, --set-packed for replaced entries, preserve others

Formats:
- Header:
    int16 signature   ('VF' 0x4656 or 'VL' 0x4C56)
    int16 version     (0x0100, 0x0200, ...)
    int16 count
    int16 entry_size
    int32 index_size
    uint32 max_offset (= file size)
- v1 index (ASCII names in-place):
    name[0x13] ASCII NUL-terminated (max 0x13 bytes)
    uint32 offset
    uint32 size
    uint32 unpacked_size
    uint8  is_packed
    ... pad to entry_size
- v2 index (Unicode name table after index):
    uint32 name_char_offset          # index into UTF-16LE char array
    6 bytes reserved (zero)
    uint32 offset       @ +0x0A
    uint32 size         @ +0x0E
    uint32 unpacked     @ +0x12
    uint8  is_packed    @ +0x16
    ... pad to entry_size
  After the v2 index:
    int32 filenames_length (count of UTF-16 chars)
    int32 reserved (zero)
    UTF-16LE char array (filenames_length * 2 bytes)

UB: We don’t implement compression here. For replaced entries we default to is_packed=0
     and set size = unpacked = len(new content). Unreplaced entries keep original flags.
"""

import argparse, sys, struct, os
from pathlib import Path

def read_u16le(b, i): return int.from_bytes(b[i:i+2], 'little')
def read_u32le(b, i): return int.from_bytes(b[i:i+4], 'little')
def write_u16le(n):   return int(n).to_bytes(2, 'little')
def write_u32le(n):   return int(n).to_bytes(4, 'little')

class Vfs:
    def __init__(self, data: bytes):
        self.data = data
        self.sig  = read_u16le(data, 0)           # 'VF' or 'VL'
        self.ver  = read_u16le(data, 2)
        self.count= read_u16le(data, 4)
        self.esz  = read_u16le(data, 6)
        self.idx_size = read_u32le(data, 8)
        self.max_off  = read_u32le(data, 0xC)
        if self.sig not in (0x4656, 0x4C56):
            raise ValueError("Not an AOI VFS (signature mismatch)")
        if self.count <= 0 or self.esz <= 0:
            raise ValueError("Bad VFS header")
        self.v1 = self.ver < 0x0200
        self.index_off = 0x10
        self.entries = []
        if self.v1:
            self._parse_v1()
        else:
            self._parse_v2()

    def _parse_v1(self):
        i = self.index_off
        for _ in range(self.count):
            name = self._read_c_ascii(self.data, i, 0x13)
            off  = read_u32le(self.data, i+0x13)
            size = read_u32le(self.data, i+0x17)
            unpack= read_u32le(self.data, i+0x1B)
            packed = self.data[i+0x1F]
            self.entries.append({
                'name': name, 'off': off, 'size': size,
                'unpacked': unpack, 'packed': packed, 'dirpos': i
            })
            i += self.esz

    def _parse_v2(self):
        i = self.index_off
        name_offsets = []
        entries_tmp = []
        for _ in range(self.count):
            name_off_chars = read_u32le(self.data, i+0x00)
            off  = read_u32le(self.data, i+0x0A)
            size = read_u32le(self.data, i+0x0E)
            unpack= read_u32le(self.data, i+0x12)
            packed = self.data[i+0x16]
            entries_tmp.append({'name_off': name_off_chars, 'off': off, 'size': size,
                                'unpacked': unpack, 'packed': packed, 'dirpos': i})
            name_offsets.append(name_off_chars)
            i += self.esz
        # names table
        filenames_offset = self.index_off + self.esz * self.count
        fn_len_chars = read_u32le(self.data, filenames_offset)         # number of UTF-16 chars
        # skip 4 reserved bytes
        fn_blob = self.data[filenames_offset+8 : filenames_offset+8 + fn_len_chars*2]
        names_chars = fn_blob.decode('utf-16le', errors='strict')
        for et in entries_tmp:
            # find NUL-terminated starting at char index
            start = et['name_off']
            end = names_chars.find('\x00', start)
            if end < 0: end = len(names_chars)
            name = names_chars[start:end]
            et['name'] = name
        self.entries = entries_tmp
        self.names_chars = names_chars  # string of chars
        self.fn_len_chars = fn_len_chars
        self.fn_table_off = filenames_offset

    @staticmethod
    def _read_c_ascii(b, i, maxlen):
        raw = b[i:i+maxlen]
        if b'\x00' in raw:
            raw = raw.split(b'\x00',1)[0]
        return raw.decode('ascii', errors='ignore')

    # --- helpers ---
    def list(self):
        return [{'name': e['name'], 'off': e['off'], 'size': e['size'], 'packed': e['packed']} for e in self.entries]

    def extract(self, name: str) -> bytes:
        e = self._find(name)
        s, n = e['off'], e['size']
        if s + n > len(self.data):
            raise ValueError(f"Entry outside file (off=0x{s:08X}, size={n})")
        return self.data[s:s+n]

    def _find(self, name: str):
        for e in self.entries:
            if e['name'] == name:
                return e
        raise KeyError(f"Entry not found: {name}")

    # --- rebuild / repack ---
    def repack(self, replacements: dict, align: int = 1, set_packed: int = None) -> bytes:
        """
        replacements: dict name -> bytes
        align: alignment for payload region (1, 0x10, 0x800, ...)
        set_packed: if not None, force 'packed' flag for replaced entries (0 or 1)
        """
        # Build index model: we’ll reconstruct *all* offsets based on new sequential layout.
        # Names:
        names_list = [e['name'] for e in self.entries]
        # Build payloads
        payloads = {}
        for e in self.entries:
            nm = e['name']
            if nm in replacements:
                payloads[nm] = replacements[nm]
            else:
                payloads[nm] = self.extract(nm)

        # Recompute offsets with alignment after index block
        # First compute new index block (because its size differs in v1/v2)
        if self.v1:
            index_bytes, name_table_bytes, name_offsets = self._build_index_v1(names_list, payloads, align)
        else:
            index_bytes, name_table_bytes, name_offsets = self._build_index_v2(names_list, payloads, align)

        # Now lay out payloads after header + index + name table
        header_size = 0x10
        data_off = header_size + len(index_bytes) + len(name_table_bytes)
        # realign the start of payload region to 'align'
        if align > 1:
            pad = (-data_off) % align
            data_off += pad
            pad_bytes = b'\x00' * pad
        else:
            pad_bytes = b''

        # Compute each entry offset with per-file alignment (also align each file start)
        file_offsets = {}
        cur = data_off
        out_payload = bytearray()
        for nm in names_list:
            if align > 1:
                padf = (-cur) % align
                if padf:
                    out_payload += b'\x00' * padf
                    cur += padf
            file_offsets[nm] = cur
            out_payload += payloads[nm]
            cur += len(payloads[nm])

        # Re-emit index bytes with final offsets/sizes
        if self.v1:
            final_index = bytearray()
            i = 0
            for nm in names_list:
                off = file_offsets[nm]
                size = len(payloads[nm])
                unpacked = size
                packed = (self._find(nm)['packed'] if nm not in replacements else (set_packed if set_packed is not None else 0))
                # write entry
                # name[0x13]
                name_raw = nm.encode('ascii', errors='ignore')[:0x12]
                name_raw += b'\x00'
                name_raw = name_raw.ljust(0x13, b'\x00')
                final_index += name_raw
                final_index += write_u32le(off)
                final_index += write_u32le(size)
                final_index += write_u32le(unpacked)
                final_index += bytes([packed & 1])
                # pad to entry_size
                need = self.esz - (0x13 + 4 + 4 + 4 + 1)
                if need > 0: final_index += b'\x00' * need
            index_bytes = bytes(final_index)
            name_table_bytes = b''  # none for v1
        else:
            # Build names table from name_offsets (UTF-16), and index using name_offsets
            names_chars, name_map = self._build_names_chars(names_list)
            names_blob = names_chars.encode('utf-16le')
            # v2 name table: [len chars (u32)] [reserved u32=0] [UTF-16LE chars]
            name_table_bytes = write_u32le(len(names_chars)) + write_u32le(0) + names_blob

            final_index = bytearray()
            for nm in names_list:
                name_off_chars = name_map[nm]
                off = file_offsets[nm]
                size = len(payloads[nm])
                unpacked = size
                packed = (self._find(nm)['packed'] if nm not in replacements else (set_packed if set_packed is not None else 0))
                # layout matches read positions used by engine:
                # 0x00 name_off (u32), 0x04..0x09 zeros, 0x0A off, 0x0E size, 0x12 unpack, 0x16 packed
                ent = bytearray(self.esz)
                ent[0x00:0x04] = write_u32le(name_off_chars)
                ent[0x0A:0x0E] = write_u32le(off)
                ent[0x0E:0x12] = write_u32le(size)
                ent[0x12:0x16] = write_u32le(unpacked)
                ent[0x16] = packed & 1
                final_index += ent
            index_bytes = bytes(final_index)

        # Build final file
        # header: sig, ver, count, entry_size, index_size, max_offset
        index_total = len(index_bytes) + len(name_table_bytes)
        # plus possible pad before payload region
        index_total_with_pad = index_total + len(pad_bytes)
        max_offset = header_size + index_total_with_pad + len(out_payload)
        out = bytearray()
        out += write_u16le(self.sig)
        out += write_u16le(self.ver)
        out += write_u16le(self.count)
        out += write_u16le(self.esz)
        out += write_u32le(index_total)      # index_size
        out += write_u32le(max_offset)       # max_offset == total file size
        out += index_bytes
        out += name_table_bytes
        out += pad_bytes
        out += out_payload
        return bytes(out)

    def _build_index_v1(self, names_list, payloads, align):
        # Placeholder; actual index is rebuilt in repack (we need final offsets then)
        return b'', b'', {}

    def _build_names_chars(self, names_list):
        # Build a single UTF-16 names char array, returning (string, map name->char_offset)
        # Use exact names (no NULs inside), join with NUL terminators
        # We will store each NUL too because name offsets assume C-string termination in char array.
        chars = []
        offsets = {}
        cur = 0
        for nm in names_list:
            offsets[nm] = cur
            chars.append(nm)
            cur += len(nm)
            chars.append('\x00')
            cur += 1
        return ''.join(chars), offsets

    def _build_index_v2(self, names_list, payloads, align):
        # Placeholder; actual index is rebuilt in repack with final offsets
        return b'', b'', {}

# ---------------- CLI commands ----------------

def cmd_vfs_list(args):
    v = Vfs(Path(args.vfs).read_bytes())
    kind = 'v1' if v.v1 else 'v2'
    print(f"{Path(args.vfs).name}: {kind}  entries={v.count}  entry_size=0x{v.esz:04X}  index_size={v.idx_size}  file_size={len(v.data)}")
    for e in v.list():
        print(f"{e['name']:<32} off=0x{e['off']:08X} size={e['size']:<8} packed={e['packed']}")

def cmd_vfs_extract(args):
    v = Vfs(Path(args.vfs).read_bytes())
    names = [args.name] if args.name else [e['name'] for e in v.entries]
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    for nm in names:
        blob = v.extract(nm)
        (outdir / nm).write_bytes(blob)
        print(f"wrote {nm} ({len(blob)} bytes)")

def cmd_vfs_replace(args):
    v = Vfs(Path(args.vfs).read_bytes())
    rep = {}
    if args.name and args.input:
        rep[args.name] = Path(args.input).read_bytes()
    elif args.map:
        # TSV: NAME \t PATH
        lines = Path(args.map).read_text(encoding='utf-8', errors='replace').splitlines()
        for ln in lines:
            if not ln.strip() or '\t' not in ln: continue
            nm, path = ln.split('\t', 1)
            rep[nm] = Path(path).read_bytes()
    else:
        raise SystemExit("Provide --name/--input or --map TSV")
    out = v.repack(rep, align=args.align, set_packed=(0 if args.set_packed is None else args.set_packed))
    Path(args.out).write_bytes(out)
    print(f"Repacked VFS → {args.out} (size {len(out)}) with {len(rep)} replacement(s)")

def main(argv=None):
    p = argparse.ArgumentParser(description="AOI VFS repacker (v1 & v2)")
    sub = p.add_subparsers(dest='cmd', required=True)

    sp = sub.add_parser('vfs-list', help='List entries in a VFS')
    sp.add_argument('--vfs', required=True)
    sp.set_defaults(func=cmd_vfs_list)

    sp = sub.add_parser('vfs-extract', help='Extract one or all entries')
    sp.add_argument('--vfs', required=True)
    sp.add_argument('--name', default=None, help='Entry to extract (omit to extract all)')
    sp.add_argument('--outdir', required=True)
    sp.set_defaults(func=cmd_vfs_extract)

    sp = sub.add_parser('vfs-replace', help='Replace one or many entries and rebuild VFS')
    sp.add_argument('--vfs', required=True)
    sp.add_argument('--name', help='Entry name (e.g., ev0000.box)')
    sp.add_argument('--input', help='File to insert for --name')
    sp.add_argument('--map', help='TSV with "NAME\\tPATH" for multiple replacements')
    sp.add_argument('--out', required=True, help='Output VFS')
    sp.add_argument('--align', type=lambda x:int(x,0), default=0x10, help='Payload alignment (default 0x10)')
    sp.add_argument('--set-packed', type=int, choices=[0,1], default=None, help='Force is_packed for replaced entries')
    sp.set_defaults(func=cmd_vfs_replace)

    args = p.parse_args(argv)
    args.func(args)

if __name__ == '__main__':
    main()

