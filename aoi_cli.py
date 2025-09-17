#!/usr/bin/env python3
"""
AOI Script CLI (BOX + EV9) — dump, decrypt, decompile, compile, and patch.

Supported:
- BOX (AOIBX10) directory parsing (fixed 16-byte ASCII names).
- XOR decrypt/encrypt with per-version constant (default for X10 = 0xB2).
- EV9-like token stream decompile to taggy text and compile back.
- Patch a BOX entry with equal-sized encrypted bytes (safe replace).

Round-trip rules:
- Shift-JIS (cp932) strings by default. Use --unicode for UTF-16LE (rare here).
- Integers are 0x82 + BE 32-bit signed.
- Strings are 0x88 + 1-byte char count + raw bytes (SJIS) or 2-byte chars (UTF-16LE).
- Commands: <music N> <background "file" L> <sprite "file" A B L> <removesprite A B>
            <name "Speaker" ["!VOICE"]> <exit> # (line break)
- Labels: standalone line ':HEX' (or ':HEX:'), references emitted/parsed.

NOTE: This CLI targets AOIBX10 (XOR 0xB2). AOIMY (offset-based key) is NOT implemented.
"""

import sys, io, struct, re
from pathlib import Path

# ------------------------------- utils -------------------------------

def be_i32(n):
    return int(n).to_bytes(4, 'big', signed=True)

def read_be_i32(b, i):
    return int.from_bytes(b[i:i+4], 'big', signed=True), i+4

def xor_bytes(buf: bytes, key: int) -> bytes:
    k = key & 0xFF
    return bytes([x ^ k for x in buf])

def sjis_encode(s: str) -> bytes:
    return s.encode('cp932', errors='strict')

def sjis_decode(b: bytes) -> str:
    return b.decode('cp932', errors='strict')

# ------------------------------- BOX (AOIBX10) -------------------------------

class BoxX10:
    def __init__(self, data: bytes):
        if data[:7] != b'AOIBX10':
            raise ValueError("Not an AOIBX10 BOX")
        self.data = bytearray(data)
        self.count = int.from_bytes(self.data[8:12], 'little')
        self.entries = []
        i = 0x10
        for _ in range(self.count):
            name = bytes(self.data[i:i+0x10]).split(b'\x00', 1)[0].decode('ascii', 'ignore')
            off  = int.from_bytes(self.data[i+0x10:i+0x14], 'little')
            size = int.from_bytes(self.data[i+0x14:i+0x18], 'little')
            self.entries.append({'name': name, 'off': off, 'size': size, 'dirpos': i})
            i += 0x18

    def list(self):
        return [{'name': e['name'], 'off': e['off'], 'size': e['size']} for e in self.entries]

    def get(self, name: str) -> bytes:
        e = next((e for e in self.entries if e['name'] == name), None)
        if not e:
            raise KeyError(f"Entry not found: {name}")
        s, n = e['off'], e['size']
        return bytes(self.data[s:s+n])

    def patch(self, name: str, new_bytes: bytes):
        e = next((e for e in self.entries if e['name'] == name), None)
        if not e:
            raise KeyError(f"Entry not found: {name}")
        if len(new_bytes) != e['size']:
            raise ValueError(f"Length mismatch. Expected {e['size']} bytes, got {len(new_bytes)}. (Resize not supported)")
        s = e['off']
        self.data[s:s+len(new_bytes)] = new_bytes

    def save(self, path: Path):
        path.write_bytes(self.data)

# ------------------------------- EV9 decompiler -------------------------------

TOK_INT   = 0x82
TOK_STR   = 0x88
CMD_PREFIX= 0x2B

# tag codes
T_MUSIC   = 0x41
T_VIDEO   = 0x49
T_BG      = 0x4C
T_SPRITE  = 0x52
T_RMSPR   = 0x56

# inline opcodes (no prefix)
OP_NAME   = 0x03
OP_TEXT   = 0x02
OP_BRK    = 0x05
OP_EXIT   = 0x17
OP_LABEL  = 0x92

def read_sjis_string(b: bytes, i: int, using_unicode: bool):
    if i >= len(b) or b[i] != TOK_STR:
        return None, i
    i += 1
    if i >= len(b): return None, i
    length_chars = b[i]; i += 1
    n = length_chars * (2 if using_unicode else 1)
    if n == 0 or i + n > len(b): return None, i
    raw = b[i:i+n]; i += n
    try:
        s = raw.decode('utf-16le' if using_unicode else 'cp932')
    except Exception:
        s = raw.decode('cp932', errors='replace')
    return s, i

def read_int(b: bytes, i: int):
    if i >= len(b) or b[i] != TOK_INT:
        return None, i
    i += 1
    if i + 4 > len(b): return None, i
    val = int.from_bytes(b[i:i+4], 'big', signed=True); i += 4
    if -32500 < val < 32500:
        return str(val), i
    return '0x' + format((val + (1<<32)) % (1<<32), '08X'), i

def _q(s: str) -> str:
    return '"' + s.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n').replace('\r','\\r').replace('\x00','\\0') + '"'

def decompile_tokens(buf: bytes, using_unicode=False, max_lines=100000):
    out = []
    i = 0
    n = len(buf)
    # heuristic: skip EV9 header "AOIEV9" if present by scanning for first plausible token
    if buf[:5] == b'AOIEV':
        # search for first OP_NAME/OP_TEXT/CMD_PREFIX in next 4KB
        scan_end = min(4096, n-1)
        best = 0
        best_i = None
        for s in range(0, scan_end):
            score = 0; j = s; steps = 0
            while j < n and steps < 80:
                b = buf[j]
                if b == CMD_PREFIX and j+1 < n and buf[j+1] in (T_MUSIC,T_VIDEO,T_BG,T_SPRITE,T_RMSPR):
                    score += 3; j += 2; steps += 1
                elif b in (OP_TEXT, OP_NAME, OP_BRK, OP_EXIT, OP_LABEL):
                    score += 2; j += 1; steps += 1
                else:
                    j += 1; steps += 1
            if score > best:
                best = score; best_i = s
        if best_i is not None and best >= 30:
            i = best_i

    while i < n and len(out) < max_lines:
        b = buf[i]
        if b == CMD_PREFIX and i+1 < n:
            cmd = buf[i+1]; i += 2
            if cmd == T_MUSIC:
                v,i = read_int(buf, i); out.append(f'<music {v if v else ""}>'); continue
            if cmd == T_VIDEO:
                s,i = read_sjis_string(buf, i, using_unicode); out.append(f'<video {_q(s) if s else ""}>'); continue
            if cmd == T_BG:
                s,i = read_sjis_string(buf, i, using_unicode)
                v,i = read_int(buf, i)
                out.append(f'<background {_q(s) if s else ""} {v if v else ""}>'); continue
            if cmd == T_SPRITE:
                s,i = read_sjis_string(buf, i, using_unicode)
                a,i = read_int(buf, i); b2,i = read_int(buf, i); c,i = read_int(buf, i)
                # consume possible 2-byte padding for Unicode builds
                if using_unicode and i+1<n and buf[i]==0 and buf[i+1]==0: i += 2
                out.append(f'<sprite {_q(s) if s else ""} {a} {b2} {c}>'); continue
            if cmd == T_RMSPR:
                a,i = read_int(buf, i); b2,i = read_int(buf, i)
                if using_unicode and i+1<n and buf[i]==0 and buf[i+1]==0: i += 2
                out.append(f'<removesprite {a} {b2}>'); continue
            out.append(f'\\x2B\\x{cmd:02X}'); continue

        if b == OP_NAME:
            i += 1
            s1,i = read_sjis_string(buf, i, using_unicode)
            tag = '<name' + (f' {_q(s1)}' if s1 else '')
            # optional voice id or 0x00
            if i < n:
                if buf[i] == 0:
                    i += 1
                else:
                    s2,i = read_sjis_string(buf, i, using_unicode)
                    if s2: tag += f' {_q(s2)}'
            if using_unicode and i<n and buf[i]==0: i += 1
            out.append(tag + '>'); continue

        if b == OP_TEXT:
            i += 1
            s,i = read_sjis_string(buf, i, using_unicode)
            out.append(s if s else ''); continue

        if b == OP_BRK:
            i += 1; out.append('#'); continue

        if b == OP_EXIT:
            i += 1; out.append('<exit>'); continue

        if b == OP_LABEL and i+5 <= n:
            i += 1
            addr = int.from_bytes(buf[i:i+4], 'big', signed=True); i += 4
            out.append(':'+format(addr, 'X')); continue

        # raw unknown byte (kept for round-trip safety)
        out.append('\\x'+format(b, '02X')); i += 1

    return '\n'.join(out)

# ------------------------------- EV9 compiler -------------------------------

class CompileCtx:
    def __init__(self, using_unicode=False):
        self.using_unicode = using_unicode
        self.out = bytearray()
        self.labels_defs = {}   # label hex -> position
        self.labels_refs = []   # (pos_to_patch, label_hex)

    def emit_int(self, v: int):
        self.out.append(TOK_INT); self.out += be_i32(v)

    def emit_str(self, s: str):
        if self.using_unicode:
            raw = s.encode('utf-16le')
            chars = len(s)  # approximate; engine uses char count
            self.out.append(TOK_STR); self.out.append(chars & 0xFF); self.out += raw
        else:
            raw = sjis_encode(s)
            if len(raw) > 0xFF:
                raise ValueError(f"String too long for 1-byte length: {len(raw)} bytes")
            self.out.append(TOK_STR); self.out.append(len(raw)); self.out += raw

    def emit_cmd(self, code: int):
        self.out.append(CMD_PREFIX); self.out.append(code)

    def emit_label_def(self, label_hex: str):
        # store mapping but also emit a line for readability (not an opcode)
        try:
            val = int(label_hex, 16)
        except:
            raise ValueError(f"Bad label: {label_hex}")
        # Opcode form in stream uses OP_LABEL when referenced, not for def.
        # For def, we just note current byte offset for lookups if needed.
        self.labels_defs[label_hex.upper()] = len(self.out)

    def emit_label_ref(self, label_hex: str):
        self.out.append(OP_LABEL)
        patch_pos = len(self.out)
        self.out += b'\x00\x00\x00\x00'  # placeholder
        self.labels_refs.append((patch_pos, label_hex.upper()))

    def patch_labels(self):
        for pos, name in self.labels_refs:
            if name not in self.labels_defs:
                raise ValueError(f"Undefined label :{name}")
            addr = self.labels_defs[name]
            self.out[pos:pos+4] = be_i32(addr)

def parse_line_compile(ctx: CompileCtx, line: str):
    s = line.strip()
    if not s:
        return
    # label def like :1A2B or :1A2B:
    if s.startswith(':'):
        lab = s[1:].strip(':').strip()
        if re.fullmatch(r'[0-9A-Fa-f]+', lab):
            ctx.emit_label_def(lab)
            return
    if s == '#':
        ctx.out.append(OP_BRK); return
    if s == '<exit>':
        ctx.out.append(OP_EXIT); return

    m = re.match(r'<music\s+(.+?)\s*>$', s)
    if m:
        ctx.emit_cmd(T_MUSIC)
        v = int(m.group(1), 0)
        ctx.emit_int(v)
        return

    m = re.match(r'<video\s+"(.+?)"\s*>$', s)
    if m:
        ctx.emit_cmd(T_VIDEO)
        ctx.emit_str(m.group(1))
        return

    m = re.match(r'<background\s+"(.+?)"\s+(.+?)\s*>$', s)
    if m:
        ctx.emit_cmd(T_BG)
        ctx.emit_str(m.group(1))
        ctx.emit_int(int(m.group(2), 0))
        return

    m = re.match(r'<sprite\s+"(.+?)"\s+(.+?)\s+(.+?)\s+(.+?)\s*>$', s)
    if m:
        ctx.emit_cmd(T_SPRITE)
        ctx.emit_str(m.group(1))
        ctx.emit_int(int(m.group(2), 0))
        ctx.emit_int(int(m.group(3), 0))
        ctx.emit_int(int(m.group(4), 0))
        if ctx.using_unicode:
            ctx.out += b'\x00\x00'  # observed padding in Unicode builds
        return

    m = re.match(r'<removesprite\s+(.+?)\s+(.+?)\s*>$', s)
    if m:
        ctx.emit_cmd(T_RMSPR)
        ctx.emit_int(int(m.group(1), 0))
        ctx.emit_int(int(m.group(2), 0))
        if ctx.using_unicode:
            ctx.out += b'\x00\x00'
        return

    m = re.match(r'<name\s+"(.+?)"(?:\s+"(.+?)")?\s*>$', s)
    if m:
        ctx.out.append(OP_NAME)
        ctx.emit_str(m.group(1))
        if m.group(2) is None:
            ctx.out.append(0x00)  # observed "null" between name and voice id
        else:
            ctx.emit_str(m.group(2))
        if ctx.using_unicode:
            ctx.out.append(0x00)
        return

    # choice with label and two bytes at the end: <choice :LABEL: "caption" \x12\x34>
    m = re.match(r'<choice\s+:(.+?):\s+"(.+?)"\s+(\\x[0-9A-Fa-f]{2})(\\x[0-9A-Fa-f]{2})\s*>$', s)
    if m:
        ctx.out.append(0x07)
        ctx.emit_label_ref(m.group(1))
        ctx.emit_str(m.group(2))
        b1 = int(m.group(3)[2:], 16); b2 = int(m.group(4)[2:], 16)
        ctx.out.append(b1); ctx.out.append(b2)
        return

    # Plain text line: emit text opcode + string
    # (Allow quoted syntax too: "text")
    if s.startswith('"') and s.endswith('"'):
        s = bytes(s[1:-1], 'utf-8').decode('unicode_escape')
    ctx.out.append(OP_TEXT)
    ctx.emit_str(s)

def compile_text(lines, using_unicode=False):
    ctx = CompileCtx(using_unicode=using_unicode)
    for raw in lines:
        parse_line_compile(ctx, raw.rstrip('\n'))
    ctx.patch_labels()
    return bytes(ctx.out)

# ------------------------------- CLI -------------------------------

def cmd_list(args):
    box = BoxX10(Path(args.box).read_bytes())
    for e in box.list():
        print(f"{e['name']:<16}  off=0x{e['off']:08X}  size={e['size']}")

def cmd_extract(args):
    box = BoxX10(Path(args.box).read_bytes())
    raw = box.get(args.name)
    dec = xor_bytes(raw, args.key)
    Path(args.out).write_bytes(dec)
    print(f"Wrote decrypted: {args.out} ({len(dec)} bytes)")

def cmd_decompile(args):
    data = Path(args.input).read_bytes()
    text = decompile_tokens(data, using_unicode=args.unicode)
    Path(args.out).write_text(text, encoding='utf-8')
    print(f"Wrote decompiled text: {args.out} ({len(text.splitlines())} lines)")

def cmd_compile(args):
    lines = Path(args.input).read_text(encoding='utf-8', errors='replace').splitlines()
    data = compile_text(lines, using_unicode=args.unicode)
    Path(args.out).write_bytes(data)
    print(f"Wrote compiled EV bytes: {args.out} ({len(data)} bytes)")

def cmd_encrypt(args):
    data = Path(args.input).read_bytes()
    enc = xor_bytes(data, args.key)
    Path(args.out).write_bytes(enc)
    print(f"Wrote encrypted: {args.out} ({len(enc)} bytes)")

def cmd_patch(args):
    box = BoxX10(Path(args.box).read_bytes())
    new_bytes = Path(args.input).read_bytes()
    box.patch(args.name, new_bytes)
    box.save(Path(args.out))
    print(f"Patched BOX entry '{args.name}' into {args.out}")

def main(argv=None):
    p = argparse.ArgumentParser(description="AOI BOX/EV9 CLI")
    sub = p.add_subparsers(dest='cmd', required=True)

    sp = sub.add_parser('list', help='List entries in AOIBX10 box')
    sp.add_argument('--box', required=True)
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser('extract', help='Decrypt and extract an entry to .dec')
    sp.add_argument('--box', required=True)
    sp.add_argument('--name', required=True, help='Entry name (e.g., ev0101.txt)')
    sp.add_argument('--out', required=True)
    sp.add_argument('--key', type=lambda x:int(x,0), default=0xB2, help='XOR key (default 0xB2)')
    sp.set_defaults(func=cmd_extract)

    sp = sub.add_parser('decompile', help='Decompile EV9 to taggy text')
    sp.add_argument('--input', required=True, help='.dec (decrypted) file')
    sp.add_argument('--out', required=True)
    sp.add_argument('--unicode', action='store_true', help='Use UTF-16LE strings (rare)')
    sp.set_defaults(func=cmd_decompile)

    sp = sub.add_parser('compile', help='Compile taggy text to EV bytes')
    sp.add_argument('--input', required=True, help='taggy .txt')
    sp.add_argument('--out', required=True)
    sp.add_argument('--unicode', action='store_true')
    sp.set_defaults(func=cmd_compile)

    sp = sub.add_parser('encrypt', help='Encrypt EV bytes back to .enc')
    sp.add_argument('--input', required=True)
    sp.add_argument('--out', required=True)
    sp.add_argument('--key', type=lambda x:int(x,0), default=0xB2)
    sp.set_defaults(func=cmd_encrypt)

    sp = sub.add_parser('patch', help='Replace a BOX entry with a new encrypted blob (same size)')
    sp.add_argument('--box', required=True)
    sp.add_argument('--name', required=True)
    sp.add_argument('--input', required=True, help='.enc file (same size as original)')
    sp.add_argument('--out', required=True, help='output BOX file')
    sp.set_defaults(func=cmd_patch)

    args = p.parse_args(argv)
    args.func(args)

if __name__ == '__main__':
    main()
