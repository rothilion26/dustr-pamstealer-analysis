#!/usr/bin/env python3
"""Statically recover the secret-share constants of the stage-3 binary.
Parses otool disassembly text, re-implements the 8x16-bit combiner
(FUN_100084668) in Python, and maps every write site of the eight
shares (0x1000e0ad8..0x1000e0b10) to the K constant it XORs in.

Input: disasm_arm64.txt in the working directory
       (otool -arch arm64 -tV <sample> > disasm_arm64.txt).
Known limitation: K functions that set the combiner mode inline
(`strb wzr/w8, [sp]` instead of calling a stub: 0x100084464, 0x100084b70,
0x100084c20, 0x100084cd0) are reported with mode None. Their modes (0, 4, 6, 6)
were read manually and are hard-coded in stage3_config.py."""
import json
import re

COMBINER = 0x100084668
SHARES = [0x1000e0ad8 + 8 * i for i in range(8)]
READERS = range(0x100084384, 0x100084464)
M16 = 0xFFFF


def load():
    rows = []
    for line in open('disasm_arm64.txt'):
        m = re.match(r'^([0-9a-f]{16})\t(\S+)\t?(.*)$', line.rstrip('\n'))
        if m:
            rows.append((int(m.group(1), 16), m.group(2), m.group(3)))
    return rows


def inv16(x):
    x |= 1
    y = x
    for _ in range(5):
        y = (y * (2 - x * y)) & 0xFFFFFFFF
    return y


def rotr16(v, n):
    v &= M16
    n &= 15
    return ((v >> n) | (v << (16 - n))) & M16 if n else v


def rotl16(v, n):
    v &= M16
    n &= 15
    return ((v << n) | (v >> (16 - n))) & M16 if n else v


def lane(mode, a, b, idx):
    if mode == 0:
        return a ^ b
    if mode == 1:
        return (rotr16(a, b) ^ b) if idx in (1, 3) else (a ^ b)
    if mode == 2:
        return (a ^ b) - b
    if mode == 3:
        return (a ^ b) * inv16(b)
    if mode == 4:
        v = (a ^ b) & M16
        return ((v & 0xFF) << 8) | (v >> 8)
    if mode == 5:
        return ~(a ^ b)
    if mode == 6:
        return rotl16(a - b, b)
    return (((a - b) * inv16(b)) ^ b)


def combine(args, mode):
    r = [lane(mode, args[i], args[i + 4], i) & M16 for i in range(4)]
    return (r[0] << 48) | (r[1] << 32) | (r[2] << 16) | r[3]


def main():
    rows = load()
    idx = {a: i for i, (a, _, _) in enumerate(rows)}

    def stub_mode(addr):
        i = idx[addr]
        for a, op, arg in rows[i:i + 6]:
            m = re.match(r'w8, #(0x[0-9a-f]+|\d+)', arg)
            if op == 'mov' and m:
                return int(m.group(1), 0)
            if op == 'ret':
                break
        return None

    kfuncs = {}
    for i, (a, op, arg) in enumerate(rows):
        if op == 'bl' and arg.startswith(hex(COMBINER)):
            args = {}
            stub = None
            for pa, pop, parg in rows[max(0, i - 12):i]:
                m = re.match(r'w([0-7]), #(0x[0-9a-f]+|\d+)', parg)
                if pop == 'mov' and m:
                    args[int(m.group(1))] = int(m.group(2), 0)
                if pop == 'bl':
                    stub = int(parg.split()[0], 16)
            start = rows[max(0, i - 12)][0]
            for back in range(i, max(0, i - 14), -1):
                if rows[back][1] == 'sub' and rows[back][2].startswith('sp, sp'):
                    start = rows[back][0]
                    break
            mode = stub_mode(stub) if stub else None
            vals = [args.get(k, 0) for k in range(8)]
            kfuncs[start] = {'args': vals, 'stub': hex(stub) if stub else None, 'mode': mode,
                             'K': hex(combine(vals, mode)) if mode is not None else None}

    adr = re.compile(r'(\w+), #(-?\d+)')
    writers = []
    for i, (a, op, arg) in enumerate(rows):
        if op != 'adr' or a in READERS:
            continue
        m = adr.match(arg)
        tgt = a + int(m.group(2)) if m else None
        if tgt not in SHARES:
            continue
        kf = None
        for pa, pop, parg in reversed(rows[max(0, i - 40):i + 8]):
            if pop == 'bl':
                t = int(parg.split()[0], 16)
                if t in kfuncs:
                    kf = t
                    if pa < a:
                        break
        writers.append({'share': hex(tgt), 'site': hex(a), 'kfunc': hex(kf) if kf else None,
                        'K': kfuncs[kf]['K'] if kf else None})

    for k, v in sorted(kfuncs.items()):
        print(hex(k), v)
    print()
    for w in sorted(writers, key=lambda x: x['share']):
        print(w)
    json.dump({'kfuncs': {hex(k): v for k, v in kfuncs.items()}, 'writers': writers},
              open('shares.json', 'w'), indent=1)


if __name__ == '__main__':
    main()
