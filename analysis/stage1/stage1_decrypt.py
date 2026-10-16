#!/usr/bin/env python3
"""Recover the victim key of the Dustr stage-1 JXA loader and decrypt its blobs.

Reads the ORIGINAL (not restringer-folded) loader as text. Array literals are
parsed with a tiny single-operation evaluator, and the loader's RC4-drop cipher
and three-round RC4-MAC are re-implemented in Python. No sample code is ever
evaluated or executed. Every blob is accepted only if its 16-byte tag verifies.

The check labels and fixed arrays below are build-specific
(SHA-256 08d9c67a…49b5); see docs/writeup.md section 4.2.

usage: python3 -I stage1_decrypt.py <stage1.js> <out_dir>
"""
import os
import re
import sys

MAC_KEY = [213, 10, 91, 1, 114, 88, 225, 125, 205, 14, 155, 54, 236, 142, 25, 204]
BLOBS = {
    'applyLaunchAdapter': 'stage3_url.txt',
    'getConnectionValidator': 'install_dir.txt',
    'updateServiceAgent': 'stage2_installer.js',
}
ELEMENT = re.compile(r'^\(?\s*(-?\d+)\s*(?:([-+*^])\s*(-?\d+))?\s*\)?$')


def rc4_drop(key, data, drop):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    for _ in range(drop):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    for c in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def mac(data):
    d = list(data)
    while len(d) < 64:
        d.append(len(d) ^ 254)
    desc = list(rc4_drop(MAC_KEY, d, 744))
    fold = desc[:16]
    for off in range(16, len(desc), 16):
        for k in range(16):
            if off + k < len(desc):
                fold[k] ^= desc[off + k]
    desc = list(rc4_drop(fold, desc, 543))
    desc = list(rc4_drop([desc[i] ^ (i * 67 + 221) for i in range(16)], desc, 230))
    return bytes(desc[:32])


def label(s):
    return list(mac(s.encode())[:8])


def victim_key():
    material = (
        label('tcpRulebHcd')                              # no hypervisor
        + [176, 193, 194, 88, 103, 71, 230, 98]           # hardware model not a VM
        + label('batQuotavO7B')                           # SIP enabled
        + [99, 36, 175, 130, 148, 104, 215, 231]          # real AppleSMC
        + label('abmResultRPp6')                          # no debugger / injection / slowdown
        + label('dskURIjNvf') + label('smdCodegHzF')      # non-CIS locale and country
        + [31, 250, 206, 218, 193, 51, 45, 254]           # no CIS keyboard
        + [128, 150, 41, 34, 135, 132, 89, 8]             # non-CIS timezone
    )
    return list(mac(material))


def parse_array(src, name):
    m = re.search(r'var ' + name + r'\s*=\s*\[(.*?)\];', src, re.S)
    if not m:
        raise SystemExit(f'array {name} not found (different build?)')
    vals = []
    for item in m.group(1).split(','):
        e = ELEMENT.match(item.strip())
        if not e:
            raise SystemExit(f'unexpected element in {name}: {item!r}')
        a = int(e.group(1))
        if e.group(2):
            b = int(e.group(3))
            a = {'+': a + b, '-': a - b, '*': a * b, '^': a ^ b}[e.group(2)]
        vals.append(a & 0xFF)
    return vals


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    src = open(sys.argv[1], encoding='utf-8', errors='replace').read()
    out_dir = sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    key = victim_key()
    print('victim key:', bytes(key).hex())
    for name, out_name in BLOBS.items():
        blob = parse_array(src, name)
        tag, ct = bytes(blob[:16]), bytes(blob[16:])
        pt = rc4_drop(key, ct, 3113)
        ok = mac(pt)[:16] == tag
        print(f'{name:24s} {len(pt):5d} B  tag {"OK" if ok else "FAIL"}')
        if ok:
            path = os.path.join(out_dir, out_name + '.inert')
            with open(path, 'wb') as f:
                f.write(pt)
            os.chmod(path, 0o444)
            if len(pt) < 100:
                print('   ', pt.decode())


if __name__ == '__main__':
    main()
