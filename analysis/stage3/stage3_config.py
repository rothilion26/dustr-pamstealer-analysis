#!/usr/bin/env python3
"""Statically decrypt the Dustr stage-3 (Rust) agent's configuration.

Scheme (docs/writeup.md section 6):
    global = XOR of the environment-gated K constants (8 shares, 4 of them decoys)
    key    = HKDF-SHA256(salt=field1, ikm=global_u64_le, info=master16)
    pt     = XChaCha20-Poly1305(key, nonce=field2).decrypt(field3)

The K constants are recomputed from the immediates fed to the combiner at
0x100084668. The script self-checks that every decoy evaluates to 0, finds the
single global that authenticates, then decrypts every config literal.
With --helper it also extracts the ChaCha20-encrypted kh_tmp helper as an
inert, non-executable file. Nothing from the sample is executed.

Addresses are build-specific (arm64 LC_UUID 4AC4E1F7-446B-3549-9A69-6F7DDD4E260F).

usage: python3 -I stage3_config.py <stage3 universal or arm64 Mach-O> [--helper <out_dir>]
requires: pycryptodome
"""
import hashlib
import hmac
import os
import struct
import sys

from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305

BASE = 0x100000000
MASTER = (0x1000b8e20, 0x20)
LITERALS = {
    'campaign tag': (0x1000b8d84, 0x9c),
    'C2 URL': (0x1000b8e40, 0xd2),
    'ETH contract': (0x1000b8f17, 0xe6),
    '32-byte key': (0x1000b8ffd, 0xd2),
}
HELPER = {'blob': (0x1000b90d2, 0xdb70), 'key': (0x1000c6c42, 32), 'nonce': (0x1000c6c62, 12)}

# (function VA, 8 x u16 immediates, combiner mode)
REAL_K = [
    (0x100084a58, [22563, 27464, 32426, 12581, 5306, 13355, 52634, 47206], 5),
    (0x100084be8, [41907, 62595, 30598, 28481, 26202, 27358, 14136, 44880], 3),
    (0x100084464, [0x5362, 0xaba2, 0xa929, 0x367b, 0x2566, 0x4cae, 0x6a1d, 0x8d1d], 0),
    (0x100084a90, [2334, 27359, 27240, 21447, 35475, 4035, 29163, 61764], 7),
    (0x100084bb0, [30833, 397, 54966, 29317, 20514, 52960, 6418, 52456], 7),
    (0x100084a20, [46319, 57525, 16204, 5075, 20144, 32611, 56018, 55478], 5),
    (0x100084b70, [0x4e8c, 0x584b, 0xc911, 0x7c95, 0x992e, 0xf284, 0x6b59, 0x1ed1], 4),
    (0x100084978, [18608, 49115, 56971, 10071, 30648, 44991, 2108, 31854], 5),
    (0x1000849e8, [20571, 45363, 29332, 22012, 25583, 28447, 40411, 62036], 2),
]
DECOY_K = [
    (0x1000849b0, [40416, 58648, 56128, 51756, 5744, 28967, 42078, 227], 7),
    (0x100084ac8, [17510, 28634, 59264, 11054, 45853, 649, 22655, 24629], 7),
    (0x100084b00, [14251, 10455, 57924, 62379, 14251, 55080, 57924, 54777], 1),
    (0x100084b38, [0, 0, 0, 0, 47772, 8734, 13877, 39059], 2),
    (0x100084c20, [0x961a, 0xffc0, 0xdf4e, 0x34c] * 2, 6),
    (0x100084c60, [60716, 15149, 20909, 36688] * 2, 3),
    (0x100084c98, [8796, 38296, 25522, 49464, 10291, 35898, 15249, 12039], 7),
    (0x100084cd0, [0xfe6a, 0x71ff, 0x407a, 0xa49b] * 2, 6),
]
M16 = 0xFFFF


def inv(x):
    x |= 1
    y = x
    for _ in range(5):
        y = (y * (2 - x * y)) & 0xFFFFFFFF
    return y


def rot16(v, n, left):
    v &= M16
    n &= 15
    if not n:
        return v
    return ((v << n) | (v >> (16 - n))) & M16 if left else ((v >> n) | (v << (16 - n))) & M16


def lane(mode, a, b, idx):
    if mode == 0:
        return a ^ b
    if mode == 1:
        return rot16(a, b, False) ^ b if idx in (1, 3) else a ^ b
    if mode == 2:
        return (a ^ b) - b
    if mode == 3:
        return (a ^ b) * inv(b)
    if mode == 4:
        v = (a ^ b) & M16
        return ((v & 0xFF) << 8) | (v >> 8)
    if mode == 5:
        return ~(a ^ b)
    if mode == 6:
        return rot16(a - b, b, True)
    return ((a - b) * inv(b)) ^ b


def combine(args, mode):
    r = [lane(mode, args[i], args[i + 4], i) & M16 for i in range(4)]
    return (r[0] << 48) | (r[1] << 32) | (r[2] << 16) | r[3]


def hkdf_sha256(salt, ikm, info):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b'\x01', hashlib.sha256).digest()


def arm64_slice(data):
    magic = struct.unpack('>I', data[:4])[0]
    if magic == 0xcafebabe:
        for i in range(struct.unpack('>I', data[4:8])[0]):
            cpu, _, off, size, _ = struct.unpack('>IIIII', data[8 + 20 * i:28 + 20 * i])
            if cpu == 0x0100000c:
                return data[off:off + size]
        raise SystemExit('no arm64 slice')
    if data[:4] == b'\xcf\xfa\xed\xfe':
        return data
    raise SystemExit('not a Mach-O')


def main():
    if len(sys.argv) not in (2, 4):
        raise SystemExit(__doc__)
    sl = arm64_slice(open(sys.argv[1], 'rb').read())

    def read(va, n):
        return sl[va - BASE:va - BASE + n]

    for va, args, mode in DECOY_K:
        assert combine(args, mode) == 0, f'decoy {hex(va)} is not zero'
    print(f'{len(DECOY_K)} decoy K constants evaluate to 0 (combiner re-implementation OK)')

    master = bytes.fromhex(read(*MASTER).decode())
    fields = {name: [bytes.fromhex(x) for x in read(va, n).decode().split(':')]
              for name, (va, n) in LITERALS.items()}

    def try_decrypt(global_value, parts):
        salt, nonce, ct = parts
        key = hkdf_sha256(salt, struct.pack('<Q', global_value), master)
        return ChaCha20_Poly1305.new(key=key, nonce=nonce).decrypt_and_verify(ct[:-16], ct[-16:])

    ks = [combine(a, m) for _, a, m in REAL_K]
    hits = []
    for mask in range(1 << len(ks)):
        g = 0
        for i, k in enumerate(ks):
            if mask >> i & 1:
                g ^= k
        try:
            try_decrypt(g, fields['campaign tag'])
            hits.append((mask, g))
        except ValueError:
            pass
    if len(hits) != 1:
        raise SystemExit(f'expected exactly one authenticating global, got {len(hits)}')
    mask, g = hits[0]
    absent = [hex(REAL_K[i][0]) for i in range(len(REAL_K)) if not mask >> i & 1]
    print(f'global = {g:#018x}  (1 of {1 << len(ks)}; shares absent: {absent})')

    for name, parts in fields.items():
        pt = try_decrypt(g, parts)
        shown = pt.decode() if all(32 <= c < 127 for c in pt) else pt.hex()
        print(f'  {name:13s} {shown}')

    if len(sys.argv) == 4 and sys.argv[2] == '--helper':
        blob = read(*HELPER['blob'])
        plain = ChaCha20.new(key=read(*HELPER['key']), nonce=read(*HELPER['nonce'])).decrypt(blob)
        if plain[:4] != b'\xcf\xfa\xed\xfe':
            raise SystemExit('helper did not decrypt to a Mach-O')
        os.makedirs(sys.argv[3], exist_ok=True)
        path = os.path.join(sys.argv[3], 'kh_tmp.bin.inert')
        with open(path, 'wb') as f:
            f.write(plain)
        os.chmod(path, 0o444)
        print(f'kh_tmp -> {path} (sha256 {hashlib.sha256(plain).hexdigest()})')


if __name__ == '__main__':
    main()
