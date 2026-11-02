#!/usr/bin/env python3
"""Decode TWDIW 1.0.14 public resources from APKs and existing JADX exports."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import zipfile

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
PRIVATE_ASSETS = {"dwapp201i_private", "dwapp201i_private.txt"}


def fnv_name(name):
    value = 2166136261
    for byte in name.encode("utf-8"):
        value = ((value ^ (byte if byte < 128 else byte - 256)) * 16777619) & MASK32
    return value if value < 1 << 31 else value - (1 << 32)


def outer(data, seed):
    state = 0
    increment = ((-2931877044612338191 << 1) | 1) & MASK64

    def step():
        nonlocal state
        old = state
        state = (old * 6364136223846793005 + increment) & MASK64
        value = (((old >> 18) ^ old) >> 27) & MASK32
        rotate = old >> 59
        return ((value >> rotate) | (value << ((-rotate) & 31))) & MASK32

    step()
    state = (state + seed) & MASK64
    step()
    result = bytearray(data)
    for position in range(0, len(result), 8):
        result[position] ^= step() & 255
    return bytes(result)


def unpad(data, size):
    count = data[-1]
    if not 0 < count <= size or data[-count:] != bytes([count]) * count:
        raise ValueError("Invalid resource padding")
    return data[:-count]


class BlowfishReader:
    def __init__(self, source):
        arrays = [[int(v.strip()) & MASK32 for v in value.split(",")]
                  for value in re.findall(r"new int\[\]\{([^}]+)\}", source)]
        self.boxes = [array for array in arrays if len(array) == 256][:4]
        self.p = next(array for array in arrays if len(array) == 18)[:10]
        assert len(self.boxes) == 4
        seed = -6639427643208925628 & MASK64
        mask = -1395600743
        key = [((seed >> 32) ^ mask) & MASK32, (seed ^ mask) & MASK32]
        self.p = [value ^ key[i % 2] for i, value in enumerate(self.p)]
        left = right = 0
        for i in range(0, 10, 2):
            left, right = self.block(left, right, self.p)
            self.p[i:i + 2] = [left, right]

    def block(self, left, right, keys):
        a, b, c, d = self.boxes
        for key in keys[:-2]:
            value = (left ^ key) & MASK32
            f = (((a[value >> 24] + b[(value >> 16) & 255]) ^ c[(value >> 8) & 255]) + d[value & 255]) & MASK32
            left, right = (right ^ f) & MASK32, value
        return (right ^ keys[-1]) & MASK32, (left ^ keys[-2]) & MASK32

    def decode(self, data):
        previous = bytes([113, 52, 179, 37, 242, 102, 103, 72])
        result = bytearray()
        for i in range(0, len(data), 8):
            block = data[i:i + 8]
            plain = struct.pack(">II", *self.block(*struct.unpack(">II", block), self.p[::-1]))
            result.extend(a ^ b for a, b in zip(plain, previous))
            previous = block
        return unpad(bytes(result), 8)


def tea_reader(data):
    seed = 4839887100434401090
    mask = -534197003
    high = ((seed >> 32) ^ mask) & MASK32
    low = (seed ^ mask) & MASK32
    a, b, c, d = low, (low * 133194826) & MASK32, low ^ 133194826, high
    previous = bytes([2, 121, 79, 65, 25, 0, 99, 121])
    result = bytearray()
    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        left, right = struct.unpack(">II", block)
        for round_number in range(16, 0, -1):
            total = -25033 * round_number
            right = (right - ((total + left) ^ ((left << 4) + c) ^ ((left >> 5) + d))) & MASK32
            left = (left - (((right << 4) + a) ^ (total + right) ^ ((right >> 5) + b))) & MASK32
        result.extend(x ^ y for x, y in zip(struct.pack(">II", left, right), previous))
        previous = block
    return unpad(bytes(result), 8)


def multiply(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 128 else 0)) & 255
        b >>= 1
    return result


class RijndaelReader:
    def __init__(self):
        forward = []
        for value in range(256):
            inverse = next((candidate for candidate in range(1, 256) if multiply(value, candidate) == 1), 0)
            mapped = inverse ^ 99
            for shift in range(1, 5):
                mapped ^= ((inverse << shift) | (inverse >> (8 - shift))) & 255
            forward.append(mapped)
        self.inverse = [forward.index(value) for value in range(256)]
        self.tables = [[] for _ in range(4)]
        for value in self.inverse:
            word = (multiply(value, 14) << 24) | (multiply(value, 9) << 16) | (multiply(value, 13) << 8) | multiply(value, 11)
            for row in range(4):
                self.tables[row].append(((word >> (row * 8)) | (word << ((32 - row * 8) % 32))) & MASK32)
        key = bytearray([68, 90, 74, 14, 53, 251, 53, 159, 22, 39, 184, 173, 174, 105, 26, 177])
        for i in range(16):
            if (-5690177298485300937 & MASK64) & (1 << i):
                key[i] ^= 177
        expanded = list(struct.unpack(">4I", key))
        constant = 1
        for i in range(4, 44):
            word = expanded[-1]
            if i % 4 == 0:
                word = ((forward[(word >> 16) & 255] << 24) | (forward[(word >> 8) & 255] << 16)
                        | (forward[word & 255] << 8) | forward[word >> 24]) ^ (constant << 24)
                constant = multiply(constant, 2)
            expanded.append(expanded[i - 4] ^ word)
        self.keys = expanded[40:44]
        for i in range(36, 0, -4):
            for word in expanded[i:i + 4]:
                self.keys.append(self.tables[0][forward[word >> 24]] ^ self.tables[1][forward[(word >> 16) & 255]]
                                 ^ self.tables[2][forward[(word >> 8) & 255]] ^ self.tables[3][forward[word & 255]])
        self.keys.extend(expanded[:4])
        permutation = [[(2022170910 >> (row * 8 + column * 2)) & 3 for column in range(4)] for row in range(4)]
        self.rows = [[row.index(column) for column in range(4)] for row in permutation]

    def decode(self, data):
        result = bytearray()
        t0, t1, t2, t3 = self.tables
        p0, p1, p2, p3 = self.rows
        keys, inverse = self.keys, self.inverse
        for i in range(0, len(data), 16):
            words = [v ^ k for v, k in zip(struct.unpack(">4I", data[i:i + 16]), keys)]
            for start in range(4, 40, 4):
                words = [t0[words[p0[c]] >> 24] ^ t1[(words[p1[c]] >> 16) & 255]
                         ^ t2[(words[p2[c]] >> 8) & 255] ^ t3[words[p3[c]] & 255] ^ keys[start + c] for c in range(4)]
            words = [((inverse[words[p0[c]] >> 24] << 24) | (inverse[(words[p1[c]] >> 16) & 255] << 16)
                      | (inverse[(words[p2[c]] >> 8) & 255] << 8) | inverse[words[p3[c]] & 255]) ^ keys[40 + c] for c in range(4)]
            result.extend(struct.pack(">4I", *words))
        return unpad(bytes(result), 16)


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk-dir", type=Path, required=True)
    parser.add_argument("--jadx-main", type=Path, required=True)
    parser.add_argument("--jadx-stage-b", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source = (args.jadx_stage_b / "o/JcPQWBA.java").read_text()
    seeds = {int(k): int(v) for k, v in re.findall(r"r0.put\((-?\d+), (-?\d+)L\)", source)}
    algorithms = {int(k): int(v) for k, v in re.findall(r"r1.put\((-?\d+), (\d+)\)", source)}
    blowfish = BlowfishReader((args.jadx_main / "o/jHzEsshZ.java").read_text())
    rijndael = RijndaelReader()
    decoders = {0: blowfish.decode, 2: rijndael.decode, 3: tea_reader}
    manifest = []
    for apk in sorted(args.apk_dir.glob("*.apk")):
        with zipfile.ZipFile(apk) as package:
            for entry in package.infolist():
                if not entry.filename.startswith("assets/") or entry.is_dir():
                    continue
                name = entry.filename[len("assets/"):]
                if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
                    raise ValueError("Unsafe asset path")
                item = dict(apk=apk.name, path=entry.filename, raw_bytes=entry.file_size,
                            filename_hash=fnv_name(name), algorithm=algorithms.get(fnv_name(name)))
                manifest.append(item)
                data = package.read(entry)
                item["raw_sha256"] = hashlib.sha256(data).hexdigest()
                if name in PRIVATE_ASSETS:
                    dump(args.out / "raw" / apk.name / entry.filename, data)
                    item["status"] = "preserved_original_private_asset_not_decoded"
                    continue
                dump(args.out / "raw" / apk.name / entry.filename, data)
                try:
                    if item["algorithm"] is None:
                        plain = data
                        item["status"] = "original_unprotected"
                    else:
                        plain = decoders[item["algorithm"]](outer(data, seeds[fnv_name(name)]))
                        item["status"] = "decoded"
                    dump(args.out / "decoded" / entry.filename, plain)
                    item["decoded_bytes"] = len(plain)
                    item["decoded_sha256"] = hashlib.sha256(plain).hexdigest()
                    item["decoded_magic_hex"] = plain[:16].hex()
                except Exception as error:
                    item["status"] = "decode_failed"
                    item["error"] = type(error).__name__ + ": " + str(error)
                print(json.dumps(item))
    dump(args.out / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())


if __name__ == "__main__":
    main()
