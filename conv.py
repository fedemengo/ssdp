#!/usr/bin/env python3

import argparse, sys, re
from typing import Tuple

ALLOWED = {"RAW","NOT_RAW","INT_BE","INT_LE","NOT_BE","NOT_LE","BIN","BIN_NOT"}

def bitwise_not_bytes(b: bytes) -> bytes:
    return bytes((~x) & 0xFF for x in b)

def _pad_trunc_left(s: str, width: int) -> str:
    """Left-pad with zeros, then keep the rightmost width chars."""
    if len(s) < width:
        s = s.zfill(width)
    return s[-width:]

def _to_sized_bytes_from_int(iv: int, size: int, endian: str) -> bytes:
    if size <= 0:
        raise ValueError("size must be > 0")
    mask = (1 << (8 * size)) - 1
    iv &= mask  # truncate to requested width
    return iv.to_bytes(size, endian, signed=False)

def parse_value_by_rep(rep: str, value: str, size: int) -> bytes:
    """
    Parse `value` according to representation `rep`, and return exactly `size` bytes.
    For RAW/BIN inputs, we do lenient sizing: zero-pad left, then truncate on the left if too long.
    For INT inputs, we mask to the requested width.
    """
    rep = rep.upper()
    if rep not in ALLOWED:
        raise ValueError(f"format must be one of: {', '.join(sorted(ALLOWED))}")

    if rep in ("RAW", "NOT_RAW"):
        hexstr = re.sub(r"[ _]", "", value)
        if not re.fullmatch(r"[0-9a-fA-F]*", hexstr or ""):
            raise ValueError("RAW contains non-hex characters")
        hexstr = _pad_trunc_left(hexstr, size * 2)
        b = bytes.fromhex(hexstr)
        return bitwise_not_bytes(b) if rep == "NOT_RAW" else b

    if rep in ("INT_BE", "INT_LE", "NOT_BE", "NOT_LE"):
        endian = "big" if rep.endswith("BE") else "little"
        try:
            iv = int(value, 0)  # accepts 0x..., decimal, etc.
        except ValueError:
            raise ValueError("Invalid integer format")
        b = _to_sized_bytes_from_int(iv, size, endian)
        return bitwise_not_bytes(b) if rep.startswith("NOT") else b

    if rep in ("BIN", "BIN_NOT"):
        bits = re.sub(r"[ _]", "", value)
        if not bits:  # allow empty -> zero
            bits = "0"
        if not set(bits) <= {"0", "1"}:
            raise ValueError("BIN contains non-binary characters")
        bits = _pad_trunc_left(bits, size * 8)
        iv = int(bits, 2)
        b = _to_sized_bytes_from_int(iv, size, "big")
        return bitwise_not_bytes(b) if rep.endswith("NOT") else b

    raise ValueError("Unsupported format")

def all_formats(value: str, size: int):
    for rep in sorted(ALLOWED):
        try:
            b = parse_value_by_rep(rep, value, size)
            yield rep, b.hex()
        except Exception as e:
            # Only emit valid outputs; skip noisy errors
            continue

def main():
    ap = argparse.ArgumentParser(
        description="Interpret VALUE in all supported formats and print each as a hex string of SIZE bytes."
    )
    ap.add_argument("VALUE", help="The input value (hex for RAW, 0/1 for BIN, int for INT_*)")
    ap.add_argument("SIZE", type=int, help="Output width in bytes")
    args = ap.parse_args()

    any_out = False
    for rep, hx in all_formats(args.VALUE, args.SIZE):
        print(f"{rep:7}: {hx}")
        any_out = True
    if not any_out:
        print("No representations could be parsed. Check your input.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
