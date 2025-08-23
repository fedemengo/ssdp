#!/usr/bin/env python3

import argparse, sys

ALLOWED = {"RAW","NOT_RAW","INT_BE","INT_LE","NOT_BE","NOT_LE","BIN","BIN_NOT"}

def bitwise_not_bytes(b: bytes) -> bytes:
    return bytes((~x) & 0xFF for x in b)

def parse_value_by_rep(rep: str, value: str, size: int) -> bytes:
    rep = rep.upper()
    if rep not in ALLOWED:
        raise ValueError(f"format must be one of: {', '.join(sorted(ALLOWED))}")

    if rep in ("RAW", "NOT_RAW"):
        hexstr = value.replace(" ", "").replace("_", "")
        if len(hexstr) != size * 2:
            raise ValueError(f"RAW expects exactly {size} bytes ({size*2} hex chars)")
        try:
            b = bytes.fromhex(hexstr)
        except ValueError:
            raise ValueError("RAW contains non-hex characters")
        return bitwise_not_bytes(b) if rep == "NOT_RAW" else b

    if rep in ("INT_BE", "INT_LE", "NOT_BE", "NOT_LE"):
        endian = "big" if rep.endswith("BE") else "little"
        try:
            iv = int(value, 0)  # accepts 123, 0xff, 0b1010
        except ValueError:
            raise ValueError("INT expects a valid integer (decimal/0x/0b)")
        if iv < 0 or iv >= (1 << (8 * size)):
            raise ValueError(f"integer out of range for {size} bytes")
        b = iv.to_bytes(size, endian, signed=False)
        return bitwise_not_bytes(b) if rep.startswith("NOT_") else b

    if rep in ("BIN", "BIN_NOT"):
        bits = value.replace(" ", "").replace("_", "")
        if not bits or any(c not in "01" for c in bits):
            raise ValueError("BIN expects only 0/1 digits")
        if len(bits) > size * 8:
            raise ValueError(f"BIN too long for {size} bytes")
        iv = int(bits, 2)
        b = iv.to_bytes(size, "big")
        return bitwise_not_bytes(b) if rep == "BIN_NOT" else b

    # unreachable
    raise ValueError("unknown format")

def main():
    ap = argparse.ArgumentParser(description="Interactively convert values to bytes.")
    ap.add_argument("N", type=int, help="number of values to collect")
    args = ap.parse_args()

    for i in range(1, args.N + 1):
        print(f"[{i}/{args.N}]")
        # size
        while True:
            s = input("  size (bytes): ").strip()
            try:
                size = int(s, 10)
                if size <= 0:
                    raise ValueError
                break
            except ValueError:
                print("    error: enter a positive integer (e.g., 2, 4, 8)")
        # format
        while True:
            rep = input(f"  format {sorted(ALLOWED)}: ").strip().upper()
            if rep in ALLOWED:
                break
            print("    error: invalid format")
        # value
        while True:
            val = input("  value: ").strip()
            try:
                b = parse_value_by_rep(rep, val, size)
                break
            except Exception as e:
                print(f"    error: {e}")
        # output
        hex_bytes = " ".join(f"{x:02x}" for x in b)
        print(f"  bytes: {hex_bytes}")
        print(f"  len  : {len(b)}")
        print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

