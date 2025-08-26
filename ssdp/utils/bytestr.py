"""Byte string utilities and conversion functions."""

from __future__ import annotations

import re
from typing import Set

from ..core.errors import ConversionError
from ..core.types import Rep

ALLOWED_REPS: Set[Rep] = {
    "RAW", "NOT_RAW", "INT_BE", "INT_LE", "NOT_BE", "NOT_LE", "BIN", "BIN_NOT"
}


def bitwise_not_bytes(b: bytes) -> bytes:
    """Apply bitwise NOT to all bytes."""
    return bytes((~x) & 0xFF for x in b)


def _pad_trunc_left(s: str, width: int) -> str:
    """Left-pad with zeros, then keep the rightmost width chars."""
    if len(s) < width:
        s = s.zfill(width)
    return s[-width:]


def _to_sized_bytes_from_int(iv: int, size: int, endian: str) -> bytes:
    """Convert integer to bytes of specified size and endianness."""
    if size <= 0:
        raise ValueError("size must be > 0")
    mask = (1 << (8 * size)) - 1
    iv &= mask  # truncate to requested width
    return iv.to_bytes(size, endian, signed=False)


def parse_value_by_rep(rep: Rep, value: str, size: int) -> bytes:
    """
    Parse `value` according to representation `rep`, and return exactly `size` bytes.
    For RAW/BIN inputs, we do lenient sizing: zero-pad left, then truncate on the left if too long.
    For INT inputs, we mask to the requested width.
    """
    if rep not in ALLOWED_REPS:
        raise ValueError(f"format must be one of: {', '.join(sorted(ALLOWED_REPS))}")

    try:
        if rep in ("RAW", "NOT_RAW"):
            hexstr = re.sub(r"[ _]", "", value)
            if not re.fullmatch(r"[0-9a-fA-F]*", hexstr or ""):
                raise ValueError("RAW contains non-hex characters")
            hexstr = _pad_trunc_left(hexstr, size * 2)
            b = bytes.fromhex(hexstr)
            return bitwise_not_bytes(b) if rep == "NOT_RAW" else b

        if rep in ("INT_BE", "INT_LE", "NOT_BE", "NOT_LE"):
            endian = "big" if rep.endswith("BE") else "little"
            iv = int(value, 0)  # accepts 0x..., decimal, etc.
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
    
    except Exception as e:
        if isinstance(e, ConversionError):
            raise
        raise ConversionError(value, rep, "bytes", e) from e


def bytes_to_rep(b: bytes, rep: Rep) -> str:
    """Convert bytes to specified representation."""
    if rep not in ALLOWED_REPS:
        raise ValueError(f"format must be one of: {', '.join(sorted(ALLOWED_REPS))}")

    try:
        if rep == "RAW":
            return " ".join(f"{x:02X}" for x in b)
        elif rep == "NOT_RAW":
            return " ".join(f"{x:02X}" for x in bitwise_not_bytes(b))
        elif rep == "INT_BE":
            return str(int.from_bytes(b, "big", signed=False))
        elif rep == "INT_LE":
            return str(int.from_bytes(b, "little", signed=False))
        elif rep == "NOT_BE":
            return str(int.from_bytes(bitwise_not_bytes(b), "big", signed=False))
        elif rep == "NOT_LE":
            return str(int.from_bytes(bitwise_not_bytes(b), "little", signed=False))
        elif rep == "BIN":
            iv = int.from_bytes(b, "big", signed=False)
            return format(iv, f"0{len(b)*8}b")
        elif rep == "BIN_NOT":
            iv = int.from_bytes(bitwise_not_bytes(b), "big", signed=False)
            return format(iv, f"0{len(b)*8}b")
        else:
            raise ValueError(f"Unsupported representation: {rep}")
    
    except Exception as e:
        if isinstance(e, ConversionError):
            raise
        raise ConversionError(b.hex(), "bytes", rep, e) from e


def all_formats_from_value(value: str, size: int) -> dict[Rep, str]:
    """Get all possible representations of a value."""
    results: dict[Rep, str] = {}
    
    for rep in sorted(ALLOWED_REPS):
        try:
            b = parse_value_by_rep(rep, value, size)
            results[rep] = b.hex()
        except Exception:
            # Skip formats that can't parse this value
            continue
    
    return results


def hex_bytes(b: bytes) -> str:
    """Convert bytes to space-separated hex string."""
    return " ".join(f"{x:02X}" for x in b)


def ascii_bytes(b: bytes) -> str:
    """Convert bytes to ASCII string, replacing non-printable chars with '.'."""
    return "".join(chr(x) if 32 <= x <= 126 else "." for x in b)


def int_be(b: bytes) -> int:
    """Convert bytes to big-endian integer."""
    return int.from_bytes(b, byteorder="big", signed=False)


def int_le(b: bytes) -> int:
    """Convert bytes to little-endian integer."""
    return int.from_bytes(b, byteorder="little", signed=False)


def bin_str(val: int, bit_width: int) -> str:
    """Convert integer to binary string with specified width."""
    return format(val, f"0{bit_width}b")