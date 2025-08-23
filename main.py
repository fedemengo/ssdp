#!/usr/bin/env python3
"""
classic-diff — minimal MIFARE Classic dump comparator (v0.9)

Updates in v0.9:
- Added NOT_RAW (hex of bitwise-NOTed unit bytes) as an optional display column.
- --show can now include NOT_RAW; --colorize can target NOT_RAW too (with validation).
- RAW remains always shown; NOT_RAW is shown only if selected via --show.

Recent features:
- --show selects which columns to display per unit (subset of INT_BE,INT_LE,NOT_BE,NOT_LE,BIN,BIN_NOT,NOT_RAW).
- --colorize accepts a comma-separated list (RAW and/or any shown columns). Errors if you colorize a column you didn't show.
- Only differing units are printed in detail; FULL 16-byte orientation lines stay highlighted per alias.

Spec:
- Formats: mf1k (1K, 64 blocks) and mf4k (4K, 256 blocks)
- Inputs: ≥2 raw dumps with exact length for the chosen format
- Step 1: Identify 16-byte blocks that differ across files
- Step 2: For each differing block, print selected unit sizes (2/4/8)
    * Show RAW + user-selected columns, only for differing units
- Color: each alias assigned a distinct ANSI color (cycled if more aliases than colors)
"""

from __future__ import annotations
import argparse
from pathlib import Path
import sys
from typing import List, Tuple, Callable

BYTES_PER_BLOCK = 16

ANSI_COLORS = [
    "\033[31m",  # red
    "\033[36m",  # cyan
    "\033[32m",  # green
    "\033[35m",  # magenta
    "\033[33m",  # yellow
    "\033[34m",  # blue
]
ANSI_RESET = "\033[0m"

ALL_COLUMNS = ["NOT_RAW", "INT_BE", "INT_LE", "NOT_BE", "NOT_LE", "BIN", "BIN_NOT"]
ALLOWED_COLORIZE = ["RAW"] + ALL_COLUMNS

# --- Per-format configuration -------------------------------------------------


def to_sector_block_mf1k(abs_block: int) -> Tuple[int, int]:
    if not (0 <= abs_block < 64):
        raise ValueError("abs_block out of range for mf1k")
    sector = abs_block // 4
    block_in_sector = abs_block % 4
    return sector, block_in_sector


def to_sector_block_mf4k(abs_block: int) -> Tuple[int, int]:
    if not (0 <= abs_block < 256):
        raise ValueError("abs_block out of range for mf4k")
    if abs_block < 128:
        sector = abs_block // 4
        block_in_sector = abs_block % 4
        return sector, block_in_sector
    idx = abs_block - 128
    sector = 32 + (idx // 16)
    block_in_sector = idx % 16
    return sector, block_in_sector


FORMAT_CFG = {
    "mf1k": {
        "total_blocks": 64,
        "total_bytes": 64 * BYTES_PER_BLOCK,
        "to_sector_block": to_sector_block_mf1k,
    },
    "mf4k": {
        "total_blocks": 256,
        "total_bytes": 256 * BYTES_PER_BLOCK,
        "to_sector_block": to_sector_block_mf4k,
    },
}

# --- IO helpers ---------------------------------------------------------------


def read_file_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except Exception as e:
        print(f"error: could not read '{path}': {e}", file=sys.stderr)
        sys.exit(2)


def hex_bytes(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


def int_be(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def int_le(b: bytes) -> int:
    return int.from_bytes(b, byteorder="little", signed=False)


def bitwise_not_bytes(b: bytes) -> bytes:
    return bytes((~x) & 0xFF for x in b)


def bin_str(val: int, bit_width: int) -> str:
    return format(val, f"0{bit_width}b")


# --- Core diff logic ----------------------------------------------------------


def blocks_that_differ(datas: List[bytes], total_blocks: int) -> List[int]:
    differing = []
    for i in range(total_blocks):
        start = i * BYTES_PER_BLOCK
        end = start + BYTES_PER_BLOCK
        first = datas[0][start:end]
        if any(d[start:end] != first for d in datas[1:]):
            differing.append(i)
    return differing


def unit_offsets(size: int) -> List[int]:
    if size == 2:
        return [0, 2, 4, 6, 8, 10, 12, 14]
    if size == 4:
        return [0, 4, 8, 12]
    if size == 8:
        return [0, 8]
    raise ValueError("invalid unit size; expected 2, 4, or 8")


def parse_units_arg(units_arg: str | None) -> List[int]:
    if not units_arg:
        return [2, 4, 8]
    try:
        parts = [p.strip() for p in units_arg.split(",") if p.strip()]
        units = [int(p) for p in parts]
    except ValueError:
        print(
            "error: --units must be a comma-separated list of 2, 4, 8", file=sys.stderr
        )
        sys.exit(2)
    valid = {2, 4, 8}
    if any(u not in valid for u in units):
        print("error: --units values must be among {2,4,8}", file=sys.stderr)
        sys.exit(2)
    return units


# --- Printing helpers ---------------------------------------------------------


def colorize(s: str, color: str, enable: bool) -> str:
    return f"{color}{s}{ANSI_RESET}" if enable else s


def print_input_aliases(names: List[str], aliases: List[str]):
    print("Inputs:")
    for alias, name in zip(aliases, names):
        print(f"  {alias}: {name}")
    print()


def print_header_diff_blocks(
    blocks: List[int], to_sector_block: Callable[[int], Tuple[int, int]]
):
    if not blocks:
        print("No differing blocks.")
        return
    print("Diff blocks:")
    for i in blocks:
        s, b = to_sector_block(i)
        print(f"  S={s} B={b} (abs={i})")
    print()


# --- Column selection & colorization -----------------------------------------


def parse_show_arg(show_arg: str | None) -> List[str]:
    if not show_arg:
        return ALL_COLUMNS.copy()
    parts = [p.strip().upper() for p in show_arg.split(",") if p.strip()]
    bad = [p for p in parts if p not in ALL_COLUMNS]
    if bad:
        print(
            "error: --show contains invalid columns: " + ", ".join(bad), file=sys.stderr
        )
        print("       valid: " + ", ".join(ALL_COLUMNS), file=sys.stderr)
        sys.exit(2)
    return parts


def parse_colorize_arg(colorize_arg: str | None, show_cols: List[str]) -> List[str]:
    if not colorize_arg:
        return ["RAW"]
    parts = [p.strip().upper() for p in colorize_arg.split(",") if p.strip()]
    bad = [p for p in parts if p not in ALLOWED_COLORIZE]
    if bad:
        print(
            "error: --colorize contains invalid columns: " + ", ".join(bad),
            file=sys.stderr,
        )
        print("       valid: " + ", ".join(ALLOWED_COLORIZE), file=sys.stderr)
        sys.exit(2)
    missing = [p for p in parts if p != "RAW" and p not in show_cols]
    if missing:
        print(
            "error: --colorize includes columns not being displayed (add them to --show): "
            + ", ".join(missing),
            file=sys.stderr,
        )
        sys.exit(2)
    # dedupe preserving order
    seen = set()
    out = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


# --- Block printing -----------------------------------------------------------


def print_block_units(
    abs_block: int,
    datas: List[bytes],
    aliases: List[str],
    to_sector_block: Callable[[int], Tuple[int, int]],
    units: List[int],
    use_color: bool,
    show_cols: List[str],
    colorize_cols: List[str],
):
    s, b = to_sector_block(abs_block)
    print(f"[BLOCK] S={s} B={b} (abs={abs_block})")

    block_start = abs_block * BYTES_PER_BLOCK
    full_slices = [d[block_start : block_start + BYTES_PER_BLOCK] for d in datas]
    colors = [ANSI_COLORS[i % len(ANSI_COLORS)] for i in range(len(datas))]

    width_map = {2: 5, 4: 10, 8: 20}

    for size in units:
        print(f"  [units={size}]")
        # Find differing unit offsets for this size
        differing_offsets: List[int] = []
        for off in unit_offsets(size):
            units_here = [
                d[block_start + off : block_start + off + size] for d in datas
            ]
            if any(u != units_here[0] for u in units_here[1:]):
                differing_offsets.append(off)
        # Orientation: FULL block (with differing units highlighted)
        for data, alias, col in zip(full_slices, aliases, colors):
            raw_hex = hex_bytes(data)
            if differing_offsets:
                chunks = []
                for j in range(0, BYTES_PER_BLOCK, size):
                    unit_bytes = data[j : j + size]
                    raw = " ".join(f"{x:02X}" for x in unit_bytes)
                    differs = j in differing_offsets
                    chunk = colorize(raw, col, use_color) if differs else raw
                    chunks.append(chunk)
                raw_hex = " | ".join(chunks)
            print(f"    {alias}: FULL={raw_hex}")
        # Detailed rows: only differing units
        for off in differing_offsets:
            print(f"    +{off:02d}")
            for data, alias, col in zip(datas, aliases, colors):
                unit = data[block_start + off : block_start + off + size]
                raw_hex = hex_bytes(unit)
                be = int_be(unit)
                le = int_le(unit)
                not_bytes = bitwise_not_bytes(unit)
                not_be = int_be(not_bytes)
                not_le = int_le(not_bytes)
                bit_width = size * 8
                bin_norm = bin_str(be, bit_width)
                bin_not = bin_str(int.from_bytes(not_bytes, "big"), bit_width)
                not_raw_hex = hex_bytes(not_bytes)
                w = width_map[size]

                # Build ordered column list
                parts = []
                # RAW always first
                raw_out = raw_hex
                if "RAW" in colorize_cols:
                    raw_out = colorize(raw_out, col, use_color)
                parts.append(f"RAW={raw_out}")

                for cname in show_cols:
                    if cname == "NOT_RAW":
                        val = not_raw_hex
                    elif cname == "INT_BE":
                        val = f"{be:>{w}d}"
                    elif cname == "INT_LE":
                        val = f"{le:>{w}d}"
                    elif cname == "NOT_BE":
                        val = f"{not_be:>{w}d}"
                    elif cname == "NOT_LE":
                        val = f"{not_le:>{w}d}"
                    elif cname == "BIN":
                        val = bin_norm
                    elif cname == "BIN_NOT":
                        val = bin_not
                    else:
                        continue
                    if cname in colorize_cols:
                        val = colorize(val, col, use_color)
                    parts.append(f"{cname}={val}")

                print(f"      {alias}: " + " | ".join(parts))
        print()


# --- CLI ---------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        description="Compare MIFARE Classic dumps (mf1k/mf4k) at 2/4/8-byte units (v0.9)"
    )
    ap.add_argument(
        "--format", required=True, choices=["mf1k", "mf4k"], help="Input format"
    )
    ap.add_argument(
        "--units",
        help="Comma-separated list of unit sizes to display (subset of 2,4,8). Default: 2,4,8",
    )
    ap.add_argument(
        "--show",
        help="Comma-separated subset of columns to show from: INT_BE,INT_LE,NOT_BE,NOT_LE,BIN,BIN_NOT,NOT_RAW. Default: all",
    )
    ap.add_argument(
        "--colorize",
        help="Comma-separated list of columns to colorize: RAW and/or any shown columns. Default: RAW",
    )
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    ap.add_argument(
        "files", nargs="+", type=Path, help="Raw dumps for the chosen format"
    )
    args = ap.parse_args()

    fmt = args.format
    cfg = FORMAT_CFG[fmt]
    total_blocks = cfg["total_blocks"]
    total_bytes = cfg["total_bytes"]
    to_sb = cfg["to_sector_block"]

    units = parse_units_arg(args.units)

    # parse show/colorize
    show_cols = parse_show_arg(args.show)
    colorize_cols = parse_colorize_arg(args.colorize, show_cols)

    if len(args.files) < 2:
        print("error: provide at least two dump files to compare", file=sys.stderr)
        sys.exit(2)

    names = [str(p) for p in args.files]
    datas = [read_file_bytes(p) for p in args.files]

    bad = [(n, len(d)) for n, d in zip(names, datas) if len(d) != total_bytes]
    if bad:
        for n, l in bad:
            print(
                f"error: '{n}' length {l} != {total_bytes} for format {fmt}",
                file=sys.stderr,
            )
        sys.exit(2)

    aliases = [f"data{i:02d}" for i in range(1, len(names) + 1)]

    # header
    print("Inputs:")
    for alias, name in zip(aliases, names):
        print(f"  {alias}: {name}")
    print()

    diff_blocks = blocks_that_differ(datas, total_blocks)
    print_header_diff_blocks(diff_blocks, to_sb)

    use_color = (not args.no_color) and sys.stdout.isatty()

    for i in diff_blocks:
        print_block_units(
            i, datas, aliases, to_sb, units, use_color, show_cols, colorize_cols
        )


if __name__ == "__main__":
    main()
