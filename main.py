#!/usr/bin/env python3
"""
classic-diff — minimal MIFARE Classic dump comparator (v0.13)

New in v0.13:
- **xxd formatting** now groups bytes **4-by-4** (extra gap between groups).
- In diff exports, each differing block now includes a leading **"same"** line that shows only
  the bytes that are identical across all inputs; bytes that differ are left **blank** (kept
  aligned). Example:

    [BLOCK] S=12 B=1 (abs=49)
    same  00000130: 4B 4B 20 20   20 20 20 20   11 22       44            KK  ..    .."  D
    data01 00000130: 4B 4B 20 21   20 20 20 20   11 22 33 44 55 66 77 88  KK !    .."3DUfw.

  (The hex gaps reflect groups of 4; blanks keep columns aligned.)

What it modifies:
- `--xxd-diff` and `--xxd-diff-first` now include the `same` line per differing block.
- All xxd-style outputs (`--xxd-full-dir`, `--xxd-diff*`) use the new 4×4 grouping.

Everything remains **read-only**: no binary dumps are written or modified.
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
ANSI_DIM = "\033[2m"

ALL_COLUMNS = ["INT_BE", "INT_LE", "NOT_BE", "NOT_LE", "BIN", "BIN_NOT", "NOT_RAW"]
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


def ascii_bytes(b: bytes) -> str:
    return "".join(chr(x) if 32 <= x <= 126 else "." for x in b)


def int_be(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def int_le(b: bytes) -> int:
    return int.from_bytes(b, byteorder="little", signed=False)


def bitwise_not_bytes(b: bytes) -> bytes:
    return bytes((~x) & 0xFF for x in b)


def bin_str(val: int, bit_width: int) -> str:
    return format(val, f"0{bit_width}b")


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


# --- SAME byte computations for exports --------------------------------------


def same_byte_mask(block_slices: List[bytes]) -> List[bool]:
    """Return a 16-length mask where True means the byte is equal across all slices."""
    mask = [True] * BYTES_PER_BLOCK
    first = block_slices[0]
    for j in range(BYTES_PER_BLOCK):
        v = first[j]
        for s in block_slices[1:]:
            if s[j] != v:
                mask[j] = False
                break
    return mask


# --- xxd-style export helpers (4x4 grouping) ---------------------------------


def _hex_groups_4x4(sixteen: bytes, mask: List[bool] | None = None) -> str:
    """Return hex string grouped 4-by-4, double space between groups.
    If mask is given (len 16), print byte hex if mask[i] True, else two spaces.
    """
    tokens: List[str] = []
    for i, b in enumerate(sixteen):
        if mask is None or mask[i]:
            tokens.append(f"{b:02x}")
        else:
            tokens.append("  ")  # keep column width
    groups: List[str] = []
    for g in range(4):
        start = g * 4
        grp = " ".join(tokens[start : start + 4])
        groups.append(grp)
    return "  ".join(groups)


def _ascii_groups_4x4(sixteen: bytes, mask: List[bool] | None = None) -> str:
    chars: List[str] = []
    for i, b in enumerate(sixteen):
        ch = chr(b) if 32 <= b <= 126 else "."
        if mask is not None and not mask[i]:
            ch = " "  # blank out differing bytes
        chars.append(ch)
    return "".join(chars)


def xxd_line_group4(offset: int, sixteen: bytes, mask: List[bool] | None = None) -> str:
    left = f"{offset:08x}:"
    hex_part = _hex_groups_4x4(sixteen, mask)
    ascii_part = _ascii_groups_4x4(sixteen, mask)
    return f"{left} {hex_part}  {ascii_part}"


def write_xxd_full(dirpath: Path, aliases: List[str], datas: List[bytes]):
    dirpath.mkdir(parents=True, exist_ok=True)
    for alias, data in zip(aliases, datas):
        out_path = dirpath / f"{alias}.xxd"
        with out_path.open("w", encoding="utf-8") as f:
            for off in range(0, len(data), BYTES_PER_BLOCK):
                chunk = data[off : off + BYTES_PER_BLOCK]
                f.write(xxd_line_group4(off, chunk) + "\n")


def write_xxd_diff(
    path: Path, fmt: str, aliases: List[str], datas: List[bytes], diff_blocks: List[int]
):
    with path.open("w", encoding="utf-8") as f:
        for abs_block in diff_blocks:
            s, b = FORMAT_CFG[fmt]["to_sector_block"](abs_block)
            block_start = abs_block * BYTES_PER_BLOCK
            slices = [d[block_start : block_start + BYTES_PER_BLOCK] for d in datas]
            mask = same_byte_mask(slices)
            f.write(f"[BLOCK] S={s} B={b} (abs={abs_block})\n")
            # SAME line: show only identical bytes across all inputs
            f.write("same   " + xxd_line_group4(block_start, slices[0], mask) + "\n")
            # Then each alias line (full bytes)
            for alias, chunk in zip(aliases, slices):
                f.write(f"{alias} " + xxd_line_group4(block_start, chunk) + "\n")
            f.write("\n")


def write_xxd_diff_first(
    path: Path,
    fmt: str,
    first_alias: str,
    first_data: bytes,
    diff_blocks: List[int],
    other_datas: List[bytes],
):
    with path.open("w", encoding="utf-8") as f:
        for abs_block in diff_blocks:
            s, b = FORMAT_CFG[fmt]["to_sector_block"](abs_block)
            block_start = abs_block * BYTES_PER_BLOCK
            first_chunk = first_data[block_start : block_start + BYTES_PER_BLOCK]
            # Build mask vs all inputs (first + others)
            slices = [first_data[block_start : block_start + BYTES_PER_BLOCK]] + [
                d[block_start : block_start + BYTES_PER_BLOCK] for d in other_datas
            ]
            mask = same_byte_mask(slices)
            f.write(f"[BLOCK] S={s} B={b} (abs={abs_block})\n")
            f.write("same  " + xxd_line_group4(block_start, first_chunk, mask) + "\n")
            f.write(
                f"{first_alias} " + xxd_line_group4(block_start, first_chunk) + "\n\n"
            )


# --- Printing (console) -------------------------------------------------------


def colorize_token(token: str, color: str, enable: bool) -> str:
    return f"{color}{token}{ANSI_RESET}" if enable else token


def dim_token(token: str, enable: bool) -> str:
    return f"{ANSI_DIM}{token}{ANSI_RESET}" if enable else token


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


# --- "same" computation for console (already in v0.12) -----------------------


def units_equal(datas: List[bytes], block_start: int, off: int, size: int) -> bool:
    a = datas[0][block_start + off : block_start + off + size]
    return all(d[block_start + off : block_start + off + size] == a for d in datas[1:])


def collect_same_unit_offsets(
    datas: List[bytes], block_start: int, size: int
) -> List[int]:
    return [
        off for off in unit_offsets(size) if units_equal(datas, block_start, off, size)
    ]


def collect_same_byte_idxs(datas: List[bytes], block_start: int) -> set[int]:
    idxs: set[int] = set()
    for j in range(BYTES_PER_BLOCK):
        b0 = datas[0][block_start + j]
        if all(d[block_start + j] == b0 for d in datas[1:]):
            idxs.add(j)
    return idxs


def idxs_to_ranges_str(sorted_idxs: List[int]) -> str:
    if not sorted_idxs:
        return "(none)"
    ranges = []
    start = prev = sorted_idxs[0]
    for x in sorted_idxs[1:]:
        if x == prev + 1:
            prev = x
            continue
        ranges.append((start, prev))
        start = prev = x
    ranges.append((start, prev))
    parts = []
    for a, b in ranges:
        if a == b:
            parts.append(f"{a:02d}")
        else:
            parts.append(f"{a:02d}-{b:02d}")
    return ", ".join(parts)


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


# --- Console block printing ---------------------------------------------------


def print_block_units(
    abs_block: int,
    datas: List[bytes],
    aliases: List[str],
    to_sector_block: Callable[[int], Tuple[int, int]],
    units: List[int],
    use_color: bool,
    show_cols: List[str],
    colorize_cols: List[str],
    show_same_mode: str,
):
    s, b = to_sector_block(abs_block)
    print(f"[BLOCK] S={s} B={b} (abs={abs_block})")

    block_start = abs_block * BYTES_PER_BLOCK
    full_slices = [d[block_start : block_start + BYTES_PER_BLOCK] for d in datas]
    colors = [ANSI_COLORS[i % len(ANSI_COLORS)] for i in range(len(datas))]

    width_map = {2: 5, 4: 10, 8: 20}

    same_bytes_global = (
        collect_same_byte_idxs(datas, block_start)
        if show_same_mode in ("bytes", "both")
        else set()
    )

    for size in units:
        print(f"  [units={size}]")
        differing_offsets: List[int] = []
        same_offsets: List[int] = [] if show_same_mode in ("units", "both") else []
        for off in unit_offsets(size):
            a = datas[0][block_start + off : block_start + off + size]
            equal_all = all(
                d[block_start + off : block_start + off + size] == a for d in datas[1:]
            )
            if equal_all:
                if show_same_mode in ("units", "both"):
                    same_offsets.append(off)
            else:
                differing_offsets.append(off)

        for data, alias, col in zip(full_slices, aliases, colors):
            chunks: List[str] = []
            for j in range(0, BYTES_PER_BLOCK, size):
                unit_bytes = data[j : j + size]
                if j in differing_offsets:
                    raw = " ".join(f"{x:02X}" for x in unit_bytes)
                    chunks.append(colorize_token(raw, col, use_color))
                elif show_same_mode in ("units", "both") and j in same_offsets:
                    raw = " ".join(f"{x:02X}" for x in unit_bytes)
                    chunks.append(dim_token(raw, use_color))
                elif show_same_mode in ("bytes", "both") and same_bytes_global:
                    parts = []
                    for k, x in enumerate(unit_bytes):
                        token = f"{x:02X}"
                        idx = j + k
                        parts.append(
                            dim_token(token, use_color)
                            if idx in same_bytes_global
                            else token
                        )
                    chunks.append(" ".join(parts))
                else:
                    chunks.append(" ".join(f"{x:02X}" for x in unit_bytes))
            raw_hex = " | ".join(chunks)
            print(f"    {alias}: FULL={raw_hex}")

        if show_same_mode in ("units", "both"):
            offs = (
                " ".join(f"+{o:02d}" for o in same_offsets)
                if same_offsets
                else "(none)"
            )
            print(f"    Same units (size={size}): {offs}")
        if show_same_mode in ("bytes", "both") and same_bytes_global:
            rng = idxs_to_ranges_str(sorted(same_bytes_global))
            print(f"    Same bytes: {rng}")

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

                parts = []
                raw_out = raw_hex
                if "RAW" in colorize_cols:
                    raw_out = colorize_token(raw_out, col, use_color)
                parts.append(f"RAW={raw_out}")

                for cname in show_cols:
                    if cname == "INT_BE":
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
                    elif cname == "NOT_RAW":
                        val = not_raw_hex
                    else:
                        continue
                    if cname in colorize_cols:
                        val = colorize_token(val, col, use_color)
                    parts.append(f"{cname}={val}")

                print(f"      {alias}: " + " | ".join(parts))
        print()


# --- CLI ---------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        description="Compare MIFARE Classic dumps (mf1k/mf4k) at 2/4/8-byte units (v0.13)"
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
    ap.add_argument(
        "--show-same",
        choices=["none", "units", "bytes", "both"],
        default="none",
        help="Highlight what is identical across inputs at the unit and/or byte level (console only).",
    )
    ap.add_argument(
        "--xxd-diff",
        type=Path,
        help="Write xxd-like report of differing blocks for all inputs to this file",
    )
    ap.add_argument(
        "--xxd-diff-first",
        type=Path,
        help="Write xxd-like report of differing blocks using only the first input's bytes",
    )
    ap.add_argument(
        "--xxd-full-dir",
        type=Path,
        help="Directory to write full xxd-like dumps (<alias>.xxd) for each input",
    )
    ap.add_argument(
        "--no-color", action="store_true", help="Disable ANSI color output (console)"
    )
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
            i,
            datas,
            aliases,
            to_sb,
            units,
            use_color,
            show_cols,
            colorize_cols,
            args.show_same,
        )

    # xxd exports (read-only)
    if args.xxd_full_dir:
        write_xxd_full(args.xxd_full_dir, aliases, datas)
        print(f"Wrote full xxd dumps to: {args.xxd_full_dir}/<alias>.xxd")
    if args.xxd_diff:
        write_xxd_diff(args.xxd_diff, fmt, aliases, datas, diff_blocks)
        print(f"Wrote diff-only xxd report (all inputs) to: {args.xxd_diff}")
    if args.xxd_diff_first:
        # pass other datas to compute SAME mask
        write_xxd_diff_first(
            args.xxd_diff_first, fmt, aliases[0], datas[0], diff_blocks, datas[1:]
        )
        print(
            f"Wrote diff-only xxd report (first input only) to: {args.xxd_diff_first}"
        )


if __name__ == "__main__":
    main()
