"""Plain argparse version of diff command."""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

def main():
    """Compare binary dumps at 2/4/8-byte units."""
    
    ap = argparse.ArgumentParser(
        description="Compare binary dumps at 2/4/8-byte units"
    )
    ap.add_argument(
        "--block-size", type=int, default=16, help="Block size in bytes (default: 16)"
    )
    ap.add_argument(
        "--format", choices=["mf1k", "mf4k"], help="Optional format for additional block labeling"
    )
    ap.add_argument(
        "--units",
        help="Comma-separated list of unit sizes to display (subset of 2,4,8). Default: 2,4,8",
    )
    ap.add_argument(
        "--show",
        help="Comma-separated subset of columns to show from: RAW,INT_BE,INT_LE,NOT_BE,NOT_LE,BIN,BIN_NOT,NOT_RAW. Default: all",
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
        "--save-ctx", type=Path, help="Save diff context to file for use with 'ssdp view --ctx'"
    )
    ap.add_argument(
        "files", nargs="+", type=Path, help="Raw dumps for the chosen format"
    )
    args = ap.parse_args()

    from ..core.io import read_file_bytes
    
    # Read files first to determine total size
    if len(args.files) < 2:
        print("error: provide at least two dump files to compare", file=sys.stderr)
        sys.exit(2)
    
    names = [str(p) for p in args.files]
    try:
        datas = [read_file_bytes(p) for p in args.files]
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
    
    # Use the first file's size as reference
    total_bytes = len(datas[0])
    total_blocks = (total_bytes + args.block_size - 1) // args.block_size  # Ceiling division
    
    # Validate all files have same size
    bad = [(n, len(d)) for n, d in zip(names, datas) if len(d) != total_bytes]
    if bad:
        for n, l in bad:
            print(f"error: '{n}' length {l} != {total_bytes} (reference)", file=sys.stderr)
        sys.exit(2)
    
    # Optional format-specific validation
    if args.format:
        from ..core.mifare import get_chip_config
        try:
            cfg = get_chip_config(args.format)
            if total_bytes != cfg.total_bytes:
                print(f"warning: file size {total_bytes} doesn't match {args.format} expected size {cfg.total_bytes}", file=sys.stderr)
        except Exception as e:
            print(f"warning: format validation failed: {e}", file=sys.stderr)
    
    # Parse arguments
    from ..utils.cli import parse_units_arg, parse_show_arg, parse_colorize_arg
    from ..core.render_units import print_block_units
    
    try:
        units_list = parse_units_arg(args.units)
        show_cols = parse_show_arg(args.show)  
        colorize_cols = parse_colorize_arg(args.colorize, show_cols)
    except:
        # Use defaults if parsing fails
        units_list = [2, 4, 8]
        show_cols = ["INT_BE", "INT_LE", "NOT_BE", "NOT_LE", "BIN", "BIN_NOT", "NOT_RAW"]
        colorize_cols = ["RAW"]
    
    
    aliases = [f"data{i:02d}" for i in range(1, len(names) + 1)]
    
    # Print exactly like original
    print("Inputs:")
    for alias, name in zip(aliases, names):
        print(f"  {alias}: {name}")
    print()
    
    # Find differing blocks
    from ..core.diff_engine import blocks_that_differ
    diff_blocks = blocks_that_differ(datas, total_blocks)
    
    if not diff_blocks:
        print("No differing blocks.")
        return
        
    print("Diff blocks:")
    
    # Optional format-specific labeling
    format_labeler = None
    if args.format:
        try:
            from ..core.mifare import get_sector_block_mapper
            format_labeler = get_sector_block_mapper(args.format)
        except Exception:
            format_labeler = None
    
    for i in diff_blocks:
        if format_labeler:
            try:
                s, b = format_labeler(i)
                print(f"  [BLOCK] ID={i} S={s} B={b}")
            except Exception:
                print(f"  [BLOCK] ID={i}")
        else:
            print(f"  [BLOCK] ID={i}")
    print()
    
    # Print blocks exactly like original main.py
    use_color = (not args.no_color) and sys.stdout.isatty()
    
    for i in diff_blocks:
        print_block_units(
            i, datas, aliases, format_labeler, units_list, use_color,
            show_cols, colorize_cols, args.show_same, args.block_size
        )
    
    # Handle xxd exports exactly like original
    if args.xxd_full_dir:
        from ..core.xxd import write_xxd_full_file
        args.xxd_full_dir.mkdir(parents=True, exist_ok=True)
        for alias, data in zip(aliases, datas):
            out_path = args.xxd_full_dir / f"{alias}.xxd"
            write_xxd_full_file(str(out_path), data)
        print(f"Wrote full xxd dumps to: {args.xxd_full_dir}/<alias>.xxd")
        
    if args.xxd_diff:
        from ..core.xxd import generate_xxd_diff_lines
        lines = generate_xxd_diff_lines(
            diff_blocks, datas, aliases, format_labeler, args.block_size, 4, False, True
        )
        with args.xxd_diff.open("w") as f:
            for line in lines:
                f.write(line + "\n")
        print(f"Wrote diff-only xxd report (all inputs) to: {args.xxd_diff}")
        
    if args.xxd_diff_first:
        from ..core.xxd import generate_xxd_diff_lines
        lines = generate_xxd_diff_lines(
            diff_blocks, datas, aliases, format_labeler, args.block_size, 4, True, True
        )
        with args.xxd_diff_first.open("w") as f:
            for line in lines:
                f.write(line + "\n")
        print(f"Wrote diff-only xxd report (first input only) to: {args.xxd_diff_first}")
    
    # Save diff context for view command
    if args.save_ctx:
        import json
        
        # Create context data with differing unit positions
        ctx_data = {
            "block_size": args.block_size,
            "format": args.format,  # Optional, may be None
            "files": names,
            "aliases": {alias: name for alias, name in zip(aliases, names)},
            "units": units_list,  # The unit sizes that were analyzed
            "diff_blocks": [],
            "diff_units": {}  # Units organized by size
        }
        
        # Initialize diff_units for each unit size
        for unit_size in units_list:
            ctx_data["diff_units"][str(unit_size)] = []
        
        # Add block-level differences and find differing units
        for block_idx in diff_blocks:
            block_info = {
                "abs_block": block_idx,
                "offset_start": block_idx * args.block_size,
                "offset_end": (block_idx * args.block_size) + args.block_size - 1
            }
            
            # Add format-specific labeling if available
            if format_labeler:
                try:
                    s, b = format_labeler(block_idx)
                    block_info["sector"] = s
                    block_info["block"] = b
                except Exception:
                    pass
            
            ctx_data["diff_blocks"].append(block_info)
            
            # Find differing units within this block for each unit size
            block_start = block_idx * args.block_size
            block_slices = [d[block_start:block_start + args.block_size] for d in datas]
            
            for unit_size in units_list:
                from ..core.render_units import unit_offsets
                for unit_offset in unit_offsets(unit_size):
                    # Check if this unit differs across files
                    first_unit = block_slices[0][unit_offset:unit_offset + unit_size]
                    unit_differs = any(
                        s[unit_offset:unit_offset + unit_size] != first_unit 
                        for s in block_slices[1:]
                    )
                    
                    if unit_differs:
                        abs_offset = block_start + unit_offset
                        ctx_data["diff_units"][str(unit_size)].append({
                            "offset": abs_offset,
                            "size": unit_size,
                            "block": block_idx
                        })
        
        with args.save_ctx.open("w") as f:
            json.dump(ctx_data, f, indent=2)
        print(f"Saved diff context to: {args.save_ctx}")


if __name__ == "__main__":
    main()