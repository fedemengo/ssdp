"""View command implementation."""

import argparse
import sys
from pathlib import Path


def main():
    """View a binary file with optional annotations."""
    
    ap = argparse.ArgumentParser(
        description="View a binary file with optional annotations"
    )
    ap.add_argument("path", type=Path, help="File to view")
    ap.add_argument("--xxd", action="store_true", help="Use xxd hex dump format instead of unit analysis")
    ap.add_argument("--json", action="store_true", help="Output in JSON format")
    ap.add_argument("--offset", type=int, help="Start offset (bytes)")
    ap.add_argument("--len", dest="length", type=int, help="Length to read (bytes)")
    ap.add_argument("--range", dest="range_opt", help="Range to view (start:end, e.g., 0x100:0x200)")
    ap.add_argument("--block-size", type=int, default=16, help="Block size in bytes")
    ap.add_argument(
        "--format",
        help="Optional format for block labeling/annotations: mf1k, mf4k, mf1k[value], mf4k[value]",
    )
    ap.add_argument("--units", help="Comma-separated list of unit sizes to display (subset of 1,2,4,8). Default: 2,4,8")
    ap.add_argument("--show", help="Comma-separated subset of columns to show from: RAW,INT_BE,INT_LE,NOT_BE,NOT_LE,BIN,BIN_NOT,NOT_RAW. Default: all")
    ap.add_argument("--colorize", help="Comma-separated list of columns to colorize: RAW and/or any shown columns. Default: RAW")
    ap.add_argument("--ctx", type=Path, help="Diff context file (generated with 'ssdp diff --save-ctx')")
    ap.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="When to emit ANSI color: auto, always, or never (default: auto)",
    )
    ap.add_argument(
        "--no-color",
        action="store_const",
        const="never",
        dest="color",
        help="Disable ANSI color output (same as --color=never)",
    )
    ap.add_argument("--output", "-o", type=Path, help="Output file (stdout if not specified)")
    args = ap.parse_args()
    
    try:
        from ..core.io import read_file_bytes
        
        # Read the file
        if not args.path.exists():
            print(f"error: file '{args.path}' does not exist", file=sys.stderr)
            sys.exit(2)
            
        data = read_file_bytes(args.path)
        
        # Parse range if provided
        start_offset = 0
        view_length = None
        
        if args.range_opt:
            if args.offset is not None or args.length is not None:
                print("error: cannot use --range with --offset or --len", file=sys.stderr)
                sys.exit(2)
            
            if ":" not in args.range_opt:
                print("error: range must be in format 'start:end' (e.g., '0x100:0x200')", file=sys.stderr)
                sys.exit(2)
            
            start_str, end_str = args.range_opt.split(":", 1)
            try:
                start_offset = int(start_str, 0)  # Support hex with 0x prefix
                end = int(end_str, 0)
                
                if start_offset < 0 or end < 0:
                    print("error: range values must be non-negative", file=sys.stderr)
                    sys.exit(2)
                if start_offset >= end:
                    print("error: range start must be less than end", file=sys.stderr)
                    sys.exit(2)
                
                view_length = end - start_offset
            except ValueError:
                print("error: invalid number format in range", file=sys.stderr)
                sys.exit(2)
        else:
            if args.offset is not None:
                start_offset = args.offset
            if args.length is not None:
                view_length = args.length
        
        # Validate range
        if start_offset >= len(data):
            print(f"error: offset {start_offset} is beyond file size {len(data)}", file=sys.stderr)
            sys.exit(2)
        
        if view_length is not None and start_offset + view_length > len(data):
            # Truncate to file size
            view_length = len(data) - start_offset
            print(f"warning: length truncated to {view_length} bytes", file=sys.stderr)
        
        # Get the data slice to view
        if view_length is not None:
            view_data = data[start_offset:start_offset + view_length]
        else:
            view_data = data[start_offset:]
        
        # Choose output format
        if args.json:
            import json
            json_obj = {
                "offset": start_offset,
                "length": len(view_data),
                "data": " ".join(f"{b:02X}" for b in view_data),
            }
            print(json.dumps(json_obj, separators=(',', ':')))
            
        elif args.xxd:
            from ..utils.cli import should_use_color

            # Load diff context for highlighting if provided
            diff_units = {}
            if args.ctx:
                try:
                    import json
                    with args.ctx.open("r") as f:
                        ctx_data = json.load(f)
                    diff_units = ctx_data.get("diff_units", {})
                    print(f"Loaded diff context for highlighting", file=sys.stderr)
                except Exception as e:
                    print(f"warning: could not load context file: {e}", file=sys.stderr)
            
            # Build set of differing byte positions for highlighting
            byte_to_unit = {}
            unit_to_color = {}
            color_index = 0
            colors = ["\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m"]
            
            # Sort all units by offset for consistent colors
            all_units = []
            for unit_size_str, units in diff_units.items():
                unit_size = int(unit_size_str)
                for unit_info in units:
                    all_units.append((unit_info["offset"], unit_size, unit_info))
            
            all_units.sort()
            
            for offset, unit_size, unit_info in all_units:
                unit_key = (offset, unit_size)
                if unit_key not in unit_to_color:
                    unit_to_color[unit_key] = colors[color_index % len(colors)]
                    color_index += 1
                
                for i in range(unit_size):
                    byte_to_unit[offset + i] = unit_key
            
            use_color = should_use_color(args.color, sys.stdout.isatty())
            RESET = "\033[0m" if use_color and byte_to_unit else ""
            
            # xxd format with optional highlighting
            for i in range(0, len(view_data), 16):
                chunk = view_data[i:i + 16]
                offset = start_offset + i
                
                # Hex part with highlighting
                hex_parts = []
                for j in range(4):
                    group_start = j * 4
                    group = chunk[group_start:group_start + 4]
                    if group:
                        hex_bytes = []
                        for k, b in enumerate(group):
                            byte_offset = offset + group_start + k
                            if use_color and byte_offset in byte_to_unit:
                                unit_key = byte_to_unit[byte_offset]
                                color = unit_to_color[unit_key]
                                hex_bytes.append(f"{color}{b:02x}{RESET}")
                            else:
                                hex_bytes.append(f"{b:02x}")
                        hex_part = " ".join(hex_bytes)
                        hex_parts.append(hex_part)
                    else:
                        hex_parts.append(" " * 11)
                
                # ASCII part with highlighting
                ascii_chars = []
                for k, b in enumerate(chunk):
                    byte_offset = offset + k
                    ch = chr(b) if 32 <= b <= 126 else "."
                    if use_color and byte_offset in byte_to_unit:
                        unit_key = byte_to_unit[byte_offset]
                        color = unit_to_color[unit_key]
                        ascii_chars.append(f"{color}{ch}{RESET}")
                    else:
                        ascii_chars.append(ch)
                ascii_part = "".join(ascii_chars)
                
                line = f"{offset:08x}: {' '.join(hex_parts)}  {ascii_part}"
                print(line)
        
        else:
            # Default: Unit-based analysis like diff command
            from ..utils.cli import (
                parse_colorize_arg,
                parse_show_arg,
                parse_units_arg,
                should_use_color,
            )
            from ..core.render_units import print_block_units
            
            # Optional format-specific validation, labeling, and annotations
            format_labeler = None
            try:
                from ..core.mifare import parse_format_filter

                chip_format, block_filter = parse_format_filter(args.format)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                sys.exit(2)
            detect_mifare_values = chip_format in {"mf1k", "mf4k"}
            only_value_blocks = block_filter == "value"

            # Parse arguments. MIFARE value blocks are organized as 4-byte value
            # fields, so prefer that view unless the caller explicitly asks.
            try:
                default_units = "4" if chip_format in {"mf1k", "mf4k"} else None
                units_list = parse_units_arg(args.units or default_units)
                show_cols = parse_show_arg(args.show)
                colorize_cols = parse_colorize_arg(args.colorize, show_cols)
            except Exception as e:
                print(f"error: {e}", file=sys.stderr)
                sys.exit(2)

            if chip_format in {"mf1k", "mf4k"}:
                try:
                    from ..core.mifare import get_chip_config, get_sector_block_mapper
                    cfg = get_chip_config(chip_format)
                    if len(view_data) % cfg.total_bytes != 0:
                        print(f"warning: file size {len(view_data)} doesn't align with {chip_format} block structure", file=sys.stderr)
                    format_labeler = get_sector_block_mapper(chip_format)
                except Exception as e:
                    print(f"warning: format setup failed: {e}", file=sys.stderr)
            
            # Parse diff context to get differing unit offsets and blocks
            differing_unit_offsets = None
            differing_blocks = None
            if args.ctx:
                try:
                    import json
                    with args.ctx.open("r") as f:
                        ctx_data = json.load(f)
                    
                    # Extract differing blocks
                    differing_blocks = set()
                    diff_blocks = ctx_data.get("diff_blocks", [])
                    for block_info in diff_blocks:
                        differing_blocks.add(block_info["abs_block"])
                    
                    # Extract differing unit offsets from requested unit sizes only.
                    differing_unit_offsets = set()
                    diff_units = ctx_data.get("diff_units", {})
                    found_unit_sizes = []
                    for unit_size in units_list:
                        unit_size_str = str(unit_size)
                        units = diff_units.get(unit_size_str)
                        if units is None:
                            print(f"warning: unit size {unit_size} not found in context", file=sys.stderr)
                            continue
                        found_unit_sizes.append(unit_size_str)
                        for unit_info in units:
                            differing_unit_offsets.add(unit_info["offset"])
                    
                    sizes = ",".join(found_unit_sizes) if found_unit_sizes else "none"
                    print(f"Loaded diff context: {len(differing_blocks)} differing blocks, {len(differing_unit_offsets)} differing units (sizes: {sizes})", file=sys.stderr)
                except Exception as e:
                    print(f"warning: could not load context file: {e}", file=sys.stderr)
            
            # Calculate blocks 
            total_blocks = (len(view_data) + args.block_size - 1) // args.block_size
            use_color = should_use_color(args.color, sys.stdout.isatty())
            max_block_idx = max(total_blocks - 1, 0)
            if chip_format in {"mf1k", "mf4k"}:
                try:
                    from ..core.mifare import get_chip_config

                    max_block_idx = get_chip_config(chip_format).total_blocks - 1
                except Exception:
                    pass
            block_index_width = len(str(max_block_idx))
            block_hex_width = max(2, len(f"{max_block_idx:X}"))
            
            print(f"File: {args.path}")
            print(f"Size: {len(view_data)} bytes ({total_blocks} blocks of {args.block_size} bytes)")
            if start_offset > 0:
                print(f"Range: {start_offset:08x}-{start_offset + len(view_data) - 1:08x}")
            if format_labeler:
                print("MIFARE: sec=sector, blk=block within sector")
            print()
            
            # Create a single "file" for the view data
            datas = [view_data]
            aliases = ["data"]
            
            # Show each block using the same format as diff
            for block_idx in range(total_blocks):
                # Calculate the actual block data for this view slice
                block_start = block_idx * args.block_size
                if block_start >= len(view_data):
                    break
                
                # For display purposes, use the absolute block index from the original file
                abs_block_idx = (start_offset + block_start) // args.block_size
                
                # If using diff context, skip blocks that don't differ
                if differing_blocks is not None and abs_block_idx not in differing_blocks:
                    continue
                
                # But for data access, use the relative block index within view_data
                display_block_idx = abs_block_idx  # Absolute block number to display.
                data_block_idx = block_idx  # Index for accessing data within view_data
                
                # Determine MIFARE annotations and optional block filters.
                block_notes = []
                value_block = None
                if detect_mifare_values:
                    from ..core.mifare_value import detect_value_block

                    block_bytes = view_data[block_start:block_start + args.block_size]
                    value_block = detect_value_block(block_bytes)
                    if value_block is not None:
                        block_notes.append(
                            f"[MIFARE VALUE] value={value_block.value} adr={value_block.address} (0x{value_block.address:02X})"
                        )

                if only_value_blocks and value_block is None:
                    continue

                # Determine which units to show based on context
                if differing_unit_offsets:
                    # With diff context: only show units that were different
                    print_block_units(
                        display_block_idx, datas, aliases, format_labeler, units_list, use_color,
                        show_cols, colorize_cols, "none", args.block_size, 
                        force_show_all_units=False, differing_unit_offsets=differing_unit_offsets,
                        data_block_idx=data_block_idx, block_notes=block_notes,
                        mark_diffs=True, block_index_width=block_index_width,
                        block_hex_width=block_hex_width
                    )
                else:
                    # Without diff context: show all units for comprehensive analysis
                    print_block_units(
                        display_block_idx, datas, aliases, format_labeler, units_list, use_color,
                        show_cols, colorize_cols, "none", args.block_size, force_show_all_units=True,
                        data_block_idx=data_block_idx, block_notes=block_notes,
                        mark_diffs=True, block_index_width=block_index_width,
                        block_hex_width=block_hex_width
                    )
        
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
