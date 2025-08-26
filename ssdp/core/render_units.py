"""Unit-based block rendering with correct format."""

from typing import List, Callable, Tuple, Optional
from ..utils.bytestr import (
    hex_bytes, int_be, int_le, bitwise_not_bytes, bin_str,
    ascii_bytes
)

# ANSI color codes
ANSI_COLORS = [
    "\033[31m",  # red
    "\033[36m",  # cyan
    "\033[32m",  # green
    "\033[35m",  # magenta
    "\033[33m",  # yellow
    "\033[34m",  # blue
]
ANSI_RESET = "\033[0m"


def colorize_token(token: str, color: str, enable: bool) -> str:
    """Apply ANSI color to a token if enabled."""
    return f"{color}{token}{ANSI_RESET}" if enable else token

def print_block_units(
    abs_block: int,
    datas: List[bytes],
    aliases: List[str],
    to_sector_block: Optional[Callable[[int], Tuple[int, int]]] = None,
    units: Optional[List[int]] = None,
    use_color: bool = False,
    show_cols: Optional[List[str]] = None,
    colorize_cols: Optional[List[str]] = None,
    show_same_mode: str = "none",
    block_size: int = 16,
    force_show_all_units: bool = False,
    differing_unit_offsets: Optional[set] = None,
    data_block_idx: Optional[int] = None,
):
    """Print block with correct format matching original."""
    # Set defaults
    if units is None:
        units = [2, 4, 8]
    if show_cols is None:
        show_cols = ["INT_BE", "INT_LE", "NOT_BE", "NOT_LE", "BIN", "BIN_NOT", "NOT_RAW"]
    if colorize_cols is None:
        colorize_cols = ["RAW"]
    
    # Print block header with color
    header_color = "\033[1;33m"  # Bold yellow
    reset = "\033[0m"
    
    if to_sector_block:
        s, b = to_sector_block(abs_block)
        header = f"[BLOCK] ID={abs_block} S={s} B={b}"
    else:
        header = f"[BLOCK] ID={abs_block}"
    
    if use_color:
        print(f"{header_color}{header}{reset}")
    else:
        print(header)

    # Use data_block_idx for data access if provided, otherwise use abs_block
    actual_block_idx = data_block_idx if data_block_idx is not None else abs_block
    block_start = actual_block_idx * block_size
    full_slices = [d[block_start : block_start + block_size] for d in datas]

    for size in units:
        unit_header_color = "\033[1;36m"  # Bold cyan
        if use_color:
            print(f"  {unit_header_color}[units={size}]{reset}")
        else:
            print(f"  [units={size}]")
        
        # Get colors for each file
        colors = [ANSI_COLORS[i % len(ANSI_COLORS)] for i in range(len(aliases))]
        
        # Find which units differ in this block for colorization
        differing_units = set()
        for off in range(0, 16, size):
            unit_slices = [s[off:off+size] for s in full_slices]
            first_unit = unit_slices[0]
            if any(unit != first_unit for unit in unit_slices[1:]):
                differing_units.add(off)
        
        # First show FULL row for each file with colorized differing units
        for i, (alias, data_slice) in enumerate(zip(aliases, full_slices)):
            # Split into unit-size groups with | separators
            groups = []
            for j in range(0, 16, size):
                group = data_slice[j:j+size]
                if len(group) == size:
                    # Check if this specific unit differs
                    group_has_diff = j in differing_units
                    
                    group_str = " ".join(f"{b:02X}" for b in group)
                    # Colorize if this unit differs (always colorize FULL if any colorization is enabled)
                    if group_has_diff and use_color:
                        group_str = colorize_token(group_str, colors[i], use_color)
                    groups.append(group_str)
                else:
                    # Pad if less than unit size
                    padded = " ".join(f"{b:02X}" for b in group)
                    groups.append(padded)
            
            full_line = " | ".join(groups)
            print(f"    {alias}: FULL={full_line}")
        
        # Then show each unit offset - BUT ONLY if it differs
        for off in range(0, 16, size):
            unit_slices = [s[off:off+size] for s in full_slices]
            
            # Check if this unit differs or if we're forcing all units to show
            first_unit = unit_slices[0]
            differs = any(unit != first_unit for unit in unit_slices[1:])
            
            # Also check if this specific unit offset is marked as differing in context
            abs_offset = abs_block * block_size + off
            is_in_diff_context = differing_unit_offsets and abs_offset in differing_unit_offsets
            
            if differs or force_show_all_units or is_in_diff_context:
                print(f"    +{off:02d}")
                
                # Get colors for each file
                colors = [ANSI_COLORS[i % len(ANSI_COLORS)] for i in range(len(aliases))]
                
                for i, (alias, unit_data) in enumerate(zip(aliases, unit_slices)):
                    # Format the representations with colorization
                    raw_str = hex_bytes(unit_data)
                    if "RAW" in colorize_cols:
                        raw_str = colorize_token(raw_str, colors[i], use_color)
                    
                    parts = [f"RAW={raw_str}"]
                    
                    if "INT_LE" in show_cols:
                        try:
                            int_le_val = int_le(unit_data)
                            val_str = f"{int_le_val:>10}"
                            if "INT_LE" in colorize_cols:
                                val_str = colorize_token(val_str, colors[i], use_color)
                            parts.append(f"INT_LE={val_str}")
                        except:
                            parts.append("INT_LE=ERR")
                    
                    if "INT_BE" in show_cols:
                        try:
                            int_be_val = int_be(unit_data)
                            val_str = f"{int_be_val:>10}"
                            if "INT_BE" in colorize_cols:
                                val_str = colorize_token(val_str, colors[i], use_color)
                            parts.append(f"INT_BE={val_str}")
                        except:
                            parts.append("INT_BE=ERR")
                    
                    if "NOT_LE" in show_cols:
                        try:
                            not_le_val = int_le(bitwise_not_bytes(unit_data))
                            val_str = f"{not_le_val:>10}"
                            if "NOT_LE" in colorize_cols:
                                val_str = colorize_token(val_str, colors[i], use_color)
                            parts.append(f"NOT_LE={val_str}")
                        except:
                            parts.append("NOT_LE=ERR")
                    
                    if "NOT_BE" in show_cols:
                        try:
                            not_be_val = int_be(bitwise_not_bytes(unit_data))
                            val_str = f"{not_be_val:>10}"
                            if "NOT_BE" in colorize_cols:
                                val_str = colorize_token(val_str, colors[i], use_color)
                            parts.append(f"NOT_BE={val_str}")
                        except:
                            parts.append("NOT_BE=ERR")
                    
                    if "BIN" in show_cols:
                        try:
                            int_val = int_le(unit_data)
                            bit_width = len(unit_data) * 8
                            bin_val = bin_str(int_val, bit_width)
                            val_str = f"{bin_val}"
                            if "BIN" in colorize_cols:
                                val_str = colorize_token(val_str, colors[i], use_color)
                            parts.append(f"BIN={val_str}")
                        except:
                            parts.append("BIN=ERR")
                    
                    if "BIN_NOT" in show_cols:
                        try:
                            not_bytes = bitwise_not_bytes(unit_data)
                            int_val = int_le(not_bytes)
                            bit_width = len(unit_data) * 8
                            bin_not_val = bin_str(int_val, bit_width)
                            val_str = f"{bin_not_val}"
                            if "BIN_NOT" in colorize_cols:
                                val_str = colorize_token(val_str, colors[i], use_color)
                            parts.append(f"BIN_NOT={val_str}")
                        except:
                            parts.append("BIN_NOT=ERR")
                    
                    if "NOT_RAW" in show_cols:
                        try:
                            not_raw_str = hex_bytes(bitwise_not_bytes(unit_data))
                            if "NOT_RAW" in colorize_cols:
                                not_raw_str = colorize_token(not_raw_str, colors[i], use_color)
                            parts.append(f"NOT_RAW={not_raw_str}")
                        except:
                            parts.append("NOT_RAW=ERR")
                    
                    line = " | ".join(parts)
                    print(f"      {alias}: {line}")
        
        print()  # Blank line between unit sizes


# Helper functions from original
def unit_offsets(size: int) -> List[int]:
    """Get byte offsets for units of given size within a 16-byte block."""
    if size not in (2, 4, 8):
        raise ValueError("invalid unit size; expected 2, 4, or 8")
    return list(range(0, 16, size))