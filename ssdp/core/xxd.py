"""xxd-style formatting utilities with configurable grouping."""

from __future__ import annotations

from typing import List, Optional

from ..utils.bytestr import ascii_bytes


def same_byte_mask(block_slices: List[bytes]) -> List[bool]:
    """Return a 16-length mask where True means the byte is equal across all slices."""
    if not block_slices:
        return [False] * 16
    
    mask = [True] * 16
    first = block_slices[0]
    
    # Handle cases where blocks might be shorter than 16 bytes
    min_len = min(len(slice_) for slice_ in block_slices)
    
    for j in range(min(16, min_len)):
        v = first[j]
        for slice_ in block_slices[1:]:
            if j >= len(slice_) or slice_[j] != v:
                mask[j] = False
                break
    
    # Mark bytes beyond the shortest slice as different
    for j in range(min_len, 16):
        mask[j] = False
    
    return mask


def _hex_groups_4x4(sixteen: bytes, mask: Optional[List[bool]] = None, group_size: int = 4) -> str:
    """Return hex string grouped by group_size, double space between groups.
    If mask is given (len 16), print byte hex if mask[i] True, else two spaces.
    """
    tokens: List[str] = []
    
    # Handle cases where sixteen might be shorter than 16 bytes
    for i in range(16):
        if i < len(sixteen):
            b = sixteen[i]
            if mask is None or mask[i]:
                tokens.append(f"{b:02x}")
            else:
                tokens.append("  ")  # keep column width
        else:
            tokens.append("  ")  # pad with spaces if data is shorter
    
    groups: List[str] = []
    num_groups = 16 // group_size
    for g in range(num_groups):
        start = g * group_size
        grp = " ".join(tokens[start : start + group_size])
        groups.append(grp)
    
    return "  ".join(groups)


def _ascii_groups_4x4(sixteen: bytes, mask: Optional[List[bool]] = None) -> str:
    """Return ASCII representation, blanking out differing bytes if mask provided."""
    chars: List[str] = []
    
    for i in range(16):
        if i < len(sixteen):
            b = sixteen[i]
            ch = chr(b) if 32 <= b <= 126 else "."
            if mask is not None and not mask[i]:
                ch = " "  # blank out differing bytes
            chars.append(ch)
        else:
            chars.append(" ")  # pad with spaces if data is shorter
    
    return "".join(chars)


def xxd_line_group4(
    offset: int, 
    sixteen: bytes, 
    mask: Optional[List[bool]] = None, 
    group_size: int = 4
) -> str:
    """Format a single xxd-style line with configurable grouping."""
    left = f"{offset:08x}:"
    hex_part = _hex_groups_4x4(sixteen, mask, group_size)
    ascii_part = _ascii_groups_4x4(sixteen, mask)
    return f"{left} {hex_part}  {ascii_part}"


def xxd_block_lines(
    data: bytes, 
    start_offset: int = 0, 
    group_size: int = 4,
    bytes_per_line: int = 16
) -> List[str]:
    """Generate xxd-style lines for a block of data."""
    lines: List[str] = []
    
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        offset = start_offset + i
        line = xxd_line_group4(offset, chunk, group_size=group_size)
        lines.append(line)
    
    return lines


def xxd_diff_block(
    abs_block: int,
    sector: int,
    block_index: int,
    block_slices: List[bytes],
    aliases: List[str],
    group_size: int = 4,
    bytes_per_block: int = 16,
    include_same_line: bool = True
) -> List[str]:
    """Generate xxd-style diff lines for a single block."""
    lines: List[str] = []
    
    # Block header
    lines.append(f"[BLOCK] S={sector} B={block_index} (abs={abs_block})")
    
    if include_same_line and len(block_slices) > 1:
        # SAME line: show only identical bytes across all inputs
        mask = same_byte_mask(block_slices)
        block_start = abs_block * bytes_per_block
        same_line = "same   " + xxd_line_group4(block_start, block_slices[0], mask, group_size)
        lines.append(same_line)
    
    # Then each alias line (full bytes)
    for alias, chunk in zip(aliases, block_slices):
        block_start = abs_block * bytes_per_block
        alias_line = f"{alias} " + xxd_line_group4(block_start, chunk, group_size=group_size)
        lines.append(alias_line)
    
    return lines


def write_xxd_full_file(file_path: str, data: bytes, group_size: int = 4) -> None:
    """Write full xxd dump to file."""
    with open(file_path, "w", encoding="utf-8") as f:
        lines = xxd_block_lines(data, group_size=group_size)
        for line in lines:
            f.write(line + "\n")


def generate_xxd_diff_lines(
    diff_blocks: List[int],
    datas: List[bytes],
    aliases: List[str],
    chip_mapper_func,
    bytes_per_block: int = 16,
    group_size: int = 4,
    first_only: bool = False,
    include_same_line: bool = True
) -> List[str]:
    """Generate xxd-style diff lines for multiple differing blocks."""
    lines: List[str] = []
    
    for abs_block in diff_blocks:
        if chip_mapper_func:
            sector, block_index = chip_mapper_func(abs_block)
        else:
            sector, block_index = 0, abs_block
        
        block_start = abs_block * bytes_per_block
        block_slices = [d[block_start : block_start + bytes_per_block] for d in datas]
        
        if first_only:
            # Only show first file's data, but compute SAME mask across all
            block_lines = xxd_diff_block(
                abs_block, sector, block_index, 
                block_slices, [aliases[0]], 
                group_size, bytes_per_block, include_same_line
            )
        else:
            # Show all files
            block_lines = xxd_diff_block(
                abs_block, sector, block_index,
                block_slices, aliases,
                group_size, bytes_per_block, include_same_line
            )
        
        lines.extend(block_lines)
        lines.append("")  # Empty line after each block
    
    return lines