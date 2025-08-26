"""Rendering utilities for text, JSON, and xxd output formats."""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Set

from .mifare import get_sector_block_mapper
from .types import DiffSpan, Format
from .xxd import generate_xxd_diff_lines, xxd_block_lines
from ..utils.bytestr import hex_bytes


def render_diff_text(
    spans: List[DiffSpan], 
    files: List[str],
    aliases: Dict[str, str]
) -> List[str]:
    """Render diff spans as text output."""
    lines: List[str] = []
    
    if not spans:
        lines.append("No differences found.")
        return lines
    
    for span in spans:
        # Format: @offset +length | file1:bytes | file2:bytes
        offset_info = f"@{span.offset} +{span.length}"
        
        value_parts = []
        for label in sorted(span.values.keys()):
            value = span.values[label]
            hex_str = hex_bytes(value)
            value_parts.append(f"{label}:{hex_str}")
        
        line = f"{offset_info} | " + " | ".join(value_parts)
        lines.append(line)
    
    return lines


def render_diff_json(
    spans: List[DiffSpan], 
    files: List[str],
    aliases: Dict[str, str]
) -> List[str]:
    """Render diff spans as JSON lines (JSONL format)."""
    lines: List[str] = []
    
    for span in spans:
        # Convert span to JSON-serializable dict
        json_obj = {
            "offset": span.offset,
            "len": span.length,
            "values": {
                label: hex_bytes(value)
                for label, value in span.values.items()
            },
            "files": files,
        }
        
        # Add block information if available
        if span.block:
            json_obj["block"] = {
                "abs": span.block.abs_block,
                "sector": span.block.sector,
                "index": span.block.index,
            }
        
        # Add same_mask if we can compute it
        if len(span.values) > 1:
            # Simple same mask: 'X' for positions where all values match
            value_list = list(span.values.values())
            same_mask_chars = []
            
            for i in range(span.length):
                if i < min(len(v) for v in value_list):
                    byte_val = value_list[0][i]
                    is_same = all(v[i] == byte_val for v in value_list[1:] if i < len(v))
                    same_mask_chars.append('X' if is_same else '_')
                else:
                    same_mask_chars.append('_')
            
            json_obj["same_mask"] = "".join(same_mask_chars)
        
        lines.append(json.dumps(json_obj, separators=(',', ':')))
    
    return lines


def render_diff_xxd(
    spans: List[DiffSpan],
    datas: Dict[str, bytes],
    files: List[str],
    aliases: Dict[str, str],
    chip_type: str = "none",
    group_size: int = 4,
    only_diff: bool = True,
    first_only: bool = False
) -> List[str]:
    """Render diff spans as xxd-style output."""
    lines: List[str] = []
    
    if not spans:
        lines.append("No differences found.")
        return lines
    
    # Extract differing block numbers
    diff_blocks = []
    for span in spans:
        if span.block:
            if span.block.abs_block not in diff_blocks:
                diff_blocks.append(span.block.abs_block)
        else:
            # For non-block-aligned diffs, use offset-based blocks
            block_num = span.offset // 16
            if block_num not in diff_blocks:
                diff_blocks.append(block_num)
    
    diff_blocks.sort()
    
    # Get chip mapper if available
    chip_mapper = None
    if chip_type != "none":
        try:
            chip_mapper = get_sector_block_mapper(chip_type)
        except Exception:
            chip_mapper = None
    
    # Generate xxd lines
    data_list = [datas[label] for label in sorted(datas.keys())]
    alias_list = [label for label in sorted(datas.keys())]
    
    xxd_lines = generate_xxd_diff_lines(
        diff_blocks=diff_blocks,
        datas=data_list,
        aliases=alias_list,
        chip_mapper_func=chip_mapper,
        bytes_per_block=16,
        group_size=group_size,
        first_only=first_only,
        include_same_line=True
    )
    
    lines.extend(xxd_lines)
    return lines


def render_view_xxd(
    data: bytes,
    start_offset: int = 0,
    length: Optional[int] = None,
    group_size: int = 4,
    annotations: Optional[Set[int]] = None
) -> List[str]:
    """Render a single file as xxd output with optional annotations."""
    if length is not None:
        data = data[start_offset:start_offset + length]
    else:
        data = data[start_offset:]
    
    lines = xxd_block_lines(data, start_offset, group_size)
    
    # TODO: Apply annotations if provided
    # This would highlight specific byte positions that differ
    
    return lines


def render_view_json(
    data: bytes,
    start_offset: int = 0,
    length: Optional[int] = None,
    annotations: Optional[Set[int]] = None
) -> List[str]:
    """Render a single file as JSON output."""
    if length is not None:
        data = data[start_offset:start_offset + length]
    else:
        data = data[start_offset:]
    
    json_obj = {
        "offset": start_offset,
        "length": len(data),
        "data": hex_bytes(data),
    }
    
    if annotations:
        # Convert absolute annotations to relative
        relative_annotations = [
            pos - start_offset 
            for pos in annotations 
            if start_offset <= pos < start_offset + len(data)
        ]
        json_obj["annotations"] = relative_annotations
    
    return [json.dumps(json_obj, separators=(',', ':'))]


def render_conv_output(results: Dict[str, str], to_formats: Optional[List[str]] = None) -> List[str]:
    """Render conversion results."""
    lines: List[str] = []
    
    # Filter results if specific output formats requested
    if to_formats:
        filtered_results = {k: v for k, v in results.items() if k in to_formats}
    else:
        filtered_results = results
    
    # Find the maximum key length for alignment
    max_key_len = max(len(k) for k in filtered_results.keys()) if filtered_results else 0
    
    for rep in sorted(filtered_results.keys()):
        value = filtered_results[rep]
        lines.append(f"{rep:<{max_key_len}}: {value}")
    
    return lines


def render_summary(
    spans: List[DiffSpan],
    files: List[str],
    aliases: Dict[str, str]
) -> List[str]:
    """Render summary statistics for diff results."""
    lines: List[str] = []
    
    if not spans:
        lines.append("Summary: No differences found")
        return lines
    
    total_bytes = sum(span.length for span in spans)
    blocks_affected = len({span.block.abs_block for span in spans if span.block})
    
    lines.append("Summary:")
    lines.append(f"  Total diff spans: {len(spans)}")
    lines.append(f"  Total diff bytes: {total_bytes}")
    lines.append(f"  Files compared: {len(files)}")
    
    if blocks_affected > 0:
        lines.append(f"  Blocks affected: {blocks_affected}")
    
    # Per-file statistics
    lines.append("  Per file:")
    for file_path in files:
        # Find alias for this file
        alias = None
        for a, path in aliases.items():
            if path == file_path:
                alias = a
                break
        display_name = alias or file_path
        
        file_bytes = sum(
            len(span.values.get(alias, b""))
            for span in spans
            if alias and alias in span.values
        )
        lines.append(f"    {display_name}: {file_bytes} bytes")
    
    return lines


def render_input_summary(files: List[str], aliases: Dict[str, str]) -> List[str]:
    """Render summary of input files."""
    lines = ["Inputs:"]
    
    for file_path in files:
        # Find alias for this file
        alias = None
        for a, path in aliases.items():
            if path == file_path:
                alias = a
                break
        
        display_name = alias or "unknown"
        lines.append(f"  {display_name}: {file_path}")
    
    return lines