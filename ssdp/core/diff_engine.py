"""Diff engine for comparing byte buffers and generating diff spans."""

from __future__ import annotations

from typing import Dict, List, Optional

from .mifare import abs_block_to_addr, get_chip_config
from .types import BlockAddr, ChipType, DiffSpan


def blocks_that_differ(datas: List[bytes], total_blocks: int, bytes_per_block: int = 16) -> List[int]:
    """Find all blocks that differ between the input data files."""
    differing = []
    
    for i in range(total_blocks):
        start = i * bytes_per_block
        end = start + bytes_per_block
        first = datas[0][start:end]
        
        if any(d[start:end] != first for d in datas[1:]):
            differing.append(i)
    
    return differing


def diff_by_offset(
    datas: Dict[str, bytes], 
    block_size: int = 16,
    chip_type: ChipType = "none",
    max_gap: int = 1
) -> List[DiffSpan]:
    """
    Compare N byte buffers by offset and return differing spans.
    
    Args:
        datas: Dict mapping file labels to byte data
        block_size: Size of blocks for chip addressing (default 16)
        chip_type: Type of chip for block addressing
        max_gap: Maximum gap between differing bytes to coalesce into one span
    
    Returns:
        List of DiffSpan objects representing differing regions
    """
    if not datas:
        return []
    
    labels = list(datas.keys())
    byte_arrays = list(datas.values())
    
    # Find the minimum length across all inputs
    min_length = min(len(data) for data in byte_arrays)
    if min_length == 0:
        return []
    
    # Find all differing byte offsets
    differing_offsets: List[int] = []
    
    for offset in range(min_length):
        first_byte = byte_arrays[0][offset]
        if any(data[offset] != first_byte for data in byte_arrays[1:]):
            differing_offsets.append(offset)
    
    if not differing_offsets:
        return []
    
    # Coalesce adjacent offsets into spans
    spans: List[DiffSpan] = []
    current_start = differing_offsets[0]
    current_end = differing_offsets[0]
    
    for offset in differing_offsets[1:]:
        if offset <= current_end + max_gap + 1:
            # Extend current span
            current_end = offset
        else:
            # Create span and start a new one
            span = _create_diff_span(
                current_start, current_end, datas, labels, block_size, chip_type
            )
            spans.append(span)
            current_start = current_end = offset
    
    # Don't forget the last span
    span = _create_diff_span(
        current_start, current_end, datas, labels, block_size, chip_type
    )
    spans.append(span)
    
    return spans


def _create_diff_span(
    start_offset: int,
    end_offset: int,
    datas: Dict[str, bytes],
    labels: List[str],
    block_size: int,
    chip_type: ChipType
) -> DiffSpan:
    """Create a DiffSpan from start/end offsets."""
    length = end_offset - start_offset + 1
    values = {}
    
    for label in labels:
        data = datas[label]
        values[label] = data[start_offset:start_offset + length]
    
    # Calculate block address if we have chip info
    block_addr: Optional[BlockAddr] = None
    if chip_type != "none":
        abs_block = start_offset // block_size
        try:
            block_addr = abs_block_to_addr(abs_block, chip_type)
        except Exception:
            # If block addressing fails, just use None
            pass
    
    return DiffSpan(
        offset=start_offset,
        length=length,
        values=values,
        block=block_addr
    )


def same_mask_for_block(block_slices: List[bytes]) -> bytes:
    """
    Generate a same mask for a block, where each bit represents whether
    that byte is identical across all inputs.
    
    Returns a bytes object where 'X' means same, '\0' means different.
    This is used for xxd header generation.
    """
    if not block_slices:
        return b'\0' * 16
    
    mask_bytes = bytearray()
    first = block_slices[0]
    min_len = min(len(s) for s in block_slices)
    
    for i in range(16):  # Always generate 16-byte mask
        if i < min_len:
            byte_val = first[i]
            is_same = all(
                i < len(s) and s[i] == byte_val 
                for s in block_slices[1:]
            )
            mask_bytes.append(ord('X') if is_same else 0)
        else:
            mask_bytes.append(0)  # Beyond data length = different
    
    return bytes(mask_bytes)


def compute_diff_summary(spans: List[DiffSpan]) -> Dict[str, int]:
    """Compute summary statistics for diff results."""
    if not spans:
        return {"total_spans": 0, "total_bytes": 0}
    
    total_bytes = sum(span.length for span in spans)
    files = set()
    for span in spans:
        files.update(span.values.keys())
    
    return {
        "total_spans": len(spans),
        "total_bytes": total_bytes,
        "files_compared": len(files),
        "blocks_affected": len({span.block.abs_block for span in spans if span.block}),
    }


def filter_spans_by_context(
    spans: List[DiffSpan], 
    context_bytes: int,
    total_length: int
) -> List[DiffSpan]:
    """Filter spans to include context around differences."""
    if context_bytes <= 0:
        return spans
    
    # For now, just extend each span by the context amount
    # In a full implementation, you'd merge overlapping contexts
    filtered_spans = []
    
    for span in spans:
        start = max(0, span.offset - context_bytes)
        end = min(total_length, span.offset + span.length + context_bytes)
        
        # Create new span with extended range
        new_values = {}
        for label, data_dict in span.values.items():
            # We'd need access to the full data here, this is simplified
            new_values[label] = data_dict  # Placeholder
        
        filtered_span = DiffSpan(
            offset=start,
            length=end - start,
            values=new_values,
            block=span.block
        )
        filtered_spans.append(filtered_span)
    
    return filtered_spans


def align_data_to_shortest(datas: Dict[str, bytes]) -> tuple[Dict[str, bytes], Optional[DiffSpan]]:
    """
    Align all data to the shortest file length and return truncation info.
    
    Returns:
        - Dict of aligned data
        - Optional DiffSpan representing the truncated tail region
    """
    if not datas:
        return {}, None
    
    min_length = min(len(data) for data in datas.values())
    aligned_datas = {label: data[:min_length] for label, data in datas.items()}
    
    # Check if any files had extra data
    tail_values = {}
    max_length = max(len(data) for data in datas.values())
    
    if max_length > min_length:
        for label, data in datas.items():
            if len(data) > min_length:
                tail_values[label] = data[min_length:]
            else:
                tail_values[label] = b""  # Empty for shorter files
        
        tail_span = DiffSpan(
            offset=min_length,
            length=max_length - min_length,
            values=tail_values,
            block=None  # Tail doesn't align to blocks
        )
        return aligned_datas, tail_span
    
    return aligned_datas, None