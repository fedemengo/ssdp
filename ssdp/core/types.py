"""Core types for SSDP package."""

from __future__ import annotations

from typing import Dict, List, Literal, NamedTuple, Optional

Format = Literal["text", "json", "xxd"]
Rep = Literal[
    "RAW", "NOT_RAW", "INT_BE", "INT_LE", "NOT_BE", "NOT_LE", "BIN", "BIN_NOT"
]
ChipType = Literal["mf1k", "mf4k", "auto", "none"]


class BlockAddr(NamedTuple):
    """Address information for a block within a chip layout."""
    
    abs_block: int
    sector: int
    index: int


class DiffSpan(NamedTuple):
    """Represents a contiguous span of differing bytes between files."""
    
    offset: int
    length: int
    values: Dict[str, bytes]  # label -> raw bytes
    block: Optional[BlockAddr]


class ChipConfig(NamedTuple):
    """Configuration for a specific chip type."""
    
    total_blocks: int
    total_bytes: int
    bytes_per_block: int = 16


class DiffResult(NamedTuple):
    """Complete result of a diff operation."""
    
    spans: List[DiffSpan]
    files: List[str]
    aliases: Dict[str, str]
    chip_config: Optional[ChipConfig]


class ViewOptions(NamedTuple):
    """Options for viewing a single file."""
    
    offset: int = 0
    length: Optional[int] = None
    chip_type: ChipType = "auto"
    block_size: int = 16
    xxd_group: int = 4


class DiffOptions(NamedTuple):
    """Options for diff operations."""
    
    format: Format = "text"
    chip_type: ChipType = "auto"
    block_size: int = 16
    xxd_group: int = 4
    only_diff: bool = True
    context: int = 0
    first_only: bool = False
    summary: bool = False
    exit_code: bool = False