"""MIFARE Classic chip utilities and sector/block addressing."""

from __future__ import annotations

from typing import Callable, Tuple

from .errors import ChipConfigError
from .types import BlockAddr, ChipConfig, ChipType


def to_sector_block_mf1k(abs_block: int) -> Tuple[int, int]:
    """Convert absolute block to (sector, block_in_sector) for MF1K."""
    if not (0 <= abs_block < 64):
        raise ChipConfigError(f"Block {abs_block} out of range for mf1k (0-63)")
    sector = abs_block // 4
    block_in_sector = abs_block % 4
    return sector, block_in_sector


def to_sector_block_mf4k(abs_block: int) -> Tuple[int, int]:
    """Convert absolute block to (sector, block_in_sector) for MF4K."""
    if not (0 <= abs_block < 256):
        raise ChipConfigError(f"Block {abs_block} out of range for mf4k (0-255)")
    if abs_block < 128:
        # First 32 sectors have 4 blocks each
        sector = abs_block // 4
        block_in_sector = abs_block % 4
        return sector, block_in_sector
    # Remaining sectors have 16 blocks each
    idx = abs_block - 128
    sector = 32 + (idx // 16)
    block_in_sector = idx % 16
    return sector, block_in_sector


CHIP_CONFIGS = {
    "mf1k": ChipConfig(
        total_blocks=64,
        total_bytes=64 * 16,
        bytes_per_block=16,
    ),
    "mf4k": ChipConfig(
        total_blocks=256,
        total_bytes=256 * 16,
        bytes_per_block=16,
    ),
}

CHIP_MAPPERS = {
    "mf1k": to_sector_block_mf1k,
    "mf4k": to_sector_block_mf4k,
}


def get_chip_config(chip_type: str) -> ChipConfig:
    """Get configuration for a specific chip type."""
    if chip_type not in CHIP_CONFIGS:
        raise ChipConfigError(f"Unknown chip type: {chip_type}")
    return CHIP_CONFIGS[chip_type]


def get_sector_block_mapper(chip_type: str) -> Callable[[int], Tuple[int, int]]:
    """Get sector/block mapper function for a specific chip type."""
    if chip_type not in CHIP_MAPPERS:
        raise ChipConfigError(f"Unknown chip type: {chip_type}")
    return CHIP_MAPPERS[chip_type]


def detect_chip_type(file_size: int) -> str:
    """Auto-detect chip type based on file size."""
    for chip_type, config in CHIP_CONFIGS.items():
        if file_size == config.total_bytes:
            return chip_type
    return "none"


def abs_block_to_addr(abs_block: int, chip_type: str) -> BlockAddr:
    """Convert absolute block number to BlockAddr with sector/index info."""
    if chip_type == "none":
        return BlockAddr(abs_block=abs_block, sector=0, index=abs_block)
    
    mapper = get_sector_block_mapper(chip_type)
    sector, index = mapper(abs_block)
    return BlockAddr(abs_block=abs_block, sector=sector, index=index)


def blocks_in_sector(sector: int, chip_type: str) -> int:
    """Get the number of blocks in a specific sector."""
    if chip_type == "mf1k":
        return 4
    elif chip_type == "mf4k":
        return 4 if sector < 32 else 16
    else:
        return 1  # For "none" or unknown types


def validate_file_size(file_size: int, chip_type: str) -> None:
    """Validate that file size matches expected size for chip type."""
    if chip_type == "none":
        return  # Any size is valid for none
    
    config = get_chip_config(chip_type)
    if file_size != config.total_bytes:
        raise ChipConfigError(
            f"File size {file_size} doesn't match expected size {config.total_bytes} "
            f"for chip type {chip_type}"
        )