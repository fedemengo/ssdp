"""Tests for MIFARE chip utilities."""

import pytest

from ssdp.core.mifare import (
    abs_block_to_addr,
    detect_chip_type,
    get_chip_config,
    to_sector_block_mf1k,
    to_sector_block_mf4k,
    validate_file_size,
)
from ssdp.core.errors import ChipConfigError


class TestMF1K:
    """Test MIFARE Classic 1K utilities."""

    def test_to_sector_block_mf1k_valid(self):
        """Test valid block conversions for MF1K."""
        assert to_sector_block_mf1k(0) == (0, 0)
        assert to_sector_block_mf1k(3) == (0, 3)
        assert to_sector_block_mf1k(4) == (1, 0)
        assert to_sector_block_mf1k(63) == (15, 3)
    
    def test_to_sector_block_mf1k_invalid(self):
        """Test invalid block numbers for MF1K."""
        with pytest.raises(ChipConfigError):
            to_sector_block_mf1k(-1)
        with pytest.raises(ChipConfigError):
            to_sector_block_mf1k(64)


class TestMF4K:
    """Test MIFARE Classic 4K utilities."""

    def test_to_sector_block_mf4k_small_sectors(self):
        """Test block conversions in first 32 sectors (4 blocks each)."""
        assert to_sector_block_mf4k(0) == (0, 0)
        assert to_sector_block_mf4k(127) == (31, 3)
    
    def test_to_sector_block_mf4k_large_sectors(self):
        """Test block conversions in remaining sectors (16 blocks each)."""
        assert to_sector_block_mf4k(128) == (32, 0)
        assert to_sector_block_mf4k(143) == (32, 15)
        assert to_sector_block_mf4k(144) == (33, 0)
        assert to_sector_block_mf4k(255) == (39, 15)
    
    def test_to_sector_block_mf4k_invalid(self):
        """Test invalid block numbers for MF4K."""
        with pytest.raises(ChipConfigError):
            to_sector_block_mf4k(-1)
        with pytest.raises(ChipConfigError):
            to_sector_block_mf4k(256)


class TestChipConfig:
    """Test chip configuration utilities."""

    def test_get_chip_config_valid(self):
        """Test getting valid chip configurations."""
        mf1k_config = get_chip_config("mf1k")
        assert mf1k_config.total_blocks == 64
        assert mf1k_config.total_bytes == 1024
        assert mf1k_config.bytes_per_block == 16

        mf4k_config = get_chip_config("mf4k")
        assert mf4k_config.total_blocks == 256
        assert mf4k_config.total_bytes == 4096
        assert mf4k_config.bytes_per_block == 16
    
    def test_get_chip_config_invalid(self):
        """Test getting invalid chip configurations."""
        with pytest.raises(ChipConfigError):
            get_chip_config("invalid")


class TestChipDetection:
    """Test chip type auto-detection."""

    def test_detect_chip_type_mf1k(self):
        """Test detecting MF1K from file size."""
        assert detect_chip_type(1024) == "mf1k"
    
    def test_detect_chip_type_mf4k(self):
        """Test detecting MF4K from file size."""
        assert detect_chip_type(4096) == "mf4k"
    
    def test_detect_chip_type_unknown(self):
        """Test detecting unknown size."""
        assert detect_chip_type(512) == "none"
        assert detect_chip_type(2048) == "none"


class TestBlockAddr:
    """Test block address conversion."""

    def test_abs_block_to_addr_mf1k(self):
        """Test converting absolute block to BlockAddr for MF1K."""
        addr = abs_block_to_addr(5, "mf1k")
        assert addr.abs_block == 5
        assert addr.sector == 1
        assert addr.index == 1
    
    def test_abs_block_to_addr_none(self):
        """Test converting with no chip mapping."""
        addr = abs_block_to_addr(10, "none")
        assert addr.abs_block == 10
        assert addr.sector == 0
        assert addr.index == 10


class TestFileValidation:
    """Test file size validation."""

    def test_validate_file_size_valid(self):
        """Test valid file sizes."""
        # Should not raise for correct sizes
        validate_file_size(1024, "mf1k")
        validate_file_size(4096, "mf4k")
        validate_file_size(999, "none")  # Any size valid for none
    
    def test_validate_file_size_invalid(self):
        """Test invalid file sizes."""
        with pytest.raises(ChipConfigError):
            validate_file_size(1000, "mf1k")
        with pytest.raises(ChipConfigError):
            validate_file_size(4000, "mf4k")