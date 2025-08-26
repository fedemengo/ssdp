"""Tests for diff engine."""

import pytest

from ssdp.core.diff_engine import (
    align_data_to_shortest,
    blocks_that_differ,
    diff_by_offset,
)
from ssdp.core.types import DiffSpan


class TestBlocksThatDiffer:
    """Test finding blocks that differ."""

    def test_no_differences(self):
        """Test with identical data."""
        data1 = b"\x00" * 32  # 2 blocks
        data2 = b"\x00" * 32
        datas = [data1, data2]
        
        result = blocks_that_differ(datas, 2, 16)
        assert result == []
    
    def test_single_difference(self):
        """Test with one differing block."""
        data1 = b"\x00" * 16 + b"\x11" * 16
        data2 = b"\x00" * 16 + b"\x22" * 16
        datas = [data1, data2]
        
        result = blocks_that_differ(datas, 2, 16)
        assert result == [1]
    
    def test_multiple_differences(self):
        """Test with multiple differing blocks."""
        data1 = b"\x00" * 16 + b"\x11" * 16 + b"\x22" * 16
        data2 = b"\x99" * 16 + b"\x11" * 16 + b"\x33" * 16
        datas = [data1, data2]
        
        result = blocks_that_differ(datas, 3, 16)
        assert result == [0, 2]


class TestAlignDataToShortest:
    """Test data alignment."""

    def test_same_length(self):
        """Test with files of same length."""
        datas = {"a": b"\x00\x01", "b": b"\x02\x03"}
        
        aligned, tail = align_data_to_shortest(datas)
        
        assert aligned == datas
        assert tail is None
    
    def test_different_lengths(self):
        """Test with files of different lengths."""
        datas = {"a": b"\x00\x01\x02", "b": b"\x03\x04"}
        
        aligned, tail = align_data_to_shortest(datas)
        
        assert aligned == {"a": b"\x00\x01", "b": b"\x03\x04"}
        assert tail is not None
        assert tail.offset == 2
        assert tail.length == 1
        assert tail.values == {"a": b"\x02", "b": b""}


class TestDiffByOffset:
    """Test offset-based diffing."""

    def test_no_differences(self):
        """Test with identical files."""
        datas = {"file1": b"\x00\x01\x02", "file2": b"\x00\x01\x02"}
        
        result = diff_by_offset(datas)
        assert result == []
    
    def test_single_byte_difference(self):
        """Test with single byte difference."""
        datas = {"file1": b"\x00\x01\x02", "file2": b"\x00\x99\x02"}
        
        result = diff_by_offset(datas)
        
        assert len(result) == 1
        span = result[0]
        assert span.offset == 1
        assert span.length == 1
        assert span.values["file1"] == b"\x01"
        assert span.values["file2"] == b"\x99"
    
    def test_adjacent_differences_coalesced(self):
        """Test that adjacent differences are coalesced."""
        datas = {"file1": b"\x00\x01\x02\x03", "file2": b"\x00\x99\x88\x03"}
        
        result = diff_by_offset(datas, max_gap=1)
        
        assert len(result) == 1
        span = result[0]
        assert span.offset == 1
        assert span.length == 2
        assert span.values["file1"] == b"\x01\x02"
        assert span.values["file2"] == b"\x99\x88"
    
    def test_separated_differences(self):
        """Test that separated differences remain separate."""
        datas = {"file1": b"\x00\x01\x02\x03\x04", "file2": b"\x00\x99\x02\x03\x88"}
        
        result = diff_by_offset(datas, max_gap=1)
        
        assert len(result) == 2
        
        # First difference at offset 1
        assert result[0].offset == 1
        assert result[0].length == 1
        assert result[0].values["file1"] == b"\x01"
        assert result[0].values["file2"] == b"\x99"
        
        # Second difference at offset 4
        assert result[1].offset == 4
        assert result[1].length == 1
        assert result[1].values["file1"] == b"\x04"
        assert result[1].values["file2"] == b"\x88"
    
    def test_three_files(self):
        """Test diffing with three files."""
        datas = {
            "a": b"\x00\x01\x02",
            "b": b"\x00\x99\x02", 
            "c": b"\x00\x88\x02"
        }
        
        result = diff_by_offset(datas)
        
        assert len(result) == 1
        span = result[0]
        assert span.offset == 1
        assert span.length == 1
        assert span.values["a"] == b"\x01"
        assert span.values["b"] == b"\x99"
        assert span.values["c"] == b"\x88"
    
    def test_empty_data(self):
        """Test with empty data."""
        result = diff_by_offset({})
        assert result == []
        
        result = diff_by_offset({"a": b"", "b": b""})
        assert result == []