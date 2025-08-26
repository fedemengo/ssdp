"""Tests for byte string utilities."""

import pytest

from ssdp.core.errors import ConversionError
from ssdp.utils.bytestr import (
    ascii_bytes,
    bitwise_not_bytes,
    bytes_to_rep,
    hex_bytes,
    int_be,
    int_le,
    parse_value_by_rep,
)


class TestByteUtils:
    """Test basic byte manipulation utilities."""

    def test_bitwise_not_bytes(self):
        """Test bitwise NOT operation on bytes."""
        assert bitwise_not_bytes(b"\x00") == b"\xff"
        assert bitwise_not_bytes(b"\xff") == b"\x00"
        assert bitwise_not_bytes(b"\x12\x34") == b"\xed\xcb"
    
    def test_hex_bytes(self):
        """Test converting bytes to hex string."""
        assert hex_bytes(b"\x00") == "00"
        assert hex_bytes(b"\x12\x34") == "12 34"
        assert hex_bytes(b"\xff\xaa\x55") == "FF AA 55"
    
    def test_ascii_bytes(self):
        """Test converting bytes to ASCII."""
        assert ascii_bytes(b"hello") == "hello"
        assert ascii_bytes(b"\x00\x20\x7f\x80") == ". .."
    
    def test_int_be(self):
        """Test big-endian integer conversion."""
        assert int_be(b"\x12\x34") == 0x1234
        assert int_be(b"\x00\x01") == 1
    
    def test_int_le(self):
        """Test little-endian integer conversion."""
        assert int_le(b"\x12\x34") == 0x3412
        assert int_le(b"\x00\x01") == 0x0100


class TestParseValueByRep:
    """Test parsing values by representation."""

    def test_parse_raw(self):
        """Test parsing RAW hex values."""
        assert parse_value_by_rep("RAW", "1234", 2) == b"\x12\x34"
        assert parse_value_by_rep("RAW", "12 34", 2) == b"\x12\x34"
        assert parse_value_by_rep("RAW", "12", 2) == b"\x00\x12"  # zero-padded
    
    def test_parse_not_raw(self):
        """Test parsing NOT_RAW values."""
        result = parse_value_by_rep("NOT_RAW", "1234", 2)
        expected = bitwise_not_bytes(b"\x12\x34")
        assert result == expected
    
    def test_parse_int_be(self):
        """Test parsing big-endian integers."""
        assert parse_value_by_rep("INT_BE", "0x1234", 2) == b"\x12\x34"
        assert parse_value_by_rep("INT_BE", "1234", 2) == b"\x04\xd2"
    
    def test_parse_int_le(self):
        """Test parsing little-endian integers."""
        assert parse_value_by_rep("INT_LE", "0x1234", 2) == b"\x34\x12"
        assert parse_value_by_rep("INT_LE", "1234", 2) == b"\xd2\x04"
    
    def test_parse_bin(self):
        """Test parsing binary values."""
        assert parse_value_by_rep("BIN", "10110000", 1) == b"\xb0"
        assert parse_value_by_rep("BIN", "1011", 1) == b"\x0b"  # zero-padded
    
    def test_parse_bin_not(self):
        """Test parsing NOT binary values."""
        result = parse_value_by_rep("BIN_NOT", "10110000", 1)
        expected = bitwise_not_bytes(b"\xb0")
        assert result == expected
    
    def test_parse_invalid_format(self):
        """Test parsing with invalid format."""
        with pytest.raises(ValueError, match="format must be one of"):
            parse_value_by_rep("INVALID", "1234", 2)
    
    def test_parse_invalid_raw(self):
        """Test parsing invalid RAW values."""
        with pytest.raises(ConversionError):
            parse_value_by_rep("RAW", "GGGG", 2)
    
    def test_parse_invalid_int(self):
        """Test parsing invalid integer values."""
        with pytest.raises(ConversionError):
            parse_value_by_rep("INT_BE", "not_a_number", 2)
    
    def test_parse_invalid_bin(self):
        """Test parsing invalid binary values."""
        with pytest.raises(ConversionError):
            parse_value_by_rep("BIN", "10102", 2)


class TestBytesToRep:
    """Test converting bytes to representations."""

    def test_bytes_to_raw(self):
        """Test converting bytes to RAW."""
        assert bytes_to_rep(b"\x12\x34", "RAW") == "12 34"
    
    def test_bytes_to_not_raw(self):
        """Test converting bytes to NOT_RAW."""
        expected = "ED CB"  # bitwise NOT of 0x1234
        assert bytes_to_rep(b"\x12\x34", "NOT_RAW") == expected
    
    def test_bytes_to_int_be(self):
        """Test converting bytes to big-endian int."""
        assert bytes_to_rep(b"\x12\x34", "INT_BE") == "4660"
    
    def test_bytes_to_int_le(self):
        """Test converting bytes to little-endian int."""
        assert bytes_to_rep(b"\x12\x34", "INT_LE") == "13330"
    
    def test_bytes_to_bin(self):
        """Test converting bytes to binary."""
        assert bytes_to_rep(b"\xb0", "BIN") == "10110000"
    
    def test_bytes_to_invalid_format(self):
        """Test converting with invalid format."""
        with pytest.raises(ValueError, match="format must be one of"):
            bytes_to_rep(b"\x12\x34", "INVALID")