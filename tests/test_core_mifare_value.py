"""Tests for MIFARE Classic value block detection."""

from ssdp.core.mifare_value import ValueBlock, detect_value_block


def test_detect_value_block_example_from_datasheet():
    block = bytes.fromhex("87 D6 12 00 78 29 ED FF 87 D6 12 00 11 EE 11 EE")

    assert detect_value_block(block) == ValueBlock(value=1234567, address=17)


def test_detect_value_block_signed_negative_value():
    value = (-42).to_bytes(4, "little", signed=True)
    inverted = bytes((~b) & 0xFF for b in value)
    block = value + inverted + value + bytes([0x22, 0xDD, 0x22, 0xDD])

    assert detect_value_block(block) == ValueBlock(value=-42, address=0x22)


def test_rejects_invalid_value_copy():
    block = bytearray.fromhex("87 D6 12 00 78 29 ED FF 87 D6 12 00 11 EE 11 EE")
    block[8] ^= 0x01

    assert detect_value_block(bytes(block)) is None


def test_rejects_invalid_address_copy():
    block = bytearray.fromhex("87 D6 12 00 78 29 ED FF 87 D6 12 00 11 EE 11 EE")
    block[14] = 0x12

    assert detect_value_block(bytes(block)) is None
