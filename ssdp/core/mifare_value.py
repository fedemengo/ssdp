"""MIFARE Classic value block detection."""

from __future__ import annotations

from typing import NamedTuple

from ..utils.bytestr import bitwise_not_bytes


class ValueBlock(NamedTuple):
    """Decoded MIFARE Classic value block."""

    value: int
    address: int


def detect_value_block(block: bytes) -> ValueBlock | None:
    """Return decoded value block data when a 16-byte block is valid."""
    if len(block) != 16:
        return None

    value = block[0:4]
    inverted_value = block[4:8]
    value_copy = block[8:12]

    if value != value_copy:
        return None
    if bitwise_not_bytes(value) != inverted_value:
        return None

    addr = block[12]
    not_addr = block[13]
    addr_copy = block[14]
    not_addr_copy = block[15]

    if addr != addr_copy:
        return None
    if not_addr != not_addr_copy:
        return None
    if ((~addr) & 0xFF) != not_addr:
        return None

    return ValueBlock(
        value=int.from_bytes(value, "little", signed=True),
        address=addr,
    )
