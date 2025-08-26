"""Simple Stupid Dump Parser - MIFARE Classic dump comparator and analyzer."""

__version__ = "0.1.0"

from .core.types import ChipType, DiffSpan, Format, Rep
from .core.errors import SSDPError, FileReadError, FileSizeError, ConversionError, ChipConfigError

__all__ = [
    "__version__",
    "ChipType",
    "DiffSpan", 
    "Format",
    "Rep",
    "SSDPError",
    "FileReadError",
    "FileSizeError", 
    "ConversionError",
    "ChipConfigError",
]