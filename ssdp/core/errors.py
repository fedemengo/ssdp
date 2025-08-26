"""Error types for SSDP package."""

from __future__ import annotations


class SSDPError(Exception):
    """Base exception for all SSDP errors."""
    
    pass


class FileReadError(SSDPError):
    """Error reading a file."""
    
    def __init__(self, path: str, cause: Exception) -> None:
        self.path = path
        self.cause = cause
        super().__init__(f"Could not read '{path}': {cause}")


class FileSizeError(SSDPError):
    """File size doesn't match expected format."""
    
    def __init__(self, path: str, actual_size: int, expected_size: int, format_name: str) -> None:
        self.path = path
        self.actual_size = actual_size
        self.expected_size = expected_size
        self.format_name = format_name
        super().__init__(
            f"File '{path}' has size {actual_size}, expected {expected_size} for format {format_name}"
        )


class InvalidFormatError(SSDPError):
    """Invalid format specifier."""
    
    def __init__(self, format_name: str, valid_formats: list[str]) -> None:
        self.format_name = format_name
        self.valid_formats = valid_formats
        super().__init__(
            f"Invalid format '{format_name}', must be one of: {', '.join(valid_formats)}"
        )


class ConversionError(SSDPError):
    """Error converting between representations."""
    
    def __init__(self, value: str, from_rep: str, to_rep: str, cause: Exception) -> None:
        self.value = value
        self.from_rep = from_rep
        self.to_rep = to_rep
        self.cause = cause
        super().__init__(
            f"Cannot convert '{value}' from {from_rep} to {to_rep}: {cause}"
        )


class ChipConfigError(SSDPError):
    """Error in chip configuration or block addressing."""
    
    pass