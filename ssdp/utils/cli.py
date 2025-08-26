"""CLI argument parsing utilities."""

from typing import List

ALL_COLUMNS = ["RAW", "INT_BE", "INT_LE", "NOT_BE", "NOT_LE", "BIN", "BIN_NOT", "NOT_RAW"]
ALLOWED_COLORIZE = ALL_COLUMNS


def parse_units_arg(units_arg: str | None) -> List[int]:
    """Parse --units argument into list of unit sizes."""
    if not units_arg:
        return [2, 4, 8]
    try:
        parts = [p.strip() for p in units_arg.split(",") if p.strip()]
        units = [int(p) for p in parts]
    except ValueError:
        raise ValueError("--units must be a comma-separated list of 2, 4, 8")
    valid = {2, 4, 8}
    if any(u not in valid for u in units):
        raise ValueError("--units values must be among {2,4,8}")
    return units


def parse_show_arg(show_arg: str | None) -> List[str]:
    """Parse --show argument into list of column names."""
    if not show_arg:
        return ALL_COLUMNS.copy()
    parts = [p.strip().upper() for p in show_arg.split(",") if p.strip()]
    bad = [p for p in parts if p not in ALL_COLUMNS]
    if bad:
        raise ValueError(f"--show contains invalid columns: {', '.join(bad)}")
    return parts


def parse_colorize_arg(colorize_arg: str | None, show_cols: List[str]) -> List[str]:
    """Parse --colorize argument into list of column names to colorize."""
    if not colorize_arg:
        return ["RAW"]
    parts = [p.strip().upper() for p in colorize_arg.split(",") if p.strip()]
    bad = [p for p in parts if p not in ALLOWED_COLORIZE]
    if bad:
        raise ValueError(f"--colorize contains invalid columns: {', '.join(bad)}")
    # Only allow colorizing columns that are shown
    shown_and_colorizable = set(show_cols + ["RAW"])
    invalid = [p for p in parts if p not in shown_and_colorizable]
    if invalid:
        raise ValueError(f"--colorize references columns not in --show: {', '.join(invalid)}")
    return parts