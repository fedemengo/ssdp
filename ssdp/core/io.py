"""I/O utilities for reading files and handling aliases."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, TextIO

from .errors import FileReadError


def read_file_bytes(path: Path) -> bytes:
    """Read bytes from a file, raising FileReadError on failure."""
    try:
        return path.read_bytes()
    except Exception as e:
        raise FileReadError(str(path), e) from e


def load_files_with_aliases(
    file_paths: List[Path], 
    aliases: Optional[Dict[str, str]] = None
) -> tuple[Dict[str, bytes], Dict[str, str]]:
    """
    Load files with optional aliases.
    
    Args:
        file_paths: List of file paths to load
        aliases: Optional dict mapping alias names to file paths
    
    Returns:
        Tuple of (data_dict, final_aliases_dict)
        - data_dict maps labels to byte data
        - final_aliases_dict maps labels back to file paths
    """
    data_dict: Dict[str, bytes] = {}
    final_aliases: Dict[str, str] = {}
    
    # Create default aliases if none provided
    if aliases is None:
        aliases = {}
    
    # Generate labels for each file
    for i, path in enumerate(file_paths):
        path_str = str(path)
        
        # Check if this path has an explicit alias
        label = None
        for alias_name, alias_path in aliases.items():
            if alias_path == path_str:
                label = alias_name
                break
        
        # If no explicit alias, generate one
        if label is None:
            label = f"data{i+1:02d}"
        
        # Load the file
        data = read_file_bytes(path)
        data_dict[label] = data
        final_aliases[label] = path_str
    
    return data_dict, final_aliases


def parse_aliases_from_args(alias_args: List[str]) -> Dict[str, str]:
    """
    Parse alias arguments in the format "name=path".
    
    Args:
        alias_args: List of strings like ["data1=/path/to/file1", "data2=/path/to/file2"]
    
    Returns:
        Dict mapping alias names to file paths
    """
    aliases = {}
    
    for arg in alias_args:
        if "=" not in arg:
            raise ValueError(f"Invalid alias format: {arg}. Expected 'name=path'")
        
        name, path = arg.split("=", 1)
        name = name.strip()
        path = path.strip()
        
        if not name:
            raise ValueError(f"Empty alias name in: {arg}")
        if not path:
            raise ValueError(f"Empty path in: {arg}")
        
        aliases[name] = path
    
    return aliases


class OutputWriter:
    """Context manager for writing output to file or stdout."""
    
    def __init__(self, output_path: Optional[Path] = None):
        self.output_path = output_path
        self.file_handle: Optional[TextIO] = None
    
    def __enter__(self) -> TextIO:
        if self.output_path:
            self.file_handle = open(self.output_path, "w", encoding="utf-8")
            return self.file_handle
        else:
            return sys.stdout
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file_handle:
            self.file_handle.close()


def write_lines_to_output(lines: List[str], output_path: Optional[Path] = None) -> None:
    """Write lines to output file or stdout."""
    with OutputWriter(output_path) as f:
        for line in lines:
            f.write(line + "\n")


def validate_input_files(file_paths: List[Path], min_files: int = 2) -> None:
    """Validate that we have enough input files and they exist."""
    if len(file_paths) < min_files:
        raise ValueError(f"Need at least {min_files} files, got {len(file_paths)}")
    
    for path in file_paths:
        if not path.exists():
            raise FileReadError(str(path), FileNotFoundError(f"File not found: {path}"))
        if not path.is_file():
            raise FileReadError(str(path), ValueError(f"Not a file: {path}"))


def auto_generate_aliases(file_paths: List[Path]) -> Dict[str, str]:
    """Generate automatic aliases for file paths."""
    aliases = {}
    
    for i, path in enumerate(file_paths):
        alias = f"data{i+1:02d}"
        aliases[alias] = str(path)
    
    return aliases


def resolve_output_path(output_arg: Optional[str]) -> Optional[Path]:
    """Resolve output path argument to Path object."""
    if output_arg is None:
        return None
    return Path(output_arg)


def read_json_annotations(json_path: Path) -> List[Dict]:
    """Read JSON annotations from a file (for view command)."""
    import json
    
    try:
        with json_path.open("r", encoding="utf-8") as f:
            # Handle both single JSON object and JSONL format
            content = f.read().strip()
            if content.startswith("["):
                # JSON array
                return json.loads(content)
            else:
                # JSONL format
                annotations = []
                for line in content.split("\n"):
                    line = line.strip()
                    if line:
                        annotations.append(json.loads(line))
                return annotations
    except Exception as e:
        raise FileReadError(str(json_path), e) from e