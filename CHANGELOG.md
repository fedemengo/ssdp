# Changelog

## v0.1.0 - 2025-01-XX - Complete Refactor

### Added
- **New CLI structure**: Refactored from monolithic script to maintainable Python package
- **Three main commands**:
  - `ssdp diff`: Compare multiple dump files (replaces original main.py functionality)
  - `ssdp view`: View single files with optional annotations
  - `ssdp conv`: Convert between different representations (replaces conv.py)
- **Multiple output formats**: text, JSON, and xxd formats for diff command
- **Enhanced xxd format**: 4-byte grouping with SAME lines showing identical bytes across inputs
- **Package installation**: Installable via `pip install -e .`
- **Comprehensive tests**: Unit tests for core functionality
- **Type annotations**: Full type annotations throughout the codebase
- **Error handling**: Proper exception hierarchy with user-friendly error messages

### Changed
- **Migration from scripts**: 
  - `python main.py --format mf1k file1 file2` → `ssdp diff file1 file2 --chip mf1k`
  - `python conv.py VALUE SIZE` → `ssdp conv VALUE SIZE`
- **Improved auto-detection**: Better chip type detection based on file sizes
- **Enhanced CLI**: More consistent and user-friendly command-line interface
- **Modular architecture**: Code organized into logical modules (core, commands, utils)

### Technical Improvements
- **Pure functions**: Core logic separated from I/O operations
- **Deterministic output**: Consistent formatting across different runs
- **Stream-friendly**: Efficient handling of large files
- **Configurable formatting**: Flexible output formatting options
- **Better error reporting**: Clear error messages without stack traces for user errors

### Backward Compatibility
- **Preserved functionality**: All original features are available in the new CLI
- **Migration guide**: Clear mapping from old commands to new ones in README
- **Same algorithms**: Identical diff and conversion logic as original scripts

### Development
- **Modern tooling**: Uses pyproject.toml, black, isort, mypy
- **CI-ready**: Prepared for automated testing and linting
- **Documentation**: Comprehensive README with examples and migration guide