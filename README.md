# SSDP - Simple Stupid Dump Parser

A Python CLI tool for comparing and analyzing binary dump files with unit-based analysis. Supports MIFARE Classic dumps and other binary formats with multi-byte unit comparison (2, 4, 8 byte units) and multiple data representations.

## Installation

### From source

```bash
pip install -e .
```

### Development installation

```bash
pip install -e ".[dev]"
```

## Usage

SSDP provides three main commands:

### `ssdp diff` - Compare dump files

Compare multiple dump files and show unit-level differences:

```bash
# Basic diff with default 2,4,8 byte chunks
ssdp diff dump1.bin dump2.bin

# MIFARE 1K format with sector/block labels
ssdp diff dump1.bin dump2.bin --format mf1k

# MIFARE 1K, only differing value blocks
ssdp diff dump1.bin dump2.bin --format 'mf1k[value]'

# Custom chunk sizes and representations
ssdp diff dump1.bin dump2.bin --units 4,8 --show RAW,INT_LE,NOT_LE

# Save diff context for later viewing
ssdp diff dump1.bin dump2.bin --save-ctx diff.ctx

# Export xxd-style reports
ssdp diff dump1.bin dump2.bin --xxd-diff report.xxd
```

### `ssdp view` - Analyze single file

View and analyze binary files with unit-based breakdown:

```bash
# View with unit analysis (default behavior)
ssdp view dump.bin

# View specific range
ssdp view dump.bin --range 0x60:0x70

# Use diff context to highlight changed units
ssdp view new_dump.bin --ctx diff.ctx

# Detect MIFARE Classic value blocks while showing all blocks
ssdp view dump.bin --format mf1k

# Show only valid MIFARE Classic value blocks
ssdp view dump.bin --format 'mf1k[value]'

# Traditional xxd hex dump
ssdp view dump.bin --xxd

# Custom analysis
ssdp view dump.bin --units 4 --show RAW,INT_LE,BIN --format mf1k
```

### `ssdp conv` - Convert between representations

Convert values between different data representations:

```bash
# Convert value to all representations
ssdp conv 0x1234ABCD 4

# Convert from specific format
ssdp conv "11110000" 1 --from BIN --to RAW,INT_LE

# Output to file
ssdp conv 12345 4 -o conversions.txt
```

## Data Representations

SSDP supports multiple data representations for comprehensive analysis:

- **RAW**: Hexadecimal bytes (e.g., `61 9A 79 2D`)
- **INT_LE**: Little-endian signed integer (e.g., `762944097`)
- **INT_BE**: Big-endian signed integer (e.g., `1637513517`)
- **NOT_LE**: Little-endian bitwise NOT (e.g., `3532023198`)
- **NOT_BE**: Big-endian bitwise NOT (e.g., `2657453778`)
- **BIN**: Binary representation (e.g., `00101101011110011001101001100001`)
- **BIN_NOT**: Binary bitwise NOT (e.g., `11010010100001100110010110011110`)
- **NOT_RAW**: Hexadecimal bitwise NOT (e.g., `9E 65 86 D2`)

## Example: MIFARE Classic Credit Analysis

Let's analyze two MIFARE Classic dumps where 2 credits were added between dumps:

```bash
ssdp diff dump1.bin dump2.bin --format mf1k --units 4 --show RAW,INT_LE,NOT_LE
```

Output:
```
Inputs:
  data01: dump1.bin
  data02: dump2.bin

Diff blocks:
  MIFARE: sec=sector, blk=block within sector
  [BLOCK] abs=06 (0x06) sec=1 blk=2
  [BLOCK] abs=08 (0x08) sec=2 blk=0
  [BLOCK] abs=09 (0x09) sec=2 blk=1

[BLOCK] abs=08 (0x08) sec=2 blk=0
  [chunk-size=4]
    data01: FULL=96 00 00 00 | 69 FF FF FF | 96 00 00 00 | 09 F6 09 F6
    data02: FULL=5E 01 00 00 | A1 FE FF FF | 5E 01 00 00 | 09 F6 09 F6
    +00
      data01: RAW=96 00 00 00 | INT_LE=       150 | NOT_LE=4294967145
      data02: RAW=5E 01 00 00 | INT_LE=       350 | NOT_LE=4294966945
```

From this output, we can see:
- Block 8 contains current credit: 150 cents (1.50) → 350 cents (3.50)
- The credit is stored in three locations: +00, +04 (bitwise NOT), +08 (duplicate)
- NOT_LE representation shows the bitwise complement used for data integrity

### Writing New Credit Value

To write 69.42 credits (6942 cents) to the card:

```bash
ssdp conv 6942 4 --show RAW,INT_LE,NOT_LE
```

Output:
```
RAW    : 1E 1B 00 00
INT_LE : 6942
NOT_LE : 4294960354
```

Use these values to construct the block data for Proxmark3:

```bash
[usb] pm3 --> hf mf wrbl --blk 8 -d 1e1b0000e1e4ffff1e1b000009f609f6 -k FFFFFFFFFFFF
```

## Diff Context Workflow

Save analysis context and apply it to new files:

```bash
# Generate diff context
ssdp diff original.bin modified.bin --save-ctx changes.ctx

# Apply context to analyze a new file
ssdp view new_file.bin --ctx changes.ctx
```

This shows only the units that differed in the original comparison, making it easy to focus on relevant changes.

## Command Options

### Common Options

- `--units 1,2,4,8`: Chunk sizes for analysis (default: 2,4,8; MIFARE formats default to 4)
- `--show RAW,INT_LE,NOT_LE`: Columns to display (default: all)
- `--colorize RAW,INT_LE`: Columns to colorize (default: RAW)
- `--color auto|always|never`: Control ANSI color output (default: auto)
- `--format mf1k|mf4k|mf1k[value]|mf4k[value]`: MIFARE sector/block labeling and value block annotations; `[value]` shows only valid value blocks
- `--block-size N`: Block size in bytes (default: 16)
- `--no-color`: Disable color output (same as `--color never`)

### Diff-specific Options

- `--show-same none|units|bytes|both`: Highlight identical data
- `--xxd-diff FILE`: Export xxd-style diff report
- `--xxd-full-dir DIR`: Export full xxd dumps
- `--save-ctx FILE`: Save diff context for view command

### View-specific Options

- `--range 0x100:0x200`: View specific byte range
- `--xxd`: Use traditional xxd hex dump format
- `--ctx FILE`: Use diff context to show only changed units
- `--json`: Output in JSON format (xxd mode only)
