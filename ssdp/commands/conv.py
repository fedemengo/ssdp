"""Plain argparse version of conv command."""

import argparse
import sys
from pathlib import Path

def main():
    """Convert VALUE between different representations (RAW, INT_BE, BIN, etc.)."""
    
    ap = argparse.ArgumentParser(
        description="Convert VALUE between different representations (RAW, INT_BE, BIN, etc.)"
    )
    ap.add_argument("value", help="The input value to convert")
    ap.add_argument("size", type=int, help="Output size in bytes")
    ap.add_argument(
        "--from", dest="from_format", 
        choices=["RAW", "NOT_RAW", "INT_BE", "INT_LE", "NOT_BE", "NOT_LE", "BIN", "BIN_NOT"],
        help="Input format (auto-detect if not specified)"
    )
    ap.add_argument(
        "--show",
        help="Comma-separated subset of columns to show from: RAW,INT_BE,INT_LE,NOT_BE,NOT_LE,BIN,BIN_NOT,NOT_RAW. Default: all"
    )
    ap.add_argument(
        "--output", "-o", type=Path, help="Output file (stdout if not specified)"
    )
    args = ap.parse_args()
    
    try:
        from ..core.errors import ConversionError, SSDPError
        from ..core.render import render_conv_output
        from ..utils.bytestr import all_formats_from_value, bytes_to_rep, parse_value_by_rep
        from ..utils.cli import parse_show_arg
        
        if args.size <= 0:
            raise ValueError("Size must be positive")
        
        # Parse show argument to determine which columns to display
        try:
            show_cols = parse_show_arg(args.show)
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(2)
        
        if args.from_format:
            # Convert from specific format to bytes, then to all target formats
            try:
                byte_data = parse_value_by_rep(args.from_format, args.value, args.size)
            except Exception as e:
                raise ConversionError(args.value, args.from_format, "bytes", e) from e
            
            # Convert to requested formats
            results = {}
            for target in show_cols:
                try:
                    results[target] = bytes_to_rep(byte_data, target)
                except Exception as e:
                    # Skip formats that can't represent this value
                    continue
        else:
            # Auto-detect input format and show all possible interpretations
            results = all_formats_from_value(args.value, args.size)
            
            # Filter results to show only requested columns  
            results = {k: v for k, v in results.items() if k in show_cols}
        
        if not results:
            print("No valid representations could be generated.", file=sys.stderr)
            sys.exit(1)
        
        # Find the maximum key length for alignment
        max_key_len = max(len(k) for k in results.keys()) if results else 0
        
        # Simple output without render_conv_output bloat
        output_lines = []
        for rep in sorted(results.keys()):
            value = results[rep]
            output_lines.append(f"{rep:<{max_key_len}}: {value}")
        
        # Write to output
        if args.output:
            with args.output.open("w") as f:
                for line in output_lines:
                    f.write(line + "\n")
        else:
            for line in output_lines:
                print(line)
                
    except (ConversionError, SSDPError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()