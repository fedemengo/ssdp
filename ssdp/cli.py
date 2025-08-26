"""Main CLI entry point for SSDP."""

import sys
import argparse

def run() -> None:
    """Main entry point for the CLI."""
    
    if len(sys.argv) < 2:
        print("usage: ssdp <command> [<args>]")
        print()
        print("Simple Stupid Dump Parser - Binary dump comparator and analyzer")
        print()
        print("commands:")
        print("  diff    Compare multiple dump files and show differences")
        print("  view    View a single file with optional annotations") 
        print("  conv    Convert values between different representations")
        print()
        print("See 'ssdp <command> --help' for more information on a specific command.")
        sys.exit(1)
    
    command = sys.argv[1]
    
    # Remove the command from argv so subcommands see clean args
    sys.argv = [f"ssdp {command}"] + sys.argv[2:]
    
    if command == "diff":
        from .commands.diff import main
        main()
    elif command == "conv":
        from .commands.conv import main
        main() 
    elif command == "view":
        from .commands.view import main
        main()
    else:
        print(f"error: unknown command '{command}'", file=sys.stderr)
        print("Run 'ssdp' for usage information.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    run()