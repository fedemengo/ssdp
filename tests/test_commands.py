"""Tests for command line interface."""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys
from io import StringIO


class TestGenericDiff:
    """Test generic diff functionality."""
    
    def test_no_format_required(self):
        """Test that diff works without --format parameter."""
        # Create test data
        data1 = b'\x00' * 32  # 32 bytes = 2 blocks of 16
        data2 = b'\x01' * 16 + b'\x00' * 16  # First block differs
        
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = Path(tmpdir) / "file1.bin"
            file2 = Path(tmpdir) / "file2.bin"
            ctx_file = Path(tmpdir) / "test.ctx"
            
            file1.write_bytes(data1)
            file2.write_bytes(data2)
            
            # Mock sys.argv for the command
            test_argv = [
                "ssdp diff",
                "--units", "2", 
                "--save-ctx", str(ctx_file),
                str(file1), str(file2)
            ]
            
            with patch.object(sys, 'argv', test_argv):
                from ssdp.commands.diff_plain import main
                
                # Capture output
                captured_output = StringIO()
                with patch('sys.stdout', captured_output):
                    try:
                        main()
                    except SystemExit:
                        pass
                
                output = captured_output.getvalue()
                
                # Should show generic block labeling
                assert "[BLOCK] ID=" in output
                
                # Context file should be created
                assert ctx_file.exists()
                
                # Context should have block_size and no format
                ctx_data = json.loads(ctx_file.read_text())
                assert ctx_data["block_size"] == 16
                assert ctx_data["format"] is None
                assert "2" in ctx_data["diff_units"]


class TestViewUnitsFilter:
    """Test view command --units filtering."""
    
    def test_units_parameter_filters_context(self):
        """Test that --units parameter filters available units in view."""
        # Create mock context with multiple unit sizes
        mock_ctx_data = {
            "block_size": 16,
            "format": None,
            "files": ["file1.bin", "file2.bin"],
            "aliases": {"data01": "file1.bin", "data02": "file2.bin"},
            "units": [2, 4, 8],
            "diff_blocks": [],
            "diff_units": {
                "2": [{"offset": 0, "size": 2, "block": 0}],
                "4": [{"offset": 4, "size": 4, "block": 0}],
                "8": [{"offset": 8, "size": 8, "block": 0}]
            }
        }
        
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx_file = Path(tmpdir) / "test.ctx"
            data_file = Path(tmpdir) / "data.bin"
            
            ctx_file.write_text(json.dumps(mock_ctx_data))
            data_file.write_bytes(b'\x00' * 32)
            
            test_argv = [
                "ssdp view",
                str(data_file),
                "--ctx", str(ctx_file),
                "--units", "2,4"  # Only request 2 and 4-byte units
            ]
            
            with patch.object(sys, 'argv', test_argv):
                from ssdp.commands.view_plain import main
                
                # Capture stderr to see the loaded message
                captured_stderr = StringIO()
                with patch('sys.stderr', captured_stderr):
                    try:
                        main()
                    except SystemExit:
                        pass
                
                stderr_output = captured_stderr.getvalue()
                
                # Should mention only 2 differing units (not 3)
                assert "2 differing units (sizes: 2,4)" in stderr_output
    
    def test_invalid_units_warning(self):
        """Test warning when requesting units not in context."""
        mock_ctx_data = {
            "diff_units": {"4": []},  # Only has 4-byte units
            "diff_blocks": []
        }
        
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx_file = Path(tmpdir) / "test.ctx"
            data_file = Path(tmpdir) / "data.bin"
            
            ctx_file.write_text(json.dumps(mock_ctx_data))
            data_file.write_bytes(b'\x00' * 16)
            
            test_argv = [
                "ssdp view",
                str(data_file),
                "--ctx", str(ctx_file),
                "--units", "2,8"  # Request units not in context
            ]
            
            with patch.object(sys, 'argv', test_argv):
                from ssdp.commands.view_plain import main
                
                captured_stderr = StringIO()
                with patch('sys.stderr', captured_stderr):
                    try:
                        main()
                    except SystemExit:
                        pass
                
                stderr_output = captured_stderr.getvalue()
                
                # Should warn about missing unit sizes
                assert "warning: unit size 2 not found" in stderr_output
                assert "warning: unit size 8 not found" in stderr_output