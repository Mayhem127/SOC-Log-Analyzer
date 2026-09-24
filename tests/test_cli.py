"""Unit tests for the SOC Log Analyzer CLI entry point (main.py)."""

import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from main import build_argument_parser, main


class TestSOCAnalyzerCLI(unittest.TestCase):
    """Test suite verifying CLI argument parsing, execution pipeline, and error handling."""

    def setUp(self):
        """Set sample log path."""
        self.sample_log = "data/sample_auth.log"

    def test_cli_help_displays_and_exits_cleanly(self):
        """Verify --help flag displays documentation and raises SystemExit(0)."""
        parser = build_argument_parser()
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stdout", new_callable=io.StringIO):
                parser.parse_args(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_cli_error_on_missing_argument(self):
        """Verify calling main without arguments exits with code 1."""
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            exit_code = main([])
        self.assertEqual(exit_code, 1)
        self.assertIn("Error: No input log file specified", stderr_capture.getvalue())

    def test_cli_error_on_nonexistent_file(self):
        """Verify calling main with non-existent file returns code 1."""
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            exit_code = main(["non_existent_auth.log"])
        self.assertEqual(exit_code, 1)
        self.assertIn("Error: Log file not found", stderr_capture.getvalue())

    def test_cli_error_on_directory_target(self):
        """Verify calling main with a directory returns code 1."""
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            exit_code = main(["data"])
        self.assertEqual(exit_code, 1)
        self.assertIn("Specified path is not a file", stderr_capture.getvalue())

    def test_cli_error_on_invalid_threshold(self):
        """Verify negative or zero threshold returns code 1."""
        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            exit_code = main([self.sample_log, "-t", "0"])
        self.assertEqual(exit_code, 1)
        self.assertIn("threshold must be a positive integer", stderr_capture.getvalue())

    def test_cli_runs_successfully_on_sample_log(self):
        """Verify main successfully runs full pipeline on sample_auth.log."""
        stdout_capture = io.StringIO()
        with patch("sys.stdout", stdout_capture):
            exit_code = main([self.sample_log])
        self.assertEqual(exit_code, 0)
        output = stdout_capture.getvalue()
        self.assertIn("SOC LOG ANALYZER - SECURITY INCIDENT REPORT", output)
        self.assertIn("Total Events Analyzed : 30", output)
        self.assertIn("Total Alerts Generated: 5", output)

    def test_cli_exports_csv_file(self):
        """Verify --csv argument exports report to target file path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "output.csv")
            stdout_capture = io.StringIO()
            with patch("sys.stdout", stdout_capture):
                exit_code = main([self.sample_log, "--csv", csv_path])

            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(csv_path))
            with open(csv_path, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("Alert ID,Rule ID,Rule Name", content)
                self.assertIn("ALT-0001", content)

    def test_cli_min_severity_filter(self):
        """Verify -s / --min-severity filters alerts properly."""
        stdout_capture = io.StringIO()
        with patch("sys.stdout", stdout_capture):
            # Only CRITICAL alerts (2 alerts)
            exit_code = main([self.sample_log, "-s", "CRITICAL"])
        self.assertEqual(exit_code, 0)
        output = stdout_capture.getvalue()
        self.assertIn("Total Alerts Generated: 2", output)
        self.assertIn("CRITICAL : 2", output)
        self.assertIn("HIGH     : 0", output)

    def test_cli_quiet_mode_suppresses_stdout(self):
        """Verify -q / --quiet suppresses terminal summary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "output.csv")
            stdout_capture = io.StringIO()
            with patch("sys.stdout", stdout_capture):
                exit_code = main([self.sample_log, "-q", "--csv", csv_path])
            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout_capture.getvalue().strip(), "")
            self.assertTrue(os.path.exists(csv_path))


if __name__ == "__main__":
    unittest.main()
