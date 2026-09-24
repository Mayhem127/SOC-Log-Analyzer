#!/usr/bin/env python3
"""SOC Log Analyzer - Command Line Interface (CLI).

Connects the defensive security log analysis pipeline:
  AuthLogParser -> SOCDetector -> SOCReporter
"""

import argparse
import os
from pathlib import Path
import sys
from typing import List, Optional

from src.config import DetectionConfig
from src.detector import SOCDetector
from src.models import Severity
from src.parser import AuthLogParser
from src.reporter import SOCReporter


def build_argument_parser() -> argparse.ArgumentParser:
    """Build and configure the CLI argument parser with comprehensive help."""
    parser = argparse.ArgumentParser(
        prog="soc-analyzer",
        description="Defensive SOC Log Analyzer: Detect SSH brute-force, password spraying, and host compromise.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py data/sample_auth.log\n"
            "  python main.py data/sample_auth.log --csv reports/alerts.csv\n"
            "  python main.py -f data/sample_auth.log -t 3 -s HIGH --csv reports/alerts.csv\n"
            "  python main.py data/sample_auth.log --suppress-whitelisted\n"
        ),
    )

    # Input log file
    parser.add_argument(
        "log_file",
        nargs="?",
        default=None,
        help="Path to Linux authentication log file (e.g. /var/log/auth.log)",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="file_flag",
        default=None,
        help="Alternative flag to specify input log file path",
    )

    # Export options
    parser.add_argument(
        "-o",
        "--csv",
        dest="csv_output",
        default=None,
        help="Destination path for exported CSV incident report (e.g. reports/alerts.csv)",
    )

    # Threshold overrides
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=None,
        help="Override threshold for SSH brute-force detection (default: 5 attempts)",
    )
    parser.add_argument(
        "-w",
        "--window",
        type=int,
        default=None,
        help="Override sliding time window in minutes (default: 10 minutes)",
    )

    # Filtering options
    parser.add_argument(
        "-s",
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        type=str.upper,
        default=None,
        help="Filter alerts to only those at or above this severity level",
    )
    parser.add_argument(
        "--suppress-whitelisted",
        action="store_true",
        default=False,
        help="Suppress alerts triggered by whitelisted IPs instead of tagging them",
    )
    parser.add_argument(
        "--whitelist-ip",
        action="append",
        default=None,
        help="Add IP or CIDR to whitelist (can be specified multiple times)",
    )

    # Parser options
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year for syslog timestamp reconstruction (default: current year)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress terminal report output (useful when exporting only CSV)",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Execute the SOC Log Analyzer CLI pipeline.

    Args:
        argv: Optional command-line arguments list (defaults to sys.argv[1:]).

    Returns:
        Exit code: 0 on success, non-zero on error.
    """
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    # Resolve input log file
    target_file = args.file_flag or args.log_file
    if not target_file:
        sys.stderr.write("Error: No input log file specified.\n")
        sys.stderr.write("Usage: python main.py <log_file> [options]\n")
        sys.stderr.write("Run 'python main.py --help' for details.\n")
        return 1

    # Validate file existence and accessibility
    if not os.path.exists(target_file):
        sys.stderr.write(f"Error: Log file not found: '{target_file}'\n")
        return 1

    if not os.path.isfile(target_file):
        sys.stderr.write(f"Error: Specified path is not a file: '{target_file}'\n")
        return 1

    # Validate threshold arguments
    if args.threshold is not None and args.threshold <= 0:
        sys.stderr.write("Error: Brute-force threshold must be a positive integer.\n")
        return 1

    if args.window is not None and args.window <= 0:
        sys.stderr.write("Error: Time window must be a positive integer.\n")
        return 1

    # Configure detection parameters
    config = DetectionConfig()
    if args.threshold is not None:
        config.brute_force_threshold = args.threshold
    if args.window is not None:
        config.time_window_minutes = args.window
    if args.suppress_whitelisted:
        config.suppress_whitelisted = True
    if args.whitelist_ip:
        config.whitelisted_ips.extend(args.whitelist_ip)
        config.__post_init__()

    # 1. Pipeline: Ingestion & Normalization
    try:
        log_parser = AuthLogParser(year=args.year)
        events = log_parser.parse_file(target_file)
    except Exception as exc:
        sys.stderr.write(f"Error: Failed to parse log file '{target_file}': {exc}\n")
        return 1

    # 2. Pipeline: Threat Detection & Correlation
    detector = SOCDetector(config=config)
    alerts = detector.detect(events)

    # Apply minimum severity filter if requested
    if args.min_severity:
        min_sev = Severity(args.min_severity)
        alerts = [a for a in alerts if a.severity >= min_sev]

    # 3. Pipeline: Reporting & Exporting
    reporter = SOCReporter()

    if args.csv_output:
        try:
            csv_path = reporter.export_csv(alerts, args.csv_output)
            if not args.quiet:
                print(f"[+] Security incident CSV report exported to: {csv_path}\n")
        except Exception as exc:
            sys.stderr.write(f"Error: Failed to export CSV to '{args.csv_output}': {exc}\n")
            return 1

    if not args.quiet:
        reporter.print_terminal_report(alerts, total_events=len(events))

    return 0


if __name__ == "__main__":
    sys.exit(main())
