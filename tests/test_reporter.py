"""Unit tests for the SOC Log Analyzer reporter module."""

import csv
from datetime import datetime
import io
import os
import tempfile
import unittest

from src.models import Alert, Severity
from src.reporter import SOCReporter


class TestSOCReporter(unittest.TestCase):
    """Test suite verifying CSV export accuracy and terminal reporting structure."""

    def setUp(self):
        """Set up reporter and sample alerts for tests."""
        self.reporter = SOCReporter()
        self.sample_alerts = [
            Alert(
                alert_id="ALT-0001",
                rule_id="SOC-RULE-001",
                rule_name="SSH Brute-Force Attack Detected",
                severity=Severity.HIGH,
                timestamp=datetime(2026, 10, 24, 11, 45, 34),
                source_ip="198.51.100.23",
                target_users=["admin", "root", "guest"],
                attempt_count=7,
                description="Detected 7 failed SSH login attempts from 198.51.100.23 within 24s.",
                mitre_technique="T1110.001 - Password Guessing",
                is_whitelisted=False,
                evidence=[
                    "Oct 24 11:45:10 prod-srv-01 sshd[16100]: Failed password for invalid user admin",
                    "Oct 24 11:45:13 prod-srv-01 sshd[16102]: Failed password for invalid user root",
                ],
            ),
            Alert(
                alert_id="ALT-0002",
                rule_id="SOC-RULE-003",
                rule_name="Post-Brute-Force Successful Login (Potential Compromise)",
                severity=Severity.CRITICAL,
                timestamp=datetime(2026, 10, 24, 14, 3, 5),
                source_ip="203.0.113.42",
                target_users=["devops"],
                attempt_count=9,
                description="User 'devops' logged in from 203.0.113.42 after 8 failed attempts.",
                mitre_technique="T1110 - Brute Force / T1078 - Valid Accounts",
                is_whitelisted=False,
                evidence=[
                    "Oct 24 14:02:11 prod-srv-01 sshd[17201]: Failed password for devops",
                    "Oct 24 14:03:05 prod-srv-01 sshd[17225]: Accepted password for devops",
                ],
            ),
            Alert(
                alert_id="ALT-0003",
                rule_id="SOC-RULE-001",
                rule_name="SSH Brute-Force Attack Detected",
                severity=Severity.HIGH,
                timestamp=datetime(2026, 10, 24, 16, 0, 0),
                source_ip="10.0.0.50",
                target_users=["sysadmin"],
                attempt_count=5,
                description="Simulated attack from whitelisted IP.",
                mitre_technique="T1110.001 - Password Guessing",
                is_whitelisted=True,
                evidence=["Simulated failure evidence line"],
            ),
        ]

    # -------------------------------------------------------------------------
    # CSV Exporter Tests
    # -------------------------------------------------------------------------

    def test_csv_headers_match_specification(self):
        """Verify CSV header row matches the required schema fields."""
        expected_headers = [
            "Alert ID",
            "Rule ID",
            "Rule Name",
            "Severity",
            "Timestamp",
            "Source IP",
            "Target Users",
            "Attempt Count",
            "MITRE Technique",
            "Description",
            "Whitelisted Status",
            "Evidence",
        ]
        self.assertEqual(self.reporter.CSV_HEADERS, expected_headers)

    def test_alert_to_csv_row_field_mapping(self):
        """Verify accurate row mapping from an Alert instance."""
        alert = self.sample_alerts[0]
        row = self.reporter.alert_to_csv_row(alert)

        self.assertEqual(row[0], "ALT-0001")
        self.assertEqual(row[1], "SOC-RULE-001")
        self.assertEqual(row[2], "SSH Brute-Force Attack Detected")
        self.assertEqual(row[3], "HIGH")
        self.assertEqual(row[4], "2026-10-24 11:45:34")
        self.assertEqual(row[5], "198.51.100.23")
        self.assertEqual(row[6], "admin, root, guest")
        self.assertEqual(row[7], "7")
        self.assertEqual(row[8], "T1110.001 - Password Guessing")
        self.assertEqual(row[9], alert.description)
        self.assertEqual(row[10], "False")
        self.assertIn("Oct 24 11:45:10", row[11])
        self.assertIn("Oct 24 11:45:13", row[11])

    def test_to_csv_string_format_and_parsing(self):
        """Verify in-memory CSV string is valid CSV parsable by csv.reader."""
        csv_str = self.reporter.to_csv_string(self.sample_alerts)
        reader = list(csv.reader(io.StringIO(csv_str)))

        # Header + 3 alert rows = 4 rows
        self.assertEqual(len(reader), 4)
        self.assertEqual(reader[0], self.reporter.CSV_HEADERS)
        self.assertEqual(reader[1][0], "ALT-0001")
        self.assertEqual(reader[2][0], "ALT-0002")
        self.assertEqual(reader[3][0], "ALT-0003")
        self.assertEqual(reader[3][10], "True")  # Whitelisted status

    def test_export_csv_to_file(self):
        """Verify export_csv writes correctly to an actual filesystem path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "reports", "subfolder", "alerts.csv")
            result_path = self.reporter.export_csv(self.sample_alerts, out_file)

            self.assertTrue(os.path.exists(out_file))
            self.assertEqual(result_path, str(out_file))

            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("Alert ID,Rule ID,Rule Name", content)
                self.assertIn("ALT-0001", content)
                self.assertIn("ALT-0002", content)
                self.assertIn("ALT-0003", content)

    # -------------------------------------------------------------------------
    # Terminal Report Tests
    # -------------------------------------------------------------------------

    def test_terminal_report_contains_all_required_sections(self):
        """Verify terminal report contains all 6 required summary elements."""
        report = self.reporter.generate_terminal_report(self.sample_alerts, total_events=30)

        # 1. Total events analyzed
        self.assertIn("Total Events Analyzed : 30", report)

        # 2. Total alerts
        self.assertIn("Total Alerts Generated: 3", report)

        # 3. Alerts by severity
        self.assertIn("[+] ALERTS BY SEVERITY", report)
        self.assertIn("CRITICAL : 1", report)
        self.assertIn("HIGH     : 2", report)
        self.assertIn("MEDIUM   : 0", report)
        self.assertIn("LOW      : 0", report)

        # 4. Alerts by rule
        self.assertIn("[+] ALERTS BY RULE", report)
        self.assertIn("[SOC-RULE-001] SSH Brute-Force Attack Detected", report)
        self.assertIn("[SOC-RULE-003] Post-Brute-Force Successful Login (Potential Compromise)", report)

        # 5. Source IPs involved
        self.assertIn("[+] SOURCE IPS INVOLVED", report)
        self.assertIn("198.51.100.23", report)
        self.assertIn("203.0.113.42", report)
        self.assertIn("10.0.0.50", report)

        # 6. Concise explanation of each alert
        self.assertIn("[+] DETAILED ALERT BREAKDOWN & EXPLANATIONS", report)
        self.assertIn("ALT-0001", report)
        self.assertIn("ALT-0002", report)
        self.assertIn("ALT-0003", report)
        self.assertIn("Detected 7 failed SSH login attempts", report)
        self.assertIn("T1110.001 - Password Guessing", report)

    def test_terminal_report_zero_alerts_handling(self):
        """Verify graceful reporting when no alerts are detected."""
        report = self.reporter.generate_terminal_report([], total_events=15)
        self.assertIn("Total Events Analyzed : 15", report)
        self.assertIn("Total Alerts Generated: 0", report)
        self.assertIn("No security incidents detected", report)


if __name__ == "__main__":
    unittest.main()
