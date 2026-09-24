"""Reporting and export module for SOC Log Analyzer.

Provides CSV export conforming to SOC triage schema and structured,
professional terminal reports detailing detected security incidents.
"""

from collections import Counter, defaultdict
import csv
import io
import os
from pathlib import Path
from typing import Dict, List, Optional, TextIO, Tuple, Union

from src.models import Alert, Severity


class SOCReporter:
    """Security report generator for alerts produced by the SOC Log Analyzer."""

    CSV_HEADERS: List[str] = [
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

    def __init__(self, use_colors: bool = False):
        """Initialize reporter.

        Args:
            use_colors: If True, optionally render ANSI color codes for severities.
        """
        self.use_colors = use_colors

    def alert_to_csv_row(self, alert: Alert) -> List[str]:
        """Convert a single Alert instance into a standardized CSV row.

        Args:
            alert: The Alert instance to convert.

        Returns:
            List of string values matching CSV_HEADERS.
        """
        return [
            alert.alert_id,
            alert.rule_id,
            alert.rule_name,
            alert.severity.value,
            alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            alert.source_ip,
            ", ".join(alert.target_users) if alert.target_users else "N/A",
            str(alert.attempt_count),
            alert.mitre_technique,
            alert.description,
            "True" if alert.is_whitelisted else "False",
            " | ".join(alert.evidence) if alert.evidence else "N/A",
        ]

    def to_csv_string(self, alerts: List[Alert]) -> str:
        """Export alerts to an in-memory CSV string.

        Args:
            alerts: List of Alert instances to format.

        Returns:
            Formatted CSV content as a string.
        """
        output = io.StringIO()
        self.export_csv(alerts, output)
        return output.getvalue()

    def export_csv(
        self,
        alerts: List[Alert],
        destination: Union[str, Path, TextIO],
    ) -> str:
        """Export alerts to a CSV file or file-like object.

        Args:
            alerts: List of Alert instances to export.
            destination: File path (str/Path) or an open TextIO stream.

        Returns:
            String path of the generated file if destination was a path,
            or an empty string if destination was an open stream.
        """
        if isinstance(destination, (str, Path)):
            dest_path = Path(destination)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            with open(dest_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(self.CSV_HEADERS)
                for alert in alerts:
                    writer.writerow(self.alert_to_csv_row(alert))
            return str(dest_path)
        else:
            writer = csv.writer(destination)
            writer.writerow(self.CSV_HEADERS)
            for alert in alerts:
                writer.writerow(self.alert_to_csv_row(alert))
            return ""

    def generate_terminal_report(
        self,
        alerts: List[Alert],
        total_events: int = 0,
        title: str = "SOC LOG ANALYZER - SECURITY INCIDENT REPORT",
    ) -> str:
        """Generate a structured, professional plaintext terminal report.

        Summarizes:
            - Total events analyzed & total alerts
            - Alerts grouped by severity
            - Alerts grouped by detection rule
            - Involved source IPs and their impact
            - Concise explanation and evidence for each alert

        Args:
            alerts: List of generated Alert instances.
            total_events: Total number of raw log lines analyzed.
            title: Header title for the report.

        Returns:
            A formatted multi-line string ready for terminal display.
        """
        lines: List[str] = []
        width = 80
        divider = "=" * width
        sub_divider = "-" * width

        lines.append(divider)
        lines.append(title.center(width))
        lines.append(divider)

        # 1. Executive Summary
        lines.append("[+] EXECUTIVE SUMMARY")
        lines.append(sub_divider)
        lines.append(f"  Total Events Analyzed : {total_events}")
        lines.append(f"  Total Alerts Generated: {len(alerts)}")

        unique_ips = sorted(list({a.source_ip for a in alerts}))
        lines.append(f"  Unique Source IPs     : {len(unique_ips)} ({', '.join(unique_ips) if unique_ips else 'None'})")

        if not alerts:
            lines.append(sub_divider)
            lines.append("  [INFO] No security incidents detected.")
            lines.append("         All analyzed events fall within baseline security thresholds.")
            lines.append(divider)
            return "\n".join(lines)

        lines.append("")

        # 2. Alerts by Severity
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }
        for a in alerts:
            if a.severity in severity_counts:
                severity_counts[a.severity] += 1

        lines.append("[+] ALERTS BY SEVERITY")
        lines.append(sub_divider)
        lines.append(f"  CRITICAL : {severity_counts[Severity.CRITICAL]}")
        lines.append(f"  HIGH     : {severity_counts[Severity.HIGH]}")
        lines.append(f"  MEDIUM   : {severity_counts[Severity.MEDIUM]}")
        lines.append(f"  LOW      : {severity_counts[Severity.LOW]}")
        lines.append("")

        # 3. Alerts by Rule
        lines.append("[+] ALERTS BY RULE")
        lines.append(sub_divider)
        rules_counter: Dict[str, Tuple[str, int]] = {}
        for a in alerts:
            if a.rule_id not in rules_counter:
                rules_counter[a.rule_id] = (a.rule_name, 0)
            name, count = rules_counter[a.rule_id]
            rules_counter[a.rule_id] = (name, count + 1)

        for rule_id, (rule_name, count) in sorted(rules_counter.items()):
            lines.append(f"  [{rule_id}] {rule_name.ljust(50)} : {count}")
        lines.append("")

        # 4. Source IPs Involved
        lines.append("[+] SOURCE IPS INVOLVED")
        lines.append(sub_divider)
        ip_alerts: Dict[str, List[Alert]] = defaultdict(list)
        for a in alerts:
            ip_alerts[a.source_ip].append(a)

        for ip, ip_alert_list in sorted(ip_alerts.items()):
            sev_breakdown = Counter(a.severity.value for a in ip_alert_list)
            breakdown_str = ", ".join(f"{k}: {v}" for k, v in sorted(sev_breakdown.items()))
            wl_str = "WHITELISTED" if any(a.is_whitelisted for a in ip_alert_list) else "EXTERNAL"
            lines.append(f"  - {ip.ljust(18)} : {len(ip_alert_list)} alert(s) [{breakdown_str}] (Status: {wl_str})")
        lines.append("")

        # 5. Concise Explanation of Each Alert
        lines.append("[+] DETAILED ALERT BREAKDOWN & EXPLANATIONS")
        lines.append(sub_divider)

        for alert in alerts:
            prefix = "[CRITICAL]" if alert.severity == Severity.CRITICAL else f"[{alert.severity.value}]"
            lines.append(f"{prefix} {alert.alert_id} | {alert.rule_id} | {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"  Rule Name    : {alert.rule_name}")
            lines.append(f"  Source IP    : {alert.source_ip} (Whitelisted: {alert.is_whitelisted})")
            lines.append(f"  Target User  : {', '.join(alert.target_users)}")
            lines.append(f"  Attempts     : {alert.attempt_count}")
            lines.append(f"  MITRE ATT&CK : {alert.mitre_technique}")
            lines.append(f"  Explanation  : {alert.description}")

            if alert.evidence:
                lines.append("  Evidence     :")
                for ev in alert.evidence[:4]:
                    lines.append(f"    * {ev}")
                if len(alert.evidence) > 4:
                    lines.append(f"    * ... (+{len(alert.evidence) - 4} additional log lines recorded)")
            lines.append("")

        lines.append(divider)
        return "\n".join(lines)

    def print_terminal_report(
        self,
        alerts: List[Alert],
        total_events: int = 0,
        title: str = "SOC LOG ANALYZER - SECURITY INCIDENT REPORT",
    ) -> None:
        """Print the generated terminal report to standard output."""
        print(self.generate_terminal_report(alerts, total_events, title))
