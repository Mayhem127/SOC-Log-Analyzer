"""Unit tests for the SOC Log Analyzer threat detection engine."""

from datetime import datetime, timedelta
import unittest

from src.config import DetectionConfig
from src.detector import SOCDetector
from src.models import Alert, EventType, LogEvent, Severity


class TestSOCDetector(unittest.TestCase):
    """Test suite verifying SOC detection rules, correlation, and thresholds."""

    def setUp(self):
        """Configure test detector with standard thresholds."""
        self.config = DetectionConfig(
            brute_force_threshold=5,
            repeated_failures_threshold=3,
            post_failure_success_threshold=3,
            user_enumeration_threshold=3,
            time_window_minutes=10,
            whitelisted_ips=["127.0.0.1", "10.0.0.50"],
            suppress_whitelisted=False,
        )
        self.detector = SOCDetector(self.config)
        self.base_time = datetime(2026, 10, 24, 12, 0, 0)

    def _create_log_event(
        self,
        event_type: EventType,
        ip: str = "192.0.2.1",
        user: str = "victim",
        offset_seconds: int = 0,
        raw: str = "test raw line",
    ) -> LogEvent:
        """Helper to generate mock LogEvents with relative offsets."""
        return LogEvent(
            timestamp=self.base_time + timedelta(seconds=offset_seconds),
            hostname="test-host",
            process="sshd",
            pid=1234,
            event_type=event_type,
            username=user,
            source_ip=ip,
            port=55000,
            auth_method="password",
            raw_line=raw,
        )

    # -------------------------------------------------------------------------
    # Rule 1: SSH Brute-Force Tests
    # -------------------------------------------------------------------------

    def test_brute_force_triggers_above_threshold(self):
        """Verify brute-force rule triggers when failures meet threshold within window."""
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="192.0.2.100", offset_seconds=i * 5)
            for i in range(5)
        ]
        alerts = self.detector.detect(events)

        bf_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-001"]
        self.assertEqual(len(bf_alerts), 1)
        self.assertEqual(bf_alerts[0].severity, Severity.HIGH)
        self.assertEqual(bf_alerts[0].source_ip, "192.0.2.100")
        self.assertEqual(bf_alerts[0].attempt_count, 5)
        self.assertEqual(len(bf_alerts[0].evidence), 5)

    def test_brute_force_ignores_below_threshold(self):
        """Verify no brute-force alert is raised if failures are below threshold."""
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="192.0.2.100", offset_seconds=i * 10)
            for i in range(4)
        ]
        alerts = self.detector.detect(events)
        bf_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-001"]
        self.assertEqual(len(bf_alerts), 0)

    def test_brute_force_ignores_spaced_out_failures(self):
        """Verify failures spaced outside the time window do not trigger an alert."""
        # 5 failures spaced 15 minutes apart (window is 10 min)
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="192.0.2.100", offset_seconds=i * 900)
            for i in range(5)
        ]
        alerts = self.detector.detect(events)
        bf_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-001"]
        self.assertEqual(len(bf_alerts), 0)

    def test_brute_force_aggregates_contiguous_bursts(self):
        """Verify 8 rapid failures in a single burst generate 1 aggregated incident alert."""
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="192.0.2.100", offset_seconds=i * 2)
            for i in range(8)
        ]
        alerts = self.detector.detect(events)
        bf_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-001"]
        self.assertEqual(len(bf_alerts), 1)
        self.assertEqual(bf_alerts[0].attempt_count, 8)
        self.assertEqual(len(bf_alerts[0].evidence), 8)

    # -------------------------------------------------------------------------
    # Rule 2: User Enumeration / Password Spraying Tests
    # -------------------------------------------------------------------------

    def test_user_enumeration_triggers_for_multiple_usernames(self):
        """Verify alert triggers when single IP targets >= user_enumeration_threshold users."""
        users = ["alice", "bob", "charlie", "david"]
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="192.0.2.200", user=u, offset_seconds=i * 3)
            for i, u in enumerate(users)
        ]
        alerts = self.detector.detect(events)
        spray_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-002"]
        self.assertEqual(len(spray_alerts), 1)
        self.assertEqual(spray_alerts[0].severity, Severity.HIGH)
        self.assertEqual(spray_alerts[0].source_ip, "192.0.2.200")
        self.assertEqual(sorted(spray_alerts[0].target_users), sorted(users))

    def test_user_enumeration_does_not_trigger_for_single_user_attack(self):
        """Verify targeted attack against 1 user does not trigger user enumeration rule."""
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="192.0.2.200", user="admin", offset_seconds=i * 3)
            for i in range(6)
        ]
        alerts = self.detector.detect(events)
        spray_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-002"]
        self.assertEqual(len(spray_alerts), 0)

    # -------------------------------------------------------------------------
    # Rule 3: Post-Brute-Force Successful Login Tests
    # -------------------------------------------------------------------------

    def test_post_brute_success_triggers_critical_alert(self):
        """Verify critical alert when success follows failures exceeding threshold."""
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="192.0.2.50", user="devops", offset_seconds=i * 5)
            for i in range(4)
        ]
        # Successful login 10s after last failure
        events.append(
            self._create_log_event(
                EventType.ACCEPTED_LOGIN, ip="192.0.2.50", user="devops", offset_seconds=25, raw="Accepted password for devops"
            )
        )
        alerts = self.detector.detect(events)
        comp_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-003"]
        self.assertEqual(len(comp_alerts), 1)
        self.assertEqual(comp_alerts[0].severity, Severity.CRITICAL)
        self.assertEqual(comp_alerts[0].source_ip, "192.0.2.50")
        self.assertEqual(comp_alerts[0].target_users, ["devops"])
        # Evidence should contain the 4 failed attempts + 1 accepted attempt = 5
        self.assertEqual(len(comp_alerts[0].evidence), 5)

    def test_single_typo_does_not_trigger_compromise_alert(self):
        """Verify single failed login followed by success does not trigger critical alert."""
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="192.0.2.50", user="sysadmin", offset_seconds=0),
            self._create_log_event(EventType.ACCEPTED_LOGIN, ip="192.0.2.50", user="sysadmin", offset_seconds=5),
        ]
        alerts = self.detector.detect(events)
        comp_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-003"]
        self.assertEqual(len(comp_alerts), 0)

    # -------------------------------------------------------------------------
    # Rule 4: Suspicious Sudo Activity Tests
    # -------------------------------------------------------------------------

    def test_suspicious_sudo_triggers_when_correlated_with_compromise(self):
        """Verify sudo execution shortly after compromised login triggers critical alert."""
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="192.0.2.50", user="devops", offset_seconds=i * 5)
            for i in range(4)
        ]
        # Compromised login
        events.append(
            self._create_log_event(
                EventType.ACCEPTED_LOGIN, ip="192.0.2.50", user="devops", offset_seconds=25, raw="Accepted password for devops"
            )
        )
        # Sudo execution 5s later
        events.append(
            LogEvent(
                timestamp=self.base_time + timedelta(seconds=30),
                hostname="test-host",
                process="sudo",
                pid=5000,
                event_type=EventType.SUDO_COMMAND,
                username="devops",
                raw_line="sudo: devops : TTY=pts/0 ; COMMAND=/bin/bash",
            )
        )
        alerts = self.detector.detect(events)
        sudo_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-004"]
        self.assertEqual(len(sudo_alerts), 1)
        self.assertEqual(sudo_alerts[0].severity, Severity.CRITICAL)
        self.assertEqual(sudo_alerts[0].source_ip, "192.0.2.50")
        self.assertEqual(sudo_alerts[0].target_users, ["devops"])

    def test_benign_sudo_does_not_trigger_alert(self):
        """Verify routine sudo command without prior attack does not trigger alert."""
        events = [
            self._create_log_event(EventType.ACCEPTED_LOGIN, ip="10.0.0.50", user="sysadmin", offset_seconds=0),
            LogEvent(
                timestamp=self.base_time + timedelta(seconds=10),
                hostname="test-host",
                process="sudo",
                pid=5000,
                event_type=EventType.SUDO_COMMAND,
                username="sysadmin",
                raw_line="sudo: sysadmin : TTY=pts/0 ; COMMAND=/usr/bin/apt update",
            ),
        ]
        alerts = self.detector.detect(events)
        sudo_alerts = [a for a in alerts if a.rule_id == "SOC-RULE-004"]
        self.assertEqual(len(sudo_alerts), 0)

    # -------------------------------------------------------------------------
    # Whitelisting Tests
    # -------------------------------------------------------------------------

    def test_whitelisted_ip_tagged_when_suppression_disabled(self):
        """Verify whitelisted IP alerts are tagged with is_whitelisted=True."""
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="10.0.0.50", offset_seconds=i * 2)
            for i in range(5)
        ]
        alerts = self.detector.detect(events)
        self.assertTrue(len(alerts) > 0)
        self.assertTrue(all(a.is_whitelisted for a in alerts))

    def test_whitelisted_ip_suppressed_when_suppression_enabled(self):
        """Verify whitelisted IP alerts are dropped when suppress_whitelisted is True."""
        self.config.suppress_whitelisted = True
        events = [
            self._create_log_event(EventType.FAILED_LOGIN, ip="10.0.0.50", offset_seconds=i * 2)
            for i in range(5)
        ]
        alerts = self.detector.detect(events)
        self.assertEqual(len(alerts), 0)

    # -------------------------------------------------------------------------
    # Sample Log End-to-End Integration Test
    # -------------------------------------------------------------------------

    def test_sample_auth_log_incident_flow(self):
        """Verify detector on real sample_auth.log triggers all expected incident alerts."""
        from src.parser import AuthLogParser

        parser = AuthLogParser(year=2026)
        events = parser.parse_file("data/sample_auth.log")
        alerts = self.detector.detect(events)

        self.assertEqual(len(alerts), 5)
        rule_ids = [a.rule_id for a in alerts]
        self.assertIn("SOC-RULE-001", rule_ids)
        self.assertIn("SOC-RULE-002", rule_ids)
        self.assertIn("SOC-RULE-003", rule_ids)
        self.assertIn("SOC-RULE-004", rule_ids)

        # Check severity breakdown
        severities = [a.severity for a in alerts]
        self.assertEqual(severities.count(Severity.HIGH), 3)
        self.assertEqual(severities.count(Severity.CRITICAL), 2)


if __name__ == "__main__":
    unittest.main()
