"""Threat detection and correlation engine for Linux authentication logs."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from src.config import DetectionConfig
from src.models import Alert, EventType, LogEvent, Severity
from src.parser import AuthLogParser


class SOCDetector:
    """Correlation and threat detection engine for defensive SOC operations.

    Evaluates normalized LogEvent sequences against defensive security rules,
    applying sliding time windows, threshold evaluations, and host/user correlation.
    """

    def __init__(self, config: Optional[DetectionConfig] = None):
        """Initialize detector with tuning configuration.

        Args:
            config: DetectionConfig instance containing thresholds and whitelists.
                    Defaults to standard DetectionConfig if not provided.
        """
        self.config = config or DetectionConfig()
        self._alert_counter = 0

    def _next_alert_id(self) -> str:
        """Generate a deterministic, sequential alert identifier."""
        self._alert_counter += 1
        return f"ALT-{self._alert_counter:04d}"

    def detect(self, events: List[LogEvent]) -> List[Alert]:
        """Execute all detection rules across the provided chronological log events.

        Args:
            events: Chronologically sorted list of LogEvent instances.

        Returns:
            List of generated Alert instances, sorted by timestamp and severity.
        """
        self._alert_counter = 0
        alerts: List[Alert] = []

        if not events:
            return alerts

        # Guarantee chronological ordering for accurate sliding windows
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # 1. Rule 3: Detect Post-Brute-Force Successful Logins (Potential Compromise)
        compromise_alerts, compromised_sessions = self._detect_post_brute_success(sorted_events)
        alerts.extend(compromise_alerts)

        # 2. Rule 1: Detect SSH Brute-Force Attacks
        brute_force_alerts = self._detect_brute_force(sorted_events)
        alerts.extend(brute_force_alerts)

        # 3. Rule 2: Detect SSH User Enumeration / Password Spraying
        spray_alerts = self._detect_user_enumeration(sorted_events)
        alerts.extend(spray_alerts)

        # 4. Rule 4: Detect Suspicious Sudo Privilege Escalation
        sudo_alerts = self._detect_suspicious_sudo(sorted_events, compromised_sessions)
        alerts.extend(sudo_alerts)

        # Filter suppressed whitelisted alerts if configured
        final_alerts: List[Alert] = []
        for alert in alerts:
            is_wl = self.config.is_ip_whitelisted(alert.source_ip)
            alert.is_whitelisted = is_wl
            if is_wl and self.config.suppress_whitelisted:
                continue
            final_alerts.append(alert)

        # Sort alerts chronologically, then by severity rank (CRITICAL -> LOW)
        final_alerts.sort(key=lambda a: (a.timestamp, -a.severity.level))

        # Re-index alert IDs sequentially for deterministic presentation
        for idx, alert in enumerate(final_alerts, start=1):
            alert.alert_id = f"ALT-{idx:04d}"

        return final_alerts

    def detect_file(self, file_path: str, parser: Optional[AuthLogParser] = None) -> List[Alert]:
        """Convenience method to parse an auth.log file and run detections.

        Args:
            file_path: Path to the Linux authentication log file.
            parser: Optional AuthLogParser instance.

        Returns:
            List of generated Alert instances.
        """
        p = parser or AuthLogParser()
        events = p.parse_file(file_path)
        return self.detect(events)

    def _detect_brute_force(self, events: List[LogEvent]) -> List[Alert]:
        """Rule 1: Detect SSH brute-force attacks against target accounts.

        Identifies source IPs that generate failed logins exceeding brute_force_threshold
        within the configured time window. Aggregates contiguous bursts into a single
        actionable incident to prevent alert fatigue.
        """
        alerts: List[Alert] = []
        window = timedelta(minutes=self.config.time_window_minutes)

        # Group failed login events by source IP
        failures_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
        for e in events:
            if e.event_type == EventType.FAILED_LOGIN and e.source_ip:
                failures_by_ip[e.source_ip].append(e)

        for ip, fail_events in failures_by_ip.items():
            if len(fail_events) < self.config.brute_force_threshold:
                continue

            # Cluster consecutive failures that fall within sliding window gaps
            clusters: List[List[LogEvent]] = []
            current_cluster: List[LogEvent] = [fail_events[0]]

            for curr in fail_events[1:]:
                prev = current_cluster[-1]
                if (curr.timestamp - prev.timestamp) <= window:
                    current_cluster.append(curr)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [curr]
            clusters.append(current_cluster)

            # Evaluate each cluster
            for cluster in clusters:
                # Check if any sliding window within this cluster meets or exceeds threshold
                has_brute_force = False
                n = len(cluster)
                for i in range(n):
                    sub_count = 0
                    for j in range(i, n):
                        if (cluster[j].timestamp - cluster[i].timestamp) <= window:
                            sub_count += 1
                        else:
                            break
                    if sub_count >= self.config.brute_force_threshold:
                        has_brute_force = True
                        break

                if has_brute_force:
                    target_users = sorted(list({e.username for e in cluster if e.username}))
                    evidence_lines = [e.raw_line for e in cluster if e.raw_line]
                    first_ts = cluster[0].timestamp
                    last_ts = cluster[-1].timestamp
                    duration_secs = int((last_ts - first_ts).total_seconds())

                    alert = Alert(
                        alert_id=self._next_alert_id(),
                        rule_id="SOC-RULE-001",
                        rule_name="SSH Brute-Force Attack Detected",
                        severity=Severity.HIGH,
                        timestamp=last_ts,
                        source_ip=ip,
                        target_users=target_users,
                        attempt_count=len(cluster),
                        description=(
                            f"Detected {len(cluster)} failed SSH login attempts from {ip} "
                            f"targeting {len(target_users)} user(s) ({', '.join(target_users[:5])}) "
                            f"within {duration_secs}s (threshold: {self.config.brute_force_threshold} "
                            f"in {self.config.time_window_minutes}m)."
                        ),
                        mitre_technique="T1110.001 - Password Guessing",
                        is_whitelisted=False,
                        evidence=evidence_lines,
                    )
                    alerts.append(alert)

        return alerts

    def _detect_user_enumeration(self, events: List[LogEvent]) -> List[Alert]:
        """Rule 2: Detect SSH user enumeration and password spraying.

        Identifies source IPs attempting authentication against multiple distinct
        usernames within the configured time window.
        """
        alerts: List[Alert] = []
        window = timedelta(minutes=self.config.time_window_minutes)
        spray_threshold = getattr(self.config, "user_enumeration_threshold", 3)

        # Collect failed login / invalid user events by IP
        auth_attempts_by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
        for e in events:
            if (e.event_type in (EventType.FAILED_LOGIN, EventType.INVALID_USER)) and e.source_ip:
                auth_attempts_by_ip[e.source_ip].append(e)

        for ip, ip_events in auth_attempts_by_ip.items():
            # Cluster events by time window
            clusters: List[List[LogEvent]] = []
            if not ip_events:
                continue

            current_cluster: List[LogEvent] = [ip_events[0]]
            for curr in ip_events[1:]:
                prev = current_cluster[-1]
                if (curr.timestamp - prev.timestamp) <= window:
                    current_cluster.append(curr)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [curr]
            clusters.append(current_cluster)

            for cluster in clusters:
                distinct_users = sorted(list({e.username for e in cluster if e.username}))
                if len(distinct_users) >= spray_threshold:
                    last_ts = cluster[-1].timestamp
                    first_ts = cluster[0].timestamp
                    duration_secs = int((last_ts - first_ts).total_seconds())
                    evidence_lines = [e.raw_line for e in cluster if e.raw_line]

                    alert = Alert(
                        alert_id=self._next_alert_id(),
                        rule_id="SOC-RULE-002",
                        rule_name="SSH User Enumeration / Password Spraying",
                        severity=Severity.HIGH,
                        timestamp=last_ts,
                        source_ip=ip,
                        target_users=distinct_users,
                        attempt_count=len(cluster),
                        description=(
                            f"Detected authentication attempts against {len(distinct_users)} "
                            f"distinct username(s) from {ip} within {duration_secs}s "
                            f"(threshold: {spray_threshold} distinct users in {self.config.time_window_minutes}m). "
                            f"Targeted accounts: {', '.join(distinct_users[:8])}."
                        ),
                        mitre_technique="T1110.003 - Password Spraying / T1087.001 - Account Discovery",
                        is_whitelisted=False,
                        evidence=evidence_lines,
                    )
                    alerts.append(alert)

        return alerts

    def _detect_post_brute_success(
        self, events: List[LogEvent]
    ) -> Tuple[List[Alert], List[Dict[str, object]]]:
        """Rule 3: Detect successful login after repeated failed attempts (Compromise).

        Identifies when an ACCEPTED_LOGIN is immediately preceded by failed attempts
        from the same source IP exceeding post_failure_success_threshold within
        the sliding time window.

        Returns:
            Tuple of (List of generated Alerts, List of compromised session contexts).
        """
        alerts: List[Alert] = []
        compromised_sessions: List[Dict[str, object]] = []
        window = timedelta(minutes=self.config.time_window_minutes)

        # Track history of failed logins per IP
        failed_history: Dict[str, List[LogEvent]] = defaultdict(list)

        for e in events:
            if not e.source_ip:
                continue

            if e.event_type == EventType.FAILED_LOGIN:
                failed_history[e.source_ip].append(e)

            elif e.event_type == EventType.ACCEPTED_LOGIN:
                ip = e.source_ip
                # Gather preceding failures within the sliding window prior to this accepted login
                preceding_failures = [
                    f
                    for f in failed_history[ip]
                    if (e.timestamp >= f.timestamp) and ((e.timestamp - f.timestamp) <= window)
                ]

                if len(preceding_failures) >= self.config.post_failure_success_threshold:
                    target_user = e.username or "unknown"
                    evidence_lines = [f.raw_line for f in preceding_failures if f.raw_line]
                    if e.raw_line:
                        evidence_lines.append(e.raw_line)

                    alert = Alert(
                        alert_id=self._next_alert_id(),
                        rule_id="SOC-RULE-003",
                        rule_name="Post-Brute-Force Successful Login (Potential Compromise)",
                        severity=Severity.CRITICAL,
                        timestamp=e.timestamp,
                        source_ip=ip,
                        target_users=[target_user],
                        attempt_count=len(preceding_failures) + 1,
                        description=(
                            f"CRITICAL: User '{target_user}' successfully logged in from {ip} "
                            f"after {len(preceding_failures)} failed login attempts within "
                            f"{self.config.time_window_minutes}m. High probability of credential compromise."
                        ),
                        mitre_technique="T1110 - Brute Force / T1078 - Valid Accounts",
                        is_whitelisted=False,
                        evidence=evidence_lines,
                    )
                    alerts.append(alert)

                    # Store session context for correlation with downstream activities (e.g. sudo)
                    compromised_sessions.append(
                        {
                            "username": target_user,
                            "source_ip": ip,
                            "login_timestamp": e.timestamp,
                            "alert_id": alert.alert_id,
                            "login_event": e,
                        }
                    )

                    # Reset failed history for this IP to prevent re-alerting on the same burst
                    failed_history[ip] = []

        return alerts, compromised_sessions

    def _detect_suspicious_sudo(
        self, events: List[LogEvent], compromised_sessions: List[Dict[str, object]]
    ) -> List[Alert]:
        """Rule 4: Detect sudo privilege escalation following suspicious authentication.

        Correlates SUDO_COMMAND events with recently compromised accounts / sessions
        within the sliding time window. Routine sudo usage by non-compromised accounts
        is ignored to prevent false positives.
        """
        alerts: List[Alert] = []
        window = timedelta(minutes=self.config.time_window_minutes)

        if not compromised_sessions:
            return alerts

        for e in events:
            if e.event_type != EventType.SUDO_COMMAND or not e.username:
                continue

            # Look for a matching compromised session for this username
            for session in compromised_sessions:
                sess_user = session["username"]
                sess_ip = str(session["source_ip"])
                sess_ts = session["login_timestamp"]

                if e.username == sess_user and isinstance(sess_ts, datetime):
                    # Check if sudo was executed after login and within the time window
                    time_diff = (e.timestamp - sess_ts).total_seconds()
                    if 0 <= time_diff <= window.total_seconds():
                        evidence_lines: List[str] = []
                        login_ev = session.get("login_event")
                        if isinstance(login_ev, LogEvent) and login_ev.raw_line:
                            evidence_lines.append(login_ev.raw_line)
                        if e.raw_line:
                            evidence_lines.append(e.raw_line)

                        alert = Alert(
                            alert_id=self._next_alert_id(),
                            rule_id="SOC-RULE-004",
                            rule_name="Suspicious Sudo Privilege Escalation Post-Compromise",
                            severity=Severity.CRITICAL,
                            timestamp=e.timestamp,
                            source_ip=sess_ip,
                            target_users=[e.username],
                            attempt_count=1,
                            description=(
                                f"CRITICAL: User '{e.username}' executed privileged sudo command "
                                f"{int(time_diff)}s after suspicious authentication from {sess_ip}. "
                                f"Command evidence: {e.raw_line}"
                            ),
                            mitre_technique="T1548.003 - Sudo and Sudo Caching",
                            is_whitelisted=False,
                            evidence=evidence_lines,
                        )
                        alerts.append(alert)

        return alerts


# Alias for backward and architectural compatibility
DetectionEngine = SOCDetector
