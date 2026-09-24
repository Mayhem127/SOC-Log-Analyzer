"""Log parser module for Linux authentication logs (auth.log / secure)."""

import re
from datetime import datetime
from typing import List, Optional

from src.models import EventType, LogEvent

# Regex for standard syslog header: "Oct 24 08:12:01 hostname process[pid]: message"
SYSLOG_HEADER_PATTERN = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# OpenSSH specific message patterns
SSH_FAILED_INVALID_PATTERN = re.compile(
    r"^Failed\s+(?P<method>\S+)\s+for\s+invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)

SSH_FAILED_VALID_PATTERN = re.compile(
    r"^Failed\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)

SSH_ACCEPTED_PATTERN = re.compile(
    r"^Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)

SSH_INVALID_USER_PATTERN = re.compile(
    r"^Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)

PAM_SESSION_OPENED = re.compile(
    r"^pam_unix\((?:\S+)\):\s+session\s+opened\s+for\s+user\s+(?P<user>\S+)"
)

PAM_SESSION_CLOSED = re.compile(
    r"^pam_unix\((?:\S+)\):\s+session\s+closed\s+for\s+user\s+(?P<user>\S+)"
)

SUDO_COMMAND_PATTERN = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s+TTY=.*COMMAND=(?P<cmd>.*)$"
)


class AuthLogParser:
    """Parses raw auth.log lines into normalized LogEvent data objects."""

    MONTHS = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    def __init__(self, year: Optional[int] = None):
        """Initialize parser with optional year (defaults to current year)."""
        self.year = year or datetime.now().year

    def parse_timestamp(self, month_str: str, day_str: str, time_str: str) -> datetime:
        """Parse syslog date components into a datetime object."""
        month = self.MONTHS.get(month_str, 1)
        day = int(day_str)
        hour, minute, second = map(int, time_str.split(":"))
        return datetime(self.year, month, day, hour, minute, second)

    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single log line into a LogEvent object.

        Returns None if line is blank. Categorizes non-matching or system lines as OTHER.
        """
        line = line.strip()
        if not line:
            return None

        match = SYSLOG_HEADER_PATTERN.match(line)
        if not match:
            # Not a standard syslog format line
            return None

        data = match.groupdict()
        timestamp = self.parse_timestamp(data["month"], data["day"], data["time"])
        hostname = data["hostname"]
        process = data["process"]
        pid = int(data["pid"]) if data.get("pid") else None
        message = data["message"]

        # Default values
        event_type = EventType.OTHER
        username: Optional[str] = None
        source_ip: Optional[str] = None
        port: Optional[int] = None
        auth_method: Optional[str] = None

        # 1. Check for Failed Password with Invalid User
        m_failed_inv = SSH_FAILED_INVALID_PATTERN.match(message)
        if m_failed_inv:
            event_type = EventType.FAILED_LOGIN
            auth_method = m_failed_inv.group("method")
            username = m_failed_inv.group("user")
            source_ip = m_failed_inv.group("ip")
            port = int(m_failed_inv.group("port"))
            return LogEvent(
                timestamp=timestamp,
                hostname=hostname,
                process=process,
                pid=pid,
                event_type=event_type,
                username=username,
                source_ip=source_ip,
                port=port,
                auth_method=auth_method,
                raw_line=line,
            )

        # 2. Check for Failed Password for Valid User
        m_failed_val = SSH_FAILED_VALID_PATTERN.match(message)
        if m_failed_val:
            event_type = EventType.FAILED_LOGIN
            auth_method = m_failed_val.group("method")
            username = m_failed_val.group("user")
            source_ip = m_failed_val.group("ip")
            port = int(m_failed_val.group("port"))
            return LogEvent(
                timestamp=timestamp,
                hostname=hostname,
                process=process,
                pid=pid,
                event_type=event_type,
                username=username,
                source_ip=source_ip,
                port=port,
                auth_method=auth_method,
                raw_line=line,
            )

        # 3. Check for Accepted Login (password or publickey)
        m_accepted = SSH_ACCEPTED_PATTERN.match(message)
        if m_accepted:
            event_type = EventType.ACCEPTED_LOGIN
            auth_method = m_accepted.group("method")
            username = m_accepted.group("user")
            source_ip = m_accepted.group("ip")
            port = int(m_accepted.group("port"))
            return LogEvent(
                timestamp=timestamp,
                hostname=hostname,
                process=process,
                pid=pid,
                event_type=event_type,
                username=username,
                source_ip=source_ip,
                port=port,
                auth_method=auth_method,
                raw_line=line,
            )

        # 4. Check for Invalid User Probe
        m_inv = SSH_INVALID_USER_PATTERN.match(message)
        if m_inv:
            event_type = EventType.INVALID_USER
            username = m_inv.group("user")
            source_ip = m_inv.group("ip")
            port = int(m_inv.group("port"))
            return LogEvent(
                timestamp=timestamp,
                hostname=hostname,
                process=process,
                pid=pid,
                event_type=event_type,
                username=username,
                source_ip=source_ip,
                port=port,
                auth_method=auth_method,
                raw_line=line,
            )

        # 5. PAM Sessions
        m_pam_open = PAM_SESSION_OPENED.match(message)
        if m_pam_open:
            event_type = EventType.SESSION_OPENED
            username = m_pam_open.group("user")
            return LogEvent(
                timestamp=timestamp,
                hostname=hostname,
                process=process,
                pid=pid,
                event_type=event_type,
                username=username,
                raw_line=line,
            )

        m_pam_close = PAM_SESSION_CLOSED.match(message)
        if m_pam_close:
            event_type = EventType.SESSION_CLOSED
            username = m_pam_close.group("user")
            return LogEvent(
                timestamp=timestamp,
                hostname=hostname,
                process=process,
                pid=pid,
                event_type=event_type,
                username=username,
                raw_line=line,
            )

        # 6. Sudo commands
        if process == "sudo":
            m_sudo = SUDO_COMMAND_PATTERN.match(message)
            if m_sudo:
                event_type = EventType.SUDO_COMMAND
                username = m_sudo.group("user")
                return LogEvent(
                    timestamp=timestamp,
                    hostname=hostname,
                    process=process,
                    pid=pid,
                    event_type=event_type,
                    username=username,
                    raw_line=line,
                )

        # Non-security / generic syslog line
        return LogEvent(
            timestamp=timestamp,
            hostname=hostname,
            process=process,
            pid=pid,
            event_type=EventType.OTHER,
            raw_line=line,
        )

    def parse_file(self, file_path: str) -> List[LogEvent]:
        """Read and parse an entire log file, returning sorted LogEvent objects."""
        events: List[LogEvent] = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                event = self.parse_line(line)
                if event:
                    events.append(event)

        # Sort chronologically to guarantee deterministic window correlation
        events.sort(key=lambda e: e.timestamp)
        return events
