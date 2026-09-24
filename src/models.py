"""Data models and enums for the SOC Log Analyzer."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    """Alert severity levels adhering to standard SOC triage hierarchy."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for sorting and filtering."""
        ranks = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return ranks.get(self.value, 0)

    def __ge__(self, other: "Severity") -> bool:
        if isinstance(other, Severity):
            return self.level >= other.level
        return NotImplemented

    def __gt__(self, other: "Severity") -> bool:
        if isinstance(other, Severity):
            return self.level > other.level
        return NotImplemented

    def __le__(self, other: "Severity") -> bool:
        if isinstance(other, Severity):
            return self.level <= other.level
        return NotImplemented

    def __lt__(self, other: "Severity") -> bool:
        if isinstance(other, Severity):
            return self.level < other.level
        return NotImplemented


class EventType(str, Enum):
    """Normalized security event classifications."""

    FAILED_LOGIN = "FAILED_LOGIN"
    ACCEPTED_LOGIN = "ACCEPTED_LOGIN"
    INVALID_USER = "INVALID_USER"
    SESSION_OPENED = "SESSION_OPENED"
    SESSION_CLOSED = "SESSION_CLOSED"
    SUDO_COMMAND = "SUDO_COMMAND"
    OTHER = "OTHER"


@dataclass
class LogEvent:
    """Normalized authentication log event extracted from raw syslog."""

    timestamp: datetime
    hostname: str
    process: str
    pid: Optional[int]
    event_type: EventType
    username: Optional[str] = None
    source_ip: Optional[str] = None
    port: Optional[int] = None
    auth_method: Optional[str] = None
    raw_line: str = ""


@dataclass
class Alert:
    """Actionable security incident alert produced by detection rules."""

    alert_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    timestamp: datetime
    source_ip: str
    target_users: List[str]
    attempt_count: int
    description: str
    mitre_technique: str
    is_whitelisted: bool = False
    evidence: List[str] = field(default_factory=list)
