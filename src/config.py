"""Configuration settings and detection thresholds for SOC Log Analyzer."""

import ipaddress
from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class DetectionConfig:
    """Configurable thresholds and rules parameters for detection tuning."""

    # Brute Force Thresholds
    brute_force_threshold: int = 5  # Number of failures within window to trigger HIGH alert
    repeated_failures_threshold: int = 3  # Low-volume repeated failures trigger (LOW/MEDIUM)
    post_failure_success_threshold: int = 3  # Failures before an accepted login triggers CRITICAL alert
    user_enumeration_threshold: int = 3  # Distinct usernames targeted within window to trigger spray alert
    time_window_minutes: int = 10  # Sliding time window for counting failures

    # False Positive Reduction - Whitelisting
    whitelisted_ips: List[str] = field(default_factory=lambda: ["127.0.0.1", "10.0.0.50"])
    suppress_whitelisted: bool = False  # If True, discard alerts for whitelisted IPs; if False, tag them

    # Pre-parsed IP networks for fast CIDR / IP lookup
    _parsed_networks: Set[ipaddress.IPv4Network] = field(default_factory=set, init=False)

    def __post_init__(self):
        """Parse string IPs / CIDRs into ipaddress objects."""
        parsed = set()
        for item in self.whitelisted_ips:
            try:
                # Support both single IP ("192.168.1.100") and CIDR ("10.0.0.0/24")
                if "/" in item:
                    parsed.add(ipaddress.ip_network(item.strip(), strict=False))
                else:
                    parsed.add(ipaddress.ip_network(f"{item.strip()}/32", strict=False))
            except ValueError:
                continue
        self._parsed_networks = parsed

    def is_ip_whitelisted(self, ip_str: str) -> bool:
        """Check if an IP address belongs to the whitelisted IP list or CIDR ranges."""
        if not ip_str:
            return False
        try:
            target_ip = ipaddress.ip_address(ip_str)
            return any(target_ip in net for net in self._parsed_networks)
        except ValueError:
            return False
