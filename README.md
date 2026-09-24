# SOC Log Analyzer

A Python-based security tool for analyzing Linux authentication logs (`auth.log / secure`). It looks for suspicious SSH activity, detects common attack patterns, and connects related events to create a clearer picture of a possible intrusion.
---

## Overview

SOC analysts often need to go through authentication logs to find failed login attempts, suspicious access, and other signs of an attack. This project automates some of that process by parsing Linux syslog records and checking them against a set of detection rules.

The analyzer can detect patterns such as repeated SSH login failures, attempts against multiple usernames, successful logins after multiple failures, and suspicious sudo activity that happens after a possible compromise. The results can be viewed directly in the terminal or exported as a CSV report.

The detection engine uses only Python's standard library, so no third-party packages are required to run the analyzer itself.

---

## Key Detection Capabilities

The analyzer implements four defensive detection rules mapped to the MITRE ATT&CK framework:

| Rule ID | Rule Name | MITRE ATT&CK | Default Threshold | Severity | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SOC-RULE-001** | SSH Brute-Force Attack | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) (Password Guessing) | $\ge 5$ failed attempts in 10 min | **HIGH** | Identifies repeated failed SSH login attempts originating from a single source IP against one or more accounts within a sliding window. |
| **SOC-RULE-002** | SSH User Enumeration / Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (Password Spraying) / [T1087.001](https://attack.mitre.org/techniques/T1087/001/) (Account Discovery) | $\ge 3$ distinct users in 10 min | **HIGH** | Detects an IP attempting to authenticate against multiple distinct usernames, indicating username harvesting or horizontal password spraying. |
| **SOC-RULE-003** | Post-Brute-Force Successful Login | [T1110](https://attack.mitre.org/techniques/T1110/) (Brute Force) / [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) | Successful login after $\ge 3$ failures in 10 min | **CRITICAL** | Flags an accepted SSH login immediately preceded by repeated failed attempts from the same IP, highlighting a suspicious authentication pattern that warrants investigation for potential account compromise. |
| **SOC-RULE-004** | Suspicious Sudo Privilege Escalation Post-Compromise | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) (Sudo and Sudo Caching) | Sudo command within 10 min of compromise alert | **CRITICAL** | Correlates privilege escalation commands (`sudo`) executed by an account flagged under `SOC-RULE-003` within the time window. Routine sudo usage by accounts without prior authentication anomalies is not flagged. |

### False Positive Tuning & Whitelisting
The engine supports IP and CIDR whitelisting. By default, alerts involving trusted IPs (such as internal bastions or monitoring hosts) can either be flagged with a `WHITELISTED` tag for auditing or completely suppressed using `--suppress-whitelisted`.

---

## Architecture

The project follows a linear, decoupled defensive processing pipeline:

```
Log File (auth.log)
   ↓
AuthLogParser
   ↓ (Normalized LogEvents)
SOCDetector
   ↓ (Rule Evaluation)
Alert Correlation
   ↓ (Multi-Stage Alerts)
SOCReporter
   ↓
Terminal Report + CSV Export
```

1. **Ingestion & Normalization (`AuthLogParser`)**: Reads syslog-formatted lines, extracts timestamps, hostnames, processes, usernames, source IPs, and ports, and outputs structured `LogEvent` dataclasses.
2. **Detection Engine (`SOCDetector`)**: Evaluates events chronologically across configurable sliding windows. Tracks authentication histories per IP and user session.
3. **Alert Correlation**: Correlates preceding failed login bursts with subsequent successful logins, and links downstream privileged commands executed within the correlation window.
4. **Reporting (`SOCReporter`)**: Generates an executive terminal summary with granular evidence and exports standardized incident rows for CSV triage.

---

## Project Structure

```text
SOC Analyzer/
├── main.py                  # CLI entry point orchestrating parser, detector, and reporter
├── requirements.txt         # Development and testing dependencies (pytest, pytest-cov)
├── data/
│   └── sample_auth.log      # Simulated lab authentication log with multi-stage attack scenarios
├── reports/                 # Output directory for generated CSV reports (created at runtime)
├── src/
│   ├── __init__.py          # Package initialization
│   ├── config.py            # Detection thresholds, sliding window parameters, and IP whitelisting
│   ├── detector.py          # Threat detection logic and session correlation engine
│   ├── models.py            # Dataclasses and enums (LogEvent, Alert, Severity, EventType)
│   ├── parser.py            # Syslog and OpenSSH log parser with regex extraction
│   └── reporter.py          # Terminal report generator and CSV export formatter
└── tests/
    ├── __init__.py          # Test suite package
    ├── test_cli.py          # Tests for CLI flags, argument parsing, and exit codes
    ├── test_detector.py     # Tests for detection rules, time windows, and correlation
    └── test_reporter.py     # Tests for CSV export accuracy and terminal report formatting
```

---

## Technologies Used

- **Python 3**: Core application logic implemented entirely with the Python Standard Library (`re`, `argparse`, `csv`, `datetime`, `ipaddress`, `dataclasses`, `enum`, `collections`).
- **pytest & pytest-cov**: Automated testing framework and code coverage measurement.
- **Linux Authentication Log Format**: Standard Syslog / OpenSSH `auth.log` format matching Debian, Ubuntu, and CentOS/RHEL (`secure`).
- **MITRE ATT&CK Framework**: Industry-standard threat tactic and technique categorization for all alert outputs.

---

## Installation & Setup

### Prerequisites
- Python 3.8 or higher installed on your system.

### 1. Clone the Repository
```bash
git clone https://github.com/Mayhem127/soc-log-analyzer.git
cd soc-log-analyzer
```

### 2. Set Up a Virtual Environment (Optional, Recommended)
```bash
python -m venv venv

# Linux/macOS:
source venv/bin/activate

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
```

### 3. Install Test Dependencies
The core detection engine does not require third-party libraries. If you want to run the test suite and verify test coverage, install the development dependencies:
```bash
pip install -r requirements.txt
```

---

## Usage

### Basic CLI Command
Run the analyzer against the included sample log file and export findings to CSV:

```bash
python main.py data/sample_auth.log --csv reports/cli_alerts.csv
```

### CLI Options

| Argument | Flag | Type | Description |
| :--- | :--- | :--- | :--- |
| `log_file` | `-f`, `--file` | String | Path to the Linux authentication log file to analyze. |
| `--csv` | `-o` | String | Destination path for the exported CSV report. |
| `--threshold` | `-t` | Integer | Override the failed-attempt threshold for brute-force detection (default: `5`). |
| `--window` | `-w` | Integer | Override the sliding time window in minutes (default: `10`). |
| `--min-severity` | `-s` | String | Filter alerts by minimum severity level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `--suppress-whitelisted` | - | Flag | Suppress alerts triggered by whitelisted IPs instead of tagging them. |
| `--whitelist-ip` | - | String | Add an IP or CIDR range to the whitelist (can be specified multiple times). |
| `--year` | - | Integer | Manually specify the year for syslog timestamps (defaults to current year). |
| `--quiet` | `-q` | Flag | Suppress terminal output (useful when only generating a CSV report). |

### Example CLI Queries

Filter and display only `CRITICAL` incidents:
```bash
python main.py data/sample_auth.log -s CRITICAL
```

Tune detection with custom thresholds (3 attempts in a 5-minute window):
```bash
python main.py data/sample_auth.log -t 3 -w 5 --csv reports/custom_alerts.csv
```

Add an internal subnet to the whitelist and suppress alerts:
```bash
python main.py data/sample_auth.log --whitelist-ip 192.168.1.0/24 --suppress-whitelisted
```

---

## Example Detection Scenario (Simulated Lab)

The included `data/sample_auth.log` file contains a simulated multi-stage intrusion demonstration:

```text
Attacker IP: 203.0.113.42
   ↓
[Phase 1] 8 failed SSH password attempts against 'devops' within 38 seconds
          → Alert ALT-0003: [HIGH] SOC-RULE-001 (SSH Brute-Force)
   ↓
[Phase 2] Accepted password login for 'devops' immediately following the failures
          → Alert ALT-0004: [CRITICAL] SOC-RULE-003 (Post-Brute-Force Successful Login)
   ↓
[Phase 3] Elevated privilege execution ('sudo /bin/bash') by 'devops' 5 seconds later
          → Alert ALT-0005: [CRITICAL] SOC-RULE-004 (Suspicious Sudo Privilege Escalation)
```

Running the analyzer against this sample data outputs the following summary:

```text
================================================================================
                  SOC LOG ANALYZER - SECURITY INCIDENT REPORT                   
================================================================================
[+] EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
  Total Events Analyzed : 30
  Total Alerts Generated: 5
  Unique Source IPs     : 2 (198.51.100.23, 203.0.113.42)

[+] ALERTS BY SEVERITY
--------------------------------------------------------------------------------
  CRITICAL : 2
  HIGH     : 3
  MEDIUM   : 0
  LOW      : 0

[+] ALERTS BY RULE
--------------------------------------------------------------------------------
  [SOC-RULE-001] SSH Brute-Force Attack Detected                    : 2
  [SOC-RULE-002] SSH User Enumeration / Password Spraying           : 1
  [SOC-RULE-003] Post-Brute-Force Successful Login (Potential Compromise) : 1
  [SOC-RULE-004] Suspicious Sudo Privilege Escalation Post-Compromise : 1
...
```

Each generated alert in the report and CSV contains the full list of evidence log lines showing exact timestamps and raw syslog strings.

---

## Testing & Code Quality

The project includes unit and integration tests covering the CLI interface, regex parsing, detection algorithms, and CSV/terminal reporting.

### Running Tests and Coverage

```bash
python -m pytest --cov=src --cov-report=term-missing
```

### Verified Test Results

- **28 tests passed**
- **94% overall code coverage** (419 / 444 statements covered)
- Module breakdown:
  - `src/reporter.py`: **100%** (108 / 108 stmts)
  - `src/parser.py`: **97%** (93 / 96 stmts)
  - `src/detector.py`: **96%** (154 / 160 stmts)
  - `src/config.py`: **81%** (25 / 31 stmts)
  - `src/models.py`: **79%** (38 / 48 stmts)

---

## Security & Data Note

The log records provided in `data/sample_auth.log` are **simulated lab logs** generated specifically for testing and educational purposes. All external IP addresses utilize RFC 5737 reserved documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`, and `192.0.2.0/24`) and private RFC 1918 addresses. No actual production infrastructure, live credentials, or real-world security incidents are represented.

---

## Limitations

There are a few limitations to keep in mind:
- **Not a Full SIEM**: This is a targeted, lightweight offline log analysis tool. It is not intended to replace comprehensive enterprise SIEM solutions such as Wazuh, Splunk, or Elastic SIEM.
- **Log Scope**: Specifically focuses on Linux OpenSSH and PAM authentication logs (`auth.log` / `secure`). It does not ingest web server logs (Nginx/Apache), firewall logs, or kernel audit records (`auditd`).
- **Batch Processing**: The tool processes static log files on disk rather than streaming real-time event pipelines over network sockets.
- **Stateless Operation**: Each CLI run evaluates the provided file in isolation; it does not persist incident state to an external database between runs.

---

## Future Improvements

Some improvements I would like to add in the future include:
- **Additional Log Formats**: Support for JSON-structured logs, `systemd-journald` output, and `auditd` event logs.
- **Expanded Detection Rules**: Detection for unusual off-hours logins, geographically anomalous source IPs (GeoIP lookup), and rapid session hopping.
- **Real-Time Log Ingestion**: Continuous monitoring mode (tailing active `/var/log/auth.log` via filesystem event triggers).
- **External Notifications & SIEM Forwarding**: Webhook integration to forward critical alerts to Discord, Slack, or a centralized SIEM collector via Syslog/CEF format.

---

## Author & Contact

Developed as part of a cybersecurity and SOC analysis portfolio demonstrating log parsing, threat detection engineering, and incident correlation.

- **Author**: Nadya Roselani Bramanjaya (Dya) — Cybersecurity Student, Bina Nusantara University
- **GitHub**: [https://github.com/Mayhem127](https://github.com/Mayhem127)
- **LinkedIn**: [https://www.linkedin.com/in/margareta-nadya](https://www.linkedin.com/in/margareta-nadya)

---

