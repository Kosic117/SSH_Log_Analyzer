# SSH_Log_Analyzer
Python-based SSH authentication log analyzer featuring failed login detection, IP tracking, and time-based brute-force alerts.

# SSH Failed Login Analyzer

**Python Cybersecurity Project 01**

A Python-based security monitoring tool that analyzes Linux SSH authentication logs, identifies repeated failed login attempts, and flags potentially suspicious activity.

The project demonstrates log analysis, Python scripting, and threshold-based security detection.

## Project Overview

The SSH Failed Login Analyzer was developed to explore how security analysts can identify suspicious authentication patterns using system logs.

The project includes two successfully tested implementations:

- **Version 1:** Counts failed SSH authentication attempts by source IP address.
- **Version 2:** Uses a configurable sliding time window to identify repeated failures occurring within a short period.

Both versions use Python's standard library and require no external packages.

## Features

**Version 1 — Basic Detection**
- Reads Linux SSH authentication logs.
- Extracts source IPv4 addresses using regular expressions.
- Counts failed authentication attempts per IP.
- Generates alerts when a configurable threshold is reached.

**Version 2 — Time-Based Detection**
- Parses authentication timestamps.
- Groups failed login attempts by source IP.
- Uses a configurable five-minute sliding window.
- Identifies bursts of failed authentication attempts.
- Reduces false positives caused by failures spread over longer periods.

## Technologies Used

- Python 3
- Regular expressions (`re`)
- `collections.Counter`
- `collections.defaultdict`
- `collections.deque`
- `datetime` and `timedelta`
- Linux SSH authentication log format
- Windows PowerShell for development and testing

## Installation and Usage

### Requirements

Python 3 installed on Windows, Linux, or macOS.

No additional Python packages are required.

### Running Version 1

On Windows:

```powershell
py ssh_login_analyzer.py
```

On Linux or macOS:

```bash
python3 ssh_login_analyzer.py
```

### Running Version 2

On Windows:

```powershell
py ssh_login_analyzer_v2.py
```

On Linux or macOS:

```bash
python3 ssh_login_analyzer_v2.py
```

Both scripts expect `sample_auth.log` in the current working directory.

## Configuration

Both versions support a configurable detection threshold:

```python
THRESHOLD = 3
```

Version 2 also supports a configurable time window:

```python
WINDOW_MINUTES = 5
```

## Testing and Results

### Version 1 — Tested Successfully

The script identified five failed authentication attempts across two source IP addresses.

```text
=== SSH Failed Login Report ===
Total failed attempts: 5

192.0.2.10: 4 failed attempts
  [ALERT] Possible Brute-Force activity!
198.51.100.25: 1 failed attempts
```

**Result: PASS**

### Version 2 — Tested Successfully

Version 2 successfully implemented time-based detection using a five-minute sliding window.

The test dataset contained two source IP addresses with four failed authentication attempts each.

One source generated repeated failures within five minutes, while the other generated failures distributed over approximately 30 minutes.

Expected detection output:

```text
=== SSH Failed Login Analyzer v2 ===
Threshold: 3 attempts
Time window: 5 minutes

192.0.2.10: 4 total failures
  [ALERT] 3+ failures within 5 minutes!
  Detected at: 2026-11-08 10:15:10
198.51.100.25: 4 total failures
  No suspicious burst detected.
```

**Result: PASS**

## Security Considerations

This tool is intended for educational security analysis and authorized monitoring.

Repeated authentication failures may indicate brute-force attempts, but they do not conclusively establish malicious activity.

The sample logs use reserved documentation IP addresses rather than real infrastructure information.

## Known Limitations

- IPv4 addresses only.
- Limited SSH authentication event coverage.
- No automatic response or blocking.
- No real-time monitoring.
- Version 2 assumes timestamps belong to 2026.
- No handling of log rotation or multiple log files.
- Alerts require analyst interpretation.

## Future Improvements

- CSV report generation.
- Username extraction and tracking.
- IPv6 support.
- Improved error handling.
- Dynamic timestamp and year handling.
- Analysis of real Linux authentication logs.
- Comparison of detection results with Wazuh SIEM alerts.

## Skills Demonstrated

- Python scripting
- Log parsing
- Regular expressions
- Data aggregation
- Conditional logic
- Time-based event correlation
- Security monitoring fundamentals
- Technical documentation

## Project Documentation

For additional information about the methodology, testing, security analysis, and development process, see [PROJECT_REPORT.md](PROJECT_REPORT.md).

**Development status: Versions 1 and 2 successfully tested.**
