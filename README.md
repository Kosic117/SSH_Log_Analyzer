# SSH Failed Login Analyzer

**Python Cybersecurity Project 01 | Blue Team / Security Monitoring**

A Python-based SSH authentication log analyzer designed to identify patterns of potentially suspicious login activity.

The project demonstrates log parsing, event correlation, brute-force detection, command-line configuration, and security reporting.

## Project Overview

The analyzer processes SSH authentication logs, extracts failed login events, and groups them by source IPv4 address.

The project was developed incrementally across three versions.

| Version | Features |
|---|---|
| Version 1 | Failed login counting by IP address and threshold-based alerts |
| Version 2 | Timestamp parsing and sliding-window brute-force detection |
| Version 3 | Username tracking, CSV reporting, command-line arguments, configurable thresholds, and improved error handling |

## Version 3 Features

- Extracts timestamps, usernames, and source IPv4 addresses from supported SSH log entries.
- Groups failed authentication attempts by source IP.
- Detects repeated failures within a configurable sliding time window.
- Tracks unique usernames targeted by each IP.
- Accepts different log files through command-line arguments.
- Allows users to customize the detection threshold and time window.
- Exports findings to a CSV report.
- Handles missing or inaccessible files and skips malformed timestamps.

## Technologies Used

- Python 3
- Regular expressions (`re`)
- `collections.defaultdict` and `deque`
- `datetime` and `timedelta`
- `argparse`
- `csv`
- `pathlib`
- Windows PowerShell for development and testing

No third-party Python packages are required.

## Installation and Usage

Clone or download the repository and open a terminal in the project directory.

### Version 1

```powershell
py ssh_login_analyzer_v1.py
```

### Version 2

```powershell
py ssh_login_analyzer_v2.py
```

### Version 3 — Default Settings

```powershell
py ssh_login_analyzer_v3.py
```

Uses `sample_auth.log`, a threshold of 3 failed attempts, and a five-minute detection window.

### Version 3 — Custom Log File

```powershell
py ssh_login_analyzer_v3.py another_auth.log
```

### Version 3 — Custom Detection Settings

```powershell
py ssh_login_analyzer_v3.py sample_auth.log --threshold 5 --time_window 10
```

This configuration requires at least five failed login attempts from the same IP within a ten-minute window.

### Display Help

```powershell
py ssh_login_analyzer_v3.py --help
```

On Linux, use `python3` instead of `py`.

## Detection Methodology

Version 3 uses a sliding-window detection algorithm.

1. Read authentication log entries.
2. Extract the timestamp, username, and source IP.
3. Group failed login events by source IP.
4. Sort events chronologically.
5. Maintain a queue of attempts within the configured time window.
6. Trigger an alert when the number of attempts reaches the configured threshold.
7. Export results to CSV.

The analyzer records the first threshold crossing for each source IP.

## Testing and Results

Testing uses synthetic SSH authentication logs and documentation-range IP addresses.

### Version 1

Successfully identified five failed login attempts across two source IPs, generating an alert for the IP with four failures.

### Version 2

Successfully distinguished a burst of four failed login attempts from four attempts distributed over a longer period.

### Version 3

Successfully demonstrated:

- Extraction of usernames from failed authentication entries.
- Correct grouping of failures by IP.
- Command-line selection of the input log.
- Configurable threshold and time window.
- Generation of a CSV report.

A test with a threshold of 10 and a 15-minute window produced NORMAL results for both source IPs, each with four total failures.

## CSV Reporting

Version 3 generates `ssh_report.csv` with the following fields:

- `ip_address`
- `total_failures`
- `usernames`
- `status`
- `alert_time`

The report is overwritten each time the analyzer runs.

## Known Limitations

- Supports IPv4 addresses only.
- Processes supported SSH `Failed password` log formats rather than every possible authentication event.
- Does not currently handle year boundaries within a log file.
- Does not perform live monitoring.
- Does not automatically block source IP addresses.
- Records the first threshold crossing per IP rather than every suspicious burst.
- Does not establish malicious intent; alerts indicate potentially suspicious patterns.
- The CSV output filename is fixed and previous reports are overwritten.

**Timestamp Year Accuracy:** Traditional Linux syslog entries often omit the year. Version 3 estimates the event year using the input log file's last modification timestamp (`st_mtime`).

**Known flaw:** The modification date reflects when the file was last changed, not necessarily when the logged events occurred. Copying, editing, or regenerating a log can change this timestamp. Additionally, logs containing events from multiple years may be assigned an incorrect year.

This can affect chronological sorting, sliding-window detection, and alert timestamps.

**Planned improvement:** Extract the year from log entries when available and provide an explicit year argument for logs that omit it.

## Future Improvements

Potential future development includes:

- IPv6 support
- More robust timestamp parsing
- Additional SSH authentication event formats
- Live log monitoring
- Analysis of sanitized homelab logs
- Comparison with Wazuh SIEM detection rules

## Skills Demonstrated

Python programming, regular expressions, log analysis, event correlation, sliding-window algorithms, command-line interfaces, CSV reporting, debugging, and security documentation.

## Project Documentation

See [PROJECT_REPORT.md](PROJECT_REPORT.md) for the project methodology, testing, security analysis, and lessons learned.

**Project status:** Versions 1 and 2 tested successfully; Version 3 implemented and undergoing final validation.
