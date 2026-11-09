# SSH Failed Login Analyzer

## Cybersecurity Project Report

**Project:** Python Cybersecurity Project 01  
**Category:** Blue Team / Security Monitoring  
**Language:** Python 3  
**Environment:** Windows PowerShell / Simulated Linux SSH authentication logs  
**Status:** Versions 1–2 tested; Version 3 implemented with initial successful tests

---

## 1. Executive Summary

The SSH Failed Login Analyzer is a Python-based cybersecurity project developed to identify patterns of potentially suspicious SSH authentication failures.

The project evolved through three versions, beginning with basic failed login counting and progressing to time-based correlation, username tracking, configurable detection parameters, and CSV reporting.

Testing was conducted using simulated SSH authentication logs.

## 2. Project Objectives

The primary objectives were to:

1. Develop practical Python programming skills.
2. Understand Linux SSH authentication log formats.
3. Extract security-relevant information using regular expressions.
4. Identify repeated authentication failures by source IP.
5. Implement time-based brute-force detection.
6. Track usernames targeted by failed login attempts.
7. Develop a configurable command-line interface.
8. Generate structured CSV reports.
9. Document testing, limitations, and potential improvements.

## 3. Technical Background

SSH provides encrypted remote access to systems.

Repeated authentication failures may indicate incorrect credentials, misconfigured automation, password spraying, or brute-force activity.

Security monitoring tools can identify suspicious patterns by examining authentication events and applying detection rules.

This project focuses on repeated failures originating from individual IPv4 addresses.

## 4. Lab Environment

**Development environment:**
- Windows workstation
- Python 3
- PowerShell
- Notepad++
- Simulated Linux SSH authentication logs

**Python modules:**
- `re`
- `collections`
- `datetime`
- `argparse`
- `csv`
- `pathlib`

The project requires no external Python packages.

Synthetic logs and documentation-range IP addresses were used for testing.

## 5. Implementation Methodology

### Version 1 — Basic Failed Login Detection

Version 1 used regular expressions to extract source IPv4 addresses from failed SSH authentication entries.

The `Counter` collection counted failures per IP, and a configurable threshold determined when an alert should be displayed.

### Version 2 — Time-Based Detection

Version 2 introduced timestamp extraction and chronological sorting.

A `deque` maintained failed attempts within a five-minute sliding window.

An alert was generated when three or more failures occurred within that window.

This reduced reliance on cumulative failure counts.

### Version 3 — Configurable Analysis and Reporting

Version 3 expanded the analyzer with:

- Username extraction
- Unique username tracking using sets
- Command-line file selection through `argparse`
- Configurable detection thresholds
- Configurable detection time windows
- CSV report generation
- File access error handling
- Invalid timestamp handling
- Event-year estimation using file modification metadata

Example command:

```powershell
py ssh_login_analyzer_v3.py sample_auth.log --threshold 5 --time_window 10
```

This analyzes the selected file using a threshold of five failures within ten minutes.

## 6. Testing and Validation

### Test 1 — Version 1 Baseline

**Input:** Five simulated failed SSH login attempts across two IP addresses.

**Observed result:** Four failures from one IP triggered an alert; one failure from the other IP did not.

**Result:** PASS

### Test 2 — Version 2 Sliding Window

**Input:** Four failures from each of two IP addresses, with different timing patterns.

**Observed result:** The concentrated burst triggered an alert; the distributed attempts did not.

**Result:** PASS

### Test 3 — Version 3 Username Tracking

**Input:** Synthetic SSH entries targeting multiple usernames.

**Observed result:** Unique targeted usernames were displayed for each source IP.

**Result:** PASS

### Test 4 — Version 3 Command-Line File Selection

**Input:** Execution with the default filename and with an explicitly supplied filename.

**Observed result:** Both execution methods processed the test log successfully.

**Result:** PASS

### Test 5 — Version 3 Custom Detection Settings

**Configuration:** Threshold of 10 attempts within 15 minutes.

**Input:** Four failed attempts from each of two source IP addresses.

**Observed result:** Both IP addresses were classified as NORMAL, and the program reported successful CSV generation.

**Result:** PASS

### Additional Validation

Further recommended validation includes malformed timestamps, missing files, invalid command-line parameters, and inspection of exported CSV contents.

These tests should not be reported as passed until their results are verified.

## 7. Security Analysis

The analyzer demonstrates how security monitoring can use event correlation to distinguish repeated authentication failures from concentrated bursts.

Version 3 provides additional investigative context by identifying targeted usernames and exporting structured findings.

However, detection thresholds are heuristic. An alert does not independently establish malicious activity.

The analyzer does not perform automated response or live monitoring.

## 8. Known Limitations

### Timestamp Accuracy

### Timestamp Year Estimation — Known Design Limitation

Version 3 uses Python's `pathlib.Path.stat().st_mtime` to obtain the input file's last modification time and estimate the year of SSH authentication events.

This was implemented to avoid hardcoding a specific year into the analyzer.

However, file modification timestamps do not reliably represent the dates of individual log entries. Files may be copied, edited, restored from backups, or contain historical events spanning multiple years.

As a result, this approach may assign incorrect years to authentication events, potentially affecting event correlation and detection accuracy.

**Risk:** Incorrect timestamp interpretation can lead to inaccurate alert timestamps or false-positive and false-negative detection results, particularly when events span a year boundary.

**Future remediation:** Support timestamps containing explicit years, allow manual year selection, and implement appropriate handling of year transitions in historical logs.

**Current status:** Known limitation accepted for Version 3's controlled, synthetic test environment. Not suitable for production timestamp correlation without further improvements.

### Log Format Support

The current regular expression supports a limited set of SSH failed-password entries and IPv4 addresses.

Other authentication event formats may be ignored.

### Detection Coverage

The analyzer records the first threshold crossing per IP rather than generating separate alerts for every burst.

It does not correlate activity across multiple source IPs.

### Report Management

CSV reports are written to a fixed filename and overwritten on subsequent executions.

## 9. Future Development

Potential future improvements include:

- IPv6 support
- More accurate timestamp handling
- Additional authentication log formats
- Real-time monitoring
- Expanded alert reporting
- Sanitized homelab log analysis
- Integration or comparison with Wazuh SIEM

## 10. Skills Developed and Lessons Learned

This project provided hands-on experience with Python, regular expressions, file processing, collections, timestamp parsing, event correlation, command-line arguments, CSV exports, and exception handling.

An important lesson was the difference between cumulative event counts and time-based detection.

Additional lessons included the importance of validating command-line inputs, handling unexpected log data, and documenting assumptions that can affect detection accuracy.

## 11. Conclusion

The SSH Failed Login Analyzer progressed from a basic Python log parser into a configurable security monitoring utility.

Versions 1 and 2 were tested successfully, while Version 3 added username tracking, configurable detection settings, CSV reporting, and improved error handling.

The project provides a foundation for more advanced log analysis and future SIEM-related development.

**Final status:** Version 3 implemented with initial successful testing; remaining edge-case validation documented.
