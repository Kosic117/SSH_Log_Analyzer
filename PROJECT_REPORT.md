SSH Failed Login Analyzer
Cybersecurity Project Report
Project: Python Cybersecurity Project 01
Category: Blue Team / Security Monitoring
Language: Python 3
Environment: Windows workstation / Simulated Linux authentication logs
Status: Versions 1 and 2 successfully tested
________________________________________
1. Executive Summary
The SSH Failed Login Analyzer is a Python-based cybersecurity utility designed to identify suspicious authentication activity within Linux SSH logs.
The project was developed to gain practical experience in Python scripting, security event analysis, and basic detection engineering.
Version 1 identifies failed SSH password authentication attempts, extracts source IP addresses, and counts failures associated with each source.
Version 2 introduces timestamp analysis and a sliding detection window, allowing the script to distinguish between concentrated authentication failures and attempts occurring over longer periods.
Both implementations have been successfully tested using simulated SSH authentication logs.
2. Project Objectives
1.	Develop foundational Python scripting skills.
2.	Understand Linux SSH authentication logs.
3.	Identify failed authentication events using regular expressions.
4.	Extract and aggregate source IP addresses.
5.	Implement configurable alert thresholds.
6.	Introduce time-based event correlation.
7.	Evaluate limitations of basic detection techniques.
8.	Document implementation and testing results.
3. Technical Background
Secure Shell (SSH) is a network protocol used for secure remote administration.
Authentication failures may occur when users enter incorrect credentials or when an attacker attempts unauthorized access through repeated password guessing.
Linux systems may record SSH authentication events in /var/log/auth.log, /var/log/secure, or the systemd journal, depending on the distribution and configuration.
These events provide useful information for identifying suspicious authentication patterns.
Repeated failures alone do not establish malicious intent. Effective security analysis requires evaluating event frequency, timing, and context.
4. Lab Environment
Development platform
•	Windows workstation
•	Python 3
•	Windows PowerShell
•	Simulated Linux SSH authentication logs
Python libraries
•	re
•	collections.Counter
•	collections.defaultdict
•	collections.deque
•	datetime
•	timedelta
No third-party packages were required.
The sample data uses reserved documentation IP addresses.
5. Implementation Methodology
Phase 1 — Log Preparation
Synthetic SSH authentication records were created containing failed password attempts and successful public-key authentication events.
Phase 2 — Version 1: Basic Detection
Version 1 reads the authentication log line by line.
Regular expressions identify failed-password events and extract source IPv4 addresses.
Python's Counter class aggregates failures by source IP.
An alert is generated when the configured threshold is reached.
The initial threshold was set to three failed authentication attempts.
Phase 3 — Version 2: Time-Based Detection
Version 2 extends the original script by extracting authentication timestamps.
Events are grouped by source IP address and sorted chronologically.
A deque maintains a sliding time window, removing events that fall outside the configured period.
An alert is generated when the number of failures within the window meets or exceeds the threshold.
Detection configuration
•	Threshold: Three failed attempts
•	Time window: Five minutes
•	Grouping: Source IPv4 address
•	Detection method: Sliding-window event correlation
This approach improves detection accuracy compared with cumulative counting alone.
6. Testing and Validation
Test 1 — Version 1 Baseline
Objective: Confirm the script correctly counts failed SSH authentication attempts.
Expected results:
•	Five failed authentication attempts.
•	Four failures from 192.0.2.10.
•	One failure from 198.51.100.25.
•	Alert generated for 192.0.2.10.
Observed results: The script executed successfully and produced the expected counts and alert.
Result: PASS
Test 2 — Version 2 Time-Based Detection
Objective: Confirm that the script identifies repeated authentication failures within a five-minute window.
Test scenario:
•	Source 192.0.2.10 generated four failures within approximately three minutes.
•	Source 198.51.100.25 generated four failures spread across approximately 30 minutes.
Observed results:
•	The first source triggered an alert after its third failed authentication attempt.
•	The second source did not trigger an alert because its failures did not meet the configured threshold within five minutes.
Result: PASS
Test 3 — Detection Threshold Adjustment
Objective: Verify that increasing the threshold prevents alerts when the number of failures is below the configured value.
Expected result: Increasing the threshold to five should suppress alerts for the sample dataset.
Status: Additional validation recommended.
7. Security Analysis
Detection Capabilities
Version 1 demonstrates basic log parsing and authentication failure aggregation.
Version 2 adds time-based correlation, allowing the script to distinguish between concentrated authentication failures and attempts spread over longer periods.
This reduces false positives associated with simple cumulative counting.
Known Limitations
1.	Only matching SSH failed-password events are processed.
2.	IPv6 addresses are not supported.
3.	Version 2 assumes the log timestamps belong to 2026.
4.	The scripts analyze existing files rather than monitoring logs in real time.
5.	Alerts are displayed locally without automated notification or response.
6.	The scripts do not evaluate user behavior or supporting threat intelligence.
7.	Log rotation and multiple input files are not supported.
8.	Version 2 reports only the first detected threshold crossing for each IP.
8. Future Development
Version 3 — Enhanced Reporting
•	CSV output.
•	Username extraction.
•	IPv6 support.
•	Improved exception handling.
•	Command-line configuration options.
•	Enhanced alert reporting.
Version 4 — Homelab Integration
Future development will focus on analyzing sanitized authentication logs from a Linux homelab server.
Results may be compared against Wazuh SIEM alerts to evaluate the effectiveness of custom Python detection logic.
9. Skills Developed
•	Python scripting and debugging.
•	File handling and iteration.
•	Regular expressions.
•	Dictionaries and data aggregation.
•	Timestamp parsing.
•	Sliding-window algorithms.
•	Security event analysis.
•	Threshold-based detection.
•	Technical documentation.
10. Lessons Learned
The initial implementation demonstrated that security-relevant information can be extracted from authentication logs using relatively simple Python code.
Version 1 also highlighted the limitations of cumulative event counting.
Version 2 introduced time-based correlation, providing a more meaningful way to identify potentially suspicious authentication activity.
Developing both versions reinforced the importance of testing, debugging, and understanding the logic behind security monitoring tools.
11. Conclusion
The SSH Failed Login Analyzer demonstrates the successful development and testing of two Python-based security monitoring scripts.
Version 1 provides basic authentication failure counting and threshold alerts.
Version 2 improves the detection logic by identifying repeated failures within a configurable time window.
The project provides a foundation for future enhancements, including more detailed reporting, additional log formats, and SIEM integration.
Final status: Versions 1 and 2 successfully tested.

