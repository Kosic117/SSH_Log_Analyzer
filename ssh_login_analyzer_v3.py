from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
import argparse
import csv
import re

# Call log entry and arguments
parser = argparse.ArgumentParser(
    description="Analyze SSH authentication logs for brute-force activity."
)

parser.add_argument(
    "log_file",
    nargs="?",
    default="sample_auth.log",
    help="Path to the SSH authentication log file."
)
parser.add_argument(
    "--threshold",
    type=int,
    default=3,
    help="Number of failed logins required to trigger an alert (default: 3)"
)
parser.add_argument(
    "--time_window",
    type=int,
    default=5,
    help="Detection time window in minutes (default:5)"
)
# Check Argugments
args = parser.parse_args()
if args.threshold < 1:
    parser.error("--threshold must be at least 1")
if args.time_window < 1:
    parser.error("--time_window must be at least 1")

# Variables
LOG_FILE = args.log_file
REPORT_FILE = "ssh_report.csv"
try:
    log_path = Path(LOG_FILE)
    LOG_YEAR = datetime.fromtimestamp(
        log_path.stat().st_mtime
    ).year
except (FileNotFoundError, PermissionError, OSError) as error:
    parser.error(f"Cannot access log file: {error}")
THRESHOLD = args.threshold
WINDOW_MINUTES = args.time_window

# Match timestamp, username, and source IP for failed SSH logins.
pattern = (
    r"^(\w+\s+\d+\s+\d+:\d+:\d+).*"
    r"Failed password for (?:invalid user )?" 
    r"(\S+) from "
    r"(\d+\.\d+\.\d+\.\d+)"
)

# Store failed login timestamps by source IP.
failed_logins = defaultdict(list)

try:
    with open(LOG_FILE, "r", encoding="utf-8") as log:
        for line in log:
                match = re.search(pattern, line)
                
                if match:
                    timestamp_text = match.group(1)
                    username = match.group(2)
                    ip_address = match.group(3)
                    
                    # Syslog timestamps omit year
                    try:
                        timestamp = datetime.strptime(
                            f"{LOG_YEAR} {timestamp_text}", 
                            "%Y %b %d %H:%M:%S"
                        )
                    except ValueError:
                        print(f"[WARNING] Skipping invalid timestamp: {timestamp_text}")
                        continue
                    failed_logins[ip_address].append(
                    (timestamp, username)
                    )

except FileNotFoundError:
    print(f"[ERROR] Log file not found: {LOG_FILE}")
    raise SystemExit(1)

except PermissionError:
    print(f"[Error] Permission denied: {LOG_FILE}")
    raise SystemExit(1)
                
print("=== SSH Failed Login Analyzer V3 ===")
print(f"Threshold: {THRESHOLD} attempts")
print(f"Time window: {WINDOW_MINUTES} minutes")
print()

window = timedelta(minutes=WINDOW_MINUTES)
report_rows = []

for ip, events in failed_logins.items():
    events.sort()
    recent_attempts = deque()
    alert_time = None
    
    usernames = set()
    
    for timestamp, username in events:
        usernames.add(username)
        recent_attempts.append(timestamp)
        
        # Remove attempts outside the time window.
        while (
            recent_attempts
            and timestamp - recent_attempts[0] > window
        ):
            recent_attempts.popleft()
        
        if (
            len(recent_attempts) >= THRESHOLD 
            and alert_time is None
        ):
            alert_time = timestamp
            
    total_failures = len(events)
    alert_status = "ALERT" if alert_time else "NORMAL"
    
    print(f"IP Address: {ip}")
    print(f"Total failures: {total_failures}")
    print(f"Targeted usernames: {', '.join(sorted(usernames))}")
    print(f"Status: {alert_status}")
    print()
    
    report_rows.append({
        "ip_address": ip,
        "total_failures": total_failures, 
        "usernames": ", ".join(sorted(usernames)),
        "status": alert_status,
        "alert_time": alert_time.isoformat()
        if alert_time else ""
        })
    
try:
    with open(
        REPORT_FILE, "w", newline="", encoding="utf-8"
    ) as report:
        writer = csv.DictWriter(
            report,
            fieldnames=[
                "ip_address",
                "total_failures",
                "usernames",
                "status",
                "alert_time"
            ]
        )
        
        writer.writeheader()
        writer.writerows(report_rows)
    
    print(f"Report saved to: {REPORT_FILE}")
    
except (OSError, csv.Error) as error:
    print(f"[ERROR] Could not save report: {error}")
    raise SystemExit(1)
   