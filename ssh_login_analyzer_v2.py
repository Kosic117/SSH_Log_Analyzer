from collections import defaultdict, deque
from datetime import datetime, timedelta
import re

LOG_FILE = "sample_auth.log"
THRESHOLD = 3
WINDOW_MINUTES = 5

# Match timestamp and source IP for failed SSH logins.
pattern = (
    r"^(\w+\s+\d+\s+\d+:\d+:\d+).*"
    r"Failed password for .* from "
    r"(\d+\.\d+\.\d+\.\d+)"
)

# Store failed login timestamps by source IP.
failed_logins = defaultdict(list)

with open(LOG_FILE, "r", encoding="utf-8") as log:
    for line in log:
            match = re.search(pattern, line)
            
            if match:
                timestamp_text = match.group(1)
                ip_address = match.group(2)
                
                # Syslog timestamps omit year
                timestamp = datetime.strptime(
                    timestamp_text, "%b %d %H:%M:%S"
                ).replace(year=2026)
                
                failed_logins[ip_address].append(timestamp)
                
                
print("=== SSH Failed Login Analyzer V2 ===")
print(f"Threshold: {THRESHOLD} attempts")
print(f"Time window: {WINDOW_MINUTES} minutes")
print()

window = timedelta(minutes=WINDOW_MINUTES)
for ip, timestamps in failed_logins.items():
    timestamps.sort()
    recent_attempts = deque()
    alert_time = None
    
    for timestamp in timestamps:
        recent_attempts.append(timestamp)
        
        # Remove attempts outside the time window.
        while (
            recent_attempts
            and timestamp - recent_attempts[0] > window
        ):
            recent_attempts.popleft()
        
        if len(recent_attempts) >= THRESHOLD:
            alert_time = timestamp
            break
    print(f"{ip}: {len(timestamps)} total failures")
    
    if alert_time:
        print(
            f"    [ALERT] {THRESHOLD}+ failures within "
            f"{WINDOW_MINUTES} minutes!"
        )
        print(f"   Detected at: {alert_time}")
    else:
        print("   No suspicious burst detected.")
