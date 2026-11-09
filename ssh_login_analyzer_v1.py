from collections import Counter
import re

LOG_FILE = "sample_auth.log"
THRESHOLD = 3

# Find Source IPs in failed password attempts.
pattern = r"Failed password for .* from (\d+\.\d+\.\d+.\d+)"

failed_ips = []

with open(LOG_FILE, "r", encoding="utf-8") as log:
    for line in log:
            match = re.search(pattern, line)
            
            if match:
                failed_ips.append(match.group(1))
 
# Count how many failures came from each IP.
counts = Counter(failed_ips)

print("=== SSH Failed Login Report ===")
print(f"Total failed attempts: {len(failed_ips)}")
print()

for ip, attempts in counts.most_common():
    print(f"{ip}: {attempts} failed attempts")
    
    if attempts >= THRESHOLD:
        print(" [ALERT] Prossible Brute-Force activity!")
        

