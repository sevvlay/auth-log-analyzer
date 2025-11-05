import re
from collections import defaultdict
import datetime

# --- Configuration ---
LOG_FILE = "auth.log"  # The log file to analyze
TIME_WINDOW_MINUTES = 5  # The time window (in minutes) for detection
ATTEMPT_THRESHOLD = 10  # Min failed attempts in the window to trigger an alert

# --- Initialization ---
failed_attempts = defaultdict(list)
print(f"[INFO] Analyzing '{LOG_FILE}'...")

# --- Part 1: Read and Parse the Log File ---
try:
    with open(LOG_FILE, 'r') as f:
        for line in f:
            # Filter for relevant lines only
            if "Failed password" in line:

                # --- FIXED REGEX ---
                # Now handles variable spaces (e.g., 'Mar  6' vs 'Mar 6')
                # We use \s+ to match "one or more spaces"
                match = re.search(
                    r'^(...\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Failed password.* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                    line
                )

                if match:
                    # Extract matched groups
                    timestamp_str = match.group(1)
                    ip_address = match.group(2)

                    # Convert log time string to a datetime object
                    current_year = datetime.datetime.now().year
                    log_time = datetime.datetime.strptime(
                        f"{timestamp_str} {current_year}",
                        '%b %d %H:%M:%S %Y'
                    )

                    # Add the timestamp to the IP's list
                    failed_attempts[ip_address].append(log_time)

except FileNotFoundError:
    print(f"[ERROR] '{LOG_FILE}' not found. Ensure it's in the same directory.")
    exit()
except Exception as e:
    print(f"[ERROR] An error occurred while reading the file: {e}")
    exit()

# --- Part 2: Apply Detection Rule ---
print(f"[INFO] Log file processed. {len(failed_attempts)} unique IPs found with failed attempts.")
print(f"[INFO] Scanning for alerts (Threshold: {ATTEMPT_THRESHOLD} attempts in {TIME_WINDOW_MINUTES} mins)...")
print("-" * 30)

detected_attacks = 0

for ip, timestamps in failed_attempts.items():
    timestamps.sort()

    for i in range(len(timestamps) - ATTEMPT_THRESHOLD + 1):
        start_time = timestamps[i]
        end_time_of_window = timestamps[i + ATTEMPT_THRESHOLD - 1]
        time_diff = (end_time_of_window - start_time).total_seconds() / 60

        # --- DETECTION RULE ---
        if time_diff <= TIME_WINDOW_MINUTES:
            print(f"\n[!!!] ALERT: BRUTE-FORCE DETECTED!")
            print(f"  > IP Address: {ip}")
            print(f"  > Attempts:   At least {ATTEMPT_THRESHOLD} attempts")
            print(f"  > Time Span:  {time_diff:.2f} minutes")
            print(f"  > Start Time: {start_time}")
            print(f"  > End Time:   {end_time_of_window}")

            detected_attacks += 1
            break

        # --- Part 3: Final Report ---
print("-" * 30)
if detected_attacks == 0:
    print("[INFO] No brute-force attacks matching the rule were found.")
else:
    print(f"[INFO] Total alerts generated: {detected_attacks}")