import re
import json
import time
from datetime import datetime, timezone

LOG_FILE = "/var/log/auth.log"

SUDO_THRESHOLD = 3
SSH_FAIL_THRESHOLD = 5

failed_sudo = {}
failed_ssh = {}
successful_ssh = {}

print("[*] Starting real-time log monitoring...")
print("[*] Watching /var/log/auth.log\n")

with open(LOG_FILE, "r") as logfile:
    logfile.seek(0, 2)  # Move to end of fil

    while True:
        line = logfile.readline()

        if not line:
            time.sleep(0.5)
            continue

        if "sudo" in line and "authentication failure" in line:
            user_match = re.search(r"user\s+(\w+)", line)
            user = user_match.group(1) if user_match else "unknown"
            failed_sudo[user] = failed_sudo.get(user, 0) + 1

            if failed_sudo[user] >= SUDO_THRESHOLD:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "alert_type": "Privilege Escalation Attempt",
                    "severity": "MEDIUM",
                    "user": user,
                    "count": failed_sudo[user],
                    "technique": "T1548",
                    "description": "Multiple sudo authentication failures detected"
                }

                print("[ALERT]", alert)

                with open("alerts.json", "a") as f:
                    f.write(json.dumps(alert) + "\n")

        if "Failed password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                failed_ssh[ip] = failed_ssh.get(ip, 0) + 1

                if failed_ssh[ip] >= SSH_FAIL_THRESHOLD:
                    alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "alert_type": "SSH Brute Force",
                        "severity": "HIGH",
                        "source_ip": ip,
                        "count": failed_ssh[ip],
                        "technique": "T1110",
                        "description": "Multiple failed SSH login attempts detected"
                    }

                    print("[ALERT]", alert)

                    with open("alerts.json", "a") as f:
                        f.write(json.dumps(alert) + "\n")

        if "Accepted password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            user_match = re.search(r"for (\w+)", line)

            if ip_match and user_match:
                ip = ip_match.group(1)
                user = user_match.group(1)

                if ip in failed_ssh and failed_ssh[ip] >= SSH_FAIL_THRESHOLD:
                    alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "alert_type": "Account Compromise Suspected",
                        "severity": "CRITICAL",
                        "source_ip": ip,
                        "user": user,
                        "failed_attempts": failed_ssh[ip],
                        "technique": "T1110",
                        "description": "Successful SSH login after multiple failed attempts"
                    }

                    print("[CRITICAL]", alert)

                    with open("alerts.json", "a") as f:
                        f.write(json.dumps(alert) + "\n")
