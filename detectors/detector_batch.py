import re
import json
from datetime import datetime, timezone

LOG_FILE = "/var/log/auth.log"

SUDO_THRESHOLD = 3
SSH_FAIL_THRESHOLD = 5

failed_sudo = {}
failed_ssh = {}
successful_ssh = {}

alerts = []

# ------------------ LOG PARSING ------------------
with open(LOG_FILE, "r") as f:
    for line in f:

        # ---- SUDO AUTH FAILURES ----
        if "sudo" in line and "authentication failure" in line:
            user_match = re.search(r"user\s+(\w+)", line)
            user = user_match.group(1) if user_match else "unknown"
            failed_sudo[user] = failed_sudo.get(user, 0) + 1

        # ---- SSH FAILED PASSWORD ----
        if "Failed password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                failed_ssh[ip] = failed_ssh.get(ip, 0) + 1

        # ---- SSH SUCCESSFUL LOGIN ----
        if "Accepted password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            user_match = re.search(r"for (\w+)", line)
            if ip_match and user_match:
                ip = ip_match.group(1)
                user = user_match.group(1)
                successful_ssh[ip] = user


# ------------------ ALERT GENERATION ------------------

# SUDO FAILURE ALERTS
for user, count in failed_sudo.items():
    if count >= SUDO_THRESHOLD:
        alerts.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": "Privilege Escalation Attempt",
            "severity": "MEDIUM",
            "user": user,
            "count": count,
            "technique": "T1548",
            "description": "Multiple sudo authentication failures detected"
        })


# SSH BRUTE FORCE ALERTS
for ip, count in failed_ssh.items():
    if count >= SSH_FAIL_THRESHOLD:
        alerts.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": "SSH Brute Force",
            "severity": "HIGH",
            "source_ip": ip,
            "count": count,
            "technique": "T1110",
            "description": "Multiple failed SSH login attempts detected"
        })


# SUCCESS AFTER FAILURES ALERT
for ip, user in successful_ssh.items():
    if ip in failed_ssh and failed_ssh[ip] >= SSH_FAIL_THRESHOLD:
        alerts.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": "Account Compromise Suspected",
            "severity": "CRITICAL",
            "source_ip": ip,
            "user": user,
            "failed_attempts": failed_ssh[ip],
            "technique": "T1110",
            "description": "Successful SSH login after multiple failed attempts"
        })


# ------------------ WRITE JSON ALERTS ------------------
with open("alerts.json", "w") as outfile:
    json.dump(alerts, outfile, indent=4)

