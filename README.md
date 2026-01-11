# Log Analysis & Real-Time Incident Detection System

##  Project Overview

This project is a **SOC (Security Operations Center)–style log analysis and incident detection system** built using **Python and Linux authentication logs**.

It continuously monitors system authentication activity, detects **security incidents in real time**, and generates **SIEM-style JSON alerts** mapped to **MITRE ATT&CK** techniques.

The project simulates how **real SOC analysts and SIEM tools** detect brute-force attacks, privilege escalation attempts, and potential account compromises.

---

## Key Objectives

- Analyze Linux authentication logs (`auth.log`)
- Detect security threats using correlation and thresholds
- Monitor logs in **real time (tail -f style)**
- Generate structured **JSON alerts**
- Simulate real-world SOC detection logic


## SOC Use-Cases Implemented

### 1️⃣ SSH Brute-Force Detection

* Detects multiple failed SSH login attempts from the same IP
* Uses threshold-based correlation

**MITRE ATT&CK:**

* Technique: **T1110 – Brute Force**
* Tactic: Credential Access


### 2️⃣ Successful Login After Failures (Account Compromise)

* Detects a **successful SSH login after repeated failures**
* Indicates possible credential compromise

**MITRE ATT&CK:**

* Technique: **T1110 – Brute Force**


### 3️⃣ Privilege Escalation Attempt Detection

* Detects repeated `sudo` authentication failures
* Indicates misuse or privilege escalation attempts

**MITRE ATT&CK:**

* Technique: **T1548 – Abuse Elevation Control Mechanism**


---

## Tech Stack

- **Operating System:** Ubuntu (WSL 2)
- **Programming Language:** Python 
- **Logs:** `/var/log/auth.log`
- **Techniques:**

  - Regex-based log parsing
  - Threshold-based detection
  - Real-time file monitoring
  - Event correlation

---

## Repository Structure

```
soc-log-analysis-incident-detection/
│
├── README.md
│
├── architecture/
│   └── architecture-diagram.txt
│
├── detectors/
│   ├── detector_batch.py
│   └── realtime_detector.py
│
├── alerts/
│   ├── alerts.json
│   └── sample_alerts.json
│
├── logs/
│   └── sample_auth.log
│
├── screenshots/
│   └── realtime-alerts.png
│
└──  requirements.txt
```

---

##  How Detection Works (Logic)

### 🔹 SSH Brute Force

- Parse `Failed password` entries
- Extract source IP
- Count failures per IP
- Trigger alert if threshold is exceeded

---

### 🔹 Successful Login After Failures

- Track failed attempts per IP
- Detect `Accepted password` event
- Raise **CRITICAL alert** if login succeeds after failures

---

### 🔹 Sudo Authentication Failures

- Parse `sudo authentication failure` logs
- Track failed attempts per user
- Raise alert on repeated failures

---

## Real-Time Monitoring (tail -f Style)

The system uses a **file pointer technique** to monitor logs in real time:

- Opens `auth.log`
- Moves to end of file
- Continuously reads newly appended log entries
- Processes events instantly

This mimics how **SIEM agents stream logs**.


▶️ How to Run the Project

1. Prerequisites

* Ubuntu (WSL 2 or Linux)
* Python 3.8+

2. Clone Repository

```bash
git clone https://github.com/<your-username>/soc-log-analysis-incident-detection.git
cd soc-log-analysis-incident-detection
```

3. Run Batch Detection (Offline Analysis)

```bash
sudo python3 detectors/detector_batch.py
```
Output:
```
alerts/alerts.json
```
- Monitor authentication logs in batch for not real time analysis
- Append alerts to `alerts.json`

4. Run Real-Time Monitoring

```bash
sudo python3 detectors/realtime_detector.py
```
This will:
- Monitor authentication logs live
- Print alerts instantly
- Append alerts to `alerts.json`


* Sample Alert (SIEM-Style JSON)

```json
{
    "timestamp": "2026-01-11T13:22:45+00:00",
    "alert_type": "Account Compromise Suspected",
    "severity": "CRITICAL",
    "source_ip": "127.0.0.1",
    "user": "avdhut",
    "failed_attempts": 6,
    "technique": "T1110",
    "description": "Successful SSH login after multiple failed attempts"
}
```

---

* Security & Ethical Note

- All attack simulations were performed **only on a local test system**
- No real user data or production systems were affected
- Sample logs are sanitized for privacy

## Skills Demonstrated

- SOC operations & detection logic
- Linux log analysis
- Incident correlation
- Python automation
- SIEM-style alerting
- MITRE ATT&CK mapping
- Real-time security monitoring


## Future Enhancements

- Alert deduplication & cooldown
- Geo-IP enrichment
- SOC dashboard visualization
- Email / webhook alerting
- ELK / Splunk integration

## Author
**Avdhut Gogawale**

Cybersecurity Enthusiast 



