# CyberVision

CyberVision is a lightweight, modular **SIEM (Security Information and Event Management) and System Monitoring** platform. [cite_start]It parses host authentication logs in real-time [cite: 1][cite_start], collects granular hardware performance metrics [cite: 1][cite_start], runs stateful threat-detection heuristics and Machine Learning anomaly detection [cite: 1][cite_start], and exposes an interactive Flask API dashboard to track network incidents and server health.

---

## ✨ Features

* [cite_start]**Real-Time Log Parsing (`parser.py`):** Uses precise regular expressions to ingest system logs, instantly decoding SSH failed login attempts, `su` switch failures, and CRON session events.
* **Stateful Threat Heuristics (`detectors.py`):**
  * [cite_start]**SSH Brute-Force Detector:** Uses a sliding time window queue to identify rapid authentication failures from unique source IPs, featuring a built-in alert cooldown to prevent notification fatigue.
  * [cite_start]**System Metric Thresholds:** Evaluates streaming system metrics and triggers automated, high-priority alerts if CPU or RAM usage crosses configurable thresholds.
* [cite_start]**ML-Powered Anomaly Detection (`anomaly.py`):** Integrates Scikit-Learn’s **Isolation Forest** unsupervised algorithm to isolate outliers and catch anomalous behaviors based on event counts and port footprints.
* [cite_start]**Resource Monitoring Agent (`metrics_agent.py`):** A lightweight background daemon utilizing `psutil` to continuously capture host CPU overhead and memory footprint metrics.
* **Unified Alert Management (`alert_sink.py`):** Centralizes incident tracking by categorizing anomalies by kind, severity level (`high`, `critical`), and affected entity, saving incidents persistently to the database.
* **Web API Dashboard (`app.py`):** Powered by Flask, compiling structural charts of recent authentication traffic, database-driven overview metrics (past 10 minutes), alerts, and multi-vector cross-correlation by single IP addresses.

---

## 🛠️ Tech Stack & Dependencies

The project relies on the following core Python libraries:
* [cite_start]**Flask:** Drives the web-app routing and lightweight JSON APIs.
* [cite_start]**PyMySQL:** Facilitates persistent relational storage connections.
* **Scikit-Learn & NumPy:** Powers the Isolation Forest anomaly classification engine.
* [cite_start]**Psutil:** Gathers runtime host metrics (Memory/CPU).
* [cite_start]**Scapy:** Built-in capability for handling packet sniffing and low-level network protocol dissection.
* **Python-Dotenv:** Manages system environment decoupling securely.

---

## 📂 Repository Structure

```text
├── app.py            # Flask Web Application & Dashboard API endpoints 
├── parser.py         # Log parser checking SSH, SU, and CRON pattern matches 
├── metrics_agent.py  # Performance daemon logging CPU & RAM metrics 
├── detectors.py      # Heuristics engine evaluating brute-force & resource flags 
├── anomaly.py        # Unsupervised Isolation Forest ML anomaly model 
├── alert_sink.py     # Global alerting conduit handling DB persistence 
├── db.py             # PyMySQL execution wrappers for reading/writing events 
├── config.py         # Environmental configurations loader 
├── requirements.txt  # Python package dependencies manifest 
└── templates/
    └── index.html    # CyberVision Web UI landing page
