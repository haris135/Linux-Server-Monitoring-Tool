import re
from datetime import datetime
from db import exec_write
from time import time
from detectors import ssh_bruteforce

# ---------------- REGEX PATTERNS ---------------- #
# 1. SSH failed password – matches your exact log format (ISO with microseconds + timezone)
ssh_failed_re = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
    r'(Failed password for invalid user|Failed password for)\s+'
    r'(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)'
)

# 2. SU failed logs (keep if you need it – adjust if your format differs)
su_failed_re = re.compile(
    r'^(?P<ts>\S+)\s+(?P<host>\S+)\s+su\[\d+\]:\s+FAILED SU \(to (?P<user>\S+)\).*'
)

# 3. CRON session logs
cron_re = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+CRON\[\d+\]:\s+pam_unix\(cron:session\):\s+session\s+'
    r'(?P<action>opened|closed)\s+for\s+user\s+(?P<user>\S+)'
)

# ------------------------------------------------ #
# PARSE + INSERT FUNCTION
# ------------------------------------------------ #
def parse_and_insert(line):
    line = line.strip()
    if not line:
        return None

    # ---------------- SSH FAILED PASSWORD ----------------
    m = ssh_failed_re.search(line)
    if m:
        ts_str = m.group("ts")
        try:
            ts = datetime.fromisoformat(ts_str)
        except ValueError:
            ts = datetime.now()  # fallback

        host = m.group("host")
        user = m.group("user")
        src_ip = m.group("src_ip")

        exec_write(
            """INSERT INTO auth_events (ts, host, user, action, src_ip, raw)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (ts, host, user, "failed_password", src_ip, line),
        )
        print(f"[PARSE] SSH Failed password => host={host} user={user} ip={src_ip}")

        # Create minimal event for detector
        event = {
            "ts": time(),       # current unix timestamp (float)
            "src_ip": src_ip
        }

        return event

    # ---------------- SU FAILED ----------------
    m = su_failed_re.search(line)
    if m:
        # Adjust timestamp parsing if your SU logs also use ISO format
        ts_str = m.group("ts")
        try:
            ts = datetime.fromisoformat(ts_str)
        except ValueError:
            ts = datetime.now()

        host = m.group("host")
        user = m.group("user")

        exec_write(
            """INSERT INTO auth_events (ts, host, user, action, src_ip, raw)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (ts, host, user, "failed_su", "local", line),
        )
        print(f"[PARSE] SU FAILED => user={user}")
        return None  # No detector for SU yet

    # ---------------- CRON SESSION ----------------
    m = cron_re.search(line)
    if m:
        ts_str = m.group("ts")
        try:
            ts = datetime.fromisoformat(ts_str)
        except ValueError:
            ts = datetime.now()

        host = m.group("host")
        user = m.group("user")
        action = m.group("action")

        exec_write(
            """INSERT INTO auth_events (ts, host, user, action, src_ip, raw)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (ts, host, user, f"cron_{action}", "local", line),
        )
        print(f"[PARSE] CRON session {action} for user={user}")
        return None  # CRON does not trigger detectors

    # --------------- NO MATCH --------------- #
    return None


# ------------------------------------------------ #
# Send to detectors
# ------------------------------------------------ #
def to_detector_event(event):
    if event and event.get("src_ip"):
        print(f"[DEBUG] Sending to SSH brute-force detector: {event['src_ip']}")
        ssh_bruteforce(event)
