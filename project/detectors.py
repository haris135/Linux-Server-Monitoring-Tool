from collections import defaultdict, deque
from time import time
from alert_sink import emit_alert

failed_by_ip = defaultdict(deque)
last_alert_time = {}

def ssh_bruteforce(event):
    window = 120
    threshold = 3
    cooldown = 300

    now = time()
    event_ts = event["ts"]  # UNIX timestamp

    dq = failed_by_ip[event["src_ip"]]
    dq.append(event_ts)

    while dq and now - dq[0] > window:
        dq.popleft()

    print(f"[DETECTOR] IP={event['src_ip']} failures={len(dq)}")

    last = last_alert_time.get(event["src_ip"], 0)

    if len(dq) >= threshold and (now - last) > cooldown:
        emit_alert(
            kind="ssh_bruteforce",
            severity="high",
            entity=event["src_ip"],
            details=f"{len(dq)} failures in {window}s",
        )
        last_alert_time[event["src_ip"]] = now
        return True

    return False
from alert_sink import emit_alert
import time

last_sys_alert_time = {"cpu": 0, "ram": 0}

def cpu_threshold(event, threshold=50, cooldown=300):
    now = time.time()
    if event["cpu_load"] > threshold and (now - last_sys_alert_time["cpu"]) > cooldown:
        emit_alert(
            kind="cpu_high",
            severity="critical",
            entity=event["host"],
            details=f"CPU load {event['cpu_load']}% exceeded threshold {threshold}%"
        )
        last_sys_alert_time["cpu"] = now

def ram_threshold(event, threshold=80, cooldown=300):
    now = time.time()
    ram_usage = (event["ram_used"] / event["ram_total"]) * 100
    if ram_usage > threshold and (now - last_sys_alert_time["ram"]) > cooldown:
        emit_alert(
            kind="ram_high",
            severity="critical",
            entity=event["host"],
            details=f"RAM usage {ram_usage:.1f}% exceeded threshold {threshold}%"
        )
        last_sys_alert_time["ram"] = now

