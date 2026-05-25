# metrics_agent.py
import psutil, socket, time
from db import exec_write

host = socket.gethostname()

from detectors import cpu_threshold, ram_threshold

while True:
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    event = {
        "host": host,
        "cpu_load": cpu,
        "ram_used": mem.used,
        "ram_total": mem.total
    }

    exec_write(
        "INSERT INTO sys_metrics (ts, host, cpu_load, ram_used, ram_total) VALUES (NOW(), %s, %s, %s, %s)",
        (host, cpu, mem.used, mem.total)
    )

    cpu_threshold(event, threshold=40)
    ram_threshold(event, threshold=80)

    time.sleep(5)

