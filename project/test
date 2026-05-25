from db import exec_write
def emit_alert(kind, severity, entity, details):
    print(f"[ALERT] [{severity}] {kind} on {entity}: {details}")
    exec_write(
        "INSERT INTO alerts (ts, kind, severity, entity, details) "
        "VALUES (NOW(), %s, %s, %s, %s)",
        (kind, severity, entity, details)
    )
    print("[ALERT_DB] Inserted into alerts table")







 
