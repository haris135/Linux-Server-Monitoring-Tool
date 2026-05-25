from flask import Flask, render_template, jsonify
from db import exec_read

app = Flask(__name__)

UI_REFRESH_SEC = 5
@app.route("/api/recent_metrics")
def recent_metrics():
    return jsonify(exec_read(
        "SELECT ts, host, cpu_load, ram_used, ram_total FROM sys_metrics ORDER BY ts DESC LIMIT 10"
    ))

@app.route("/")
def index():
    return render_template(
        "index.html",
        refresh=UI_REFRESH_SEC,
        logo_url="static/logo.jpeg",  # path to your logo
        app_name="CyberVision"
    )




@app.route("/api/overview")
def overview():
    auth_failures = exec_read(
        """
        SELECT COUNT(*) AS c
        FROM auth_events
        WHERE action='failed_password'
          AND ts >= NOW() - INTERVAL 10 MINUTE
        """
    )[0]["c"]

    net_events = exec_read(
        """
        SELECT COUNT(*) AS c
        FROM net_events
        WHERE ts >= NOW() - INTERVAL 10 MINUTE
        """
    )[0]["c"]

    alerts = exec_read(
        """
        SELECT COUNT(*) AS c
        FROM alerts
        WHERE ts >= NOW() - INTERVAL 10 MINUTE
        """
    )[0]["c"]

    top_src = exec_read(
        """
        SELECT src_ip, COUNT(*) AS count
        FROM auth_events
        WHERE action='failed_password'
          AND ts >= NOW() - INTERVAL 10 MINUTE
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 5
        """
    )

    metrics = exec_read(
        "SELECT cpu_load, ram_used, ram_total FROM sys_metrics ORDER BY ts DESC LIMIT 1"
    )
    if metrics:
        cpu_load = metrics[0]["cpu_load"]
        ram_usage = (metrics[0]["ram_used"] / metrics[0]["ram_total"]) * 100
    else:
        cpu_load = 0
        ram_usage = 0

    return jsonify({
        "auth_failures": auth_failures,
        "net_events": net_events,
        "alerts": alerts,
        "top_src": top_src,
        "cpu_load": cpu_load,
        "ram_usage": ram_usage
    })

@app.route("/api/recent_net")
def recent_net():
    return jsonify(exec_read(
        "SELECT ts, src_ip, dst_ip, src_port, dst_port, proto FROM net_events ORDER BY ts DESC LIMIT 10"
    ))
@app.route("/api/events_by_ip")
def events_by_ip():
    from flask import request
    ip = request.args.get("ip")
    if not ip:
        return jsonify([])

    # Network events
    net_rows = exec_read(
        "SELECT ts, src_ip, dst_ip, src_port, dst_port, proto FROM net_events "
        "WHERE src_ip=%s OR dst_ip=%s ORDER BY ts DESC LIMIT 50",
        (ip, ip)
    )
    net_events = [
        {
            "ts": r["ts"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(r["ts"], "strftime") else r["ts"],
            "type": "net",
            "user": None,
            "details": f"{r['src_ip']}:{r['src_port']} -> {r['dst_ip']}:{r['dst_port']} ({r['proto']})"
        } for r in net_rows
    ]

    # Auth events
    auth_rows = exec_read(
        "SELECT ts, host, user, action, src_ip FROM auth_events WHERE src_ip=%s ORDER BY ts DESC LIMIT 50",
        (ip,)
    )
    auth_events = [
        {
            "ts": r["ts"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(r["ts"], "strftime") else r["ts"],
            "type": "auth",
            "user": r["user"],
            "details": f"{r['action']} on {r['host']}"
        } for r in auth_rows
    ]

    # Combine and sort by timestamp descending
    all_events = net_events + auth_events
    all_events.sort(key=lambda x: x["ts"], reverse=True)

    return jsonify(all_events)

@app.route("/api/recent_auth")
def recent_auth():
    return jsonify(exec_read(
        "SELECT ts, host, user, action, src_ip FROM auth_events ORDER BY ts DESC LIMIT 10"
    ))

@app.route("/api/recent_alerts")
def recent_alerts():
    return jsonify(exec_read(
        "SELECT ts, kind, severity, entity, details FROM alerts ORDER BY ts DESC LIMIT 10"
    ))

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

