from sniffer import start_sniffer
import threading
from ml_model import detect_anomaly
from ai_security import analyze_network
from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO
from scanner import scan_network, scan_ports
from monitor import get_network_usage
from alerts import check_suspicious
from graph import draw_network 
import time
import threading
import time
ENABLE_SNIFFER = False

def send_traffic(socketio):
    global packet_rate

    while True:
        socketio.emit("traffic", {
            "rate": packet_rate
        })

        packet_rate = 0  # إعادة التصفير
        time.sleep(2)

app = Flask(__name__)
app.secret_key = "secret123"

socketio = SocketIO(app)

# بيانات
devices = []
ports_data = {}
alerts_list = []
usage_data = {}
chart_data = {}

# 🔐 Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "1234":
            session["logged_in"] = True
            return redirect(url_for("home"))
    return render_template("login.html")

# 🏠 Home
@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/sniff")
def sniff_packets():
    thread = threading.Thread(target=start_sniffer)
    thread.start()
    return "Sniffing started!"

# 🔍 Scan
@app.route("/scan")
def scan():
    global devices, ports_data, alerts_list, usage_data, chart_data

    devices = scan_network("192.168.1")

    ports_data = {}
    for d in devices:
        ports_data[d] = scan_ports(d)

    usage_data = get_network_usage()
    alerts_list = check_suspicious(devices)

    draw_network(devices)

    chart_data = {
        "devices_count": len(devices),
        "alerts_count": len(alerts_list),
        "ports_count": sum(len(p) for p in ports_data.values())
    }

    return redirect(url_for("home"))

# 🔥 إرسال بيانات مباشرة
def send_live_data():
    while True:
        usage = get_network_usage()

        socketio.emit("update", {
            "usage": usage,
            "devices": len(devices),
            "alerts": len(alerts_list),
            "ports": sum(len(p) for p in ports_data.values())
        })

        time.sleep(2)

# تشغيل Thread
thread = threading.Thread(target=send_live_data)
thread.daemon = True
thread.start()

# تشغيل السيرفر
if __name__ == "__main__":
    socketio.run(app, debug=True)

    from sniffer import start_sniffer
import threading

@app.route("/sniff")
def sniff_packets():
    thread = threading.Thread(target=start_sniffer, args=(socketio,))
    thread.daemon = True
    thread.start()

    return redirect(url_for("home")) 
from report import generate_report

@app.route("/report")
def report():
    generate_report(devices, alerts_list)
    return "Report generated!"
import os
from flask_socketio import SocketIO

socketio = SocketIO(app, cors_allowed_origins="*")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host="0.0.0.0", port=port)