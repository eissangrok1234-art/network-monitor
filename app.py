from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO
import time
import threading
import os

# استيراد ملفات المشروع
from sniffer import start_sniffer
from scanner import scan_network, scan_ports
from monitor import get_network_usage
from alerts import check_suspicious
from graph import draw_network
from report import generate_report
from ai_security import analyze_network
from ml_model import detect_anomaly

# إعداد التطبيق
app = Flask(__name__)
app.secret_key = "secret123"

# مهم جدًا لـ Render
socketio = SocketIO(app, async_mode='eventlet')

# متغيرات عامة
packet_rate = 0
devices = []
alerts_list = []
ENABLE_SNIFFER = False

# -----------------------------
# إرسال الترافيك كل فترة
# -----------------------------
def send_traffic():
    global packet_rate
    while True:
        socketio.emit("traffic", {
            "rate": packet_rate
        })
        packet_rate = 0
        time.sleep(2)

# تشغيل thread
threading.Thread(target=send_traffic, daemon=True).start()

# -----------------------------
# الصفحة الرئيسية
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

# -----------------------------
# فحص الشبكة
# -----------------------------
@app.route("/scan")
def scan():
    global devices
    devices = scan_network()
    return {"devices": devices}

# -----------------------------
# فحص البورتات
# -----------------------------
@app.route("/scan_ports")
def scan_ports_route():
    ip = request.args.get("ip")
    result = scan_ports(ip)
    return {"ports": result}

# -----------------------------
# مراقبة الشبكة
# -----------------------------
@app.route("/monitor")
def monitor():
    usage = get_network_usage()
    return {"usage": usage}

# -----------------------------
# كشف التهديدات
# -----------------------------
@app.route("/alerts")
def alerts():
    global alerts_list
    alerts_list = check_suspicious(devices)
    return {"alerts": alerts_list}

# -----------------------------
# AI تحليل الشبكة
# -----------------------------
@app.route("/ai")
def ai_analysis():
    result = analyze_network(devices)
    return {"analysis": result}

# -----------------------------
# ML كشف الشذوذ
# -----------------------------
@app.route("/ml")
def ml_analysis():
    result = detect_anomaly(devices)
    return {"ml": result}

# -----------------------------
# رسم الشبكة
# -----------------------------
@app.route("/graph")
def graph():
    draw_network(devices)
    return "Graph generated"

# -----------------------------
# تقرير PDF
# -----------------------------
@app.route("/report")
def report():
    generate_report(devices, alerts_list)
    return "Report generated!"

# -----------------------------
# تشغيل السيرفر (مهم جدًا)
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)