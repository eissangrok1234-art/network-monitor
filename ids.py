from collections import defaultdict
import time

# =========================
# 📊 تخزين البيانات
# =========================
packet_count = defaultdict(int)        # عدد الباكيت لكل IP
port_scan_count = defaultdict(set)     # البورتات لكل IP
last_seen = defaultdict(float)         # آخر وقت تم فيه رؤية IP


# =========================
# 🚨 تحليل الباكيت (IDS)
# =========================
def analyze_packet(packet):
    alerts = []

    try:
        if packet.haslayer("IP"):
           
            src = packet["IP"].src
            current_time = time.time()
            log_event(alert)
            # تحديث الوقت
            last_seen[src] = current_time

            # =========================
            # 📊 عداد الباكيت
            # =========================
            packet_count[src] += 1

            # =========================
            # 🚨 DDoS Detection
            # =========================
            if packet_count[src] > 50:
                alerts.append(f"🚨 DDoS detected from {src}")

            # =========================
            # ⚠️ Suspicious IP
            # =========================
            last_digit = int(src.split(".")[-1])
            if last_digit > 200:
                alerts.append(f"⚠️ Suspicious IP: {src}")

        # =========================
        # 🔍 Port Scan Detection
        # =========================
        if packet.haslayer("TCP"):
            src = packet["IP"].src
            dport = packet["TCP"].dport

            port_scan_count[src].add(dport)

            if len(port_scan_count[src]) > 10:
                alerts.append(f"⚠️ Port Scanning detected from {src}")

        # =========================
        # 📡 UDP Flood Detection
        # =========================
        if packet.haslayer("UDP"):
            src = packet["IP"].src

            if packet_count[src] > 40:
                alerts.append(f"🚨 UDP Flood from {src}")

    except:
        pass

    return alerts


# =========================
# 🧠 ML بسيط (Anomaly Detection)
# =========================
def detect_anomaly(devices, ports_data):
    alerts = []

    total_ports = sum(len(p) for p in ports_data.values())

    # عدد أجهزة غير طبيعي
    if len(devices) > 20:
        alerts.append("⚠️ ML: Unusual number of devices")

    # نشاط بورتات عالي
    if total_ports > 50:
        alerts.append("⚠️ ML: Abnormal port activity")

    return alerts


# =========================
# 🧹 تنظيف البيانات القديمة
# =========================
def cleanup_data(timeout=60):
    current_time = time.time()

    for ip in list(last_seen.keys()):
        if current_time - last_seen[ip] > timeout:
            packet_count.pop(ip, None)
            port_scan_count.pop(ip, None)
            last_seen.pop(ip, None)