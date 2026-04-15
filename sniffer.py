from ips import block_ip, is_blocked
from ids import analyze_packet
from scapy.all import sniff
from collections import defaultdict
from logger import log_event
import threading
import time

from ids import analyze_packet  # IDS

# =========================
# 📊 تخزين البيانات
# =========================
packet_count = defaultdict(int)
packet_rate = 0


# =========================
# 🚨 كشف DDoS
# =========================
def detect_ddos(socketio):
    global packet_count

    while True:
        for ip, count in packet_count.items():
            if count > 50:  # Threshold
                print(f"🚨 DDoS Attack detected from {ip}")
                log_event(f"🚨 DDoS detected from {ip}")
                socketio.emit("ddos_alert", {
                    "ip": ip,
                    "count": count
                })

        packet_count.clear()
        time.sleep(3)


# =========================
# 📊 إرسال الترافيك
# =========================
def send_traffic(socketio):
    global packet_rate

    while True:
        socketio.emit("traffic", {
            "rate": packet_rate
        })

        packet_rate = 0
        time.sleep(2)


# =========================
# 🚀 تشغيل Sniffer
# =========================
def start_sniffer(socketio):

    # Thread كشف DDoS
    threading.Thread(target=detect_ddos, args=(socketio,), daemon=True).start()

    # Thread إرسال الترافيك
    threading.Thread(target=send_traffic, args=(socketio,), daemon=True).start()

    def process_packet(packet):
        global packet_rate

        try:
            if packet.haslayer("IP"):
                src = packet["IP"].src
                dst = packet["IP"].dst

                # عداد
                packet_count[src] += 1
                packet_rate += 1

                # تحديد البروتوكول
                protocol = "Other"
                if packet.haslayer("TCP"):
                    protocol = "TCP"
                elif packet.haslayer("UDP"):
                    protocol = "UDP"

                # =========================
                # 🚨 IDS Analysis
                # =========================
                alerts = analyze_packet(packet)

                for alert in alerts:
                    socketio.emit("ids_alert", {
                        "message": alert
                    })
                    alerts = analyze_packet(packet)

                for alert in alerts:
                 socketio.emit("ids_alert", {
        "message": alert
    })

                # =========================
                # 📡 إرسال الباكيت للواجهة
                # =========================
                socketio.emit("packet", {
                    "src": src,
                    "dst": dst,
                    "protocol": protocol
                })


        except:
            pass

    print("📡 Sniffing started with IDS + DDoS detection...")

    sniff(
        prn=process_packet,
        store=False
    )
