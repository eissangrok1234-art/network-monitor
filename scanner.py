import socket
from concurrent.futures import ThreadPoolExecutor

# =========================
# 🔍 فحص جهاز واحد
# =========================
def scan_host(ip):
    try:
        # محاولة معرفة اسم الجهاز
        socket.gethostbyaddr(ip)
        return ip
    except:
        return None


# =========================
# 🌐 فحص الشبكة (سريع جدًا)
# =========================
def scan_network(base_ip):
    active_hosts = []
    print("🚀 Scanning network...")

    # توليد IPs
    ips = [f"{base_ip}.{i}" for i in range(1, 255)]

    # Threads (تسريع كبير)
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(scan_host, ips)

    for result in results:
        if result:
            active_hosts.append(result)

    print(f"✅ Found {len(active_hosts)} active devices")
    return active_hosts


# =========================
# 🔓 فحص البورتات
# =========================
def scan_ports(ip):
    open_ports = []

    # بورتات مهمة (Security-focused)
    common_ports = [
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        25,   # SMTP
        53,   # DNS
        80,   # HTTP
        110,  # POP3
        139,  # NetBIOS
        143,  # IMAP
        443   # HTTPS
    ]

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)

            sock.close()

        except:
            continue

    return open_ports


# =========================
# ⚡ فحص متكامل لجهاز واحد
# =========================
def scan_device_full(ip):
    return {
        "ip": ip,
        "ports": scan_ports(ip),
        "risk": calculate_risk(ip)
    }


# =========================
# 🧠 تقييم المخاطر (للـ AI)
# =========================
def calculate_risk(ip):
    last_digit = int(ip.split(".")[-1])

    # مثال بسيط لتقييم المخاطر
    if last_digit > 200:
        return "High Risk"
    elif last_digit > 100:
        return "Medium Risk"
    else:
        return "Low Risk"