def analyze_network(devices, ports_data):
    alerts = []

    # 1. عدد الأجهزة
    if len(devices) > 20:
        alerts.append("⚠️ Unusual number of devices detected (Possible attack)")

    # 2. كثرة البورتات المفتوحة
    for ip, ports in ports_data.items():
        if len(ports) > 5:
            alerts.append(f"⚠️ Possible Port Scan on {ip}")

    # 3. IP مشبوه
    for ip in devices:
        last = int(ip.split(".")[-1])
        if last > 200:
            alerts.append(f"⚠️ Suspicious IP: {ip}")

    return alerts