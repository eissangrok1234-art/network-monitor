def check_suspicious(ip_list):
    alerts = []

    for ip in ip_list:
        if ip.endswith(".5"):  # ãËÇá ÈÓíØ
            alerts.append(f"Suspicious IP detected: {ip}")

    return alerts