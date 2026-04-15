# =========================
# 🛡️ قائمة الحظر
# =========================
blocked_ips = set()


# =========================
# 🚫 حظر IP
# =========================
def block_ip(ip):
    blocked_ips.add(ip)
    print(f"🚫 Blocked IP: {ip}")
    log_event(f"🚫 Blocked IP: {ip}")


# =========================
# ✅ التحقق من الحظر
# =========================
def is_blocked(ip):
    return ip in blocked_ips


# =========================
# 📋 عرض القائمة
# =========================
def get_blocked_ips():
    return list(blocked_ips)