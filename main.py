# -*- coding: utf-8 -*-
from scanner import scan_network, scan_ports
from monitor import get_network_usage
from alerts import check_suspicious

def main():
    base_ip = "192.168.1"

    devices = scan_network(base_ip)
    print("Active Devices:")

    for d in devices:
        print(f"\nDevice: {d}")
        
        ports = scan_ports(d)
        print(f"Open Ports: {ports}")

    usage = get_network_usage()
    print("\nNetwork Usage:")
    print(usage)

    alerts = check_suspicious(devices)
    print("\nAlerts:")
    for alert in alerts:
        print(alert)

if __name__ == "__main__":
    main()