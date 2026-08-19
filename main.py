import tomllib
import time
from collections import defaultdict
from scapy.all import IP, sniff
import ipaddress


THRESHOLD = 250
WINDOW_SIZE = 1  # 1 second

ip_tracker = defaultdict(list)
alerted_ips = set()


def is_local_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def process_packet(pkt):
    if not pkt.haslayer(IP):
        return
    src_ip = pkt[IP].src
    if is_local_ip(src_ip):
        return
    now = time.time()

    ip_tracker[src_ip].append(now)

    # Remove timestamps older than WINDOW_SIZE
    cutoff = now - WINDOW_SIZE
    ip_tracker[src_ip] = [t for t in ip_tracker[src_ip] if t > cutoff]

    count = len(ip_tracker[src_ip])

    # Alert handling logic
    if count > THRESHOLD and src_ip not in alerted_ips:
        print(f"[ALERT] High traffic detected! {src_ip} sent {count} pkts in last {WINDOW_SIZE}s")
        alerted_ips.add(src_ip)
    elif count <= THRESHOLD and src_ip in alerted_ips:
        alerted_ips.remove(src_ip)


def main():
    print("Scapy Intrusion Detector running... Press Ctrl+C to stop.")

    sniff(
        iface = "wlan0",
        prn=process_packet,
        store=0,
    )


if __name__ == "__main__":
    main()
