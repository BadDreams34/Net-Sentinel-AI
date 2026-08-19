from collections import defaultdict
from scapy.all import sniff, IP, conf
import time
from scapy.supersocket import L3RawSocket

THRESHOLD = 50
WINDOW_SIZE = 1 #1 second


ip_tracker = defaultdict(list)
alerted_ips = set()


def process_packet(pkt):
    if not pkt.has_layers(IP):
        return

        src_ip = pkt[IP].src
    now = time.time()
    
    ip_tracker[src_ip].append(now)


    # remove packets after the window size
    cutoff = now - WINDOW_SIZE
    ip_tracker[src_ip] = [t for t in ip_tracker[src_ip] if t > cutoff]


    count = len(ip_tracker[src_ip])


    if count > THRESHOLD and src_ip not in alerted_ips  :
        print(f"[ALERT] High traffic detected! {src_ip} sent {count} pkts in last {WINDOW_SIZE}s")
        alerted_ips.add(src_ip)
    elif count <= THRESHOLD and src_ip in alerted_ips:
        alerted_ips.remove(src_ip)


def main():
    print("Scapy Intrusion Detector running... Press Ctrl+C to stop.")

    # store = 0 prevents filling RAM with captured packet objects
    sniff(iface ="wlan0", L2socket=L3RawSocket, prn=process_packet, store=0)

if __name__ == "__main__":
    main()
