import time
import threading
from collections import defaultdict
from scapy.all import IP, sniff
import ipaddress
from flask_socketio import SocketIO
import flask
import numpy as np
from sklearn.ensemble import IsolationForest

WINDOW_SIZE = 1  # 1 second

# Track both timestamps and packet sizes for ML features
ip_tracker = defaultdict(lambda: {"timestamps": [], "sizes": []})
alerted_ips = set()

# Initialize Unsupervised ML Model (Isolation Forest)
model = IsolationForest(contamination=0.05, random_state=42)

baseline_data = np.array([
    [5, 400], [10, 550], [2, 250], [15, 500], [8, 450], [12, 600]
])
model.fit(baseline_data)

# backend
app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "secret!"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


@app.route("/")
def index():
    return flask.render_template("index.html")


def is_local_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def process_packet(pkt):
    if not pkt.haslayer(IP):
        return
    src_ip = pkt[IP].src
    pkt_len = len(pkt)

    now = time.time()
    
    ip_tracker[src_ip]["timestamps"].append(now)
    ip_tracker[src_ip]["sizes"].append(pkt_len)

    cutoff = now - WINDOW_SIZE
    valid_pairs = [
        (t, s) for t, s in zip(ip_tracker[src_ip]["timestamps"], ip_tracker[src_ip]["sizes"]) 
        if t > cutoff
    ]
    
    if valid_pairs:
        timestamps, sizes = zip(*valid_pairs)
        ip_tracker[src_ip]["timestamps"] = list(timestamps)
        ip_tracker[src_ip]["sizes"] = list(sizes)
    else:
        ip_tracker[src_ip]["timestamps"] = []
        ip_tracker[src_ip]["sizes"] = []

    count = len(ip_tracker[src_ip]["timestamps"])
    
    # ML Prediction & Attack Classification Logic
    is_anomaly = False
    attack_type = "Normal"
    if count > 3:  
        avg_size = sum(ip_tracker[src_ip]["sizes"]) / count
        
        features = np.array([[count, avg_size]])
        prediction = model.predict(features)[0]  
        
        if prediction == -1:
            is_anomaly = True
            if count > 20:
                attack_type = "DDoS / High-Volume Spike"
            else:
                attack_type = "Behavioral Anomaly"

    if is_anomaly and src_ip not in alerted_ips:
        avg_size_print = sum(ip_tracker[src_ip]["sizes"]) / count if count > 0 else 0
        print(
            f"[ML ALERT] {attack_type} detected! {src_ip} sent {count} pkts (Avg Size: {avg_size_print:.1f}B) in last {WINDOW_SIZE}s"
        )
        alerted_ips.add(src_ip)
    elif not is_anomaly and src_ip in alerted_ips:
        alerted_ips.remove(src_ip)

    socketio.emit(
        "ip_alert",
        {
            "src_ip": src_ip, 
            "packet_count": count, 
            "window_size": WINDOW_SIZE,
            "is_anomaly": is_anomaly,
            "attack_type": attack_type
        },
    )


def start_sniffing():
    print("Scapy ML Intrusion Detector running... Press Ctrl+C to stop.")
    sniff(
        iface="en0",  
        prn=process_packet,
        store=0,
    )


if __name__ == "__main__":
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()
    socketio.run(
        app, 
        debug=True, 
        host="0.0.0.0", 
        port=8080, 
        allow_unsafe_werkzeug=True
    )
