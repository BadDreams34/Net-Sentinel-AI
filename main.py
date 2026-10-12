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
# contamination='auto' lets the model decide standard anomaly thresholds
model = IsolationForest(contamination=0.05, random_state=42)

# Warm up the model instantly with basic "normal" traffic data [packet_count, avg_packet_size]
# This prevents errors and gives it a baseline right when it boots up.
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

    #    if is_local_ip(src_ip):
    #        return

    now = time.time()
    
    # Store timestamp and packet size
    ip_tracker[src_ip]["timestamps"].append(now)
    ip_tracker[src_ip]["sizes"].append(pkt_len)

    # Remove timestamps older than WINDOW_SIZE
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
    
    # ML Prediction Logic
    is_anomaly = False
    if count > 3:  # Need at least a few packets to analyze
        avg_size = sum(ip_tracker[src_ip]["sizes"]) / count
        
        # Pass features to ML model: [[packet_count, average_packet_size]]
        features = np.array([[count, avg_size]])
        prediction = model.predict(features)[0]  # Returns 1 for normal, -1 for anomaly
        
        if prediction == -1:
            is_anomaly = True

    # Alert handling logic based on ML decision
    if is_anomaly and src_ip not in alerted_ips:
        avg_size_print = sum(ip_tracker[src_ip]["sizes"]) / count if count > 0 else 0
        print(
            f"[ML ALERT] Anomaly detected! {src_ip} sent {count} pkts (Avg Size: {avg_size_print:.1f}B) in last {WINDOW_SIZE}s"
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
            "is_anomaly": is_anomaly
        },
    )


def start_sniffing():
    print("Scapy ML Intrusion Detector running... Press Ctrl+C to stop.")
    sniff(
        iface="en0",  # Your macOS Wi-Fi interface
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
