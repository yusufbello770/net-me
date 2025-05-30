import scapy.all as scapy
from flask import Flask, render_template, jsonify

import matplotlib
matplotlib.use('Agg')  # Use Agg backend for PNGs, no GUI required

import matplotlib.pyplot as plt
from io import BytesIO
import base64
import psutil
import threading


# Initialize Flask app
app = Flask(__name__)

# Step 1: List all available network interfaces
def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

# Step 2: Function to handle packet capture in the background
def capture_packets(interface, packet_list, duration=10):
    # This function will capture packets for a specified duration and append to packet_list
    def packet_callback(packet):
        packet_list.append(packet)
    
    scapy.sniff(iface=interface, prn=packet_callback, timeout=duration)

# Step 3: Analyze captured traffic (protocol distribution)
def analyze_traffic(packet_list):
    protocol_counts = {}
    for packet in packet_list:
        if packet.haslayer(scapy.IP):
            protocol = packet.proto
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    return protocol_counts

# Step 4: Generate traffic visualization (pie chart)
def generate_traffic_visualization(protocol_counts):
    labels = list(protocol_counts.keys())
    sizes = list(protocol_counts.values())
    
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  # Equal aspect ratio ensures the pie is drawn as a circle.
    
    # Convert the plot to a PNG image and encode it in base64
    buf = BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    img_data = base64.b64encode(buf.read()).decode("utf-8")
    return img_data

# Step 5: Web Interface - Display available interfaces
@app.route('/')
def index():
    interfaces = get_network_interfaces()
    return render_template('index.html', interfaces=interfaces)

# Step 6: Start packet capture on selected interface
@app.route('/start_capture/<interface>')
def start_capture(interface):
    packet_list = []
    capture_thread = threading.Thread(target=capture_packets, args=(interface, packet_list))
    capture_thread.start()
    capture_thread.join()  # Wait for the capture to finish
    
    # Analyze the captured traffic
    protocol_counts = analyze_traffic(packet_list)
    
    # Generate visualization
    img_data = generate_traffic_visualization(protocol_counts)
    
    return render_template('result.html', img_data=img_data, protocol_counts=protocol_counts)
@app.route('/capture_result')
def capture_result():
    # Initially render the page with empty data
    return render_template('result.html', img_data="", protocol_counts={})

captured_packets = []
capture_active = False

def capture_packets_continuous(interface, duration=60):
    global captured_packets, capture_active
    captured_packets = []
    capture_active = True

    def packet_callback(packet):
        captured_packets.append(packet)

    scapy.sniff(iface=interface, prn=packet_callback, timeout=duration)
    capture_active = False

@app.route('/start_capture_continuous/<interface>')
def start_capture_continuous(interface):
    thread = threading.Thread(target=capture_packets_continuous, args=(interface, 60))
    thread.start()
    return jsonify({"status": "Capture started for 60 seconds"}), 202

@app.route('/traffic_stats')
def traffic_stats():
    proto_counts = {}
    bandwidth_per_ip = {}

    for pkt in captured_packets:
        if pkt.haslayer(scapy.IP):
            proto = pkt.proto
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

            src_ip = pkt[scapy.IP].src
            pkt_len = len(pkt)
            bandwidth_per_ip[src_ip] = bandwidth_per_ip.get(src_ip, 0) + pkt_len

    # Convert bandwidth bytes to KB
    bandwidth_per_ip = {ip: round(bw / 1024, 2) for ip, bw in bandwidth_per_ip.items()}
 # Convert protocol numbers to names (optional)
    PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}
    proto_counts_named = {PROTO_MAP.get(proto, str(proto)): count for proto, count in proto_counts.items()}

   
    return jsonify({
        "protocol_counts": proto_counts_named,
        "bandwidth_per_ip_kb": bandwidth_per_ip,
        "packet_count": len(captured_packets),
        "capture_active": capture_active
    })

# Run the web server
if __name__ == '__main__':
    app.run(debug=True)
