from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import RawPcapReader, Ether, IP, TCP, UDP, Raw
import os
import tempfile

app = Flask(__name__)
CORS(app)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    # Временное сохранение
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp:
        file.save(temp.name)
        result = analyze_pcap(temp.name)
        os.unlink(temp.name)  # удалить временный файл после анализа

    return jsonify(result), 200


def analyze_pcap(file_path):
    packet_data = []
    total_packets = 0

    for pkt_data, pkt_metadata in RawPcapReader(file_path):
        total_packets += 1
        try:
            ether_pkt = Ether(pkt_data)
            pkt_info = {
                "ordinal": total_packets,
                "length": len(pkt_data),
                "timestamp": (pkt_metadata.tshigh << 32) | pkt_metadata.tslow,
                "layers": [],
            }

            # Ethernet
            pkt_info["eth"] = {
                "src": ether_pkt.src,
                "dst": ether_pkt.dst,
                "type": hex(ether_pkt.type)
            }

            # IP (если есть)
            if ether_pkt.haslayer(IP):
                ip_layer = ether_pkt[IP]
                pkt_info["ip"] = {
                    "src": ip_layer.src,
                    "dst": ip_layer.dst,
                    "proto": ip_layer.proto,
                    "ttl": ip_layer.ttl,
                    "len": ip_layer.len,
                    "id": ip_layer.id,
                    "flags": str(ip_layer.flags)
                }

            # TCP
            if ether_pkt.haslayer(TCP):
                tcp_layer = ether_pkt[TCP]
                pkt_info["tcp"] = {
                    "sport": tcp_layer.sport,
                    "dport": tcp_layer.dport,
                    "seq": tcp_layer.seq,
                    "ack": tcp_layer.ack,
                    "flags": str(tcp_layer.flags),
                    "window": tcp_layer.window
                }

            # UDP
            if ether_pkt.haslayer(UDP):
                udp_layer = ether_pkt[UDP]
                pkt_info["udp"] = {
                    "sport": udp_layer.sport,
                    "dport": udp_layer.dport,
                    "len": udp_layer.len
                }

            # Payload
            if ether_pkt.haslayer(Raw):
                raw_layer = ether_pkt[Raw]
                pkt_info["payload"] = raw_layer.load.hex()  # или .decode('utf-8', errors='ignore') для текста

            packet_data.append(pkt_info)

        except Exception as e:
            packet_data.append({
                "ordinal": total_packets,
                "error": str(e)
            })

    return {
        "total_packets": total_packets,
        "packets": packet_data
    }


if __name__ == '__main__':
    app.run(debug=True)
