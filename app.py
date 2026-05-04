from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import subprocess
import os

app = Flask(__name__)
CORS(app)

process     = None
file_offset = 0
PACKETS_FILE = "packets.json"
SNIFFER_EXE  = "sniffer.exe"


def read_new_packets():
    """Read only packets added since last call, using file offset."""
    global file_offset
    packets = []
    try:
        with open(PACKETS_FILE, "r") as f:
            f.seek(file_offset)
            for line in f:
                line = line.strip()
                if line:
                    try:
                        packets.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            file_offset = f.tell()
    except FileNotFoundError:
        pass
    return packets


def read_all_packets():
    """Read entire file — used for stats only."""
    packets = []
    try:
        with open(PACKETS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        packets.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        pass
    return packets


@app.route("/interfaces", methods=["GET"])
def list_interfaces():
    """Run sniffer with --list flag to enumerate pcap devices."""
    try:
        result = subprocess.run(
            [SNIFFER_EXE, "--list"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().splitlines()
        interfaces = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Expected format from sniffer: "1. <description or name>"
            parts = line.split(". ", 1)
            if len(parts) == 2:
                try:
                    idx = int(parts[0])
                    interfaces.append({"index": idx, "name": parts[1]})
                except ValueError:
                    pass
        return jsonify(interfaces)
    except FileNotFoundError:
        return jsonify({"status": "error", "message": f"{SNIFFER_EXE} not found"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Timed out listing interfaces"}), 500


@app.route("/start", methods=["POST"])
def start():
    global process, file_offset

    if process and process.poll() is None:
        return jsonify({"status": "already_running"})

    # Accept interface index from JSON body; default to 1
    data = request.get_json(silent=True) or {}
    iface = str(data.get("interface", "1"))

    # Reset file and offset every time
    open(PACKETS_FILE, "w").close()
    file_offset = 0

    try:
        process = subprocess.Popen(
            [SNIFFER_EXE, iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return jsonify({"status": "started"})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": f"{SNIFFER_EXE} not found in this folder"}), 500


@app.route("/stop", methods=["POST"])
def stop():
    global process
    if process:
        process.terminate()
        process = None
    return jsonify({"status": "stopped"})


@app.route("/packets")
def get_packets():
    """Returns only NEW packets since last poll."""
    return jsonify(read_new_packets())


@app.route("/stats")
def get_stats():
    """Returns stats computed from the full file."""
    import time
    from collections import Counter

    packets = read_all_packets()
    total = len(packets)
    tcp   = sum(1 for p in packets if p.get("protocol") == "TCP")
    udp   = sum(1 for p in packets if p.get("protocol") == "UDP")
    icmp  = sum(1 for p in packets if p.get("protocol") == "ICMP")
    sizes = [p.get("size", 0) for p in packets]
    avg   = sum(sizes) / total if total > 0 else 0
    total_bytes = sum(sizes)

    # Top service (exclude bare port numbers and 'icmp')
    services = [p.get("service", "") for p in packets
                if p.get("service") and not p.get("service", "").isdigit()
                and p.get("service") != "icmp"]
    top_service = Counter(services).most_common(1)
    top_service_name = top_service[0][0] if top_service else "—"

    # Packets/s and bytes/s over the last 5 seconds using timestamps
    # Timestamps are HH:MM:SS strings — compare to now
    import datetime
    now = datetime.datetime.now()
    recent = []
    for p in packets:
        ts = p.get("time", "")
        try:
            t = datetime.datetime.strptime(ts, "%H:%M:%S").replace(
                year=now.year, month=now.month, day=now.day)
            if (now - t).total_seconds() <= 5:
                recent.append(p)
        except Exception:
            pass

    pkt_rate   = len(recent)           # packets in last 5 s
    byte_rate  = sum(r.get("size", 0) for r in recent)  # bytes in last 5 s

    # Largest packet
    largest = max(sizes) if sizes else 0

    return jsonify({
        "total":         total,
        "tcp":           tcp,
        "udp":           udp,
        "icmp":          icmp,
        "avg_size":      round(avg, 1),
        "total_bytes":   total_bytes,
        "top_service":   top_service_name,
        "pkt_rate":      pkt_rate,
        "byte_rate":     byte_rate,
        "largest":       largest,
    })


@app.route("/status")
def status():
    running = process is not None and process.poll() is None
    return jsonify({"running": running})


if __name__ == "__main__":
    app.run(port=5000, debug=False)
