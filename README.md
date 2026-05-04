# DRAKEN — Network Packet Sniffer & Analyzer

Computer Networks Semester Project by Muhammad Ibraheem (BCSF24A023) and Muhammad Ali (BCSF24A024) 

DRAKEN is a real-time network packet capture and analysis tool for Windows. It combines a low-level C++ packet sniffer (powered by WinPcap/Npcap) with a Python Flask API and a dark-themed browser-based dashboard for live traffic visualization and deep packet inspection.

---

## Architecture

```
sniffer.exe  ──writes──►  packets.json  ◄──reads──  app.py (Flask API)  ◄──polls──  index.html (Dashboard)
```

| Component | File | Role |
|---|---|---|
| Packet Sniffer | `sniffer.cpp` → `sniffer.exe` | Captures raw frames via pcap, writes newline-delimited JSON |
| REST API | `app.py` | Flask server bridging the sniffer and the frontend |
| Dashboard | `index.html` | Browser UI — live table, stats, protocol chart, packet inspector |

---

## Features

- **Multi-protocol capture** — TCP, UDP, ICMP, TCP6, UDP6, ICMPv6, ARP, and raw/unknown frames
- **Deep packet inspection** — Ethernet II, IPv4/IPv6, TCP/UDP/ICMP header trees with field-level detail
- **Hex dump viewer** — full payload bytes with ASCII sidebar, inline in the inspector panel
- **Live statistics** — total packets, per-protocol counts, average/largest packet size, total bytes, packets/s and bytes/s over the last 5 seconds
- **Service resolution** — port-to-name mapping loaded from `C:\Windows\System32\drivers\etc\services` with built-in fallbacks (HTTP, HTTPS, DNS, SSH, RDP, etc.)
- **Interface selection** — enumerate and choose any pcap-visible network adapter from the UI
- **Incremental polling** — the frontend polls `/packets` every second; the API tracks a file offset so only new packets are returned each call

---

## Requirements

### System
- **Windows** (WinPcap or Npcap must be installed)
- **Python 3.8+**
- A modern browser (Chrome, Edge, Firefox)

### Python packages
```
pip install flask flask-cors
```

### C++ build (if compiling from source)
- Visual Studio or MinGW with `wpcap.lib` and `ws2_32.lib`
- WinPcap/Npcap developer SDK headers (`pcap.h`)

---

## Getting Started

### 1. Build the sniffer (skip if you have `sniffer.exe`)
```bash
# With MSVC (adjust paths to your Npcap SDK)
cl sniffer.cpp /I"C:\npcap-sdk\Include" /link /LIBPATH:"C:\npcap-sdk\Lib\x64" wpcap.lib ws2_32.lib
```

### 2. Start the Flask API
```bash
python app.py
```
The API listens on `http://localhost:5000`.

### 3. Open the dashboard
Open `index.html` directly in your browser (no build step required).

### 4. Select an interface and capture
- Use the **Interface** dropdown to pick a network adapter
- Click **Start** to begin capture
- Click **Stop** to end the session

---

## API Reference

All endpoints are served by `app.py` on port `5000`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/interfaces` | List available pcap network interfaces |
| `POST` | `/start` | Start capture. Body: `{ "interface": 1 }` |
| `POST` | `/stop` | Stop the running sniffer process |
| `GET` | `/packets` | Return new packets since last poll (incremental) |
| `GET` | `/stats` | Return aggregate statistics over the full capture |
| `GET` | `/status` | Return `{ "running": true/false }` |

### Packet JSON schema
Each line in `packets.json` is a JSON object:

```json
{
  "time": "14:32:01",
  "eth_src": "aa:bb:cc:dd:ee:ff",
  "eth_dst": "11:22:33:44:55:66",
  "ethertype": "0x0800",
  "protocol": "TCP",
  "src_ip": "192.168.1.10",
  "dst_ip": "93.184.216.34",
  "src_port": "52341",
  "dst_port": "443",
  "service": "https",
  "size": 74,
  "ip_ver": 4,
  "ip_ttl": 128,
  "ip_total_len": 60,
  "tcp_seq": 123456789,
  "tcp_ack": 0,
  "tcp_flag_syn": true,
  "tcp_window": 65535,
  "tcp_checksum": "0x1a2b",
  "payload_len": 0,
  "payload": ""
}
```

---

## Project Structure

```
draken/
├── sniffer.cpp      # C++ packet capture engine
├── sniffer.exe      # Compiled binary (required at runtime)
├── app.py           # Flask REST API
├── index.html       # Browser dashboard (single-file)
└── packets.json     # Live capture output (auto-created/reset on start)
```

---

## Notes & Limitations

- **Windows only** — `sniffer.cpp` uses Winsock2 and WinPcap/Npcap APIs
- `packets.json` is truncated on every new `/start` call; previous captures are not retained
- The stats endpoint re-reads the entire file on each request; for very long captures, `/stats` may become slower over time


---

## License

See `LICENSE` for terms.
