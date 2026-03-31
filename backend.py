import copy
import glob
import random
import os
import re
import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO

try:
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, ARP, DNS
except Exception:  # pragma: no cover - handled at runtime via health/status flags
    AsyncSniffer = None
    IP = IPv6 = TCP = UDP = ICMP = ARP = DNS = None

app = Flask(__name__, static_folder=".", static_url_path="")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

SNORT_LOG_ENV = os.environ.get("SNORT_ALERT_LOG", "").strip()
ENABLE_FALLBACK_ALERTS = os.environ.get("IDS_ENABLE_FALLBACK", "0").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
CAPTURE_INTERFACE = os.environ.get("IDS_INTERFACE", "").strip() or None
IDS_PORT = int(os.environ.get("IDS_PORT", "5000"))
ALERT_WINDOW_SEC = int(os.environ.get("IDS_ALERT_WINDOW_SEC", "30"))
PORTSCAN_THRESHOLD = int(os.environ.get("IDS_PORTSCAN_THRESHOLD", "20"))
ICMP_FLOOD_THRESHOLD = int(os.environ.get("IDS_ICMP_FLOOD_THRESHOLD", "60"))
SYN_FLOOD_THRESHOLD = int(os.environ.get("IDS_SYN_FLOOD_THRESHOLD", "120"))
DNS_THRESHOLD = int(os.environ.get("IDS_DNS_THRESHOLD", "80"))
MAX_EVENTS_PER_SOURCE = 400
SNORT_LOG_CANDIDATES = [
    path
    for path in [
        SNORT_LOG_ENV,
        "/var/log/snort/alert_fast.log",
        "/var/log/snort/alert.fast",
        "/var/log/snort/alert",
        "/var/log/snort/fast.log",
        "/var/log/snort3/alert_fast.log",
        "/var/log/snort3/alert.fast",
        "/var/log/snort3/alert",
    ]
    if path
]
MAX_ALERTS = 80
MAX_HOSTS = 120
ALERT_RE = re.compile(r"\[\*\*\]\s*\[[^\]]+\]\s*(.*?)\s*\[\*\*\]")
PRIORITY_RE = re.compile(r"\[Priority:\s*(\d+)\]")
PROTO_RE = re.compile(r"\{([A-Z0-9]+)\}")
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

state_lock = threading.Lock()
total_alerts_seen = 0
packet_bytes_total = 0
packets_seen_total = 0

detector_events = {
    "portscan": defaultdict(lambda: deque()),
    "icmp": defaultdict(lambda: deque()),
    "syn": defaultdict(lambda: deque()),
    "dns": defaultdict(lambda: deque()),
}

capture_runtime = {
    "method": "none",
    "capture_interface": CAPTURE_INTERFACE or "auto",
    "capture_running": False,
    "capture_error": "",
    "last_packet_time": None,
}

stats = {
    "pps": 0,
    "threats": 0,
    "rules": 371,
    "bandwidth_mbps": 0.0,
    "blocked_hosts": 0,
    "alerts": [],
    "hosts": {},
    "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0},
    "geo": {},
    "engine_active": True,
    "snort_log_found": False,
    "snort_log_path": SNORT_LOG_CANDIDATES[0] if SNORT_LOG_CANDIDATES else "",
    "fallback_mode": False,
    "last_alert_time": None,
    "capture_interface": CAPTURE_INTERFACE or "auto",
    "capture_running": False,
    "capture_error": "",
    "capture_method": "none",
    "last_packet_time": None,
}

FALLBACK_TEMPLATES = [
    {
        "sid": "1:2010935:2",
        "message": "GPL ATTACK_RESPONSE id check returned root",
        "priority": 2,
        "proto": "TCP",
    },
    {
        "sid": "1:1000004:1",
        "message": "ET SCAN Potential SSH Scan",
        "priority": 3,
        "proto": "TCP",
    },
    {
        "sid": "1:1000007:1",
        "message": "ET POLICY Suspicious DNS Query",
        "priority": 3,
        "proto": "UDP",
    },
    {
        "sid": "1:1000012:1",
        "message": "ET TROJAN Known C2 Beacon",
        "priority": 1,
        "proto": "TCP",
    },
    {
        "sid": "1:1000018:1",
        "message": "ICMP PING NMAP",
        "priority": 3,
        "proto": "ICMP",
    },
]


def resolve_snort_log_path():
    for path in SNORT_LOG_CANDIDATES:
        if os.path.exists(path):
            return path

    for path in glob.glob("/var/log/snort*/alert*"):
        if os.path.isfile(path):
            return path

    return SNORT_LOG_CANDIDATES[0] if SNORT_LOG_CANDIDATES else ""


def severity_from_priority(priority):
    if priority <= 1:
        return "CRITICAL"
    if priority == 2:
        return "HIGH"
    if priority == 3:
        return "MEDIUM"
    return "LOW"


def extract_message(line):
    match = ALERT_RE.search(line)
    if match:
        return match.group(1).strip()
    return line[:120].strip()


def parse_ips(line):
    ips = IP_RE.findall(line)
    src = ips[0] if len(ips) > 0 else "unknown"
    dst = ips[1] if len(ips) > 1 else "unknown"
    return src, dst


def protocol_from_line(line):
    match = PROTO_RE.search(line)
    if not match:
        return "OTHER"
    proto = match.group(1).upper()
    return proto if proto in ("TCP", "UDP", "ICMP", "ARP") else "OTHER"


def geo_bucket_for_ip(ip):
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return "Internal LAN"
    if ip == "unknown":
        return "Unknown"
    first_octet = int(ip.split(".")[0])
    if 1 <= first_octet <= 49:
        return "US/NA"
    if 50 <= first_octet <= 99:
        return "EU"
    if 100 <= first_octet <= 149:
        return "APAC"
    if 150 <= first_octet <= 199:
        return "LATAM"
    return "Other"


def host_risk_from_severity(severity):
    if severity == "CRITICAL":
        return "crit"
    if severity == "HIGH":
        return "high"
    if severity == "MEDIUM":
        return "med"
    return "low"


def upsert_host(ip, severity):
    if ip == "unknown":
        return

    host = stats["hosts"].get(ip)
    if not host:
        if len(stats["hosts"]) >= MAX_HOSTS:
            oldest_ip = next(iter(stats["hosts"]))
            stats["hosts"].pop(oldest_ip, None)
        host = {
            "ip": ip,
            "status": "online",
            "risk": "low",
            "events": 0,
            "last_seen": "",
        }
        stats["hosts"][ip] = host

    host["events"] += 1
    host["last_seen"] = time.strftime("%H:%M:%S")

    severity_rank = {"low": 1, "med": 2, "high": 3, "crit": 4}
    new_risk = host_risk_from_severity(severity)
    if severity_rank[new_risk] > severity_rank[host["risk"]]:
        host["risk"] = new_risk

    if host["risk"] == "crit":
        host["status"] = "blocked"
    elif host["risk"] in ("high", "med"):
        host["status"] = "suspect"


def parse_and_store_alert(line):
    global total_alerts_seen

    priority_match = PRIORITY_RE.search(line)
    priority = int(priority_match.group(1)) if priority_match else 3
    severity = severity_from_priority(priority)
    protocol = protocol_from_line(line)
    src, dst = parse_ips(line)
    message = extract_message(line)

    alert = {
        "time": time.strftime("%H:%M:%S"),
        "severity": severity,
        "message": message,
        "src": src,
        "dst": dst,
        "protocol": protocol,
    }

    with state_lock:
        stats["alerts"].insert(0, alert)
        stats["alerts"] = stats["alerts"][:MAX_ALERTS]
        stats["last_alert_time"] = alert["time"]
        stats["threats"] += 1
        total_alerts_seen += 1

        stats["protocols"][protocol] = stats["protocols"].get(protocol, 0) + 1
        geo_bucket = geo_bucket_for_ip(src)
        stats["geo"][geo_bucket] = stats["geo"].get(geo_bucket, 0) + 1

        upsert_host(src, severity)
        blocked = sum(1 for host in stats["hosts"].values() if host["status"] == "blocked")
        stats["blocked_hosts"] = blocked

    socketio.emit("alert", alert)


def store_structured_alert(message, src, dst, protocol, priority):
    line = (
        f"[**] [1:9000001:1] {message} [**] "
        f"[Priority: {priority}] "
        f"{{{protocol}}} {src}:0 -> {dst}:0"
    )
    parse_and_store_alert(line)


def prune_window(queue_obj, now_ts):
    while queue_obj and now_ts - queue_obj[0] > ALERT_WINDOW_SEC:
        queue_obj.popleft()


def detect_ids_events(src, dst, protocol, now_ts, is_syn=False, has_dns=False):
    portscan_q = detector_events["portscan"][src]
    if len(portscan_q) > MAX_EVENTS_PER_SOURCE:
        portscan_q.popleft()

    icmp_q = detector_events["icmp"][src]
    syn_q = detector_events["syn"][src]
    dns_q = detector_events["dns"][src]

    if protocol == "ICMP":
        icmp_q.append(now_ts)
        prune_window(icmp_q, now_ts)
        if len(icmp_q) == ICMP_FLOOD_THRESHOLD:
            store_structured_alert(
                "ANOMALY ICMP flood threshold exceeded",
                src,
                dst,
                "ICMP",
                2,
            )

    if protocol == "TCP" and is_syn:
        syn_q.append(now_ts)
        prune_window(syn_q, now_ts)
        if len(syn_q) == SYN_FLOOD_THRESHOLD:
            store_structured_alert(
                "ANOMALY TCP SYN flood threshold exceeded",
                src,
                dst,
                "TCP",
                1,
            )

    if has_dns:
        dns_q.append(now_ts)
        prune_window(dns_q, now_ts)
        if len(dns_q) == DNS_THRESHOLD:
            store_structured_alert(
                "ANOMALY DNS query burst detected",
                src,
                dst,
                "UDP",
                3,
            )


def detect_port_scan(src, dst, dport, now_ts):
    q = detector_events["portscan"][src]
    q.append((now_ts, dport, dst))
    while q and now_ts - q[0][0] > ALERT_WINDOW_SEC:
        q.popleft()

    unique_ports = {entry[1] for entry in q}
    if len(unique_ports) == PORTSCAN_THRESHOLD:
        store_structured_alert(
            f"ANOMALY Port scan detected ({len(unique_ports)} ports/{ALERT_WINDOW_SEC}s)",
            src,
            dst,
            "TCP",
            2,
        )


def process_packet(packet):
    global packet_bytes_total, packets_seen_total

    protocol = "OTHER"
    src = "unknown"
    dst = "unknown"
    dport = None
    is_syn = False
    has_dns = False
    size_bytes = len(packet)
    now_ts = time.time()

    if IP and packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    elif IPv6 and packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    elif ARP and packet.haslayer(ARP):
        src = packet[ARP].psrc or "unknown"
        dst = packet[ARP].pdst or "unknown"

    if TCP and packet.haslayer(TCP):
        protocol = "TCP"
        dport = int(packet[TCP].dport)
        flags = int(packet[TCP].flags)
        # SYN without ACK indicates connection initiation.
        is_syn = bool(flags & 0x02 and not flags & 0x10)
    elif UDP and packet.haslayer(UDP):
        protocol = "UDP"
        dport = int(packet[UDP].dport)
    elif ICMP and packet.haslayer(ICMP):
        protocol = "ICMP"
    elif ARP and packet.haslayer(ARP):
        protocol = "ARP"

    if DNS and packet.haslayer(DNS):
        has_dns = True

    with state_lock:
        packets_seen_total += 1
        packet_bytes_total += size_bytes
        stats["protocols"][protocol] = stats["protocols"].get(protocol, 0) + 1
        upsert_host(src, "LOW")
        stats["last_packet_time"] = time.strftime("%H:%M:%S")
        capture_runtime["last_packet_time"] = stats["last_packet_time"]

    if protocol == "TCP" and dport is not None:
        detect_port_scan(src, dst, dport, now_ts)

    detect_ids_events(src, dst, protocol, now_ts, is_syn=is_syn, has_dns=has_dns)


def packet_capture_thread():
    if AsyncSniffer is None:
        with state_lock:
            capture_runtime["method"] = "none"
            capture_runtime["capture_running"] = False
            capture_runtime["capture_error"] = "Scapy not installed. Install requirements to enable live capture."
        return

    with state_lock:
        capture_runtime["method"] = "scapy"
        capture_runtime["capture_running"] = True
        capture_runtime["capture_error"] = ""

    sniffer = None
    try:
        sniffer = AsyncSniffer(prn=process_packet, store=False, iface=CAPTURE_INTERFACE)
        sniffer.start()
        while True:
            time.sleep(1)
            if not sniffer.running:
                break
    except PermissionError:
        with state_lock:
            capture_runtime["capture_running"] = False
            capture_runtime["capture_error"] = "Permission denied for packet capture. Run with sudo/root."
    except OSError as exc:
        with state_lock:
            capture_runtime["capture_running"] = False
            capture_runtime["capture_error"] = f"Packet capture failed: {exc}"
    except Exception as exc:  # pragma: no cover
        with state_lock:
            capture_runtime["capture_running"] = False
            capture_runtime["capture_error"] = f"Packet capture runtime error: {exc}"
    finally:
        if sniffer and sniffer.running:
            sniffer.stop()


def random_public_ip():
    while True:
        octets = [random.randint(1, 223), random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)]
        first, second = octets[0], octets[1]
        is_private = (
            first == 10
            or first == 127
            or (first == 192 and second == 168)
            or (first == 172 and 16 <= second <= 31)
        )
        if not is_private:
            ip = ".".join(str(o) for o in octets)
            return ip


def generate_fallback_alert_line():
    tpl = random.choice(FALLBACK_TEMPLATES)
    src = random_public_ip()
    dst = random.choice(["192.168.1.10", "192.168.1.23", "192.168.1.42"])
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([22, 53, 80, 443, 8080])
    return (
        f"[**] [{tpl['sid']}] {tpl['message']} [**] "
        f"[Priority: {tpl['priority']}] "
        f"{{{tpl['proto']}}} {src}:{src_port} -> {dst}:{dst_port}"
    )


def tail_snort_log():
    fallback_tick = 0

    while True:
        snort_log_file = resolve_snort_log_path()

        if not snort_log_file or not os.path.exists(snort_log_file):
            with state_lock:
                stats["snort_log_found"] = False
                stats["snort_log_path"] = snort_log_file
                stats["fallback_mode"] = ENABLE_FALLBACK_ALERTS

            if ENABLE_FALLBACK_ALERTS:
                fallback_tick += 1
                # Emit synthetic traffic at a controlled pace so the UI remains usable.
                if fallback_tick % random.randint(2, 4) == 0:
                    parse_and_store_alert(generate_fallback_alert_line())
                time.sleep(1)
                continue

            time.sleep(2)
            continue

        with state_lock:
            stats["snort_log_found"] = True
            stats["snort_log_path"] = snort_log_file
            stats["fallback_mode"] = False

        try:
            with open(snort_log_file, "r", encoding="utf-8", errors="ignore") as log_file:
                log_file.seek(0, os.SEEK_END)
                while True:
                    line = log_file.readline()
                    if not line:
                        time.sleep(0.2)
                        if not os.path.exists(snort_log_file):
                            break
                        continue
                    parse_and_store_alert(line.strip())
        except OSError as exc:
            print(f"Failed reading Snort log: {exc}")
            time.sleep(2)


def stats_emitter_thread():
    previous_total_alerts = 0
    previous_packets = 0
    previous_bytes = 0
    while True:
        time.sleep(1)
        with state_lock:
            current_total_alerts = total_alerts_seen
            current_packets = packets_seen_total
            current_bytes = packet_bytes_total

            packet_delta = max(0, current_packets - previous_packets)
            bytes_delta = max(0, current_bytes - previous_bytes)
            alert_delta = max(0, current_total_alerts - previous_total_alerts)

            previous_packets = current_packets
            previous_bytes = current_bytes
            previous_total_alerts = current_total_alerts

            stats["pps"] = packet_delta
            stats["bandwidth_mbps"] = round((bytes_delta * 8) / 1_000_000, 3)
            stats["engine_active"] = capture_runtime["capture_running"] or stats["snort_log_found"]
            stats["capture_interface"] = capture_runtime["capture_interface"]
            stats["capture_running"] = capture_runtime["capture_running"]
            stats["capture_error"] = capture_runtime["capture_error"]
            stats["capture_method"] = capture_runtime["method"]
            stats["last_packet_time"] = capture_runtime["last_packet_time"]

            snapshot = {
                "pps": stats["pps"],
                "threats": stats["threats"],
                "rules": stats["rules"],
                "bandwidth_mbps": stats["bandwidth_mbps"],
                "packets_seen_total": current_packets,
                "blocked_hosts": stats["blocked_hosts"],
                "host_count": len(stats["hosts"]),
                "snort_log_found": stats["snort_log_found"],
                "engine_active": stats["engine_active"],
                "capture_running": stats["capture_running"],
                "capture_error": stats["capture_error"],
                "capture_method": stats["capture_method"],
                "capture_interface": stats["capture_interface"],
                "last_packet_time": stats["last_packet_time"],
                "new_alerts": alert_delta,
                "protocols": copy.deepcopy(stats["protocols"]),
                "geo": copy.deepcopy(stats["geo"]),
            }

        socketio.emit("stats", snapshot)


@app.route("/")
def dashboard():
    return send_from_directory(".", "ids_dashboard_ui.html")


@app.route("/api/stats")
def get_stats():
    with state_lock:
        payload = copy.deepcopy(stats)
        payload["host_count"] = len(payload["hosts"])
    return jsonify(payload)


@app.route("/api/alerts")
def get_alerts():
    with state_lock:
        alerts = copy.deepcopy(stats["alerts"])
    return jsonify(alerts)


@app.route("/api/health")
def health():
    with state_lock:
        payload = {
            "ok": stats["engine_active"],
            "engine_active": stats["engine_active"],
            "snort_log_found": stats["snort_log_found"],
            "snort_log_path": stats["snort_log_path"],
            "fallback_mode": stats["fallback_mode"],
            "threats": stats["threats"],
            "capture_method": stats["capture_method"],
            "capture_interface": stats["capture_interface"],
            "capture_running": stats["capture_running"],
            "capture_error": stats["capture_error"],
            "last_packet_time": stats["last_packet_time"],
            "packets_seen_total": packets_seen_total,
        }
    return jsonify(payload)


if __name__ == "__main__":
    threading.Thread(target=tail_snort_log, daemon=True).start()
    threading.Thread(target=packet_capture_thread, daemon=True).start()
    threading.Thread(target=stats_emitter_thread, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=IDS_PORT, debug=False)
