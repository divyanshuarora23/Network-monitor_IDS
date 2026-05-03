"""
=============================================================
  Real-Time Malicious Network Behaviour Detector
  Tools  : Python 3, Scapy
  Detects: Port Scanning | High-Frequency Requests
  Output : Console alerts + suspicious_ips.log
=============================================================
  HOW TO RUN (Windows – Administrator required for raw sockets)
    pip install scapy
    python network_monitor.py            # live capture
    python network_monitor.py --demo     # offline simulation (no root needed)
=============================================================
"""

import argparse
import sys
import os
from collections import defaultdict
from datetime import datetime
import threading
import time
import socket
import subprocess
import csv
import io

# ── Scapy import guard ──────────────────────────────────────
# Disable IPv6 routing before importing scapy to avoid a known
# Linux sandbox KeyError bug; on Windows this is a no-op.
os.environ.setdefault("SCAPY_IPV6_ENABLED", "0")
try:
    import scapy.config
    scapy.config.conf.ipv6_enabled = False          # suppress IPv6 noise
    scapy.config.conf.verb = 0                      # silent mode
    from scapy.all import sniff, IP, TCP, UDP       # type: ignore
    SCAPY_OK = True
except Exception as exc:
    SCAPY_OK = False
    SCAPY_ERR = str(exc)


# ══════════════════════════════════════════════════════════
#  CONFIGURATION  (tune these thresholds as needed)
# ══════════════════════════════════════════════════════════
PORT_SCAN_THRESHOLD   = 10    # unique dest-ports per IP in SCAN_WINDOW seconds
# High-frequency thresholds (per source IP within FREQ_WINDOW)
HIGH_FREQ_WARN_INBOUND   = 300
HIGH_FREQ_WARN_OUTBOUND  = 300
HIGH_FREQ_CRIT_INBOUND   = 1000
HIGH_FREQ_CRIT_OUTBOUND  = 1000
SCAN_WINDOW           = 5     # seconds to track distinct ports
FREQ_WINDOW           = 5     # seconds to track packet count
ALERT_COOLDOWN        = 10    # suppress repeated same-IP alerts for N seconds
LOG_FILE              = "suspicious_ips.log"
PROCESS_CACHE_TTL     = 5     # seconds to cache process lookups


# ══════════════════════════════════════════════════════════
#  STATE  (in-memory, thread-safe via threading.Lock)
# ══════════════════════════════════════════════════════════
lock               = threading.Lock()
port_tracker       = defaultdict(set)     # ip -> {dst_ports seen}
port_first_seen    = {}                   # ip -> timestamp of first port hit
freq_tracker       = defaultdict(int)     # ip -> packet count
freq_first_seen    = {}                   # ip -> timestamp of first packet
alerted_ips        = {}                   # ip -> last alert timestamp
total_packets      = 0
alert_counter      = 0
talker_counts      = defaultdict(int)     # src_ip -> packets seen
process_cache      = {}                   # flow-key -> (timestamp, process_label)
PROCESS_MAP_ENABLED = os.name == "nt"


# ══════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════

def now_str() -> str:
    return datetime.now().strftime("%b %d, %Y  %H:%M:%S")


def get_local_ipv4s() -> set[str]:
    """Best-effort discovery of local IPv4 addresses for direction tagging."""
    ips = {"127.0.0.1"}
    try:
        host = socket.gethostname()
        for ip in socket.gethostbyname_ex(host)[2]:
            if "." in ip:
                ips.add(ip)
    except Exception:
        pass
    return ips


LOCAL_IPV4S = get_local_ipv4s()


def classify_direction(src_ip: str, dst_ip: str) -> str:
    """Classify packet direction relative to local interfaces."""
    src_local = src_ip in LOCAL_IPV4S
    dst_local = dst_ip in LOCAL_IPV4S

    if src_local and not dst_local:
        return "OUTBOUND"
    if dst_local and not src_local:
        return "INBOUND"
    if src_local and dst_local:
        return "LOCAL"
    return "TRANSIT/UNKNOWN"


def _parse_endpoint(endpoint: str) -> tuple[str, int | None]:
    """Parse endpoint like 192.168.1.24:443 into (ip, port)."""
    endpoint = endpoint.strip()
    if ":" not in endpoint:
        return endpoint, None
    ip, port = endpoint.rsplit(":", 1)
    try:
        return ip, int(port)
    except ValueError:
        return ip, None


def _pid_to_process_label(pid: int) -> str:
    """Resolve a PID to an image name using tasklist (Windows)."""
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            text=True,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            errors="ignore",
        ).strip()
        if not out or out.startswith("INFO:"):
            return f"PID {pid}"
        row = next(csv.reader(io.StringIO(out)))
        name = row[0].strip('" ') if row else "unknown"
        return f"{name} (PID {pid})"
    except Exception:
        return f"PID {pid}"


def resolve_process_label(direction: str, proto: str,
                          src_ip: str, src_port: int | None,
                          dst_ip: str, dst_port: int | None) -> str:
    """Best-effort Windows process correlation for a packet flow."""
    if not PROCESS_MAP_ENABLED:
        return "N/A"
    if direction not in {"OUTBOUND", "INBOUND"}:
        return "N/A"
    if src_port is None or dst_port is None:
        return "N/A"

    if direction == "OUTBOUND":
        local_ip, local_port = src_ip, src_port
        remote_ip, remote_port = dst_ip, dst_port
    else:
        local_ip, local_port = dst_ip, dst_port
        remote_ip, remote_port = src_ip, src_port

    flow_key = (direction, proto, local_ip, local_port, remote_ip, remote_port)
    cached = process_cache.get(flow_key)
    if cached and (time.time() - cached[0] <= PROCESS_CACHE_TTL):
        return cached[1]

    proto_cmd = proto.lower()
    if proto_cmd not in {"tcp", "udp"}:
        return "N/A"

    label = "UNKNOWN"
    try:
        out = subprocess.check_output(
            ["netstat", "-ano", "-p", proto_cmd],
            text=True,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            errors="ignore",
        )
        for line in out.splitlines():
            parts = line.split()
            if proto_cmd == "tcp" and len(parts) >= 5 and parts[0].upper() == "TCP":
                local_ep = parts[1]
                remote_ep = parts[2]
                pid_raw = parts[-1]
                l_ip, l_port = _parse_endpoint(local_ep)
                r_ip, r_port = _parse_endpoint(remote_ep)
                if (l_ip, l_port, r_ip, r_port) == (local_ip, local_port, remote_ip, remote_port):
                    if pid_raw.isdigit():
                        label = _pid_to_process_label(int(pid_raw))
                    break
            elif proto_cmd == "udp" and len(parts) >= 4 and parts[0].upper() == "UDP":
                local_ep = parts[1]
                pid_raw = parts[-1]
                l_ip, l_port = _parse_endpoint(local_ep)
                if (l_ip, l_port) == (local_ip, local_port):
                    if pid_raw.isdigit():
                        label = _pid_to_process_label(int(pid_raw))
                    break
    except Exception:
        label = "UNKNOWN"

    process_cache[flow_key] = (time.time(), label)
    return label


def save_alert(alert_type: str, src_ip: str, dst_ip: str,
               direction: str, proto: str,
               src_port: int | None, dst_port: int | None,
               proc_label: str, detail: str) -> None:
    """Append a line to the log file."""
    flow = f"{src_ip}:{src_port if src_port is not None else '-'} -> {dst_ip}:{dst_port if dst_port is not None else '-'}"
    with open(LOG_FILE, "a") as f:
        f.write(
            f"[{now_str()}] {alert_type:<12} | DIR: {direction:<15} | PROTO: {proto:<4} | PROC: {proc_label:<25} | FLOW: {flow:<45} | {detail}\n"
        )


def print_alert(alert_type: str, src_ip: str, dst_ip: str,
                direction: str, proto: str,
                src_port: int | None, dst_port: int | None,
                proc_label: str, severity: str, detail: str) -> None:
    """Pretty-print a console alert."""
    global alert_counter
    alert_counter += 1
    bar = "=" * 56
    flow = f"{src_ip}:{src_port if src_port is not None else '-'} -> {dst_ip}:{dst_port if dst_port is not None else '-'}"
    print(f"\n{bar}")
    print(f"  !! ALERT #{alert_counter}  —  {severity}")
    print(f"  Type      : {alert_type}")
    print(f"  Direction : {direction}")
    print(f"  Protocol  : {proto}")
    print(f"  Process   : {proc_label}")
    print(f"  Flow      : {flow}")
    print(f"  Detail    : {detail}")
    print(f"  Time      : {now_str()}")
    print(f"{bar}")


def can_alert(alert_key: str) -> bool:
    """Return True only if cooldown has passed for this alert key."""
    t = alerted_ips.get(alert_key, 0)
    if time.time() - t >= ALERT_COOLDOWN:
        alerted_ips[alert_key] = time.time()
        return True
    return False


def expire_old(tracker_dict: dict, first_seen_dict: dict,
               window: int, src_ip: str) -> None:
    """Reset counters for an IP if its window has expired."""
    if src_ip in first_seen_dict:
        if time.time() - first_seen_dict[src_ip] > window:
            del tracker_dict[src_ip]
            del first_seen_dict[src_ip]


# ══════════════════════════════════════════════════════════
#  DETECTION LOGIC
# ══════════════════════════════════════════════════════════

def analyse(src_ip: str, dst_ip: str,
            proto: str, src_port: int | None,
            dst_port: int | None) -> None:
    """Core detection: port scan + high-frequency checks."""
    global freq_tracker, port_tracker, talker_counts

    now = time.time()
    direction = classify_direction(src_ip, dst_ip)
    talker_counts[src_ip] += 1

    # ── High-frequency detection ───────────────────────────
    expire_old(freq_tracker, freq_first_seen, FREQ_WINDOW, src_ip)
    if src_ip not in freq_first_seen:
        freq_first_seen[src_ip] = now
    freq_tracker[src_ip] += 1

    if direction == "INBOUND":
        warn_threshold = HIGH_FREQ_WARN_INBOUND
        crit_threshold = HIGH_FREQ_CRIT_INBOUND
    elif direction == "OUTBOUND":
        warn_threshold = HIGH_FREQ_WARN_OUTBOUND
        crit_threshold = HIGH_FREQ_CRIT_OUTBOUND
    else:
        warn_threshold = HIGH_FREQ_WARN_OUTBOUND
        crit_threshold = HIGH_FREQ_CRIT_OUTBOUND

    count = freq_tracker[src_ip]

    if count >= crit_threshold and can_alert(f"{src_ip}:HIGH-FREQ:CRITICAL"):
        proc_label = resolve_process_label(direction, proto, src_ip, src_port,
                                           dst_ip, dst_port)
        detail = (f"{count} packets in {FREQ_WINDOW}s "
                  f"(warn={warn_threshold}, critical={crit_threshold})")
        print_alert("HIGH-FREQUENCY REQUEST", src_ip, dst_ip,
                    direction, proto, src_port, dst_port,
                    proc_label, "CRITICAL", detail)
        save_alert("HIGH-FREQ", src_ip, dst_ip, direction,
                   proto, src_port, dst_port, proc_label, detail)
    elif count >= warn_threshold and can_alert(f"{src_ip}:HIGH-FREQ:WARNING"):
        proc_label = resolve_process_label(direction, proto, src_ip, src_port,
                                           dst_ip, dst_port)
        detail = (f"{count} packets in {FREQ_WINDOW}s "
                  f"(warn={warn_threshold}, critical={crit_threshold})")
        print_alert("HIGH-FREQUENCY REQUEST", src_ip, dst_ip,
                    direction, proto, src_port, dst_port,
                    proc_label, "WARNING", detail)
        save_alert("HIGH-FREQ", src_ip, dst_ip, direction,
                   proto, src_port, dst_port, proc_label, detail)

    # ── Port-scan detection ────────────────────────────────
    if dst_port is not None:
        expire_old(port_tracker, port_first_seen, SCAN_WINDOW, src_ip)
        if src_ip not in port_first_seen:
            port_first_seen[src_ip] = now
        port_tracker[src_ip].add(dst_port)

        unique = len(port_tracker[src_ip])
        if unique >= PORT_SCAN_THRESHOLD and can_alert(f"{src_ip}:PORT-SCAN"):
            proc_label = resolve_process_label(direction, proto, src_ip, src_port,
                                               dst_ip, dst_port)
            detail = (f"{unique} distinct ports probed in "
                      f"{SCAN_WINDOW}s (threshold={PORT_SCAN_THRESHOLD})")
            print_alert("PORT SCAN DETECTED", src_ip, dst_ip,
                        direction, proto, src_port, dst_port,
                        proc_label, "CRITICAL", detail)
            save_alert("PORT-SCAN", src_ip, dst_ip, direction,
                       proto, src_port, dst_port, proc_label, detail)


# ══════════════════════════════════════════════════════════
#  PACKET CALLBACK  (called by Scapy for every captured packet)
# ══════════════════════════════════════════════════════════

def packet_handler(pkt) -> None:
    global total_packets

    if not pkt.haslayer(IP):
        return

    src_ip   = pkt[IP].src
    dst_ip   = pkt[IP].dst
    proto    = "IP"
    src_port = None
    dst_port = None

    if pkt.haslayer(TCP):
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    with lock:
        total_packets += 1
        if total_packets % 50 == 0:
            print(f"  [live] {now_str()} — {total_packets} packets captured so far",
                  end="\r")
        analyse(src_ip, dst_ip, proto, src_port, dst_port)


# ══════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════

def print_summary() -> None:
    top = sorted(talker_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    print(f"""
{'=' * 56}
            SESSION SUMMARY
  Total packets captured : {total_packets:<10}
  Total alerts triggered : {alert_counter:<10}
  Log file               : {LOG_FILE}
{'=' * 56}""")

    if top:
        print("  Top source talkers:")
        for ip, count in top:
            pct = (count / total_packets * 100) if total_packets else 0
            print(f"    - {ip:<18} {count:>6} packets ({pct:5.1f}%)")
    else:
        print("  Top source talkers: no traffic captured")


# ══════════════════════════════════════════════════════════
#  LIVE CAPTURE MODE  (requires admin / root)
# ══════════════════════════════════════════════════════════

def start_live_capture(iface=None) -> None:
    if not SCAPY_OK:
        print(f"[ERROR] Scapy failed to load: {SCAPY_ERR}")
        print("        Run: pip install scapy  (and re-try as Administrator)")
        sys.exit(1)

    print("=" * 56)
    print("   Real-Time Network Malicious Behaviour Detector")
    print("=" * 56)
    print(f"  Thresholds  : port-scan={PORT_SCAN_THRESHOLD} ports/{SCAN_WINDOW}s")
    print(f"                high-freq inbound warn={HIGH_FREQ_WARN_INBOUND}, critical={HIGH_FREQ_CRIT_INBOUND} pkts/{FREQ_WINDOW}s")
    print(f"                high-freq outbound warn={HIGH_FREQ_WARN_OUTBOUND}, critical={HIGH_FREQ_CRIT_OUTBOUND} pkts/{FREQ_WINDOW}s")
    print(f"  Log file    : {LOG_FILE}")
    if iface:
        print(f"  Interface   : {iface}")
    print("  Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=iface,
            prn=packet_handler,
            store=False,         # don't accumulate packets in RAM
            filter="ip",        # BPF filter — IPv4 only
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n[ERROR] Raw-socket capture needs Administrator privileges.")
        print("        Re-run this script as Administrator (Windows) or root (Linux).")
    finally:
        print_summary()


# ══════════════════════════════════════════════════════════
#  OFFLINE DEMO MODE  (no root, no live traffic needed)
# ══════════════════════════════════════════════════════════

def _make_fake_pkt(src: str, dport: int):
    """Return a lightweight mock packet object for demo mode."""
    class FakeLayer:
        def __init__(self, dport): self.dport = dport
    class FakePkt:
        def __init__(self, src, dport):
            self._src  = src
            self._tcp  = FakeLayer(dport)
        def haslayer(self, layer):
            if layer.__name__ == "IP":  return True
            if layer.__name__ == "TCP": return True
            return False
        def __getitem__(self, layer):
            if layer.__name__ == "IP":
                class _IP: src = self._src
                return _IP()
            if layer.__name__ == "TCP":
                return self._tcp
    return FakePkt(src, dport)


def run_demo() -> None:
    """
    Simulate two attack scenarios without touching the network:
      1. Port scan  — one attacker hits 15 ports in quick succession
      2. High-freq  — another attacker floods 60 packets in 5 seconds
    """
    print("=" * 56)
    print("   DEMO MODE — offline simulation")
    print("=" * 56)
    print("  Scenario 1 : Port scan   (attacker 192.168.1.100)")
    print("  Scenario 2 : High-freq   (attacker 10.0.0.55)\n")

    LOCAL_IPV4S.add("192.168.1.24")

    # Scenario 1 — port scan
    SCANNER_IP = "192.168.1.100"
    print(f"[*] Simulating port scan from {SCANNER_IP} …")
    for port in range(20, 36):          # 16 ports — above threshold of 10
        pkt = _make_fake_pkt(SCANNER_IP, port)
        with lock:
            global total_packets
            total_packets += 1
            analyse(SCANNER_IP, "192.168.1.24", "TCP", 40000, port)
        time.sleep(0.05)

    print(f"\n[*] Simulating high-frequency flood from 10.0.0.55 …")
    FLOODER_IP = "10.0.0.55"
    for _ in range(1100):               # enough to trigger warning + critical
        pkt = _make_fake_pkt(FLOODER_IP, 80)
        with lock:
            total_packets += 1
            analyse(FLOODER_IP, "192.168.1.24", "TCP", 50000, 80)
        time.sleep(0.002)

    print_summary()

    # Show the log file contents
    print(f"\n{'─' * 56}")
    print(f"  Contents of {LOG_FILE}:")
    print(f"{'─' * 56}")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            for line in f:
                print(" ", line, end="")
    else:
        print("  (no alerts were triggered — adjust thresholds?)")
    print()


# ══════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════

def main():
    global PROCESS_MAP_ENABLED
    global HIGH_FREQ_WARN_INBOUND, HIGH_FREQ_WARN_OUTBOUND
    global HIGH_FREQ_CRIT_INBOUND, HIGH_FREQ_CRIT_OUTBOUND

    parser = argparse.ArgumentParser(
        description="Real-time malicious network behaviour detector (Scapy)"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run offline simulation without admin rights or live traffic"
    )
    parser.add_argument(
        "--iface",
        default=None,
        metavar="INTERFACE",
        help="Network interface to sniff on (e.g. Ethernet, Wi-Fi)"
    )
    parser.add_argument(
        "--no-proc-map",
        action="store_true",
        help="Disable Windows process correlation for alert flows"
    )
    parser.add_argument(
        "--hf-warn-in",
        type=int,
        default=HIGH_FREQ_WARN_INBOUND,
        help="Inbound high-frequency warning threshold (pkts/FREQ_WINDOW)"
    )
    parser.add_argument(
        "--hf-warn-out",
        type=int,
        default=HIGH_FREQ_WARN_OUTBOUND,
        help="Outbound high-frequency warning threshold (pkts/FREQ_WINDOW)"
    )
    parser.add_argument(
        "--hf-crit-in",
        type=int,
        default=HIGH_FREQ_CRIT_INBOUND,
        help="Inbound high-frequency critical threshold (pkts/FREQ_WINDOW)"
    )
    parser.add_argument(
        "--hf-crit-out",
        type=int,
        default=HIGH_FREQ_CRIT_OUTBOUND,
        help="Outbound high-frequency critical threshold (pkts/FREQ_WINDOW)"
    )
    args = parser.parse_args()

    if args.no_proc_map:
        PROCESS_MAP_ENABLED = False

    HIGH_FREQ_WARN_INBOUND = max(1, args.hf_warn_in)
    HIGH_FREQ_WARN_OUTBOUND = max(1, args.hf_warn_out)
    HIGH_FREQ_CRIT_INBOUND = max(HIGH_FREQ_WARN_INBOUND, args.hf_crit_in)
    HIGH_FREQ_CRIT_OUTBOUND = max(HIGH_FREQ_WARN_OUTBOUND, args.hf_crit_out)

    if args.demo:
        run_demo()
    else:
        start_live_capture(iface=args.iface)


if __name__ == "__main__":
    main()