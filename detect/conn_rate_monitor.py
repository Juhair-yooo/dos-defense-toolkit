#!/usr/bin/env python3
"""
conn_rate_monitor.py

General-purpose "new connections per source IP per second" monitor, useful
for catching volumetric floods (including botnet-driven ones, where no
single trick like SYN-state or slow-drip applies — it's just raw request
volume from many sources) and simple single-source application-layer
floods.

Two capture modes:

  --mode ss     (default) Polls `ss -tn` every interval and diffs the
                connection set against the previous sample to find newly
                established connections. No special privileges needed
                beyond reading the socket table; works anywhere `ss` does.

  --mode pcap   Uses scapy to sniff SYN packets live on an interface for
                an exact per-second rate (more accurate, needs root and
                scapy installed: `pip install scapy --break-system-packages`).

Alerts (and logs) when any single source IP exceeds --rate-threshold new
connections within --window seconds. This script only observes traffic;
it does not send anything.

Usage:
    python3 conn_rate_monitor.py --mode ss --interval 1 --rate-threshold 30 --window 5
    sudo python3 conn_rate_monitor.py --mode pcap --iface eth0 --rate-threshold 50 --window 5
"""

import argparse
import logging
import subprocess
import sys
import time
from collections import defaultdict, deque


def sample_ss():
    cmd = ["ss", "-tn", "state", "established"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=True)
    except FileNotFoundError:
        logging.error("`ss` not found — install iproute2.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error("ss failed: %s", e.stderr.strip())
        return set()
    except subprocess.TimeoutExpired:
        logging.warning("ss timed out this cycle — skipping sample")
        return set()

    conns = set()
    for line in out.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        peer = parts[-1]
        if ":" not in peer:
            continue
        ip, _, p = peer.rpartition(":")
        conns.add((ip.strip("[]"), p))
    return conns


def run_ss_mode(args, log):
    prev = set()
    # per-IP deque of timestamps for new connections, for a sliding window rate
    events: dict[str, deque] = defaultdict(deque)
    alerted: set[str] = set()

    while True:
        now = time.monotonic()
        current = sample_ss()
        new_conns = current - prev
        prev = current

        for ip, _port in new_conns:
            events[ip].append(now)

        bad_now = set()
        for ip, dq in events.items():
            while dq and now - dq[0] > args.window:
                dq.popleft()
            if len(dq) >= args.rate_threshold:
                bad_now.add(ip)
                if ip not in alerted:
                    log.warning(
                        "HIGH CONNECTION RATE: %s opened %d new connections in the last %.0fs (threshold %d)",
                        ip, len(dq), args.window, args.rate_threshold,
                    )

        for ip in list(alerted):
            if ip not in bad_now:
                log.info("source %s rate back under threshold", ip)
        alerted = bad_now

        time.sleep(args.interval)


def run_pcap_mode(args, log):
    try:
        from scapy.all import sniff, TCP, IP  # type: ignore
    except ImportError:
        log.error("scapy not installed. Run: pip install scapy --break-system-packages")
        sys.exit(1)

    events: dict[str, deque] = defaultdict(deque)
    alerted: set[str] = set()

    def handle(pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        if not (pkt[TCP].flags & 0x02):  # SYN flag only — count new connection attempts
            return
        now = time.monotonic()
        ip = pkt[IP].src
        dq = events[ip]
        dq.append(now)
        while dq and now - dq[0] > args.window:
            dq.popleft()
        if len(dq) >= args.rate_threshold and ip not in alerted:
            alerted.add(ip)
            log.warning(
                "HIGH SYN RATE: %s sent %d SYNs in the last %.0fs (threshold %d)",
                ip, len(dq), args.window, args.rate_threshold,
            )
        elif len(dq) < args.rate_threshold and ip in alerted:
            alerted.discard(ip)
            log.info("source %s rate back under threshold", ip)

    log.info("sniffing SYN packets on %s (requires root)...", args.iface)
    sniff(iface=args.iface, filter="tcp", prn=handle, store=False)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["ss", "pcap"], default="ss")
    ap.add_argument("--iface", default="eth0", help="interface for --mode pcap (default: eth0)")
    ap.add_argument("--interval", type=float, default=1.0, help="poll interval for --mode ss (default: 1)")
    ap.add_argument("--window", type=float, default=5.0, help="sliding window in seconds (default: 5)")
    ap.add_argument("--rate-threshold", type=int, default=30,
                     help="new connections within the window to trigger an alert (default: 30)")
    ap.add_argument("--log", default="conn_rate.log", help="log file path (default: conn_rate.log)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(args.log), logging.StreamHandler(sys.stdout)],
    )
    log = logging.getLogger("conn_rate_monitor")
    log.info("conn_rate_monitor starting: mode=%s window=%ss rate_threshold=%d", args.mode, args.window, args.rate_threshold)

    try:
        if args.mode == "ss":
            run_ss_mode(args, log)
        else:
            run_pcap_mode(args, log)
    except KeyboardInterrupt:
        log.info("stopped")


if __name__ == "__main__":
    main()
