#!/usr/bin/env python3
"""
syn_flood_monitor.py

Watches the kernel's TCP connection table for a SYN_RECV backlog spike —
the signature of a SYN flood (attacker sends SYNs, never completes the
handshake, server holds half-open connections until they time out).

Read-only: shells out to `ss -tn state syn-recv` on an interval, counts
half-open connections (total, and per source IP), and alerts when either
crosses a threshold. No packets are sent by this script.

Usage:
    sudo python3 syn_flood_monitor.py [--interval 2] [--total-threshold 200]
                                       [--per-ip-threshold 50] [--log syn_flood.log]

Requires: iproute2 (`ss`), root (to see all sockets reliably).
"""

import argparse
import logging
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone

SS_CMD = ["ss", "-tn", "state", "syn-recv"]

# Matches the local/peer address:port columns `ss` prints; we only need
# the peer (remote) address, which is column 4 in `ss -tn` output.
ADDR_RE = re.compile(r"^(.*):(\d+|\*)$")


def parse_peer_ip(line: str) -> str | None:
    """Extract the remote IP from one `ss -tn state syn-recv` output line."""
    parts = line.split()
    if len(parts) < 4:
        return None
    peer = parts[-1]  # last column is Peer Address:Port
    m = ADDR_RE.match(peer)
    if not m:
        return None
    ip = m.group(1)
    # Strip IPv6 brackets if present, e.g. [::ffff:1.2.3.4]
    return ip.strip("[]")


def sample() -> Counter:
    """Run `ss` once and return a Counter of SYN_RECV connections per peer IP."""
    try:
        out = subprocess.run(SS_CMD, capture_output=True, text=True, timeout=5, check=True)
    except FileNotFoundError:
        logging.error("`ss` not found — install iproute2.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error("ss failed: %s", e.stderr.strip())
        return Counter()
    except subprocess.TimeoutExpired:
        logging.warning("ss timed out this cycle — skipping sample")
        return Counter()

    counts: Counter = Counter()
    lines = out.stdout.splitlines()
    # First line is a header ("State Recv-Q Send-Q Local Address:Port Peer Address:Port")
    for line in lines[1:]:
        ip = parse_peer_ip(line)
        if ip:
            counts[ip] += 1
    return counts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between samples (default: 2)")
    ap.add_argument("--total-threshold", type=int, default=200,
                     help="alert if total SYN_RECV sockets exceed this (default: 200)")
    ap.add_argument("--per-ip-threshold", type=int, default=50,
                     help="alert if a single source IP holds this many half-open conns (default: 50)")
    ap.add_argument("--log", default="syn_flood.log", help="log file path (default: syn_flood.log)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(args.log), logging.StreamHandler(sys.stdout)],
    )

    logging.info(
        "syn_flood_monitor starting: interval=%ss total_threshold=%d per_ip_threshold=%d",
        args.interval, args.total_threshold, args.per_ip_threshold,
    )

    try:
        while True:
            counts = sample()
            total = sum(counts.values())

            if total >= args.total_threshold:
                top = counts.most_common(5)
                logging.warning(
                    "SYN FLOOD SUSPECTED: %d half-open connections (threshold %d). Top sources: %s",
                    total, args.total_threshold, top,
                )

            for ip, n in counts.items():
                if n >= args.per_ip_threshold:
                    logging.warning(
                        "Source %s holds %d half-open connections (threshold %d) — likely spoofed-SYN source or single-origin flood",
                        ip, n, args.per_ip_threshold,
                    )

            if total == 0 or (total and total < args.total_threshold):
                logging.debug("ok: %d half-open connections", total)

            time.sleep(args.interval)
    except KeyboardInterrupt:
        logging.info("stopped at %s", datetime.now(timezone.utc).isoformat())


if __name__ == "__main__":
    main()
