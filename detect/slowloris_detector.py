#!/usr/bin/env python3
"""
slowloris_detector.py

Slowloris (and similar slow-HTTP attacks) work by opening many HTTP
connections and trickling bytes just fast enough to avoid a read timeout,
tying up the server's worker/thread pool without much bandwidth.

The network-level signature: a source IP holding many *established*
connections to your web port, each alive far longer than a normal
request/response cycle. This script samples `ss -tn` on an interval,
tracks how long each (peer IP, peer port) pair has been seen continuously
established, and alerts when a single IP exceeds both a connection-count
and an age threshold at once (age alone catches keep-alive legitimate
clients; count alone catches NAT'd offices — the combination is what's
actually suspicious).

Read-only: inspects the connection table only, sends nothing.

Usage:
    sudo python3 slowloris_detector.py --port 80 [--interval 3]
                                        [--conn-threshold 20] [--age-threshold 60]
                                        [--log slowloris.log]
"""

import argparse
import logging
import subprocess
import sys
import time
from collections import defaultdict

STATE_FILE_NOTE = "in-memory only; restart clears history"


def sample(port: int):
    """Return the set of (peer_ip, peer_port) pairs currently ESTABLISHED on `port`."""
    cmd = ["ss", "-tn", "state", "established", f"( dport = :{port} or sport = :{port} )"]
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
        ip = ip.strip("[]")
        conns.add((ip, p))
    return conns


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=80, help="web server port to watch (default: 80)")
    ap.add_argument("--interval", type=float, default=3.0, help="seconds between samples (default: 3)")
    ap.add_argument("--conn-threshold", type=int, default=20,
                     help="min simultaneous connections from one IP to consider (default: 20)")
    ap.add_argument("--age-threshold", type=float, default=60.0,
                     help="min seconds a connection must persist to count as 'slow' (default: 60)")
    ap.add_argument("--log", default="slowloris.log", help="log file path (default: slowloris.log)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(args.log), logging.StreamHandler(sys.stdout)],
    )

    logging.info(
        "slowloris_detector starting: port=%d interval=%ss conn_threshold=%d age_threshold=%ss (%s)",
        args.port, args.interval, args.conn_threshold, args.age_threshold, STATE_FILE_NOTE,
    )

    # first_seen[(ip, port)] = monotonic timestamp when we first observed this socket
    first_seen: dict[tuple[str, str], float] = {}
    already_alerted: set[str] = set()

    try:
        while True:
            now = time.monotonic()
            current = sample(args.port)

            # drop sockets that closed since last sample
            for key in list(first_seen):
                if key not in current:
                    del first_seen[key]

            # record new sockets
            for key in current:
                first_seen.setdefault(key, now)

            # tally long-lived connections per source IP
            per_ip_old = defaultdict(int)
            for (ip, _port), ts in first_seen.items():
                if now - ts >= args.age_threshold:
                    per_ip_old[ip] += 1

            still_bad = set()
            for ip, count in per_ip_old.items():
                if count >= args.conn_threshold:
                    still_bad.add(ip)
                    if ip not in already_alerted:
                        logging.warning(
                            "SLOWLORIS SUSPECTED: %s holds %d connections each open >= %.0fs on port %d",
                            ip, count, args.age_threshold, args.port,
                        )

            # clear alert state for IPs that are no longer offending (recovered)
            for ip in list(already_alerted):
                if ip not in still_bad:
                    logging.info("source %s no longer exceeds thresholds — clearing alert state", ip)
            already_alerted = still_bad

            time.sleep(args.interval)
    except KeyboardInterrupt:
        logging.info("stopped")


if __name__ == "__main__":
    main()
