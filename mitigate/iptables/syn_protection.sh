#!/usr/bin/env bash
#
# syn_protection.sh — SYN flood mitigation via sysctl + iptables.
#
# Two layers:
#   1. SYN cookies: the kernel stops allocating real connection state for
#      incoming SYNs once the backlog queue fills, and instead encodes the
#      state into the SYN-ACK sequence number itself. The real state is only
#      reconstructed if the final ACK comes back — so a flood of SYNs that
#      never complete the handshake costs the kernel ~nothing per packet.
#   2. iptables rate limiting + per-IP connection limits as defense in depth
#      in front of that, so you're not relying on SYN cookies alone.
#
# Review the thresholds below before running in production — they're sane
# defaults for a small-to-medium web server, not a one-size-fits-all.
#
# Usage: sudo bash syn_protection.sh [--dry-run]

set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

run() {
  echo "+ $*"
  if ! $DRY_RUN; then
    "$@"
  fi
}

if [[ $EUID -ne 0 && "$DRY_RUN" == "false" ]]; then
  echo "Must run as root (or pass --dry-run to preview)." >&2
  exit 1
fi

echo "== 1. Kernel-level SYN flood protection (sysctl) =="

# Enable SYN cookies: kernel falls back to cookie-based handshake once the
# SYN backlog for a socket is full, instead of dropping new SYNs or
# exhausting memory on half-open state.
run sysctl -w net.ipv4.tcp_syncookies=1

# Increase the SYN backlog queue so legitimate bursts (e.g. a sudden spike
# in real users) don't trigger cookie fallback unnecessarily.
run sysctl -w net.ipv4.tcp_max_syn_backlog=4096

# Reduce SYN-ACK retransmits: default is 5 retries (~taking over a minute to
# give up on each half-open socket). Lowering this frees half-open slots
# faster during a flood.
run sysctl -w net.ipv4.tcp_synack_retries=2

# Shrink how long a socket stays in FIN-WAIT / TIME-WAIT-adjacent states that
# can also be exhausted by abusive clients.
run sysctl -w net.ipv4.tcp_fin_timeout=15

echo
echo "== 2. iptables: per-IP SYN rate limiting =="

# New chain so this is easy to flush/inspect independently of other rules.
run iptables -N SYN_FLOOD 2>/dev/null || true
run iptables -F SYN_FLOOD

# Allow up to 10 new SYNs/sec per source, burst 20, to the SYN_FLOOD chain;
# anything over that from the same source gets dropped before it reaches
# the connection table at all.
run iptables -A SYN_FLOOD -m limit --limit 10/s --limit-burst 20 -j RETURN
run iptables -A SYN_FLOOD -j DROP

# Route new TCP SYNs through the chain above.
run iptables -C INPUT -p tcp --syn -j SYN_FLOOD 2>/dev/null || \
  run iptables -I INPUT -p tcp --syn -j SYN_FLOOD

echo
echo "== 3. iptables: cap simultaneous connections per source IP =="

# No single IP gets more than 60 concurrent established connections to the
# web port — catches both single-source floods and Slowloris-style
# connection hoarding. Adjust 60 upward if you expect NAT'd offices/proxies
# as legitimate traffic.
for PORT in 80 443; do
  run iptables -C INPUT -p tcp --syn --dport "$PORT" -m connlimit --connlimit-above 60 --connlimit-mask 32 -j DROP 2>/dev/null || \
    run iptables -I INPUT -p tcp --syn --dport "$PORT" -m connlimit --connlimit-above 60 --connlimit-mask 32 -j DROP
done

echo
echo "Done. Current SYN_FLOOD chain:"
$DRY_RUN || iptables -L SYN_FLOOD -v -n

cat <<'EOF'

NOTE: sysctl changes above are runtime-only and revert on reboot. To persist,
add the same keys/values to /etc/sysctl.d/99-syn-protection.conf and run
`sysctl --system`. iptables rules likewise need `iptables-save` (or
netfilter-persistent on Debian/Kali) to survive a reboot.
EOF
