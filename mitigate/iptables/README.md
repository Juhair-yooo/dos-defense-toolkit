# iptables / sysctl SYN flood mitigation

`syn_protection.sh` applies two layers of defense:

| Layer | Mechanism | What it stops |
|---|---|---|
| Kernel | `tcp_syncookies=1` | Server stops allocating real state for half-open connections once the backlog is full — a flood of unfinished handshakes stops costing memory/CPU |
| Kernel | `tcp_synack_retries=2`, `tcp_max_syn_backlog=4096` | Half-open sockets get freed faster, and legitimate bursts don't trigger cookie fallback unnecessarily |
| Firewall | `limit`-matched `SYN_FLOOD` chain | Caps new SYNs per source IP to 10/s (burst 20) before they ever reach the connection table |
| Firewall | `connlimit` on ports 80/443 | Caps simultaneous established connections per source IP to 60 — also helps against Slowloris-style hoarding |

## Running it

```bash
sudo bash syn_protection.sh --dry-run   # preview every command first
sudo bash syn_protection.sh             # apply
```

## Persisting across reboots

sysctl values set with `sysctl -w` are runtime-only. To persist:

```bash
sudo tee /etc/sysctl.d/99-syn-protection.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_fin_timeout = 15
EOF
sudo sysctl --system
```

iptables rules need saving too (Debian/Kali):

```bash
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

## Undoing it

```bash
sudo iptables -D INPUT -p tcp --syn -j SYN_FLOOD
sudo iptables -F SYN_FLOOD
sudo iptables -X SYN_FLOOD
sudo iptables -D INPUT -p tcp --syn --dport 80  -m connlimit --connlimit-above 60 --connlimit-mask 32 -j DROP
sudo iptables -D INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 60 --connlimit-mask 32 -j DROP
```

## Tuning

The 10/s SYN rate and 60-connection cap are defaults for a small/medium
single-server site. If you're behind a CDN/reverse proxy, these limits should
apply to the proxy's own backend connections to origin, not to raw internet
traffic (the CDN already absorbs the bulk of a real flood upstream — see the
top-level README's note on where mitigation actually belongs for amplification
attacks).
