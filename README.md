# DoS Defense Toolkit

A set of **detection and mitigation** tools for the three common denial-of-service
patterns — SYN floods, Slowloris-style slow connections, and application-layer
request floods — built for Kali Linux and meant to be run against **infrastructure
you own or are explicitly authorized to test** (your own VM, your own web app, a
lab environment).

This repo does **not** contain attack/flooding code. It contains:

1. **Detection scripts** — watch live connection state and request patterns, flag
   abuse, and log/alert on it.
2. **Mitigation configs** — kernel (`sysctl`), firewall (`iptables`), reverse proxy
   (`nginx`), and intrusion-prevention (`fail2ban`) configuration that hardens a
   host against these patterns.
3. **A lab guide** — how to *generate* the traffic patterns using Kali's existing,
   maintained tools (`hping3`, `slowhttptest`, `ab`/`wrk`) against your own test
   target, so you can watch the detectors fire and confirm the mitigations work.

## Why split it this way

Detection and mitigation logic is reusable defensive engineering — the same code
protects any server, regardless of who's attacking it or why. Traffic-generation
tooling is dual-use in a much flatter sense: a working flooder is equally usable
against the operator's own test box or against a stranger's production site, and
nothing in the code itself can tell those cases apart. Kali already ships
well-maintained, purpose-built generators for this (see `lab/README.md`), so this
toolkit focuses on the side that's actually worth having pre-built: knowing when
you're under one of these patterns and having the config ready to blunt it.

## Layout

```
dos-defense-toolkit/
├── detect/
│   ├── syn_flood_monitor.py      # watches SYN_RECV backlog via `ss`, alerts on spikes
│   ├── slowloris_detector.py     # flags many long-lived, low-byte-rate connections per IP
│   └── conn_rate_monitor.py      # general new-connections-per-IP rate monitor + log
├── mitigate/
│   ├── iptables/
│   │   ├── syn_protection.sh     # SYN cookies, per-IP SYN rate limiting, connlimit
│   │   └── README.md
│   ├── nginx/
│   │   ├── rate_limit.conf       # limit_req / limit_conn zones for app-layer floods
│   │   └── slowloris_timeouts.conf
│   └── fail2ban/
│       ├── filter.d/dos-generic.conf
│       └── jail.d/dos-generic.conf
├── lab/
│   └── README.md                 # how to test this against your own box with hping3/slowhttptest/ab
└── docs/
    └── how-it-works.md           # protocol-level explanation of each attack class and why the defense works
```

## Quick start

```bash
# 1. Detection (run on the server you're protecting)
sudo python3 detect/syn_flood_monitor.py
sudo python3 detect/slowloris_detector.py --port 80
python3 detect/conn_rate_monitor.py --iface eth0

# 2. Mitigation (apply once, review thresholds first)
sudo bash mitigate/iptables/syn_protection.sh
sudo cp mitigate/nginx/*.conf /etc/nginx/conf.d/
sudo cp mitigate/fail2ban/filter.d/dos-generic.conf /etc/fail2ban/filter.d/
sudo cp mitigate/fail2ban/jail.d/dos-generic.conf /etc/fail2ban/jail.d/
sudo systemctl reload nginx fail2ban

# 3. Lab — generate the patterns against your OWN test target and watch it work
see lab/README.md
```

## Scope / disclaimer

Educational use against systems you own or are authorized to test. The detection
scripts are read-only (they inspect kernel connection tables and logs); the
mitigation configs change local firewall/proxy behavior only. Nothing here sends
traffic to a remote host.
