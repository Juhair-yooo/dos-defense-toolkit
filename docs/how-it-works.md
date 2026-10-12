# How it works: attack class → detection signal → mitigation mechanism

## 1. SYN flood (protocol attack)

**Mechanism:** TCP handshake is SYN → SYN-ACK → ACK. The attacker sends SYNs
and never sends the final ACK. The server allocates connection state for
each and waits — enough concurrent half-open connections exhaust the
backlog queue (and, in older kernels without SYN cookies, memory).

**Detection signal:** a spike in sockets in `SYN_RECV` state, either in
total or concentrated on one source IP (`detect/syn_flood_monitor.py`,
sourced from `ss -tn state syn-recv`).

**Mitigation mechanism:** `tcp_syncookies` moves the connection state out of
kernel memory and into the SYN-ACK's sequence number itself (cryptographically
derived from source/dest IP+port, a timestamp, and a server secret). The
server only reconstructs real state when — and if — the final ACK arrives
with the matching sequence number, so an attacker who never sends that ACK
costs the server ~nothing beyond processing the packet. `iptables --limit`
and `connlimit` add defense-in-depth by capping SYN rate and concurrent
connections per source before they reach the connection table.

**Limitation:** spoofed-source floods (`hping3 --rand-source`) defeat
per-IP connlimit rules, since every packet claims a different source — SYN
cookies are what actually matters there, not the firewall layer.

## 2. Slowloris / slow-HTTP (protocol / application boundary)

**Mechanism:** open many HTTP connections, send headers (or body) a few
bytes at a time, just fast enough to avoid the server's read timeout. Each
connection ties up one worker/thread; with a small worker pool, a few
hundred slow connections exhausts it without needing much bandwidth.

**Detection signal:** many connections from one source IP that are both
long-lived *and* established (not just open) on the web port
(`detect/slowloris_detector.py`). Age alone would flag legitimate
keep-alive clients; count alone would flag NAT'd offices; the combination
is what's actually anomalous.

**Mitigation mechanism:** tightening `client_header_timeout` /
`client_body_timeout` in nginx closes the gap the attack relies on — a
connection that isn't sending data fast enough gets dropped well before it
can accumulate. This costs real clients nothing, since normal header/body
transmission happens in milliseconds.

## 3. Volumetric / amplification / botnet floods

**Mechanism:** overwhelm network capacity with sheer traffic volume, via
either reflection off misconfigured third-party servers (spoofed small
request to an open DNS/NTP/memcached server, large reply sent to the
victim) or a botnet of compromised devices sending traffic directly.

**Detection signal:** this is genuinely hard to detect meaningfully at the
single-server level — by the time packets are filterable locally, the
upstream link may already be saturated. `detect/conn_rate_monitor.py`'s
`--mode pcap` can show an abnormal aggregate new-connection rate, which is
useful as a confirmation signal, but volumetric floods are primarily a
network-capacity problem.

**Mitigation mechanism:** mostly happens upstream of anything a single
server can do — CDN/reverse-proxy absorption (Cloudflare, Akamai) and
anycast routing spread load across capacity far larger than any origin
server has. The actual *fix* for amplification specifically is closing the
open resolvers/amplifiers themselves, which is a third-party server
hygiene problem, not something the victim can remediate.

## 4. Application-layer floods

**Mechanism:** legitimate-looking requests aimed at an expensive endpoint
(search, report generation, anything hitting the DB hard), repeated until
the backend — not the network — falls over. Hardest to filter because each
individual request is indistinguishable from real traffic.

**Detection signal:** elevated request rate per source IP, especially
concentrated on known-expensive routes (`detect/conn_rate_monitor.py`;
nginx's own access log once `rate_limit.conf` is in place, since rejected
requests show up as `429`s).

**Mitigation mechanism:** `limit_req_zone` in nginx enforces a token-bucket
rate per client IP, with a stricter zone scoped to expensive endpoints
specifically. A WAF adds a layer for catching malformed/malicious payloads
on top of plain rate limiting. `fail2ban` watches for repeated `429`s and
escalates to a firewall-level ban for sources that keep tripping the limit.
