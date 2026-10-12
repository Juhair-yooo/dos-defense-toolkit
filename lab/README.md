# Lab: exercising the detectors and mitigations

Goal: generate each traffic pattern against a target **you own and control**
(a local VM, a container, or a test deployment of your own site — never a
third party or shared network) and confirm the `detect/` scripts fire and the
`mitigate/` configs reduce impact. Kali ships everything needed to generate
these patterns legitimately — no custom flood tooling required.

## Setup

- A target you control, ideally a separate VM on an isolated/host-only
  network (e.g. VirtualBox host-only adapter, or a cloud VM you provisioned
  specifically for this). Running this against the same machine you're
  monitoring from works too, but a separate box is closer to a realistic
  server/attacker split.
- Install the generators if not already present:
  ```bash
  sudo apt update
  sudo apt install hping3 slowhttptest apache2-utils
  ```

## 1. SYN flood — `hping3`

Terminal A (on the target): start the monitor.
```bash
sudo python3 detect/syn_flood_monitor.py --total-threshold 50 --per-ip-threshold 50
```

Terminal B (on your attacking VM): send a SYN flood at the target.
```bash
sudo hping3 -S -p 80 --flood --rand-source <target-ip>
```
`--rand-source` spoofs the source address per packet, so you'll also see
*why* per-IP connlimit rules alone don't fully solve a spoofed flood — the
kernel-level SYN cookie defense is what actually matters here. Stop with
Ctrl+C after confirming the monitor alerts; a sustained flood on a shared
network can disrupt other traffic.

Apply the mitigation and repeat:
```bash
sudo bash mitigate/iptables/syn_protection.sh
```
Re-run the hping3 command and compare `ss -s` socket summary / SYN_RECV
count before and after.

## 2. Slowloris — `slowhttptest`

Terminal A (target):
```bash
sudo python3 detect/slowloris_detector.py --port 80 --conn-threshold 10 --age-threshold 20
```

Terminal B (attacker VM):
```bash
slowhttptest -c 500 -H -g -o slowloris_results -i 10 -r 200 -t GET -u http://<target-ip>/ -x 24 -p 3
```
`-c 500` opens 500 connections, `-i 10` sends a header fragment every 10s —
tune down for a faster demo. Watch the detector log connections accumulate,
then confirm the web server becomes unresponsive to a normal `curl` from a
third terminal.

Apply `mitigate/nginx/slowloris_timeouts.conf`, reload nginx, and repeat —
connections should get closed out by the timeout well before they pile up.

## 3. Application-layer flood — `ab` / `wrk`

Terminal A (target):
```bash
python3 detect/conn_rate_monitor.py --mode ss --rate-threshold 20 --window 5
```

Terminal B (attacker VM):
```bash
ab -n 5000 -c 100 http://<target-ip>/search?q=test
# or, for more realistic HTTP/1.1 keep-alive load:
wrk -t4 -c200 -d30s http://<target-ip>/search?q=test
```
Point it at whatever endpoint in your app does the most work (DB query,
template render, etc.) — that's the realistic version of this attack, not
hammering a static file.

Apply `mitigate/nginx/rate_limit.conf` (scoped tightly to that endpoint),
reload nginx, repeat, and confirm you start seeing `429`s in the access log
and in the `fail2ban` jail (`fail2ban-client status dos-generic`) instead of
the backend falling over.

## Reading the results

For each test, note: how long until the detector alerted, what the server's
error rate/latency looked like before vs. after the mitigation, and what
log line/metric you'd actually want paged on in production. That mapping —
pattern → detection signal → response — is the useful artifact from this
lab, more than the specific thresholds, which you'll want to tune per
workload anyway.
