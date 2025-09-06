# VPN and Upload Path Performance Tests

This guide documents how to measure throughput end‑to‑end and repeat the firewall and server steps when revisiting performance.

Contents:
- WireGuard tunnel tests (VPS ↔ aibox)
- Client → VPS (public Internet) tests
- nginx + Runegate sanity checklist
- Estimating upload time
- Cleanup and useful tuning

Assumptions:
- VPS wg0: `10.0.0.1`
- aibox wg0: `10.0.0.2`
- iperf3 default port: `5201`

---

## 1) WireGuard Tunnel Tests (no public ports)

Runs entirely over wg0. No router/NAT forwards required.

### 1.1 aibox UFW rules (choose one variant)

Basic (allow any WG peer):

```bash
sudo ufw allow in on wg0 to any port 5201 proto tcp
sudo ufw allow in on wg0 to any port 5201 proto udp
```

Tighter (only from VPS):

```bash
sudo ufw allow in on wg0 from 10.0.0.1 to any port 5201 proto tcp
sudo ufw allow in on wg0 from 10.0.0.1 to any port 5201 proto udp
```

List/remove rules later:

```bash
sudo ufw status numbered
sudo ufw delete <number>
```

### 1.2 Start iperf3 server on aibox (bind to WG IP)

```bash
iperf3 -s -B 10.0.0.2   # Ctrl+C to stop
```

### 1.3 TCP throughput (VPS → aibox and reverse)

```bash
# VPS -> aibox: 4 streams, 30s
iperf3 -c 10.0.0.2 -B 10.0.0.1 -t 30 -P 4

# Reverse (aibox -> VPS)
iperf3 -c 10.0.0.2 -B 10.0.0.1 -t 30 -P 4 -R
```

Interpretation: The `SUM receiver` Mbps is the effective tunnel capacity in that direction.

### 1.4 UDP sanity (loss/jitter)

Use a safe datagram size below inner MTU (e.g., 1200 bytes for inner MTU ~1380):

```bash
# VPS -> aibox, 400 Mbit/s, 30s, 1200-byte packets
iperf3 -u -c 10.0.0.2 -B 10.0.0.1 -b 400M -t 30 -l 1200

# Reverse
iperf3 -u -c 10.0.0.2 -B 10.0.0.1 -b 400M -t 30 -l 1200 -R
```

Expect near‑zero loss at reasonable rates; high loss → check MTU and kernel UDP buffers.

---

## 2) Client → VPS (public Internet) Tests

Measure your real browser‑upload ceiling to the VPS region. Temporarily open port 5201 on the VPS via UFW and a GCP VPC firewall rule.

### 2.1 Tag the VM and create VPC firewall rule (GCP)

Replace placeholders: `PROJECT_ID`, `ZONE`, `INSTANCE_NAME`, `NETWORK` (often `default`), and `CLIENT_IP` (`curl -s https://ifconfig.me`).

```bash
gcloud config set project PROJECT_ID
gcloud compute instances add-tags INSTANCE_NAME --zone=ZONE --tags=iperf-server

gcloud compute firewall-rules create allow-iperf-5201-tcp \
  --network=NETWORK \
  --direction=INGRESS --priority=1000 --action=ALLOW \
  --rules=tcp:5201 --source-ranges=CLIENT_IP/32 --target-tags=iperf-server
```

Optional UDP rule:

```bash
gcloud compute firewall-rules create allow-iperf-5201-udp \
  --network=NETWORK \
  --direction=INGRESS --priority=1000 --action=ALLOW \
  --rules=udp:5201 --source-ranges=CLIENT_IP/32 --target-tags=iperf-server
```

### 2.2 Open UFW on the VPS

```bash
sudo ufw allow 5201/tcp
sudo ufw allow 5201/udp   # only if testing UDP
```

### 2.3 Start iperf3 server on the VPS (foreground)

```bash
iperf3 -s   # Ctrl+C to stop
```

### 2.4 Run client from home

```bash
# TCP 4-streams baseline (30s)
iperf3 -c <VPS_PUBLIC_IP> -t 30 -P 4

# Optional: single stream (closer to browser behavior)
iperf3 -c <VPS_PUBLIC_IP> -t 30 -P 1

# Optional UDP probe
iperf3 -u -c <VPS_PUBLIC_IP> -b 100M -t 30
```

Receiver Mbps ≈ your practical browser upload ceiling to the VPS region.

### 2.5 Cleanup

```bash
sudo ufw delete allow 5201/tcp
sudo ufw delete allow 5201/udp

gcloud compute firewall-rules delete allow-iperf-5201-tcp
gcloud compute firewall-rules delete allow-iperf-5201-udp
gcloud compute instances remove-tags INSTANCE_NAME --zone=ZONE --tags=iperf-server
```

---

## 3) nginx + Runegate sanity checklist

nginx TLS server `location /` essentials:

```nginx
proxy_pass http://127.0.0.1:7870;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

client_max_body_size 10G;
proxy_request_buffering off;
proxy_buffering off;
proxy_read_timeout 600s;
proxy_send_timeout 600s;

gzip off;
proxy_set_header Accept-Encoding "";
```

Runegate env (`/etc/runegate/runegate.env`):

```env
RUNEGATE_BASE_URL=https://<your-domain>
RUNEGATE_TARGET_SERVICE=http://10.0.0.2:7860
# Response streaming is enabled by default; to disable set:
# RUNEGATE_STREAM_RESPONSES=false
RUNEGATE_SECURE_COOKIE=true
# RUNEGATE_COOKIE_DOMAIN=   # leave unset for host-only cookies
```

Upstream (Uvicorn/Gradio) behind a proxy:

```bash
uvicorn app:app --host 0.0.0.0 --port 7860 --proxy-headers --forwarded-allow-ips='*'
# Gradio: demo.launch(server_name="0.0.0.0", server_port=7860)
```

---

## 4) Estimate upload time (10 GiB)

Time (seconds) ≈ (10 GiB × 8) / uplink_Mbit ≈ 81920 / uplink_Mbit

- 20 Mbit/s → ~68–72 minutes
- 50 Mbit/s → ~27–29 minutes
- 100 Mbit/s → ~13–15 minutes

Single‑stream browser uploads are often slower than multi‑stream iperf; test on wired if possible.

---

## 5) Useful tuning & checks

- MTU sanity inside WG tunnel:

```bash
ping -M do -s 1352 10.0.0.2   # for wg0 MTU 1380
```

- Kernel TCP/UDP tuning on both ends (`/etc/sysctl.d/99-wg-tuning.conf`):

```conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_rmem_min = 262144
net.ipv4.udp_wmem_min = 262144
```

Apply: `sudo sysctl --system`

- WireGuard queue length: `sudo ip link set dev wg0 txqueuelen 1000`
- Disk I/O on aibox: `sudo apt-get install -y iotop sysstat && sudo iotop -oPa && iostat -mx 2`
- VPS RAM stability: Runegate streaming enabled; nginx buffering off; optional swap 2–4 GiB
