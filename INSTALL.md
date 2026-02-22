# BitTorrent Tracker — Installation Guide

## Requirements

- Ubuntu 24.04 (or any modern Linux with systemd)
- Python 3.10+
- A public-facing server with ports accessible from the internet
- A domain name pointed at your server

---

## 1. Create the Dedicated Service User

The tracker runs as a low-privilege system user for security. It has no home directory and cannot log in.

```bash
useradd --system --no-create-home --shell /sbin/nologin tracker
```

---

## 2. Deploy the Script

```bash
mkdir -p /opt/tracker
cp tracker_server.py /opt/tracker/
chown -R tracker:tracker /opt/tracker
chmod 750 /opt/tracker
chmod 640 /opt/tracker/tracker_server.py
```

---

## 3. Obtain a TLS Certificate with acme.sh

This section covers obtaining a free Let's Encrypt certificate using acme.sh in standalone mode.

### 3.1 Install acme.sh

```bash
curl https://get.acme.sh | sh
```

This installs acme.sh to `~/.acme.sh/` and adds a daily cron job for renewals.

### 3.2 Open Port 80 Temporarily

acme.sh needs port 80 to complete the HTTP challenge. Ensure it is open in your firewall/security group before proceeding. It can be closed again after issuance if desired, but must be open for the few seconds of each renewal.

### 3.3 Issue the Certificate

Run as root so acme.sh can bind to port 80. Switch to root first — do not use `sudo` directly with acme.sh.

```bash
sudo -i
```

Issue a certificate for your domain. You may include additional SANs (Subject Alternative Names) for testing IPv4/IPv6 separately:

```bash
/home/<your-user>/.acme.sh/acme.sh --issue \
  -d tracker.example.net \
  -d ipv4-tracker.example.net \
  -d ipv6-tracker.example.net \
  --standalone \
  --server letsencrypt \
  --listen-v4
```

> **Note:** `--listen-v4` forces the standalone HTTP server to bind IPv4 only. Use `--listen-v6` if your server is IPv6-only, or both flags together for dual-stack.

> **Note:** The `ipv4-tracker` and `ipv6-tracker` SANs are optional. They are useful for testing by pointing each subdomain to only an A record or only an AAAA record respectively.

### 3.4 Install the Certificate

Create the destination directory and install the cert. Using `--fullchain-file` (not `--cert-file`) is critical — it ensures both the leaf certificate and intermediate CA are included, which is required by strict TLS clients such as qBittorrent.

```bash
mkdir -p /etc/ssl/acme/tracker.example.net

/home/<your-user>/.acme.sh/acme.sh --install-cert -d tracker.example.net \
  --fullchain-file /etc/ssl/acme/tracker.example.net/fullchain.cer \
  --key-file /etc/ssl/acme/tracker.example.net/tracker.example.net.key \
  --reloadcmd "systemctl restart tracker"

chown -R tracker:tracker /etc/ssl/acme/tracker.example.net
chmod 750 /etc/ssl/acme/tracker.example.net
chmod 640 /etc/ssl/acme/tracker.example.net/*
```

The `--reloadcmd` wires up automatic tracker restarts whenever the certificate is renewed.

### 3.5 Verify the Certificate Chain

```bash
grep -c "BEGIN CERTIFICATE" /etc/ssl/acme/tracker.example.net/fullchain.cer
```

This must return `2` or more. If it returns `1`, repeat step 3.4 — you have only the leaf cert and TLS verification will fail on strict clients.

### 3.6 Set Up Root's Renewal Cron Job

Because the cert was issued as root, the renewal must also run as root. Add a crontab entry:

```bash
sudo crontab -e
```

Add the following line (adjust the path to acme.sh and the home directory):

```
16 5 * * * /home/<your-user>/.acme.sh/acme.sh --cron --home "/root/.acme.sh" > /dev/null
```

Test that renewal works (it will skip if not due, which is expected):

```bash
sudo -i
/home/<your-user>/.acme.sh/acme.sh --cron --home "/root/.acme.sh"
```

Expected output includes: `Skipping. Next renewal time is: ...` — this confirms the cron command is correct.

---

## 4. Install the systemd Service Unit

```bash
cp tracker.service /etc/systemd/system/
systemctl daemon-reload
```

Edit the `ExecStart` line in `/etc/systemd/system/tracker.service` to match your deployment. A typical production configuration using non-privileged ports:

```
ExecStart=/usr/bin/python3 /opt/tracker/tracker_server.py \
  --http-port 8080 \
  --https-port 8443 \
  --udp-port 6969 \
  --web-https-port 443 \
  --web-redirect-http \
  --cert /etc/ssl/acme/tracker.example.net/fullchain.cer \
  --key /etc/ssl/acme/tracker.example.net/tracker.example.net.key \
  --ipv6 \
  --redirect-http \
  --domain tracker.example.net:8443 \
  --tracker-id MyTracker \
  --interval 1800 \
  --min-interval 60 \
  --peer-ttl 3600 \
  --max-peers 200
```

### The --domain Flag and HTTP Redirect

When `--redirect-http` is enabled, the tracker responds to HTTP requests with a `301 Moved Permanently` redirect to HTTPS. The `--domain` flag controls the `Location` header in that redirect.

**This is a common source of confusion.** The `--domain` value must include the port if you are not running on standard port 443. If you omit the port, clients will be redirected to port 443 and fail to connect.

| HTTPS port | Correct --domain value |
|------------|----------------------|
| 443 (standard) | `tracker.example.net` |
| 8443 (non-standard) | `tracker.example.net:8443` |

For example, with `--https-port 8443` you must pass `--domain tracker.example.net:8443` — otherwise an HTTP request to port 8080 will redirect to `https://tracker.example.net/` (port 443) instead of `https://tracker.example.net:8443/` and clients will get a connection refused error.

> **Note:** When using non-privileged ports (8080/8443), the `AmbientCapabilities` and `CapabilityBoundingSet` lines in the service unit are not needed and can be removed. They are only required when binding to ports below 1024 (80/443) as a non-root user.

---

## 5. Enable and Start

```bash
systemctl enable tracker
systemctl start tracker
```

---

## 6. Verify

Check service status and live logs:

```bash
systemctl status tracker
journalctl -u tracker -f
```

Test the tracker with the query tool:

```bash
# HTTP announce
./tracker_query.py -t http://tracker.example.net/announce

# HTTPS announce
./tracker_query.py -t https://tracker.example.net/announce

# UDP announce
./tracker_query.py -t udp://tracker.example.net:6969/announce

# Scrape a specific torrent
./tracker_query.py -t https://tracker.example.net/announce -s -H <info_hash_hex>

# Test whether full scrape is allowed (should be denied by default)
./tracker_query.py -t https://tracker.example.net/announce --full-scrape
```

---

## 7. Firewall / Security Group

Ensure the following ports are open for inbound TCP and UDP traffic:

| Port | Protocol | Purpose |
|------|----------|---------|
| 80   | TCP      | HTTP (redirect to HTTPS) / Let's Encrypt renewal |
| 443  | TCP      | HTTPS announce + scrape |
| 6969 | UDP      | UDP announce + scrape |

If running on non-standard ports (e.g. 8080/8443) adjust accordingly.

>  **Oracle Cloud note:** OCI blocks ports at two levels — the Security List in the VCN console AND iptables on the instance. Both must be configured.

### Simplifying Firewall Management on Ubuntu (OCI)

On Ubuntu instances in Oracle Cloud, the local iptables rules are managed by `netfilter-persistent`. If you prefer to rely solely on the OCI VCN Security List to control access (simpler for single-instance deployments), you can disable the local firewall entirely:

```bash
sudo systemctl stop netfilter-persistent
sudo systemctl disable netfilter-persistent
```

After doing this, all port access is controlled exclusively by the OCI Security List in the VCN console. Make sure your Security List rules are correct before disabling local filtering, as there will be no secondary layer of protection on the instance itself.

---

## 8. Notable Server Options

| Flag | Default | Description |
|------|---------|-------------|
| `--http-port` | 6969 | Tracker HTTP listen port (0 to disable) |
| `--https-port` | disabled | Tracker HTTPS listen port (requires --cert and --key) |
| `--udp-port` | 6969 | Tracker UDP listen port (0 to disable) |
| `--redirect-http` | off | Redirect tracker HTTP → HTTPS (requires --https-port) |
| `--domain` | localhost | Public domain for redirect Location header (include port if not 443) |
| `--ipv6` | off | Also listen on IPv6 (:: for HTTP and UDP) |
| `--web-http-port` | 80 | Stats page HTTP port (0 to disable) |
| `--web-https-port` | disabled | Stats page HTTPS port (uses same cert/key as tracker) |
| `--web-redirect-http` | off | Redirect stats HTTP → HTTPS (requires --web-https-port) |
| `--tracker-id` | Wildkat | Tracker ID returned in HTTP announce responses |
| `--interval` | 1800 | Announce interval in seconds |
| `--min-interval` | 60 | Minimum re-announce interval in seconds |
| `--peer-ttl` | 3600 | Seconds before an inactive peer is purged |
| `--max-peers` | 200 | Maximum peers returned per announce |
| `--max-scrape-hashes` | 5 | Maximum info_hashes per scrape request |
| `--full-scrape` | off | Allow scrape with no info_hash (exposes all torrents) |
| `--verbose` | off | Enable debug logging |

---

## 9. Auto-Deploy from GitHub

The included `deploy.sh` script polls GitHub every 5 minutes and automatically deploys updates when a push to `main` is detected. It performs a syntax check before deploying so a broken push cannot take down the running tracker.

### 9.1 Prerequisites

The server must have a local clone of the repository. Verify git access works before proceeding:

```bash
cd ~/wildkat-tracker
git fetch origin main
```

### 9.2 Install the Deploy Script

```bash
sudo cp deploy.sh /opt/tracker/deploy.sh
sudo chown ubuntu:ubuntu /opt/tracker/deploy.sh
sudo chmod 750 /opt/tracker/deploy.sh
```

### 9.3 Create the Log File

```bash
sudo touch /var/log/tracker-deploy.log
sudo chown ubuntu:ubuntu /var/log/tracker-deploy.log
```

### 9.4 Wire Up the Cron Job

Add the cron job to the `ubuntu` user's crontab:

```bash
crontab -e
```

Add this line:

```
*/5 * * * * /opt/tracker/deploy.sh >> /var/log/tracker-deploy.log 2>&1
```

### 9.5 Verify

Watch the log after a push is made to GitHub:

```bash
tail -f /var/log/tracker-deploy.log
```

A successful deploy looks like:

```
[2026-02-22 00:20:01] Change detected on main
[2026-02-22 00:20:01]   local:  be658e3d...
[2026-02-22 00:20:01]   remote: c5e91ea6...
[2026-02-22 00:20:01] Pulling...
[2026-02-22 00:20:01] Updated to c5e91ea6...
[2026-02-22 00:20:01] Deploying tracker_server.py → /opt/tracker/tracker_server.py
[2026-02-22 00:20:01] Restarting tracker...
[2026-02-22 00:20:01] tracker is running — deploy successful
```

When no changes are detected the script exits silently — the log will only contain entries when a deploy actually occurred.

### 9.6 Deploy Script Configuration

The variables at the top of `deploy.sh` can be adjusted if your layout differs:

| Variable | Default | Description |
|----------|---------|-------------|
| `REPO_DIR` | `/home/ubuntu/wildkat-tracker` | Local git clone path |
| `REPO_BRANCH` | `main` | Branch to track |
| `DEPLOY_FILE` | `tracker_server.py` | File to deploy from repo |
| `DEPLOY_DEST` | `/opt/tracker/tracker_server.py` | Destination on server |
| `SERVICE_NAME` | `tracker` | systemd service to restart |

---

## 10. Manual Update

To deploy a new version of the tracker script without the auto-deploy system:

```bash
sudo cp tracker_server.py /opt/tracker/
sudo chown tracker:tracker /opt/tracker/tracker_server.py
sudo systemctl restart tracker
```
