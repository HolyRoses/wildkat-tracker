# Wildkat Tracker — Installation Guide

## Requirements

- Ubuntu 24.04 (or any modern Linux with systemd)
- Python 3.10+
- A public-facing server with ports accessible from the internet
- A domain name pointed at your server

---

## 1. Create the Dedicated Service User

The tracker runs as a low-privilege system user. It has no home directory and cannot log in interactively.

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
chmod 750 /opt/tracker/tracker_server.py
```

---

## 3. Obtain a TLS Certificate with acme.sh

### 3.1 Install acme.sh

```bash
curl https://get.acme.sh | sh
```

This installs acme.sh to `~/.acme.sh/` and adds a daily cron job for renewals.

### 3.2 Open Port 80 Temporarily

acme.sh needs port 80 to complete the HTTP challenge. Ensure it is open in your firewall/security group before proceeding.

### 3.3 Issue the Certificate

Run as root. Switch to root first — do not use `sudo` directly with acme.sh.

```bash
sudo -i
```

Issue a certificate for your domain. You may include additional SANs for testing IPv4/IPv6 separately:

```bash
/home/<your-user>/.acme.sh/acme.sh --issue \
  -d tracker.example.net \
  -d ipv4-tracker.example.net \
  -d ipv6-tracker.example.net \
  --standalone \
  --server letsencrypt \
  --listen-v4
```

> **Note:** `--listen-v4` forces the standalone HTTP server to bind IPv4 only. Use `--listen-v6` if your server is IPv6-only, or both flags for dual-stack.

> **Note:** The `ipv4-tracker` and `ipv6-tracker` SANs are optional. Useful for testing by pointing each subdomain to only an A or AAAA record respectively.

### 3.4 Install the Certificate

Using `--fullchain-file` (not `--cert-file`) is critical — it includes both the leaf certificate and intermediate CA, which is required by strict TLS clients such as qBittorrent.

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

Because the cert was issued as root, the renewal must also run as root:

```bash
sudo crontab -e
```

Add:

```
16 5 * * * /home/<your-user>/.acme.sh/acme.sh --cron --home "/root/.acme.sh" > /dev/null
```

Test that renewal works (it will skip if not due, which is expected):

```bash
sudo -i
/home/<your-user>/.acme.sh/acme.sh --cron --home "/root/.acme.sh"
```

Expected output includes: `Skipping. Next renewal time is: ...`

---

## 4. Install the systemd Service Unit

```bash
cp tracker.service /etc/systemd/system/
systemctl daemon-reload
```

Edit the `ExecStart` line in `/etc/systemd/system/tracker.service` to match your deployment.

### Tracker only (no registration mode)

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

### With registration mode enabled

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
  --max-peers 200 \
  --registration \
  --super-user youradminusername \
  --db /opt/tracker/tracker.db
```

### The --domain Flag and HTTP Redirect

When `--redirect-http` is enabled, HTTP requests receive a `301 Moved Permanently` redirect to HTTPS. The `--domain` value must include the port if you are not running on standard port 443.

| HTTPS port | Correct --domain value |
|------------|----------------------|
| 443 (standard) | `tracker.example.net` |
| 8443 (non-standard) | `tracker.example.net:8443` |

> **Note:** When using non-privileged ports (8080/8443), the `AmbientCapabilities` and `CapabilityBoundingSet` lines in the service unit are not needed and can be removed.

---

## 5. Enable and Start

```bash
systemctl enable tracker
systemctl start tracker
```

---

## 6. Verify

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
| 80   | TCP      | HTTP redirect to HTTPS / Let's Encrypt renewal |
| 443  | TCP      | HTTPS announce + scrape + management interface |
| 6969 | UDP      | UDP announce + scrape |

If running on non-standard ports (e.g. 8080/8443) adjust accordingly.

> **Oracle Cloud note:** OCI blocks ports at two levels — the Security List in the VCN console AND iptables on the instance. Both must be configured.

### Simplifying Firewall Management on Ubuntu (OCI)

On Ubuntu instances in Oracle Cloud, local iptables rules are managed by `netfilter-persistent`. To rely solely on the OCI VCN Security List:

```bash
sudo systemctl stop netfilter-persistent
sudo systemctl disable netfilter-persistent
```

Make sure your OCI Security List rules are correct before doing this.

---

## 8. Memory Considerations, Upload Limits, and Swap

The tracker is lightweight at idle, but **bulk torrent uploads are memory-intensive**. Parsing many `.torrent` files in one request requires Python to hold raw upload data and parsed metadata in memory.

Registration mode now includes server-side upload guardrails (configurable in Admin Settings):

- Max request size (default: **100 MB**)
- Max files per upload (default: **1000**)
- Max per-file size (default: **10 MB**)

When a batch exceeds file-count or per-file limits, valid files are still processed and invalid ones are skipped with a clear summary.

### How Much Memory Do You Need?

Bulk uploading 1000–1200 `.torrent` files simultaneously can consume 400–500MB of RAM at peak. On a server with less than 1GB of total RAM (such as Oracle Cloud's free tier micro instance at ~954MB), this will exhaust available memory.

```bash
free -h
cat /proc/meminfo | grep -E "MemTotal|MemAvailable|SwapTotal"
```

If `MemAvailable` is below 200MB at idle, or `SwapTotal` is 0, add swap before doing large bulk uploads.

### Adding a Swapfile

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

Verify swap is active:

```bash
free -h
```

You should see `2.0Gi` under the Swap row.

---

## 9. Registration Mode — First-Run Setup

When `--registration` is enabled the management interface is available at `https://your-domain/manage`.

### 9.1 Set the Superuser Password

On first run the superuser account is created automatically. To set its password, stop the service and run the server directly with `--super-user-password`:

```bash
systemctl stop tracker
python3 /opt/tracker/tracker_server.py \
  --registration \
  --super-user youradminusername \
  --super-user-password 'YourStrongP@ssw0rd!' \
  --db /opt/tracker/tracker.db
```

The server sets the password and exits immediately. Then restart:

```bash
systemctl start tracker
```

### 9.2 Log In

Visit `https://your-domain/manage` and log in with your superuser credentials.

### 9.3 Initial Configuration

After logging in, go to **Admin Panel → Settings** tab and configure:

- **Password Complexity** — minimum length and character requirements
- **Free Signup** — whether new users can self-register or must use an invite
- **Auto-Promote** — automatically promote Basic users to Standard after a set torrent count
- **Open Tracker** — whether to accept announces for unregistered torrents
- **Torrents Per Page** — pagination size for all torrent listings
- **Upload Limits** — max request size, max files per upload, and max per-file size
- **robots.txt** — content served to web crawlers

Then go to **Admin Panel → Economy** tab and configure the points economy:

- **Points Earn** — how many points users earn per login, per upload, per comment, and streak bonus rates
- **Points Spend** — invite code cost and point transfer fee percentage
- **Bounty Settings** — minimum escrow, payout splits, confirmation window, community vote threshold
- **Leaderboard** — top N entries per category
- **Admin Point Grants** — maximum points per admin grant/removal transaction

Then go to the **Trackers** tab and add the tracker URLs to include in generated magnet links.

### 9.4 Creating the First Users

With free signup off (the default), go to **Admin Panel → Add User** to create accounts manually, or use the **Invites** tab to generate invite links.

### 9.5 Database Location

The database is created automatically at the path given by `--db`. The service unit's `ReadWritePaths` must include the directory containing the database file — the default service unit already includes `/opt/tracker`.

SQLite WAL mode requires write access to the directory (not just the `.db` file), since WAL creates `-wal` and `-shm` sidecar files.

### 9.6 Resetting the Superuser Password

If you are locked out of the superuser account:

```bash
systemctl stop tracker
python3 /opt/tracker/tracker_server.py \
  --registration \
  --super-user youradminusername \
  --super-user-password 'NewStrongP@ssw0rd!' \
  --db /opt/tracker/tracker.db
systemctl start tracker
```

---

## 10. Notable Server Options

### Core Tracker

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

### Registration Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--registration` | off | Enable registration mode and the `/manage` web interface |
| `--super-user` | — | Superuser username — required when `--registration` is set |
| `--super-user-password` | — | Set or reset the superuser password (process exits after setting) |
| `--db` | `/opt/tracker/tracker.db` | Path to the SQLite database file |
| `--manage-port` | same as `--web-https-port` | HTTPS port for the management interface if different from stats port |
| `--manage-http-port` | 80 | HTTP redirect port for management interface (0 to disable) |

---

## 11. Auto-Deploy from GitHub

The included `deploy.sh` script polls GitHub every 5 minutes and automatically deploys updates when a push to `main` is detected. It performs a syntax check before deploying so a broken push cannot take down the running tracker.

### 11.1 Prerequisites

The server must have a local clone of the repository:

```bash
cd ~/wildkat-tracker
git fetch origin main
```

### 11.2 Make the Deploy Script Executable

```bash
chmod 750 ~/wildkat-tracker/deploy.sh
```

### 11.3 Create the Log File

```bash
sudo touch /var/log/tracker-deploy.log
sudo chown ubuntu:ubuntu /var/log/tracker-deploy.log
```

### 11.4 Wire Up the Cron Job

```bash
crontab -e
```

Add:

```
*/5 * * * * /home/ubuntu/wildkat-tracker/deploy.sh >> /var/log/tracker-deploy.log 2>&1
```

### 11.5 Verify

Watch the log after a push is made to GitHub:

```bash
tail -f /var/log/tracker-deploy.log
```

A successful deploy looks like:

```
[2026-02-26 00:20:01] Change detected on main
[2026-02-26 00:20:01]   local:  be658e3d...
[2026-02-26 00:20:01]   remote: c5e91ea6...
[2026-02-26 00:20:01] Pulling...
[2026-02-26 00:20:01] Updated to c5e91ea6...
[2026-02-26 00:20:01] Deploying tracker_server.py → /opt/tracker/tracker_server.py
[2026-02-26 00:20:01] Restarting tracker...
[2026-02-26 00:20:01] tracker is running — deploy successful
```

When no changes are detected the script exits silently.

### 11.6 Deploy Script Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REPO_DIR` | `/home/ubuntu/wildkat-tracker` | Local git clone path |
| `REPO_BRANCH` | `main` | Branch to track |
| `DEPLOY_FILE` | `tracker_server.py` | File to deploy from repo |
| `DEPLOY_DEST` | `/opt/tracker/tracker_server.py` | Destination on server |
| `SERVICE_NAME` | `tracker` | systemd service to restart |

---

## 12. Manual Update

```bash
sudo cp tracker_server.py /opt/tracker/
sudo chown tracker:tracker /opt/tracker/tracker_server.py
sudo systemctl restart tracker
```
