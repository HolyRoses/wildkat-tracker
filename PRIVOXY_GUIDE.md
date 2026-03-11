# Wildkat Tracker - Privoxy HTTP -> SOCKS5 Guide

This guide sets up a local HTTP proxy (`127.0.0.1:3128`) that forwards through a SOCKS5 parent (for example NordVPN SOCKS).

Use this when running magnet metadata submission in proxy mode.

## 1. Install Privoxy (Ubuntu)

```bash
sudo apt update
sudo apt install -y privoxy
```

## 2. Minimal Privoxy Config

Edit `/etc/privoxy/config` and set:

```conf
# Listen only on localhost
listen-address 127.0.0.1:3128

# Optional explicit default
forward / .

# Forward all traffic through SOCKS5 parent
# Format: forward-socks5 <pattern> <user:pass@host:port> <http-parent>
forward-socks5 / username:password@amsterdam.nl.socks.nordhold.net:1080 .
```

Notes:

- Keep `listen-address` on loopback only.
- Replace `username:password` and host with your provider credentials.
- Store this file with restrictive permissions because it contains credentials.

## 3. Start and Enable Service

```bash
sudo systemctl enable --now privoxy
sudo systemctl restart privoxy
sudo systemctl status privoxy
```

## 4. Verify Egress Routing

Direct (server IP):

```bash
curl -s https://api.ipify.org ; echo
```

Via Privoxy (SOCKS parent egress IP):

```bash
curl -s -x http://127.0.0.1:3128 https://api.ipify.org ; echo
```

These IPs should be different.

## 5. Wire Tracker Magnet Submission to Privoxy

In tracker admin settings:

- `magnet_submission_mode = proxy`
- `magnet_submission_proxy_url = http://127.0.0.1:3128`

When proxy mode is enabled, the tracker already strips `udp://` trackers for aria2 runtime args.

## 6. Optional Debug Logging

For troubleshooting, add these lines in `/etc/privoxy/config`:

```conf
# Log to journald when running under systemd
logfile -

# Useful debug levels (enable only while troubleshooting)
debug   1    # Request lines and basic request handling
debug  16    # I/O details (read/write activity)
debug 512    # Header parsing and header-level decisions
debug 1024   # Destination/forwarding decisions (where traffic is sent)
```

Then restart:

```bash
sudo systemctl restart privoxy
```

Follow service logs (startup/restarts/unit state):

```bash
journalctl -u privoxy -f
```

Follow transaction logs (default path):

```bash
sudo tail -f /var/log/privoxy/logfile
```

Reduce debug levels after troubleshooting to avoid excessive log noise.

By default (without `logfile -`), Privoxy logs to `/var/log/privoxy/logfile`.
