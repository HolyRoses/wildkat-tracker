# Wildkat BitTorrent Tracker

A lightweight, self-hosted BitTorrent tracker with full HTTP, HTTPS, and UDP support. Built in pure Python with no external dependencies. Includes a companion query/diagnostic tool for testing trackers — your own or any public tracker.

## Features

### Tracker Server (`tracker_server.py`)

- **HTTP/HTTPS announce and scrape** — BEP 3, BEP 23 compact peers, BEP 7 IPv6 `peers6`, BEP 24 external IP reflection
- **UDP announce and scrape** — BEP 15
- **TLS** via [acme.sh](https://github.com/acmesh-official/acme.sh) / Let's Encrypt — pass `--cert` and `--key` at startup
- **HTTP → HTTPS redirect** — optional, controlled via `--redirect-http` and `--domain`
- **IPv4/IPv6 dual-stack** — simultaneous listeners via `--ipv6`; IPv4 peers returned as `::ffff:` mapped addresses to IPv6 clients per BEP 7
- **gzip response compression** — automatic when client advertises `Accept-Encoding: gzip` (e.g. qBittorrent); only applied when compression actually reduces size
- **Tracker ID** — configurable via `--tracker-id`, returned in HTTP announce responses
- **Full scrape protection** — disabled by default; enable with `--full-scrape`. Per-request hash limit configurable via `--max-scrape-hashes`
- **Peer TTL** — inactive peers automatically purged
- **Verbose debug logging** — full request/response payloads via `--verbose`
- **systemd service unit** — hardened with `CAP_NET_BIND_SERVICE`, `NoNewPrivileges`, `ProtectSystem`, and related security directives
- **No external dependencies** — pure Python 3.10+ standard library only

### Registration Mode

Enable with `--registration`. Adds a full user and torrent management web interface at `/manage`.

- **Roles and access control** — Super, Admin, Standard, and Basic with clear permissions
- **Account onboarding** — admin-created users, invite links, or open signup (configurable)
- **Torrent management UI** — upload `.torrent` files, browse/search listings, inspect detail pages, copy hashes/magnets
- **Upload safety limits** — request-size, file-count, and per-file caps with partial-success batch handling
- **Profile and privacy controls** — DM opt-in, online status visibility, bounty alerts, torrent activity linking, optional Gravatar
- **Followers system** — follow/unfollow members, follower activity notifications, and Most Followed leaderboard category
- **Torrent peer snapshots** — manual Seeds/Peers refresh from torrent detail pages via configurable external query command with cooldown protection
- **Direct messages** — threaded inbox/sent/compose/blocked flow with optional point cost and daily limits
- **Comments and notifications** — threaded comments, @mentions, bell dropdown, and full notifications page
- **Points economy** — earning, spending, transfers, streaks, and ledger-backed accounting
- **Points top-ups** — fixed-amount purchases with provider-based checkout and order tracking
- **Bounty board** — posting, claiming, confirming, contributing, voting, and payout splitting
- **Leaderboard** — ranked categories for points, uploads, streaks, and bounty activity
- **Admin panel** — torrents, users, add user, trackers, settings, database, economy, top-ups, invites, danger, events
- **Operational controls** — IP allowlists, open-tracker switch, configurable `robots.txt`, database backup/restore

For full operational detail, see [USER_GUIDE.md](USER_GUIDE.md). For deployment and hardening steps, see [INSTALL.md](INSTALL.md).

### Security

- CSRF protection on all state-changing requests (HMAC-SHA256, session-bound, restart-persistent)
- Sensitive state changes use POST flows (including comment lock/unlock and profile messaging/privacy toggles)
- All user content HTML-escaped before output — no XSS surface
- PBKDF2-HMAC-SHA256 password hashing, 260,000 iterations, unique salt per account
- Session cookies: `HttpOnly; SameSite=Lax; Secure` (CSRF cookie remains `SameSite=Strict`)
- All database queries parameterized — no SQL injection surface
- No shell execution (`os.system`, `subprocess`, `eval`) anywhere in the codebase

### Query Tool (`tracker_query.py`)

- Tests HTTP, HTTPS, and UDP trackers
- Supports announce (all events) and scrape
- `--full-scrape` — sends scrape with no info_hash to test whether a tracker allows it
- Multiple output formats: table, JSON, CSV
- Peer list display with optional DNS reverse lookup
- IPv6 compliance validation — warns when IPv6 client receives IPv4-only peer response
- Batch mode — test multiple trackers from a file
- Retry mode — retry until success or max attempts
- Random qBittorrent client impersonation — cycles through realistic User-Agent and peer_id values
- gzip decompression — handles compressed responses from any tracker

## Files

| File | Description |
|------|-------------|
| `tracker_server.py` | The tracker server |
| `tracker_query.py` | The query and diagnostic tool |
| `tracker.service` | systemd service unit |
| `deploy.sh` | Auto-deploy script — polls GitHub and deploys updates |
| `INSTALL.md` | Full installation guide including TLS and registration mode setup |
| `USER_GUIDE.md` | End-user and admin guide for registration mode |

## Quick Start

### Run the server (HTTP only, no TLS)

```bash
python3 tracker_server.py
```

Listens on `0.0.0.0:6969` for both HTTP and UDP by default.

### Run with HTTPS + UDP + IPv6

```bash
python3 tracker_server.py \
  --http-port 8080 \
  --https-port 8443 \
  --udp-port 6969 \
  --web-https-port 443 \
  --web-redirect-http \
  --cert /etc/ssl/acme/tracker.example.net/fullchain.cer \
  --key  /etc/ssl/acme/tracker.example.net/tracker.example.net.key \
  --ipv6 \
  --redirect-http \
  --domain tracker.example.net:8443 \
  --tracker-id MyTracker
```

### Run with registration mode enabled

```bash
python3 tracker_server.py \
  --https-port 8443 \
  --udp-port 6969 \
  --web-https-port 443 \
  --cert /etc/ssl/acme/tracker.example.net/fullchain.cer \
  --key  /etc/ssl/acme/tracker.example.net/tracker.example.net.key \
  --ipv6 \
  --redirect-http \
  --domain tracker.example.net:8443 \
  --registration \
  --super-user admin \
  --db /opt/tracker/tracker.db
```

Then visit `https://tracker.example.net/manage` to log in.

### Query a tracker

```bash
# Announce to any tracker
./tracker_query.py -t udp://tracker.opentrackr.org:1337/announce

# Announce with a specific info hash and show peers
./tracker_query.py -t https://tracker.example.net:8443/announce \
  -H aabbccddeeff00112233445566778899aabbccdd -p

# Scrape a specific torrent
./tracker_query.py -t https://tracker.example.net:8443/announce \
  -s -H aabbccddeeff00112233445566778899aabbccdd

# Test whether a tracker allows full scrape
./tracker_query.py -t https://tracker.example.net:8443/announce --full-scrape
```

## BEP Compliance

| BEP | Title | Status |
|-----|-------|--------|
| BEP 3 | The BitTorrent Protocol | ✅ HTTP announce, tracker ID, failure reason, warning message |
| BEP 7 | IPv6 Tracker Extension | ✅ `peers6` compact response, IPv4-mapped addresses |
| BEP 15 | UDP Tracker Protocol | ✅ Connect, announce, scrape, error |
| BEP 23 | Tracker Returns Compact Peer Lists | ✅ Compact IPv4, dict model with `no_peer_id` support |
| BEP 24 | Tracker Returns External IP | ✅ IPv4 and IPv6 |
| BEP 48 | Tracker Protocol Extension: Scrape | ✅ Multi-hash, `flags.min_request_interval` |

## Installation

See [INSTALL.md](INSTALL.md) for the full guide including TLS certificate setup with acme.sh, systemd service configuration, registration mode first-run, and Oracle Cloud firewall notes.

## Server Options

### Core Tracker

| Flag | Default | Description |
|------|---------|-------------|
| `--http-port` | 6969 | Tracker HTTP listen port (0 to disable) |
| `--https-port` | disabled | Tracker HTTPS listen port (requires `--cert` and `--key`) |
| `--udp-port` | 6969 | Tracker UDP listen port (0 to disable) |
| `--host` | all interfaces | Bind address |
| `--ipv6` | off | Also listen on IPv6 |
| `--redirect-http` | off | Redirect tracker HTTP → HTTPS (requires `--https-port`) |
| `--domain` | localhost | Public domain for redirect Location header (include port if not 443) |
| `--cert` | — | Path to TLS fullchain certificate |
| `--key` | — | Path to TLS private key |
| `--web-http-port` | 80 | Stats page HTTP listen port (0 to disable) |
| `--web-https-port` | disabled | Stats page HTTPS listen port (uses same cert/key as tracker) |
| `--web-redirect-http` | off | Redirect stats page HTTP → HTTPS (requires `--web-https-port`) |
| `--tracker-id` | Wildkat | Tracker ID returned in HTTP announce responses |
| `--interval` | 1800 | Announce interval in seconds |
| `--min-interval` | 60 | Minimum re-announce interval in seconds |
| `--peer-ttl` | 3600 | Seconds before an inactive peer is purged |
| `--max-peers` | 200 | Maximum peers returned per announce |
| `--max-scrape-hashes` | 5 | Maximum info_hashes allowed per scrape request |
| `--full-scrape` | off | Allow scrape with no info_hash |
| `--verbose` | off | Enable debug logging |

### Registration Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--registration` | off | Enable registration mode and the `/manage` web interface |
| `--super-user` | — | Superuser username (required with `--registration`) |
| `--super-user-password` | — | Set or reset the superuser password (process exits after setting) |
| `--db` | `/opt/tracker/tracker.db` | Path to SQLite database |
| `--manage-port` | same as `--web-https-port` | Management interface HTTPS port if different from stats port |
| `--manage-http-port` | 80 | Management HTTP redirect port (0 to disable) |

## Requirements

- Python 3.10+
- No external packages — standard library only
