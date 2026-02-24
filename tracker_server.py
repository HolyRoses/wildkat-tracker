#!/usr/bin/env python3
"""
BitTorrent Tracker Server
Compatible with tracker_query.py – implements HTTP/HTTPS announce + scrape and UDP announce + scrape.

Protocols implemented:
  • HTTP/HTTPS announce  (BEP 3, BEP 23 compact peers, BEP 7 IPv6 peers6, BEP 24 external ip)
  • HTTP/HTTPS scrape    (BEP 48, multi-hash, flags.min_request_interval)
  • UDP announce + scrape (BEP 15)

HTTPS via acme.sh / Let's Encrypt:
  After issuing your cert with acme.sh, point --cert and --key at the installed files, e.g.:
    --cert /etc/ssl/acme/yourdomain.com/fullchain.cer
    --key  /etc/ssl/acme/yourdomain.com/yourdomain.com.key

Usage examples:
  # HTTP only
  python3 tracker_server.py

  # HTTP + UDP on custom ports
  python3 tracker_server.py --http-port 6969 --udp-port 6969

  # HTTPS (TLS) + UDP
  python3 tracker_server.py --https-port 443 --udp-port 6969 \\
      --cert /etc/ssl/acme/tracker.example.com/fullchain.cer \\
      --key  /etc/ssl/acme/tracker.example.com/tracker.example.com.key

  # All three simultaneously (HTTP redirect + HTTPS + UDP)
  python3 tracker_server.py --http-port 80 --https-port 443 --udp-port 6969 \\
      --cert /etc/ssl/acme/tracker.example.com/fullchain.cer \\
      --key  /etc/ssl/acme/tracker.example.com/tracker.example.com.key
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import html as _html_mod
import secrets
import sqlite3
import gzip
import ipaddress
import io
import json
import logging
import os
import re
import random
import socket
import ssl
import string
import struct
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# ─────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────

DEFAULT_HTTP_PORT   = 6969
DEFAULT_HTTPS_PORT  = None   # disabled unless cert+key supplied
DEFAULT_UDP_PORT    = 6969
DEFAULT_INTERVAL    = 1800   # seconds
DEFAULT_MIN_INTERVAL = 60
PEER_TTL            = 3600   # seconds before a peer is purged
MAX_PEERS_PER_REPLY  = 200
MAX_SCRAPE_HASHES    = 5      # max info_hashes per scrape request
ALLOW_FULL_SCRAPE    = False  # allow scrape with no info_hash (exposes all torrents)
DEFAULT_TRACKER_ID  = 'Wildkat'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('tracker')

# ─────────────────────────────────────────────────────────────
# Bencode encoder  (decoder not needed – server only sends)
# ─────────────────────────────────────────────────────────────

def bencode(obj) -> bytes:
    if isinstance(obj, int):
        return b'i' + str(obj).encode() + b'e'
    if isinstance(obj, bytes):
        return str(len(obj)).encode() + b':' + obj
    if isinstance(obj, str):
        encoded = obj.encode('utf-8')
        return str(len(encoded)).encode() + b':' + encoded
    if isinstance(obj, (list, tuple)):
        return b'l' + b''.join(bencode(i) for i in obj) + b'e'
    if isinstance(obj, dict):
        # Keys must be sorted bytewise
        items = sorted(
            ((k.encode() if isinstance(k, str) else k, v) for k, v in obj.items())
        )
        return b'd' + b''.join(bencode(k) + bencode(v) for k, v in items) + b'e'
    raise TypeError(f'Cannot bencode type {type(obj)}')

# ─────────────────────────────────────────────────────────────
# Peer registry  (thread-safe in-memory store)
# ─────────────────────────────────────────────────────────────

class PeerRegistry:
    """
    Stores peers per info_hash.

    Structure:
        _torrents[info_hash_hex] = {
            peer_key: {
                'ip': str,
                'port': int,
                'peer_id': bytes,
                'left': int,       # 0 = seeder
                'last_seen': float,
                'event': str,
            }
        }
        _downloaded[info_hash_hex] = int   # completed event counter
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._torrents: dict[str, dict] = {}
        self._downloaded: dict[str, int] = {}

    # ── Internal helpers ─────────────────────────────────────

    def _ensure(self, ih_hex: str):
        if ih_hex not in self._torrents:
            self._torrents[ih_hex] = {}
            self._downloaded[ih_hex] = 0

    def _purge_stale(self, ih_hex: str):
        now = time.time()
        stale = [k for k, p in self._torrents[ih_hex].items()
                 if now - p['last_seen'] > PEER_TTL]
        for k in stale:
            del self._torrents[ih_hex][k]

    # ── Public API ───────────────────────────────────────────

    def announce(self, ih_hex: str, peer_id: bytes, ip: str, port: int,
                 left: int, event: str):
        """Register / update / remove a peer. Returns nothing."""
        key = f'{ip}:{port}'
        with self._lock:
            self._ensure(ih_hex)
            self._purge_stale(ih_hex)

            if event == 'stopped':
                self._torrents[ih_hex].pop(key, None)
                return

            if event == 'completed':
                # Only increment downloaded counter once per peer -- same peer
                # sending completed repeatedly should not keep incrementing it,
                # just as sending started repeatedly doesn't increase leechers.
                existing = self._torrents[ih_hex].get(key)
                if existing is None or existing.get('event') != 'completed':
                    self._downloaded[ih_hex] += 1
                left = 0  # completed means download is done; force seeder status
            self._torrents[ih_hex][key] = {
                'ip':        ip,
                'port':      port,
                'peer_id':   peer_id,
                'left':      left,
                'last_seen': time.time(),
                'event':     event,
            }

    def get_peers(self, ih_hex: str, num_want: int, requester_ip: str, requester_port: int):
        """
        Return (seeds, leechers, downloaded, ipv4_compact, ipv6_compact, peer_dicts).
        ipv4_compact and ipv6_compact are bytes.
        peer_dicts is a list[dict] for callers that want the full list.
        """
        with self._lock:
            self._ensure(ih_hex)
            self._purge_stale(ih_hex)

            peers = list(self._torrents[ih_hex].values())

        seeds    = sum(1 for p in peers if p['left'] == 0)
        leechers = len(peers) - seeds
        downloaded = self._downloaded.get(ih_hex, 0)

        # Exclude the requesting peer from the list
        requester_key = f'{requester_ip}:{requester_port}'
        candidates = [p for p in peers
                      if f"{p['ip']}:{p['port']}" != requester_key]

        # Shuffle and cap
        random.shuffle(candidates)
        selected = candidates[:max(num_want, 0)]

        ipv4_compact       = b''  # for IPv4 clients: 6 bytes per peer
        ipv6_compact       = b''  # native IPv6 peers: 18 bytes each
        ipv4_mapped_compact = b'' # IPv4 peers as ::ffff:x.x.x.x: 18 bytes each
        peer_dicts         = []

        # IPv4-mapped prefix: ::ffff:0:0
        IPV4_MAPPED_PREFIX = bytes([0,0,0,0, 0,0,0,0, 0,0,0xff,0xff])

        for p in selected:
            peer_dicts.append({'ip': p['ip'], 'port': p['port'],
                               'peer_id': p['peer_id']})
            try:
                addr = ipaddress.ip_address(p['ip'])
                if isinstance(addr, ipaddress.IPv4Address):
                    # IPv4 compact for IPv4 clients
                    ipv4_compact += addr.packed + struct.pack('!H', p['port'])
                    # IPv4-mapped form for IPv6 clients (::ffff:x.x.x.x)
                    ipv4_mapped_compact += IPV4_MAPPED_PREFIX + addr.packed + struct.pack('!H', p['port'])
                else:
                    ipv6_compact += addr.packed + struct.pack('!H', p['port'])
            except ValueError:
                pass  # skip unparseable IPs

        return seeds, leechers, downloaded, ipv4_compact, ipv6_compact, ipv4_mapped_compact, peer_dicts

    def scrape_stats(self, ih_hex: str):
        """Return (complete, incomplete, downloaded) for a single info_hash."""
        with self._lock:
            self._ensure(ih_hex)
            self._purge_stale(ih_hex)
            peers = list(self._torrents[ih_hex].values())

        complete   = sum(1 for p in peers if p['left'] == 0)
        incomplete = len(peers) - complete
        downloaded = self._downloaded.get(ih_hex, 0)
        return complete, incomplete, downloaded

    def all_hashes(self):
        with self._lock:
            return list(self._torrents.keys())


# Module-level shared registry (shared by all handler threads + UDP thread)
REGISTRY = PeerRegistry()

# ─────────────────────────────────────────────────────────────
# Statistics tracker
# ─────────────────────────────────────────────────────────────

class StatsTracker:
    """Thread-safe statistics with today / yesterday / all-time buckets."""

    def __init__(self):
        self._lock   = threading.Lock()
        self.start_time = time.time()
        self._today  = datetime.date.today()

        # ── All-time ──────────────────────────────────────────
        self.all_announces       = 0
        self.all_http_announces  = 0
        self.all_https_announces = 0
        self.all_udp_announces   = 0
        self.all_ipv4_clients    = 0
        self.all_ipv6_clients    = 0
        self.all_unique_ips      = set()
        self.all_bytes_sent      = 0   # after compression
        self.all_bytes_raw       = 0   # before compression
        self.all_gzip_count      = 0
        self.all_plain_count     = 0
        self.daily_totals        = {}  # date_str -> announce count

        # ── Today ─────────────────────────────────────────────
        self.today_announces       = 0
        self.today_http_announces  = 0
        self.today_https_announces = 0
        self.today_udp_announces   = 0
        self.today_ipv4_clients    = 0
        self.today_ipv6_clients    = 0
        self.today_unique_ips      = set()
        self.today_bytes_sent      = 0
        self.today_bytes_raw       = 0
        self.today_gzip_count      = 0
        self.today_plain_count     = 0
        self.today_hourly          = [0] * 24

        # ── Yesterday snapshot ────────────────────────────────
        self.yesterday = {}

    def _rollover(self):
        yesterday_str = self._today.isoformat()
        self.yesterday = {
            'date':            yesterday_str,
            'announces':       self.today_announces,
            'http':            self.today_http_announces,
            'https':           self.today_https_announces,
            'udp':             self.today_udp_announces,
            'ipv4':            self.today_ipv4_clients,
            'ipv6':            self.today_ipv6_clients,
            'unique_ips':      len(self.today_unique_ips),
            'bytes_sent':      self.today_bytes_sent,
            'bytes_raw':       self.today_bytes_raw,
            'gzip_count':      self.today_gzip_count,
            'plain_count':     self.today_plain_count,
            'hourly':          list(self.today_hourly),
        }
        self.daily_totals[yesterday_str] = self.today_announces
        self._today                = datetime.date.today()
        self.today_announces       = 0
        self.today_http_announces  = 0
        self.today_https_announces = 0
        self.today_udp_announces   = 0
        self.today_ipv4_clients    = 0
        self.today_ipv6_clients    = 0
        self.today_unique_ips      = set()
        self.today_bytes_sent      = 0
        self.today_bytes_raw       = 0
        self.today_gzip_count      = 0
        self.today_plain_count     = 0
        self.today_hourly          = [0] * 24

    def check_rollover(self):
        with self._lock:
            if datetime.date.today() != self._today:
                self._rollover()

    def record_announce(self, protocol: str, ip: str, is_ipv6: bool):
        hour = datetime.datetime.now().hour
        with self._lock:
            self.all_announces   += 1
            self.today_announces += 1
            self.today_hourly[hour] += 1
            self.all_unique_ips.add(ip)
            self.today_unique_ips.add(ip)
            if protocol == 'http':
                self.all_http_announces   += 1
                self.today_http_announces += 1
            elif protocol == 'https':
                self.all_https_announces   += 1
                self.today_https_announces += 1
            elif protocol == 'udp':
                self.all_udp_announces   += 1
                self.today_udp_announces += 1
            if is_ipv6:
                self.all_ipv6_clients   += 1
                self.today_ipv6_clients += 1
            else:
                self.all_ipv4_clients   += 1
                self.today_ipv4_clients += 1

    def record_http_bytes(self, raw: int, sent: int, used_gzip: bool):
        with self._lock:
            self.all_bytes_raw    += raw
            self.all_bytes_sent   += sent
            self.today_bytes_raw  += raw
            self.today_bytes_sent += sent
            if used_gzip:
                self.all_gzip_count   += 1
                self.today_gzip_count += 1
            else:
                self.all_plain_count   += 1
                self.today_plain_count += 1

    def record_udp_bytes(self, sent: int):
        with self._lock:
            self.all_bytes_sent   += sent
            self.all_bytes_raw    += sent
            self.today_bytes_sent += sent
            self.today_bytes_raw  += sent

    def snapshot(self) -> dict:
        with self._lock:
            return {
                'uptime':    time.time() - self.start_time,
                'torrents':  len(REGISTRY.all_hashes()),
                'live_peers': sum(len(v) for v in REGISTRY._torrents.values()),
                'all': {
                    'announces':   self.all_announces,
                    'http':        self.all_http_announces,
                    'https':       self.all_https_announces,
                    'udp':         self.all_udp_announces,
                    'ipv4':        self.all_ipv4_clients,
                    'ipv6':        self.all_ipv6_clients,
                    'unique_ips':  len(self.all_unique_ips),
                    'bytes_sent':  self.all_bytes_sent,
                    'bytes_raw':   self.all_bytes_raw,
                    'gzip_count':  self.all_gzip_count,
                    'plain_count': self.all_plain_count,
                    'daily_totals': dict(sorted(self.daily_totals.items())[-30:]),
                },
                'today': {
                    'date':        self._today.isoformat(),
                    'announces':   self.today_announces,
                    'http':        self.today_http_announces,
                    'https':       self.today_https_announces,
                    'udp':         self.today_udp_announces,
                    'ipv4':        self.today_ipv4_clients,
                    'ipv6':        self.today_ipv6_clients,
                    'unique_ips':  len(self.today_unique_ips),
                    'bytes_sent':  self.today_bytes_sent,
                    'bytes_raw':   self.today_bytes_raw,
                    'gzip_count':  self.today_gzip_count,
                    'plain_count': self.today_plain_count,
                    'hourly':      list(self.today_hourly),
                },
                'yesterday': dict(self.yesterday),
            }


STATS = StatsTracker()

# ─────────────────────────────────────────────────────────────
# Registration mode -- SQLite DB, sessions, user management
# ─────────────────────────────────────────────────────────────


REGISTRATION_MODE  = False
REGISTRATION_DB    = None   # RegistrationDB instance, set in main()
OPEN_TRACKER       = False  # mirrors settings[open_tracker]; updated without restart
REWARD_ENABLED     = False  # mirrors settings[reward_enabled]
REWARD_THRESHOLD   = 200    # mirrors settings[reward_threshold]
SUPER_USER         = ''
_MANAGE_HTTPS_PORT = 0      # set in main() so /manage routes know the HTTPS port

# ─────────────────────────────────────────────────────────────
# Bencode decoder  (for .torrent parsing)
# ─────────────────────────────────────────────────────────────

def bdecode(data: bytes):
    def _decode(pos):
        ch = data[pos:pos+1]
        if ch == b'i':
            end = data.index(b'e', pos+1)
            return int(data[pos+1:end]), end+1
        if ch == b'l':
            lst, pos = [], pos+1
            while data[pos:pos+1] != b'e':
                val, pos = _decode(pos)
                lst.append(val)
            return lst, pos+1
        if ch == b'd':
            dct, pos = {}, pos+1
            while data[pos:pos+1] != b'e':
                key, pos = _decode(pos)
                val, pos = _decode(pos)
                dct[key] = val
            return dct, pos+1
        # byte string
        colon = data.index(b':', pos)
        length = int(data[pos:colon])
        start  = colon+1
        return data[start:start+length], start+length
    val, _ = _decode(0)
    return val


def parse_torrent(data: bytes) -> tuple:
    """Parse a .torrent file.
    Returns (info_hash, name, total_size, meta) where meta is a dict with
    extended fields for the detail page.
    """
    torrent = bdecode(data)
    if not isinstance(torrent, dict) or b'info' not in torrent:
        raise ValueError('Not a valid torrent file')
    info = torrent[b'info']
    # Locate the raw 'info' dict in the original bytes and SHA1 it
    start = data.index(b'4:info') + 6
    def _skip(pos):
        ch = data[pos:pos+1]
        if ch == b'i':
            end = data.index(b'e', pos+1)
            return end+1
        if ch in (b'l', b'd'):
            pos += 1
            while data[pos:pos+1] != b'e':
                pos = _skip(pos)
            return pos+1
        colon = data.index(b':', pos)
        length = int(data[pos:colon])
        return colon+1+length
    end = _skip(start)
    info_raw = data[start:end]
    ih = hashlib.sha1(info_raw).hexdigest().upper()
    # Name
    name_bytes = info.get(b'name.utf-8') or info.get(b'name') or b'Unknown'
    name = name_bytes.decode('utf-8', errors='replace') if isinstance(name_bytes, bytes) else str(name_bytes)
    # File list
    def _dec(b):
        return b.decode('utf-8', errors='replace') if isinstance(b, bytes) else str(b)
    if b'files' in info:
        files = []
        for f in info[b'files']:
            path_parts = [_dec(p) for p in f.get(b'path.utf-8', f.get(b'path', [b'?']))]
            files.append({'path': '/'.join(path_parts), 'size': f.get(b'length', 0)})
        total_size = sum(f['size'] for f in files)
        is_multifile = True
    else:
        total_size = info.get(b'length', 0)
        files = [{'path': name, 'size': total_size}]
        is_multifile = False
    # Pieces
    pieces_raw = info.get(b'pieces', b'')
    piece_count = len(pieces_raw) // 20
    piece_length = info.get(b'piece length', 0)
    # Privacy flag
    private = bool(info.get(b'private', 0))
    meta = {
        'piece_count':  piece_count,
        'piece_length': piece_length,
        'private':      private,
        'is_multifile': is_multifile,
        'files':        json.dumps(files),   # stored as JSON string
    }
    return ih, name, total_size, meta


# ─────────────────────────────────────────────────────────────
# Password hashing (PBKDF2 / hashlib built-in)
# ─────────────────────────────────────────────────────────────

def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Return (hash_hex, salt_hex). Generate salt if not provided."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode(), 260000)
    return dk.hex(), salt


def _verify_password(password: str, stored_hash: str, salt: str) -> bool:
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode(), 260000)
    return hmac.compare_digest(dk.hex(), stored_hash)


# ── Security helpers ────────────────────────────────────
# CSRF secret is loaded from the DB on startup so server restarts
# do not invalidate existing browser CSRF cookies.
_CSRF_SECRET: bytes = b''  # populated by _init_csrf_secret() in main()


def _init_csrf_secret(db) -> None:
    """Load persistent CSRF secret from settings, creating it if absent."""
    global _CSRF_SECRET
    stored = db.get_setting('_csrf_secret')
    if stored:
        _CSRF_SECRET = bytes.fromhex(stored)
        log.debug('CSRF secret loaded from DB (prefix=%s)', stored[:8])
    else:
        _CSRF_SECRET = secrets.token_bytes(32)
        db.set_setting('_csrf_secret', _CSRF_SECRET.hex(), 'system')
        log.debug('CSRF secret generated and saved (prefix=%s)', _CSRF_SECRET.hex()[:8])


def _h(s: str) -> str:
    """HTML-escape for safe insertion into HTML."""
    return _html_mod.escape(str(s), quote=True)


def _csrf_token(session_token: str) -> str:
    """Derive CSRF token from session token via HMAC."""
    return hmac.new(_CSRF_SECRET, session_token.encode(), 'sha256').hexdigest()[:32]


def _get_page_param(path_with_query: str) -> int:
    """Extract ?page=N from URL, default 1."""
    qs = urllib.parse.urlparse(path_with_query).query
    params = urllib.parse.parse_qs(qs)
    try:
        return max(1, int(params.get('page', ['1'])[0]))
    except (ValueError, TypeError):
        return 1


def _get_named_page_param(path_with_query: str, name: str = 'page') -> int:
    qs = urllib.parse.urlparse(path_with_query).query
    params = urllib.parse.parse_qs(qs)
    try:
        return max(1, int(params.get(name, ['1'])[0]))
    except (ValueError, TypeError):
        return 1


def _pagination_html(current_page: int, total_pages: int, base_url: str,
                     page_param: str = 'page') -> str:
    """Render compact pagination: 1 2 3 ... 8 9 10 style."""
    if total_pages <= 1:
        return ''

    def page_url(p):
        sep = '&' if '?' in base_url else '?'
        return f'{base_url}{sep}{page_param}={p}'

    # Build list of page numbers to show
    pages = set()
    pages.update([1, 2, 3])
    pages.update([total_pages - 2, total_pages - 1, total_pages])
    pages.update([current_page - 1, current_page, current_page + 1])
    pages = sorted(p for p in pages if 1 <= p <= total_pages)

    btn = ('font-family:var(--mono);font-size:0.72rem;padding:5px 10px;border-radius:5px;'
           'border:1px solid var(--border);background:transparent;color:var(--muted);'
           'cursor:pointer;text-decoration:none;display:inline-block')
    btn_active = btn.replace('var(--muted)', 'var(--accent)').replace('var(--border)', 'var(--accent)')

    items = []
    prev_p = None
    for p in pages:
        if prev_p is not None and p - prev_p > 1:
            items.append('<span style="color:var(--muted);padding:0 4px">&#8230;</span>')
        style = btn_active if p == current_page else btn
        items.append(f'<a href="{page_url(p)}" style="{style}">{p}</a>')
        prev_p = p

    # Prev / Next arrows
    prev_btn = (f'<a href="{page_url(current_page-1)}" style="{btn}">&#8592;</a> '
                if current_page > 1 else '')
    next_btn = (f' <a href="{page_url(current_page+1)}" style="{btn}">&#8594;</a>'
                if current_page < total_pages else '')

    inner = prev_btn + ' '.join(items) + next_btn
    return (
        f'<div style="display:flex;align-items:center;justify-content:center;gap:6px;'
        f'flex-wrap:wrap;margin-top:16px;padding-top:14px;border-top:1px solid var(--border)">'
        f'{inner}'
        f'<span style="color:var(--muted);font-family:var(--mono);font-size:0.68rem;margin-left:8px">'
        f'Page {current_page} of {total_pages}</span>'
        f'</div>'
    )


def _user_role(user) -> str:
    """Return 'super','admin','standard','basic' for a user row."""
    if user['username'] == SUPER_USER: return 'super'
    if user['is_admin']:               return 'admin'
    if 'is_standard' in user.keys() and user['is_standard']: return 'standard'
    return 'basic'


def _validate_username(username: str) -> str:
    """Return error string if username is invalid, else empty string."""
    if not username:
        return 'Username is required.'
    if len(username) > 32:
        return 'Username must be 32 characters or fewer.'
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return 'Username may only contain letters, digits, dots, hyphens, and underscores.'
    return ''


def _validate_password(password: str, settings: dict) -> list[str]:
    """Return list of unmet requirements. Empty = valid."""
    errors = []
    min_len = int(settings.get('pw_min_length', '12'))
    if len(password) < min_len:
        errors.append(f'At least {min_len} characters')
    if settings.get('pw_require_upper', '1') == '1' and not any(c.isupper() for c in password):
        errors.append('At least one uppercase letter')
    if settings.get('pw_require_lower', '1') == '1' and not any(c.islower() for c in password):
        errors.append('At least one lowercase letter')
    if settings.get('pw_require_digit', '1') == '1' and not any(c.isdigit() for c in password):
        errors.append('At least one digit')
    if settings.get('pw_require_symbol', '1') == '1':
        symbols = set(string.punctuation)
        if not any(c in symbols for c in password):
            errors.append('At least one symbol (!@#$%^&* etc.)')
    return errors


# ─────────────────────────────────────────────────────────────
# SQLite database
# ─────────────────────────────────────────────────────────────

class RegistrationDB:
    def __init__(self, db_path: str):
        self._path = db_path
        self._local = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, 'conn', None):
            conn = sqlite3.connect(self._path, check_same_thread=False,
                                   timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA foreign_keys=ON')
            conn.execute('PRAGMA busy_timeout=10000')  # wait up to 10s on lock
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self):
        c = self._conn()
        c.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE,
                password_hash   TEXT    NOT NULL,
                salt            TEXT    NOT NULL,
                is_admin        INTEGER NOT NULL DEFAULT 0,
                is_standard     INTEGER NOT NULL DEFAULT 0,
                is_locked       INTEGER NOT NULL DEFAULT 0,
                is_disabled     INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                created_by      TEXT    NOT NULL DEFAULT '',
                created_at      TEXT    NOT NULL,
                last_login            TEXT,
                login_count           INTEGER NOT NULL DEFAULT 0,
                last_password_change  TEXT,
                credits               INTEGER NOT NULL DEFAULT 0,
                credits_awarded       INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS invite_codes (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                code                 TEXT NOT NULL UNIQUE,
                created_by_username  TEXT NOT NULL,
                created_at           TEXT NOT NULL,
                consumed_at          TEXT,
                consumed_by_username TEXT
            );
            CREATE TABLE IF NOT EXISTS ip_allowlist (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                ip_address TEXT    NOT NULL,
                added_at   TEXT    NOT NULL,
                added_by   TEXT    NOT NULL,
                UNIQUE(user_id, ip_address),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS login_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                ip_address  TEXT    NOT NULL,
                logged_in_at TEXT   NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS torrents (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                info_hash           TEXT    NOT NULL UNIQUE,
                name                TEXT    NOT NULL,
                total_size          INTEGER NOT NULL DEFAULT 0,
                uploaded_by_id      INTEGER,
                uploaded_by_username TEXT   NOT NULL,
                registered_at       TEXT    NOT NULL,
                piece_count         INTEGER NOT NULL DEFAULT 0,
                piece_length        INTEGER NOT NULL DEFAULT 0,
                is_private          INTEGER NOT NULL DEFAULT 0,
                is_multifile        INTEGER NOT NULL DEFAULT 0,
                files_json          TEXT    NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS magnet_trackers (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                url        TEXT    NOT NULL UNIQUE,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                token       TEXT    NOT NULL UNIQUE,
                created_at  TEXT    NOT NULL,
                expires_at  TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT    NOT NULL,
                actor      TEXT    NOT NULL,
                action     TEXT    NOT NULL,
                target     TEXT    NOT NULL DEFAULT '',
                detail     TEXT    NOT NULL DEFAULT ''
            );
        ''')
        # ── Migrations ────────────────────────────────────────
        cols = [r[1] for r in c.execute('PRAGMA table_info(torrents)').fetchall()]
        if 'total_size' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN total_size INTEGER NOT NULL DEFAULT 0')
        if 'piece_count' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN piece_count INTEGER NOT NULL DEFAULT 0')
        if 'piece_length' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN piece_length INTEGER NOT NULL DEFAULT 0')
        if 'is_private' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0')
        if 'is_multifile' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN is_multifile INTEGER NOT NULL DEFAULT 0')
        if 'files_json' not in cols:
            c.execute("ALTER TABLE torrents ADD COLUMN files_json TEXT NOT NULL DEFAULT '[]'")
        ucols = [r[1] for r in c.execute('PRAGMA table_info(users)').fetchall()]
        if 'login_count' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0')
        if 'last_password_change' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN last_password_change TEXT')
        if 'is_standard' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN is_standard INTEGER NOT NULL DEFAULT 0')
        if 'credits' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN credits INTEGER NOT NULL DEFAULT 0')
        if 'credits_awarded' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN credits_awarded INTEGER NOT NULL DEFAULT 0')
        # invite_codes table (may not exist on older installs)
        c.execute('''
            CREATE TABLE IF NOT EXISTS invite_codes (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                code                 TEXT NOT NULL UNIQUE,
                created_by_username  TEXT NOT NULL,
                created_at           TEXT NOT NULL,
                consumed_at          TEXT,
                consumed_by_username TEXT
            )''')
        c.commit()

    def _init_defaults(self, announce_urls: list):
        """Seed magnet_trackers and settings if not already present."""
        c = self._conn()
        # Seed settings
        defaults = {
            'free_signup':           '0',
            'auto_promote_enabled':   '0',
            'auto_promote_threshold': '25',
            'torrents_per_page':       '50',
            'robots_txt':              'User-agent: *\nDisallow: /announce\nDisallow: /scrape\nDisallow: /manage\n',
            'pw_min_length':     '12',
            'pw_require_upper':  '1',
            'pw_require_lower':  '1',
            'pw_require_digit':  '1',
            'pw_require_symbol': '1',
            'open_tracker':       '0',
            'reward_enabled':     '0',
            'reward_threshold':   '200',
        }
        for k, v in defaults.items():
            c.execute('INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)', (k, v))
        # Seed magnet trackers from announce_urls (wildkat first) if table empty
        if not c.execute('SELECT COUNT(*) FROM magnet_trackers').fetchone()[0]:
            order = 0
            for _, url in announce_urls:
                c.execute('INSERT OR IGNORE INTO magnet_trackers (url,is_enabled,sort_order) VALUES (?,1,?)',
                          (url, order))
                order += 1
        c.commit()

    def get_setting(self, key: str, default: str = '') -> str:
        row = self._conn().execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value: str, actor: str = ''):
        self._conn().execute('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', (key, value))
        self._conn().commit()
        if actor:
            self._log(actor, 'set_setting', key, value)

    def get_all_settings(self) -> dict:
        rows = self._conn().execute('SELECT key,value FROM settings').fetchall()
        return {r[0]: r[1] for r in rows}

    def list_magnet_trackers(self) -> list:
        return self._conn().execute(
            'SELECT * FROM magnet_trackers ORDER BY sort_order, id'
        ).fetchall()

    def add_magnet_tracker(self, url: str, actor: str) -> bool:
        try:
            max_order = self._conn().execute(
                'SELECT COALESCE(MAX(sort_order),0) FROM magnet_trackers'
            ).fetchone()[0]
            self._conn().execute(
                'INSERT INTO magnet_trackers (url,is_enabled,sort_order) VALUES (?,1,?)',
                (url, max_order + 1)
            )
            self._conn().commit()
            self._log(actor, 'add_magnet_tracker', url)
            return True
        except sqlite3.IntegrityError:
            return False

    def delete_magnet_tracker(self, tid: int, actor: str):
        row = self._conn().execute('SELECT url FROM magnet_trackers WHERE id=?', (tid,)).fetchone()
        self._conn().execute('DELETE FROM magnet_trackers WHERE id=?', (tid,))
        self._conn().commit()
        if row:
            self._log(actor, 'delete_magnet_tracker', row[0])

    def toggle_magnet_tracker(self, tid: int, actor: str):
        c = self._conn()
        c.execute('UPDATE magnet_trackers SET is_enabled = 1 - is_enabled WHERE id=?', (tid,))
        c.commit()
        row = c.execute('SELECT url, is_enabled FROM magnet_trackers WHERE id=?', (tid,)).fetchone()
        if row:
            action = 'enable_tracker' if row['is_enabled'] else 'disable_tracker'
            self._log(actor, action, row['url'])

    def move_magnet_tracker(self, tid: int, direction: int, actor: str):
        """Move tracker up (-1) or down (+1) in sort order."""
        c = self._conn()
        rows = c.execute('SELECT id,sort_order FROM magnet_trackers ORDER BY sort_order,id').fetchall()
        ids = [r[0] for r in rows]
        if tid not in ids:
            return
        idx = ids.index(tid)
        swap_idx = idx + direction
        if swap_idx < 0 or swap_idx >= len(ids):
            return
        swap_id = ids[swap_idx]
        # Swap sort_orders
        o1 = rows[idx][1]
        o2 = rows[swap_idx][1]
        if o1 == o2:
            o2 = o1 + direction
        c.execute('UPDATE magnet_trackers SET sort_order=? WHERE id=?', (o2, tid))
        c.execute('UPDATE magnet_trackers SET sort_order=? WHERE id=?', (o1, swap_id))
        c.commit()

    def build_magnet(self, ih: str, name: str, total_size: int) -> str:
        """Build a magnet link using enabled trackers in sort order."""
        params = [
            ('xt', f'urn:btih:{ih.lower()}'),
            ('dn', name),
        ]
        if total_size:
            params.append(('xl', str(total_size)))
        trackers = self._conn().execute(
            'SELECT url FROM magnet_trackers WHERE is_enabled=1 ORDER BY sort_order,id'
        ).fetchall()
        for t in trackers:
            params.append(('tr', t[0]))
        return 'magnet:?' + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)

    def _ts(self) -> str:
        return datetime.datetime.now().isoformat(timespec='seconds')


    def _log(self, actor: str, action: str, target: str = '', detail: str = ''):
        c = self._conn()
        c.execute('INSERT INTO events (timestamp,actor,action,target,detail) VALUES (?,?,?,?,?)',
                  (self._ts(), actor, action, target, detail))
        c.commit()

    # ── Users ──────────────────────────────────────────────────

    def create_user(self, username: str, password: str, is_admin: bool, created_by: str) -> bool:
        ph, salt = _hash_password(password)
        try:
            self._conn().execute(
                'INSERT INTO users (username,password_hash,salt,is_admin,created_by,created_at) VALUES (?,?,?,?,?,?)',
                (username, ph, salt, 1 if is_admin else 0, created_by, self._ts())
            )
            self._conn().commit()
            self._log(created_by, 'create_user', username, f'is_admin={is_admin}')
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str) -> sqlite3.Row | None:
        return self._conn().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()

    def get_user_by_id(self, uid: int) -> sqlite3.Row | None:
        return self._conn().execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()

    def list_users(self, page: int = 1, per_page: int = 50) -> list:
        offset = (page - 1) * per_page
        return self._conn().execute(
            'SELECT * FROM users ORDER BY username LIMIT ? OFFSET ?',
            (per_page, offset)
        ).fetchall()

    def list_users_all(self) -> list:
        return self._conn().execute('SELECT * FROM users ORDER BY username').fetchall()

    def count_users(self) -> int:
        return self._conn().execute('SELECT COUNT(*) FROM users').fetchone()[0]

    def search_users(self, query: str, page: int = 1, per_page: int = 50) -> list:
        q = f'%{query}%'
        offset = (page - 1) * per_page
        return self._conn().execute(
            'SELECT * FROM users WHERE username LIKE ? ORDER BY username LIMIT ? OFFSET ?',
            (q, per_page, offset)
        ).fetchall()

    def count_search_users(self, query: str) -> int:
        q = f'%{query}%'
        return self._conn().execute(
            'SELECT COUNT(*) FROM users WHERE username LIKE ?', (q,)
        ).fetchone()[0]


    def authenticate(self, username: str, password: str) -> sqlite3.Row | None:
        """Returns user row on success, None on failure. Handles lockout tracking."""
        user = self.get_user(username)
        if user is None:
            return None
        if user['is_locked'] or user['is_disabled']:
            return None
        if not _verify_password(password, user['password_hash'], user['salt']):
            attempts = user['failed_attempts'] + 1
            locked   = 1 if attempts >= 5 else 0
            self._conn().execute(
                'UPDATE users SET failed_attempts=?, is_locked=? WHERE id=?',
                (attempts, locked, user['id'])
            )
            self._conn().commit()
            if locked:
                self._log('system', 'lock_user', username, f'locked after {attempts} failed attempts')
            return None
        # Success -- reset failed attempts, record login
        ts = self._ts()
        self._conn().execute(
            'UPDATE users SET failed_attempts=0, last_login=?, login_count=login_count+1 WHERE id=?',
            (ts, user['id'])
        )
        self._conn().commit()
        return self.get_user(username)

    def record_login_ip(self, user_id: int, ip: str):
        ts = self._ts()
        self._conn().execute(
            'INSERT INTO login_history (user_id,ip_address,logged_in_at) VALUES (?,?,?)',
            (user_id, ip, ts)
        )
        # Keep only last 20 per user
        self._conn().execute(
            'DELETE FROM login_history WHERE user_id=? AND id NOT IN '
            '(SELECT id FROM login_history WHERE user_id=? ORDER BY id DESC LIMIT 20)',
            (user_id, user_id)
        )
        self._conn().commit()

    def get_login_history(self, user_id: int, limit: int = 5) -> list:
        return self._conn().execute(
            'SELECT ip_address, logged_in_at FROM login_history '
            'WHERE user_id=? ORDER BY id DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()

    def add_ip_allowlist(self, user_id: int, ip: str, actor: str) -> bool:
        try:
            self._conn().execute(
                'INSERT INTO ip_allowlist (user_id,ip_address,added_at,added_by) VALUES (?,?,?,?)',
                (user_id, ip, self._ts(), actor)
            )
            self._conn().commit()
            self._log(actor, 'ip_allowlist_add', str(user_id), ip)
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_ip_allowlist(self, entry_id: int, actor: str):
        row = self._conn().execute('SELECT user_id,ip_address FROM ip_allowlist WHERE id=?', (entry_id,)).fetchone()
        self._conn().execute('DELETE FROM ip_allowlist WHERE id=?', (entry_id,))
        self._conn().commit()
        if row: self._log(actor, 'ip_allowlist_remove', str(row[0]), row[1])

    def clear_ip_allowlist(self, user_id: int, actor: str):
        self._conn().execute('DELETE FROM ip_allowlist WHERE user_id=?', (user_id,))
        self._conn().commit()
        self._log(actor, 'ip_allowlist_clear', str(user_id))

    def get_ip_allowlist(self, user_id: int) -> list:
        return self._conn().execute(
            'SELECT * FROM ip_allowlist WHERE user_id=? ORDER BY added_at DESC', (user_id,)
        ).fetchall()

    def is_ip_allowed(self, user_id: int, ip: str) -> bool:
        """Returns True if no allowlist exists (open) or IP is in allowlist."""
        count = self._conn().execute(
            'SELECT COUNT(*) FROM ip_allowlist WHERE user_id=?', (user_id,)
        ).fetchone()[0]
        if count == 0:
            return True  # No restriction
        row = self._conn().execute(
            'SELECT id FROM ip_allowlist WHERE user_id=? AND ip_address=?', (user_id, ip)
        ).fetchone()
        return row is not None

    def set_standard(self, username: str, is_standard: bool, actor: str):
        self._conn().execute('UPDATE users SET is_standard=? WHERE username=?',
                             (1 if is_standard else 0, username))
        self._conn().commit()
        self._log(actor, 'set_standard', username, str(is_standard))

    def delete_all_torrents_for_user(self, user_id: int, actor: str,
                                      target_username: str = ''):
        self._conn().execute('DELETE FROM torrents WHERE uploaded_by_id=?', (user_id,))
        self._conn().commit()
        detail = f'deleted all torrents for {target_username}' if target_username else f'deleted all torrents for user_id={user_id}'
        self._log(actor, 'delete_all_torrents_user', target_username or str(user_id), detail)

    def delete_all_torrents(self, actor: str):
        self._conn().execute('DELETE FROM torrents')
        self._conn().commit()
        self._log(actor, 'delete_all_torrents', 'ALL', 'deleted entire torrent database')

    def check_auto_promote(self, user_id: int) -> bool:
        """Promote basic→standard if upload threshold reached. Returns True if promoted."""
        if self.get_setting('auto_promote_enabled') != '1':
            return False
        user = self.get_user_by_id(user_id)
        if not user or user['is_standard'] or user['is_admin']:
            return False
        threshold = int(self.get_setting('auto_promote_threshold', '25'))
        count = self._conn().execute(
            'SELECT COUNT(*) FROM torrents WHERE uploaded_by_id=?', (user_id,)
        ).fetchone()[0]
        if count >= threshold:
            self._conn().execute('UPDATE users SET is_standard=1 WHERE id=?', (user_id,))
            self._conn().commit()
            self._log('system', 'auto_promote', user['username'],
                      f'promoted to standard after {count} uploads')
            return True
        return False

    def change_password(self, username: str, new_password: str, actor: str):
        ph, salt = _hash_password(new_password)
        self._conn().execute(
            'UPDATE users SET password_hash=?, salt=?, failed_attempts=0, is_locked=0, '
            'last_password_change=? WHERE username=?',
            (ph, salt, self._ts(), username)
        )
        self._conn().commit()
        self._log(actor, 'change_password', username)

    def set_admin(self, username: str, is_admin: bool, actor: str):
        self._conn().execute('UPDATE users SET is_admin=? WHERE username=?',
                             (1 if is_admin else 0, username))
        self._conn().commit()
        self._log(actor, 'set_admin', username, str(is_admin))

    def set_locked(self, username: str, locked: bool, actor: str):
        self._conn().execute(
            'UPDATE users SET is_locked=?, failed_attempts=0 WHERE username=?',
            (1 if locked else 0, username)
        )
        self._conn().commit()
        self._log(actor, 'unlock_user' if not locked else 'lock_user', username)

    def set_disabled(self, username: str, disabled: bool, actor: str):
        self._conn().execute('UPDATE users SET is_disabled=? WHERE username=?',
                             (1 if disabled else 0, username))
        self._conn().commit()
        self._log(actor, 'disable_user' if disabled else 'enable_user', username)

    def delete_all_users(self, actor: str, except_username: str) -> int:
        """Delete every user except the super-user. Returns count deleted."""
        rows = self._conn().execute(
            'SELECT username FROM users WHERE username != ?', (except_username,)
        ).fetchall()
        count = len(rows)
        # Reassign all their torrents to [deleted] before removing accounts
        self._conn().execute(
            'UPDATE torrents SET uploaded_by_id=NULL, uploaded_by_username=?'
            ' WHERE uploaded_by_username != ?', ('[deleted]', except_username)
        )
        self._conn().execute('DELETE FROM users WHERE username != ?', (except_username,))
        self._conn().commit()
        self._log(actor, 'delete_all_users', 'ALL',
                  f'deleted {count} users (super {except_username} preserved)')
        return count

    def delete_user(self, username: str, actor: str):
        # Reassign torrents to [deleted] so they are preserved but disowned
        self._conn().execute(
            'UPDATE torrents SET uploaded_by_id=NULL, uploaded_by_username=?'
            ' WHERE uploaded_by_username=?', ('[deleted]', username)
        )
        self._conn().execute('DELETE FROM users WHERE username=?', (username,))
        self._conn().commit()
        self._log(actor, 'delete_user', username)

    # ── Torrents ───────────────────────────────────────────────

    def register_torrent(self, ih: str, name: str, total_size: int,
                         user_id: int, username: str, meta: dict | None = None) -> bool:
        meta = meta or {}
        for attempt in range(5):
            try:
                self._conn().execute(
                    'INSERT INTO torrents '
                    '(info_hash,name,total_size,uploaded_by_id,uploaded_by_username,registered_at,'
                    'piece_count,piece_length,is_private,is_multifile,files_json) '
                    'VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                    (ih.upper(), name, total_size, user_id, username, self._ts(),
                     meta.get('piece_count', 0), meta.get('piece_length', 0),
                     1 if meta.get('private') else 0,
                     1 if meta.get('is_multifile') else 0,
                     meta.get('files', '[]'))
                )
                self._conn().commit()
                self._log(username, 'register_torrent', ih.upper(), name)
                return True
            except sqlite3.IntegrityError:
                return False
            except sqlite3.OperationalError as e:
                if 'locked' in str(e) and attempt < 4:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise

    # ── Credits & Invite Codes ────────────────────────────

    def check_reward_credit(self, user_id: int) -> bool:
        """Award credits if user has crossed a new reward threshold. Returns True if awarded."""
        if not REWARD_ENABLED or REWARD_THRESHOLD < 1:
            return False
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        count = self._conn().execute(
            'SELECT COUNT(*) FROM torrents WHERE uploaded_by_id=?', (user_id,)
        ).fetchone()[0]
        should_have = count // REWARD_THRESHOLD
        awarded = user['credits_awarded']
        to_give = should_have - awarded
        if to_give > 0:
            self._conn().execute(
                'UPDATE users SET credits=credits+?, credits_awarded=credits_awarded+? WHERE id=?',
                (to_give, to_give, user_id)
            )
            self._conn().commit()
            self._log('system', 'reward_credit', user['username'],
                      f'{to_give} credit(s) awarded at {count} torrents')
            return True
        return False

    def adjust_credits(self, username: str, delta: int, actor: str) -> int:
        """Add delta credits to user (can be negative, floored at 0). Returns new balance."""
        self._conn().execute(
            'UPDATE users SET credits=MAX(0, credits+?) WHERE username=?',
            (delta, username)
        )
        self._conn().commit()
        row = self._conn().execute(
            'SELECT credits FROM users WHERE username=?', (username,)
        ).fetchone()
        new_bal = row[0] if row else 0
        action = 'credit_add' if delta > 0 else 'credit_remove'
        self._log(actor, action, username, f'delta={delta:+d} balance={new_bal}')
        return new_bal

    def create_invite_code(self, created_by_username: str) -> str:
        """Generate a new invite code, spending 1 credit if user is not admin/super.
        Admin/super generate for free. Returns the token.
        """
        token = secrets.token_urlsafe(32)
        self._conn().execute(
            'INSERT INTO invite_codes (code, created_by_username, created_at) VALUES (?,?,?)',
            (token, created_by_username, self._ts())
        )
        self._conn().commit()
        self._log(created_by_username, 'create_invite', token[:12] + '...')
        return token

    def spend_credit_for_invite(self, username: str) -> str | None:
        """Spend 1 credit and create an invite. Returns token or None if no credits."""
        row = self._conn().execute(
            'SELECT credits FROM users WHERE username=?', (username,)
        ).fetchone()
        if not row or row[0] < 1:
            return None
        self._conn().execute(
            'UPDATE users SET credits=credits-1 WHERE username=?', (username,)
        )
        self._conn().commit()
        return self.create_invite_code(username)

    def list_invite_codes(self, created_by_username: str | None = None) -> list:
        """All codes (admin view) or codes for a specific user."""
        if created_by_username:
            return self._conn().execute(
                'SELECT * FROM invite_codes WHERE created_by_username=?'
                ' ORDER BY created_at DESC', (created_by_username,)
            ).fetchall()
        return self._conn().execute(
            'SELECT * FROM invite_codes ORDER BY created_at DESC'
        ).fetchall()

    def delete_invite_code(self, code: str, actor: str) -> bool:
        """Delete an invite code. Returns True if it existed."""
        cur = self._conn().execute(
            'DELETE FROM invite_codes WHERE code=? AND consumed_at IS NULL', (code,)
        )
        self._conn().commit()
        if cur.rowcount:
            self._log(actor, 'delete_invite', code[:12] + '...')
            return True
        return False

    def consume_invite_code(self, code: str, new_username: str) -> bool:
        """Mark invite as consumed. Returns True if valid & unconsumed."""
        cur = self._conn().execute(
            'UPDATE invite_codes SET consumed_at=?, consumed_by_username=?'
            ' WHERE code=? AND consumed_at IS NULL',
            (self._ts(), new_username, code)
        )
        self._conn().commit()
        return cur.rowcount > 0

    def get_invite_code(self, code: str):
        """Return invite row or None."""
        return self._conn().execute(
            'SELECT * FROM invite_codes WHERE code=?', (code,)
        ).fetchone()

    def is_registered(self, ih_upper: str) -> bool:
        row = self._conn().execute(
            'SELECT id FROM torrents WHERE info_hash=?', (ih_upper,)
        ).fetchone()
        return row is not None

    @staticmethod
    def _build_search_clauses(query: str):
        """Split query into tokens, return (where_fragment, params_list).
        Each token must match either the name (with separators normalised to spaces)
        or the raw name or the info_hash.  Dots/dashes/underscores are treated as
        spaces so 'rental family' matches 'Rental.Family.2025...'
        """
        import re
        # Normalise separators in the query too, then split on whitespace
        tokens = re.split(r'[\s.\-_]+', query.strip())
        tokens = [t for t in tokens if t]  # drop empties
        if not tokens:
            tokens = [query.strip()]
        clauses = []
        params = []
        for tok in tokens:
            like = f'%{tok}%'
            # Match raw name, separator-normalised name, or info_hash
            clauses.append(
                '(name LIKE ? OR '
                'REPLACE(REPLACE(REPLACE(name,\'.\',\' \'),\'-\',\' \'),\'_\',\' \') LIKE ? OR '
                'info_hash LIKE ?)'
            )
            params.extend([like, like, like])
        where = ' AND '.join(clauses)
        return where, params

    def search_torrents(self, query: str, user_id: int | None = None,
                        page: int = 1, per_page: int = 50) -> list:
        where, params = self._build_search_clauses(query)
        offset = (max(1, page) - 1) * per_page
        if user_id is None:
            return self._conn().execute(
                f'SELECT * FROM torrents WHERE {where} '
                'ORDER BY registered_at DESC LIMIT ? OFFSET ?',
                (*params, per_page, offset)
            ).fetchall()
        return self._conn().execute(
            f'SELECT * FROM torrents WHERE uploaded_by_id=? AND ({where}) '
            'ORDER BY registered_at DESC LIMIT ? OFFSET ?',
            (user_id, *params, per_page, offset)
        ).fetchall()

    def count_search_torrents(self, query: str, user_id: int | None = None) -> int:
        where, params = self._build_search_clauses(query)
        if user_id is None:
            return self._conn().execute(
                f'SELECT COUNT(*) FROM torrents WHERE {where}',
                params
            ).fetchone()[0]
        return self._conn().execute(
            f'SELECT COUNT(*) FROM torrents WHERE uploaded_by_id=? AND ({where})',
            (user_id, *params)
        ).fetchone()[0]

    def count_torrents(self, user_id: int | None = None) -> int:
        if user_id is None:
            return self._conn().execute('SELECT COUNT(*) FROM torrents').fetchone()[0]
        return self._conn().execute(
            'SELECT COUNT(*) FROM torrents WHERE uploaded_by_id=?', (user_id,)
        ).fetchone()[0]

    def list_torrents(self, user_id: int | None = None,
                      page: int = 1, per_page: int = 0) -> list:
        """Return torrents. per_page=0 means no pagination (all rows)."""
        if per_page <= 0:
            if user_id is None:
                return self._conn().execute(
                    'SELECT * FROM torrents ORDER BY registered_at DESC'
                ).fetchall()
            return self._conn().execute(
                'SELECT * FROM torrents WHERE uploaded_by_id=? ORDER BY registered_at DESC',
                (user_id,)
            ).fetchall()
        offset = (max(1, page) - 1) * per_page
        if user_id is None:
            return self._conn().execute(
                'SELECT * FROM torrents ORDER BY registered_at DESC LIMIT ? OFFSET ?',
                (per_page, offset)
            ).fetchall()
        return self._conn().execute(
            'SELECT * FROM torrents WHERE uploaded_by_id=? ORDER BY registered_at DESC LIMIT ? OFFSET ?',
            (user_id, per_page, offset)
        ).fetchall()

    def delete_torrent(self, ih: str, actor: str):
        # Fetch name before deleting so we can log it
        row = self._conn().execute(
            'SELECT name FROM torrents WHERE info_hash=?', (ih.upper(),)
        ).fetchone()
        torrent_name = row['name'] if row else ih.upper()
        for attempt in range(5):
            try:
                self._conn().execute('DELETE FROM torrents WHERE info_hash=?', (ih.upper(),))
                self._conn().commit()
                self._log(actor, 'delete_torrent', ih.upper(), torrent_name)
                return
            except sqlite3.OperationalError as e:
                if 'locked' in str(e) and attempt < 4:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                raise

    def get_torrent(self, ih: str) -> sqlite3.Row | None:
        return self._conn().execute(
            'SELECT * FROM torrents WHERE info_hash=?', (ih.upper(),)
        ).fetchone()

    # ── Sessions ───────────────────────────────────────────────

    def create_session(self, user_id: int) -> str:
        token      = secrets.token_hex(32)
        now        = datetime.datetime.now()
        expires_at = (now + datetime.timedelta(hours=48)).isoformat(timespec='seconds')
        self._conn().execute(
            'INSERT INTO sessions (user_id,token,created_at,expires_at) VALUES (?,?,?,?)',
            (user_id, token, now.isoformat(timespec='seconds'), expires_at)
        )
        self._conn().commit()
        return token

    def get_session_user(self, token: str) -> sqlite3.Row | None:
        """Return user row if session token is valid and not expired."""
        now = datetime.datetime.now().isoformat(timespec='seconds')
        row = self._conn().execute(
            'SELECT user_id FROM sessions WHERE token=? AND expires_at>?',
            (token, now)
        ).fetchone()
        if row is None:
            return None
        return self.get_user_by_id(row['user_id'])

    def delete_session(self, token: str):
        self._conn().execute('DELETE FROM sessions WHERE token=?', (token,))
        self._conn().commit()

    def purge_expired_sessions(self):
        now = datetime.datetime.now().isoformat(timespec='seconds')
        self._conn().execute('DELETE FROM sessions WHERE expires_at<=?', (now,))
        self._conn().commit()

    # ── Events ─────────────────────────────────────────────────

    def list_events(self, limit: int = 100) -> list:
        return self._conn().execute(
            'SELECT * FROM events ORDER BY id DESC LIMIT ?', (limit,)
        ).fetchall()




# ─────────────────────────────────────────────────────────────
# HTTP Handler
# ─────────────────────────────────────────────────────────────

class TrackerHTTPHandler(BaseHTTPRequestHandler):
    """Handles HTTP(S) announce and scrape GET requests."""

    # Suppress default access logs; we use our own
    def log_message(self, fmt, *args):
        path = getattr(self, 'path', '?').split('?')[0]
        cmd  = getattr(self, 'command', '?')
        log.info('%s %s %s', self.client_address[0], cmd, path)

    def log_error(self, fmt, *args):
        # Downgrade bad-request noise (garbage TLS probes etc.) to DEBUG
        msg = fmt % args if args else str(fmt)
        log.debug('WEB %s %s', self.client_address[0], msg)

    def do_HEAD(self):
        # Return same headers as GET but no body — satisfies scanners
        path = getattr(self, 'path', '/')
        if path.rstrip('/') in ('', '/') or path.startswith('/announce') or path.startswith('/scrape'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    # ── Routing ──────────────────────────────────────────────

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path.rstrip('/')

        if path.endswith('/announce') or path == '/announce':
            self._handle_announce(parsed)
        elif path.endswith('/scrape') or path == '/scrape':
            self._handle_scrape(parsed)
        else:
            self._send_text(404, 'Not Found')

    # ── Announce ─────────────────────────────────────────────

    def _handle_announce(self, parsed):
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        def get(key, default=None):
            vals = params.get(key)
            return vals[0] if vals else default

        # info_hash is raw bytes, URL-decoded from the query string
        raw_ih = self._get_raw_param(parsed.query, 'info_hash')
        if raw_ih is None or len(raw_ih) != 20:
            self._send_bencode(200, {b'failure reason': b'missing or invalid info_hash'})
            return
        if REGISTRATION_MODE and REGISTRATION_DB is not None:
            if not OPEN_TRACKER and \
                    not REGISTRATION_DB.is_registered(raw_ih.hex().upper()):
                self._send_bencode(200, {b'failure reason': b'torrent not registered'})
                return

        raw_pid = self._get_raw_param(parsed.query, 'peer_id')
        if raw_pid is None or len(raw_pid) != 20:
            raw_pid = os.urandom(20)

        try:
            port       = int(get('port', 0))
            left       = int(get('left', 0))
            downloaded = int(get('downloaded', 0))
            uploaded   = int(get('uploaded', 0))
            num_want   = int(get('numwant', MAX_PEERS_PER_REPLY))
            num_want   = min(num_want, MAX_PEERS_PER_REPLY)
        except (ValueError, TypeError):
            self._send_bencode(200, {b'failure reason': b'invalid numeric parameter'})
            return

        event = get('event', 'none')
        if event not in ('started', 'completed', 'stopped', 'none', ''):
            event = 'none'

        # Determine client IP: prefer X-Forwarded-For for reverse-proxy setups
        ip = self.headers.get('X-Forwarded-For', self.client_address[0]).split(',')[0].strip()
        ih_hex = raw_ih.hex().upper()
        user_agent = self.headers.get('User-Agent', 'unknown')

        log.debug(
            'HTTP ANNOUNCE  from=%s  ih=%s  peer_id=%s  port=%d  event=%s  '
            'left=%d  downloaded=%d  uploaded=%d  numwant=%d  compact=%s  user-agent=%s',
            ip, ih_hex, raw_pid.hex(), port, event,
            left, downloaded, uploaded, num_want, get('compact', '1'), user_agent
        )

        # Register / update peer
        REGISTRY.announce(ih_hex, raw_pid, ip, port, left, event)

        seeds, leechers, downloaded, ipv4_compact, ipv6_compact, ipv4_mapped_compact, peer_dicts = \
            REGISTRY.get_peers(ih_hex, num_want, ip, port)

        # Detect client compact preference (default=1 per BEP 23)
        compact = get('compact', '1') != '0'

        # no_peer_id: only relevant in dict (non-compact) mode per BEP 3
        # ignored when compact=1 since binary format has no peer_id field
        no_peer_id = get('no_peer_id', '0') == '1'

        # Detect whether client connected via IPv6
        client_is_ipv6 = ':' in ip

        response = {
            b'interval':     DEFAULT_INTERVAL,
            b'min interval': DEFAULT_MIN_INTERVAL,
            b'complete':     seeds,
            b'incomplete':   leechers,
            b'downloaded':   downloaded,
        }

        if compact:
            if client_is_ipv6:
                # IPv6 client: return only peers6, with IPv4 peers as ::ffff:x.x.x.x
                # (same approach as tracker.theoks.net)
                response[b'peers6'] = ipv6_compact + ipv4_mapped_compact
                response[b'peers']  = b''
            else:
                # IPv4 client: return only peers (IPv4 compact)
                response[b'peers'] = ipv4_compact
        else:
            # Dictionary model (older clients)
            # Honor no_peer_id=1 by omitting 'peer id' from each dict
            dict_peers = []
            for p in peer_dicts:
                peer_dict = {
                    b'ip':   p['ip'].encode(),
                    b'port': p['port'],
                }
                if not no_peer_id:
                    peer_dict[b'peer id'] = p['peer_id']
                dict_peers.append(peer_dict)
            response[b'peers'] = dict_peers

        # Tracker ID (BEP 3)
        if DEFAULT_TRACKER_ID:
            response[b'tracker id'] = DEFAULT_TRACKER_ID.encode()

        # BEP 24: external ip
        try:
            addr = ipaddress.ip_address(ip)
            response[b'external ip'] = addr.packed
        except ValueError:
            pass

        log.debug(
            'HTTP ANNOUNCE  response  seeds=%d  leechers=%d  downloaded=%d  '
            'ipv4_peers=%d  ipv6_peers=%d  ipv4_mapped=%d  ipv6_client=%s  interval=%d',
            seeds, leechers, downloaded,
            len(ipv4_compact) // 6, len(ipv6_compact) // 18,
            len(ipv4_mapped_compact) // 18, client_is_ipv6,
            DEFAULT_INTERVAL
        )
        protocol = 'https' if self.server.socket.__class__.__name__ == 'SSLSocket' else 'http'
        STATS.record_announce(protocol, ip, client_is_ipv6)
        self._send_bencode(200, response)

    # ── Scrape ───────────────────────────────────────────────

    def _handle_scrape(self, parsed):
        # Collect all info_hash values (may be repeated)
        ih_list = self._get_all_raw_params(parsed.query, 'info_hash')
        if REGISTRATION_MODE and REGISTRATION_DB is not None and ih_list:
            if not OPEN_TRACKER:
                unregistered = [ih for ih in ih_list
                                if not REGISTRATION_DB.is_registered(ih.hex().upper())]
                if unregistered:
                    self._send_bencode(200, {b'failure reason': b'torrent not registered'})
                    return

        if not ih_list:
            if not ALLOW_FULL_SCRAPE:
                log.debug('HTTP SCRAPE  full scrape denied from=%s', self.client_address[0])
                self._send_bencode(200, {b'failure reason': b'full scrape not allowed'})
                return
            # Full scrape allowed -- return all known torrents
            ih_list = [bytes.fromhex(h) for h in REGISTRY.all_hashes()]
        elif len(ih_list) > MAX_SCRAPE_HASHES:
            log.debug('HTTP SCRAPE  too many hashes (%d) from=%s', len(ih_list), self.client_address[0])
            self._send_bencode(200, {b'failure reason': f'too many info_hashes, max is {MAX_SCRAPE_HASHES}'.encode()})
            return

        files = {}
        for raw_ih in ih_list:
            if len(raw_ih) != 20:
                continue
            ih_hex = raw_ih.hex().upper()
            complete, incomplete, downloaded = REGISTRY.scrape_stats(ih_hex)
            files[raw_ih] = {
                b'complete':   complete,
                b'incomplete': incomplete,
                b'downloaded': downloaded,
            }

        log.debug(
            'HTTP SCRAPE  from=%s  hashes=%s',
            self.client_address[0],
            ', '.join(h.hex().upper() for h in ih_list if len(h) == 20)
        )
        for raw_ih, stats in files.items():
            log.debug(
                'HTTP SCRAPE  response  ih=%s  complete=%d  incomplete=%d  downloaded=%d',
                raw_ih.hex().upper(), stats[b'complete'], stats[b'incomplete'], stats[b'downloaded']
            )
        response = {
            b'files': files,
            b'flags': {b'min_request_interval': DEFAULT_MIN_INTERVAL},
        }
        self._send_bencode(200, response)

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _get_raw_param(query_string: str, param: str) -> bytes | None:
        """
        Extract a raw (percent-decoded) binary parameter from a query string.
        urllib.parse.parse_qs loses binary data – we do it manually.
        """
        for part in query_string.split('&'):
            if '=' not in part:
                continue
            k, _, v = part.partition('=')
            if urllib.parse.unquote(k) == param:
                return urllib.parse.unquote_to_bytes(v)
        return None

    @staticmethod
    def _get_all_raw_params(query_string: str, param: str) -> list[bytes]:
        """Return all occurrences of a raw binary parameter."""
        results = []
        for part in query_string.split('&'):
            if '=' not in part:
                continue
            k, _, v = part.partition('=')
            if urllib.parse.unquote(k) == param:
                results.append(urllib.parse.unquote_to_bytes(v))
        return results

    def _send_bencode(self, code: int, obj):
        body = bencode(obj)

        # Compress if client advertised gzip support and compression actually saves bytes
        accept_encoding = self.headers.get('Accept-Encoding', '')
        use_gzip = False
        if 'gzip' in accept_encoding.lower():
            compressed = gzip.compress(body)
            if len(compressed) < len(body):
                body = compressed
                use_gzip = True
                log.debug('HTTP response gzip compressed  original=%d  compressed=%d bytes',
                          len(bencode(obj)), len(body))
            else:
                log.debug('HTTP response gzip skipped  original=%d  compressed=%d bytes (no benefit)',
                          len(body), len(compressed))

        raw_len = len(bencode(obj))
        STATS.record_http_bytes(raw_len, len(body), use_gzip)
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        if use_gzip:
            self.send_header('Content-Encoding', 'gzip')
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code: int, msg: str):
        body = msg.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ─────────────────────────────────────────────────────────────
# UDP Tracker Server  (BEP 15)
# ─────────────────────────────────────────────────────────────

UDP_MAGIC        = 0x41727101980
UDP_ACT_CONNECT  = 0
UDP_ACT_ANNOUNCE = 1
UDP_ACT_SCRAPE   = 2
UDP_ACT_ERROR    = 3

# Simple connection_id cache: conn_id -> expiry timestamp
# Real trackers expire connection_ids after ~2 minutes (BEP 15)
_udp_conn_ids: dict[int, float] = {}
_udp_conn_lock = threading.Lock()
_UDP_CONN_TTL  = 120  # seconds


def _gen_connection_id() -> int:
    cid = random.getrandbits(64)
    with _udp_conn_lock:
        _udp_conn_ids[cid] = time.time() + _UDP_CONN_TTL
    return cid


def _valid_connection_id(cid: int) -> bool:
    now = time.time()
    with _udp_conn_lock:
        # Purge expired
        expired = [k for k, exp in _udp_conn_ids.items() if exp < now]
        for k in expired:
            del _udp_conn_ids[k]
        return cid in _udp_conn_ids


def run_udp_server(host: str, port: int):
    """Run the UDP tracker in a blocking loop (call from a daemon thread)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))

    while True:
        try:
            data, addr = sock.recvfrom(65536)
            threading.Thread(
                target=_handle_udp_packet,
                args=(sock, data, addr),
                daemon=True
            ).start()
        except Exception as e:
            log.error('UDP recv error: %s', e)


def run_udp6_server(host6: str, port: int):
    """Run the UDP tracker on IPv6 in a blocking loop (call from a daemon thread)."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host6, port, 0, 0))

    while True:
        try:
            data, addr = sock.recvfrom(65536)
            threading.Thread(
                target=_handle_udp_packet,
                args=(sock, data, addr),
                daemon=True
            ).start()
        except Exception as e:
            log.error('UDP6 recv error: %s', e)


def _handle_udp_packet(sock: socket.socket, data: bytes, addr):
    client_ip = addr[0]
    try:
        if len(data) < 16:
            return  # too short to be meaningful

        connection_id, action, transaction_id = struct.unpack_from('!QII', data, 0)

        # ── Connect ──────────────────────────────────────────
        if action == UDP_ACT_CONNECT:
            if connection_id != UDP_MAGIC:
                return  # Invalid connect request
            new_cid = _gen_connection_id()
            # Response: action(4) + transaction_id(4) + connection_id(8)
            resp = struct.pack('!IIQ', UDP_ACT_CONNECT, transaction_id, new_cid)
            sock.sendto(resp, addr)
            log.info('UDP connect from %s  conn_id=%d', client_ip, new_cid)
            log.debug(
                'UDP CONNECT  from=%s  transaction_id=%d  assigned_conn_id=%d',
                client_ip, transaction_id, new_cid
            )
            return

        # All further actions require a valid connection_id
        if not _valid_connection_id(connection_id):
            _udp_send_error(sock, addr, transaction_id, b'connection ID not recognized')
            return

        # ── Announce ─────────────────────────────────────────
        if action == UDP_ACT_ANNOUNCE:
            # Min length: 98 bytes
            if len(data) < 98:
                _udp_send_error(sock, addr, transaction_id, b'announce packet too short')
                return

            (ih_bytes, peer_id_bytes,
             downloaded, left, uploaded,
             event_code, ip_int, _key, num_want, port) = struct.unpack_from(
                '!20s20sQQQIIIiH', data, 16
            )

            ih_hex = ih_bytes.hex().upper()

            if REGISTRATION_MODE and REGISTRATION_DB is not None:
                if not OPEN_TRACKER and \
                        not REGISTRATION_DB.is_registered(ih_hex):
                    _udp_send_error(sock, addr, transaction_id, b'torrent not registered')
                    return

            event_map = {0: 'none', 1: 'completed', 2: 'started', 3: 'stopped'}
            event = event_map.get(event_code, 'none')

            # IP override: if ip_int is 0 use client address, else use the provided IP
            if ip_int != 0:
                try:
                    peer_ip = socket.inet_ntoa(struct.pack('!I', ip_int))
                except Exception:
                    peer_ip = client_ip
            else:
                peer_ip = client_ip

            if num_want < 0 or num_want > MAX_PEERS_PER_REPLY:
                num_want = MAX_PEERS_PER_REPLY

            log.debug(
                'UDP ANNOUNCE  from=%s  ih=%s  peer_id=%s  port=%d  event=%s  '
                'left=%d  downloaded=%d  uploaded=%d  numwant=%d  ip_override=%s',
                client_ip, ih_hex, peer_id_bytes.hex(), port, event,
                left, downloaded, uploaded, num_want,
                peer_ip if ip_int != 0 else 'none'
            )

            REGISTRY.announce(ih_hex, peer_id_bytes, peer_ip, port, left, event)

            seeds, leechers, downloaded_count, ipv4_compact, ipv6_compact, ipv4_mapped_compact, _ = \
                REGISTRY.get_peers(ih_hex, num_want, peer_ip, port)

            # UDP: detect IPv6 client and respond with appropriate peer format
            client_is_ipv6 = ':' in client_ip
            udp_peers = (ipv6_compact + ipv4_mapped_compact) if client_is_ipv6 else ipv4_compact

            log.debug(
                'UDP ANNOUNCE  response  seeds=%d  leechers=%d  peers_sent=%d  ipv6_client=%s  interval=%d',
                seeds, leechers, len(udp_peers) // (18 if client_is_ipv6 else 6),
                client_is_ipv6, DEFAULT_INTERVAL
            )

            # BEP 15 announce response:
            # action(4) + transaction_id(4) + interval(4) + leechers(4) + seeders(4) + peers(6n)
            resp_header = struct.pack('!IIIII',
                UDP_ACT_ANNOUNCE, transaction_id,
                DEFAULT_INTERVAL, leechers, seeds)
            udp_response = resp_header + udp_peers
            sock.sendto(udp_response, addr)
            STATS.record_announce('udp', client_ip, client_is_ipv6)
            STATS.record_udp_bytes(len(udp_response))
            log.info('UDP announce from %s  ih=%s  event=%s  seeds=%d  leechers=%d',
                     client_ip, ih_hex[:8], event, seeds, leechers)
            return

        # ── Scrape ───────────────────────────────────────────
        if action == UDP_ACT_SCRAPE:
            # Each info_hash is 20 bytes, starting at offset 16
            num_hashes = (len(data) - 16) // 20
            if num_hashes == 0:
                _udp_send_error(sock, addr, transaction_id, b'no info_hash in scrape')
                return

            # Response: action(4) + transaction_id(4) + [seeders(4)+completed(4)+leechers(4)] * n
            resp = struct.pack('!II', UDP_ACT_SCRAPE, transaction_id)
            for i in range(num_hashes):
                ih_bytes = data[16 + i*20 : 36 + i*20]
                ih_hex   = ih_bytes.hex().upper()
                complete, incomplete, downloaded = REGISTRY.scrape_stats(ih_hex)
                resp += struct.pack('!III', complete, downloaded, incomplete)

            sock.sendto(resp, addr)
            log.info('UDP scrape from %s  %d hashes', client_ip, num_hashes)
            log.debug('UDP SCRAPE  from=%s  transaction_id=%d  hashes=%d',
                      client_ip, transaction_id, num_hashes)
            return

        _udp_send_error(sock, addr, transaction_id, b'unknown action')

    except Exception as e:
        log.warning('UDP packet error from %s: %s', client_ip, e)


def _udp_send_error(sock: socket.socket, addr, transaction_id: int, msg: bytes):
    resp = struct.pack('!II', UDP_ACT_ERROR, transaction_id) + msg
    sock.sendto(resp, addr)


# ─────────────────────────────────────────────────────────────
# Stats web page HTML generator
# ─────────────────────────────────────────────────────────────

def _fmt_bytes(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024:
            return f'{n:.1f} {unit}' if unit != 'B' else f'{n} B'
        n /= 1024
    return f'{n:.1f} PB'

def _fmt_uptime(seconds: float) -> str:
    s = int(seconds)
    days, s    = divmod(s, 86400)
    hours, s   = divmod(s, 3600)
    minutes, _ = divmod(s, 60)
    parts = []
    if days:    parts.append(f'{days}d')
    if hours:   parts.append(f'{hours}h')
    parts.append(f'{minutes}m')
    return ' '.join(parts)

def _fmt_num(n: int) -> str:
    return f'{n:,}'

def _pct(a: int, b: int) -> float:
    return round(100 * a / b, 1) if b else 0.0

def _savings_pct(raw: int, sent: int) -> float:
    return round(100 * (raw - sent) / raw, 1) if raw > 0 else 0.0

FAVICON_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <defs>
    <radialGradient id="gl" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#ffe066"/>
      <stop offset="60%" stop-color="#f5a623"/>
      <stop offset="100%" stop-color="#e05b30" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="gr" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#ffe066"/>
      <stop offset="60%" stop-color="#f5a623"/>
      <stop offset="100%" stop-color="#e05b30" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <ellipse cx="10" cy="16" rx="7" ry="6" fill="url(#gl)" opacity="0.5"/>
  <ellipse cx="22" cy="16" rx="7" ry="6" fill="url(#gr)" opacity="0.5"/>
  <ellipse cx="10" cy="16" rx="5" ry="4" fill="#f5a623"/>
  <ellipse cx="22" cy="16" rx="5" ry="4" fill="#f5a623"/>
  <ellipse cx="10" cy="16" rx="1.2" ry="3.6" fill="#0d0e14"/>
  <ellipse cx="22" cy="16" rx="1.2" ry="3.6" fill="#0d0e14"/>
  <ellipse cx="11.5" cy="14.5" rx="0.9" ry="0.6" fill="rgba(255,255,255,0.6)" transform="rotate(-20,11.5,14.5)"/>
  <ellipse cx="23.5" cy="14.5" rx="0.9" ry="0.6" fill="rgba(255,255,255,0.6)" transform="rotate(-20,23.5,14.5)"/>
</svg>'''

FAVICON_ICO = bytes.fromhex(
    '000001000101000101000001002000280000001600000028000000'
    '010000000200000001002000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000'
)

def generate_stats_html(snap: dict, web_config: dict, show_manage: bool = False) -> str:
    uptime_str   = _fmt_uptime(snap['uptime'])
    torrents     = snap['torrents']
    live_peers   = snap['live_peers']

    a   = snap['all']
    tod = snap['today']
    yes = snap.get('yesterday', {})

    _btn_style = ('font-family:var(--mono);font-size:0.72rem;letter-spacing:0.1em;'
                  'padding:6px 16px;border-radius:6px;border:1px solid var(--border);'
                  'color:var(--muted);text-decoration:none;margin-left:8px')
    if show_manage:
        manage_btn = f'<div style="text-align:right;margin-bottom:8px"><a href="/manage/dashboard" style="{_btn_style}">&#9881; Manage</a></div>'
    elif web_config.get('free_signup'):
        manage_btn = f'<div style="text-align:right;margin-bottom:8px"><a href="/manage/signup" style="{_btn_style}">Sign Up</a></div>'
    else:
        manage_btn = ''
    announce_urls = web_config.get('announce_urls', [])
    domain        = web_config.get('domain', '')

    # Build announce URL rows
    url_rows = ''
    for proto, url in announce_urls:
        proto_class = proto.lower()
        url_rows += f'''
        <div class="url-row">
          <span class="url-badge {proto_class}">{proto}</span>
          <span class="url-text" id="url-{proto_class}">{url}</span>
          <button class="copy-btn" onclick="copyUrl('{url}', this)">Copy</button>
        </div>'''

    # ── Hourly chart (today) ──────────────────────────────────
    hourly   = tod['hourly']
    max_h    = max(hourly) or 1
    cur_hour = datetime.datetime.now().hour
    hourly_bars = ''
    for i, val in enumerate(hourly):
        h      = int(val * 100 / max_h)
        active = ' active' if i == cur_hour else ''
        label  = f'{i:02d}'
        hourly_bars += f'<div class="bar-wrap"><div class="bar{active}" style="height:{h}%" title="{val} announces"></div><div class="bar-label">{label}</div></div>'

    # ── Daily chart (all-time) ────────────────────────────────
    daily   = a['daily_totals']
    max_d   = max(daily.values()) if daily else 1
    daily_bars = ''
    for date_str, val in list(daily.items())[-30:]:
        h     = int(val * 100 / max_d) if max_d else 0
        short = date_str[5:]  # MM-DD
        daily_bars += f'<div class="bar-wrap"><div class="bar" style="height:{h}%" title="{date_str}: {val}"></div><div class="bar-label">{short}</div></div>'
    if not daily_bars:
        daily_bars = '<div class="no-data">No historical data yet</div>'

    # ── Protocol bars helper ──────────────────────────────────
    def proto_bars(d):
        total = d['announces'] or 1
        rows  = ''
        for label, key, cls in [('UDP', 'udp', 'udp'), ('HTTPS', 'https', 'https'), ('HTTP', 'http', 'http')]:
            val = d.get(key, 0)
            pct = _pct(val, total)
            rows += f'''<div class="proto-row">
              <span class="proto-label">{label}</span>
              <div class="proto-bar-bg"><div class="proto-bar {cls}" style="width:{pct}%"></div></div>
              <span class="proto-val">{_fmt_num(val)} <small>({pct}%)</small></span>
            </div>'''
        return rows

    def ipv_bars(d):
        total = (d.get('ipv4', 0) + d.get('ipv6', 0)) or 1
        v4    = d.get('ipv4', 0)
        v6    = d.get('ipv6', 0)
        p4    = _pct(v4, total)
        p6    = _pct(v6, total)
        return f'''
        <div class="proto-row">
          <span class="proto-label">IPv4</span>
          <div class="proto-bar-bg"><div class="proto-bar ipv4" style="width:{p4}%"></div></div>
          <span class="proto-val">{_fmt_num(v4)} <small>({p4}%)</small></span>
        </div>
        <div class="proto-row">
          <span class="proto-label">IPv6</span>
          <div class="proto-bar-bg"><div class="proto-bar ipv6" style="width:{p6}%"></div></div>
          <span class="proto-val">{_fmt_num(v6)} <small>({p6}%)</small></span>
        </div>'''

    # ── Stat cards helper ─────────────────────────────────────
    def cards(d, is_alltime=False):
        ann     = d['announces']
        ips     = d['unique_ips']
        sent    = d['bytes_sent']
        raw     = d['bytes_raw']
        saved   = raw - sent
        sav_pct = _savings_pct(raw, sent)
        gzip_c  = d['gzip_count']
        plain_c = d['plain_count']
        total_r = gzip_c + plain_c
        gzip_pct= _pct(gzip_c, total_r)
        return f'''
        <div class="stat-card">
          <div class="stat-value">{_fmt_num(ann)}</div>
          <div class="stat-label">ANNOUNCES</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{_fmt_num(ips)}</div>
          <div class="stat-label">UNIQUE IPs</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{_fmt_bytes(sent)}</div>
          <div class="stat-label">DATA SENT</div>
        </div>
        <div class="stat-card {'highlight' if sav_pct > 0 else ''}">
          <div class="stat-value">{_fmt_bytes(saved)}</div>
          <div class="stat-label">SAVED BY GZIP <small>({sav_pct}% / {gzip_pct}% of responses)</small></div>
        </div>'''

    # ── Yesterday panel ───────────────────────────────────────
    if yes:
        yes_hourly     = yes.get('hourly', [0]*24)
        max_yh         = max(yes_hourly) or 1
        yes_hourly_bars= ''
        for i, val in enumerate(yes_hourly):
            h = int(val * 100 / max_yh)
            yes_hourly_bars += f'<div class="bar-wrap"><div class="bar" style="height:{h}%" title="{val} announces"></div><div class="bar-label">{i:02d}</div></div>'
        yes_panel = f'''
        <div class="panel" id="panel-yesterday">
          <div class="stat-grid">{cards(yes)}</div>
          <div class="section-title">Protocol Breakdown</div>
          <div class="proto-breakdown">{proto_bars(yes)}</div>
          <div class="section-title">IPv4 / IPv6</div>
          <div class="proto-breakdown">{ipv_bars(yes)}</div>
          <div class="section-title">Hourly Activity -- {yes.get('date','')}</div>
          <div class="chart">{yes_hourly_bars}</div>
        </div>'''
    else:
        yes_panel = '<div class="panel" id="panel-yesterday"><div class="no-data">No data for yesterday yet -- check back after midnight.</div></div>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wildkat Tracker</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,{urllib.parse.quote(FAVICON_SVG.strip())}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;600&family=DM+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:       #0a0b10;
    --card:     #12141c;
    --card2:    #191b26;
    --border:   #1e2133;
    --accent:   #f5a623;
    --accent2:  #e05b30;
    --green:    #3ecf8e;
    --blue:     #4f8ef7;
    --purple:   #9b7fe8;
    --text:     #e8eaf2;
    --muted:    #555878;
    --mono:     'JetBrains Mono', monospace;
    --sans:     'DM Sans', sans-serif;
    --display:  'Orbitron', sans-serif;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --bg:       #f5f4ef;
      --card:     #ffffff;
      --card2:    #eeede8;
      --border:   #d8d6cc;
      --accent:   #c97d0a;
      --accent2:  #c04820;
      --green:    #1a9e65;
      --blue:     #2c6fd4;
      --purple:   #6b4fc2;
      --text:     #1a1a2a;
      --muted:    #888070;
    }}
    body::before {{
      background:
        radial-gradient(ellipse 80% 50% at 50% -10%, rgba(201,125,10,0.06) 0%, transparent 70%),
        radial-gradient(ellipse 40% 30% at 85% 80%, rgba(44,111,212,0.04) 0%, transparent 60%);
    }}
    .logo {{
      text-shadow: 0 0 40px rgba(201,125,10,0.25), 0 0 80px rgba(201,125,10,0.08);
    }}
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html {{ scroll-behavior: smooth; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 15px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  /* ── Background texture ── */
  body::before {{
    content: '';
    position: fixed;
    inset: 0;
    background:
      radial-gradient(ellipse 80% 50% at 50% -10%, rgba(245,166,35,0.08) 0%, transparent 70%),
      radial-gradient(ellipse 40% 30% at 85% 80%, rgba(79,142,247,0.05) 0%, transparent 60%);
    pointer-events: none;
    z-index: 0;
  }}

  .container {{
    max-width: 1100px;
    margin: 0 auto;
    padding: 0 24px;
    position: relative;
    z-index: 1;
  }}

  /* ── Header ── */
  .header {{
    padding: 60px 0 40px;
    text-align: center;
    border-bottom: 1px solid var(--border);
    margin-bottom: 40px;
  }}
  .logo {{
    font-family: var(--display);
    font-size: clamp(2rem, 5vw, 3.2rem);
    font-weight: 900;
    letter-spacing: 0.12em;
    color: var(--accent);
    text-shadow: 0 0 40px rgba(245,166,35,0.4), 0 0 80px rgba(245,166,35,0.15);
    margin-bottom: 6px;
  }}
  .logo span {{ color: var(--text); }}
  .tagline {{
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--muted);
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-bottom: 28px;
  }}
  .uptime-banner {{
    display: inline-flex;
    align-items: center;
    gap: 10px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 40px;
    padding: 10px 24px;
    font-size: 0.9rem;
    color: var(--muted);
    margin-bottom: 12px;
  }}
  .uptime-banner strong {{ color: var(--text); }}
  .live-stats {{
    display: flex;
    justify-content: center;
    gap: 32px;
    flex-wrap: wrap;
    margin-top: 8px;
  }}
  .live-stat {{
    text-align: center;
  }}
  .live-stat .num {{
    font-family: var(--mono);
    font-size: 1.8rem;
    font-weight: 600;
    color: var(--accent);
    display: block;
    line-height: 1;
  }}
  .live-stat .lbl {{
    font-size: 0.7rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
  }}

  /* ── Announce URLs ── */
  .announce-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px 28px;
    margin-bottom: 32px;
  }}
  .announce-title {{
    font-family: var(--mono);
    font-size: 0.72rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 16px;
  }}
  .url-row {{
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid var(--border);
  }}
  .url-row:last-child {{ border-bottom: none; }}
  .url-badge {{
    font-family: var(--mono);
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    padding: 3px 10px;
    border-radius: 4px;
    min-width: 52px;
    text-align: center;
  }}
  .url-badge.udp   {{ background: rgba(79,142,247,0.15); color: var(--blue); border: 1px solid rgba(79,142,247,0.3); }}
  .url-badge.https {{ background: rgba(62,207,142,0.12); color: var(--green); border: 1px solid rgba(62,207,142,0.3); }}
  .url-text {{
    font-family: var(--mono);
    font-size: 0.85rem;
    color: var(--text);
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }}
  .copy-btn {{
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: 5px 14px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }}
  .copy-btn:hover  {{ border-color: var(--accent); color: var(--accent); }}
  .copy-btn.copied {{ border-color: var(--green); color: var(--green); }}

  /* ── Tabs ── */
  .tabs {{
    display: flex;
    gap: 4px;
    margin-bottom: 28px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 4px;
    width: fit-content;
  }}
  .tab {{
    font-family: var(--mono);
    font-size: 0.78rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 8px 22px;
    border-radius: 7px;
    border: none;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    transition: all 0.15s;
  }}
  .tab:hover  {{ color: var(--text); }}
  .tab.active {{ background: var(--card2); color: var(--accent); border: 1px solid var(--border); }}

  /* ── Panels ── */
  .panel {{ display: none; }}
  .panel.visible {{ display: block; }}

  /* ── Stat cards ── */
  .stat-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 22px;
    transition: border-color 0.2s;
  }}
  .stat-card:hover {{ border-color: rgba(245,166,35,0.3); }}
  .stat-card.highlight {{ border-color: rgba(62,207,142,0.25); }}
  .stat-value {{
    font-family: var(--mono);
    font-size: 1.9rem;
    font-weight: 600;
    color: var(--accent);
    line-height: 1;
    margin-bottom: 6px;
  }}
  .stat-card.highlight .stat-value {{ color: var(--green); }}
  .stat-label {{
    font-size: 0.7rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
  }}
  .stat-label small {{ font-size: 0.65rem; display: block; margin-top: 2px; }}

  /* ── Section title ── */
  .section-title {{
    font-family: var(--mono);
    font-size: 0.72rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 28px 0 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }}

  /* ── Protocol bars ── */
  .proto-breakdown {{ display: flex; flex-direction: column; gap: 10px; margin-bottom: 8px; }}
  .proto-row {{ display: flex; align-items: center; gap: 12px; }}
  .proto-label {{
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
    width: 44px;
    text-align: right;
    flex-shrink: 0;
  }}
  .proto-bar-bg {{
    flex: 1;
    background: var(--card2);
    border-radius: 4px;
    height: 10px;
    overflow: hidden;
  }}
  .proto-bar {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.4s ease;
    min-width: 2px;
  }}
  .proto-bar.udp   {{ background: var(--blue); }}
  .proto-bar.https {{ background: var(--green); }}
  .proto-bar.http  {{ background: var(--muted); }}
  .proto-bar.ipv4  {{ background: var(--accent); }}
  .proto-bar.ipv6  {{ background: var(--purple); }}
  .proto-val {{
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--text);
    min-width: 130px;
    text-align: right;
  }}
  .proto-val small {{ color: var(--muted); }}

  /* ── Bar chart ── */
  .chart {{
    display: flex;
    align-items: flex-end;
    gap: 3px;
    height: 100px;
    padding: 8px 0 0;
  }}
  .bar-wrap {{
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    height: 100%;
    justify-content: flex-end;
  }}
  .bar {{
    width: 100%;
    background: rgba(245,166,35,0.35);
    border-radius: 3px 3px 0 0;
    min-height: 2px;
    transition: background 0.2s;
  }}
  .bar:hover {{ background: var(--accent); }}
  .bar.active {{ background: rgba(245,166,35,0.7); }}
  .bar-label {{
    font-family: var(--mono);
    font-size: 0.55rem;
    color: var(--muted);
    margin-top: 4px;
    white-space: nowrap;
  }}

  /* ── Bragging points ── */
  .brag-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 16px;
    margin-top: 8px;
  }}
  .brag-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 8px;
    padding: 16px 20px;
    font-size: 0.88rem;
    color: var(--muted);
  }}
  .brag-card strong {{ color: var(--text); display: block; margin-bottom: 2px; font-size: 0.95rem; }}

  /* ── No data ── */
  .no-data {{
    text-align: center;
    padding: 48px;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.85rem;
  }}

  /* ── Footer ── */
  .footer {{
    margin-top: 56px;
    padding: 28px 0 40px;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--muted);
    font-size: 0.82rem;
    line-height: 1.8;
  }}
  .footer a {{ color: var(--muted); text-decoration: underline; }}
  .footer .stateless {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 20px;
    margin: 16px auto;
    max-width: 640px;
    font-size: 0.8rem;
    line-height: 1.7;
    color: var(--muted);
  }}

  @media (max-width: 600px) {{
    .live-stats {{ gap: 20px; }}
    .url-text {{ font-size: 0.75rem; }}
    .proto-val {{ min-width: 80px; font-size: 0.72rem; }}
  }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    {manage_btn}
    <div class="logo">&#128008; WILD<span>KAT</span></div>
    <div class="tagline">BitTorrent Tracker &nbsp;&#183;&nbsp; HTTP &nbsp;&#183;&nbsp; HTTPS &nbsp;&#183;&nbsp; UDP &nbsp;&#183;&nbsp; IPv4/IPv6</div>
    <div class="uptime-banner">
      &#9679; Running for <strong>&nbsp;{uptime_str}</strong>
    </div>
    <div class="live-stats">
      <div class="live-stat">
        <span class="num">{_fmt_num(torrents)}</span>
        <span class="lbl">Active Torrents</span>
      </div>
      <div class="live-stat">
        <span class="num">{_fmt_num(live_peers)}</span>
        <span class="lbl">Live Peers</span>
      </div>
      <div class="live-stat">
        <span class="num">{_fmt_num(a['announces'])}</span>
        <span class="lbl">All-Time Announces</span>
      </div>
    </div>
  </div>

  <!-- Announce URLs -->
  <div class="announce-card">
    <div class="announce-title">&#10148; Add this tracker to your torrent client</div>
    {url_rows}
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab active" onclick="showTab('today',this)">Today</button>
    <button class="tab" onclick="showTab('yesterday',this)">Yesterday</button>
    <button class="tab" onclick="showTab('alltime',this)">All Time</button>
  </div>

  <!-- Today panel -->
  <div class="panel visible" id="panel-today">
    <div class="stat-grid">{cards(tod)}</div>
    <div class="section-title">Protocol Breakdown</div>
    <div class="proto-breakdown">{proto_bars(tod)}</div>
    <div class="section-title">IPv4 / IPv6</div>
    <div class="proto-breakdown">{ipv_bars(tod)}</div>
    <div class="section-title">Hourly Activity &mdash; {tod['date']}</div>
    <div class="chart">{hourly_bars}</div>
  </div>

  <!-- Yesterday panel -->
  {yes_panel}

  <!-- All-time panel -->
  <div class="panel" id="panel-alltime">
    <div class="stat-grid">{cards(a, is_alltime=True)}</div>
    <div class="section-title">Protocol Breakdown</div>
    <div class="proto-breakdown">{proto_bars(a)}</div>
    <div class="section-title">IPv4 / IPv6</div>
    <div class="proto-breakdown">{ipv_bars(a)}</div>
    <div class="section-title">Daily Announces &mdash; Last 30 Days</div>
    <div class="chart">{daily_bars}</div>
    <div class="section-title">About This Tracker</div>
    <div class="brag-grid">
      <div class="brag-card"><strong>BEP 3 &mdash; Core Protocol</strong>HTTP announce with tracker ID, failure reason, warning message</div>
      <div class="brag-card"><strong>BEP 7 &mdash; IPv6 Extension</strong>peers6 compact response, IPv4-mapped ::ffff: addresses for dual-stack swarms</div>
      <div class="brag-card"><strong>BEP 15 &mdash; UDP Protocol</strong>Full connect / announce / scrape / error over UDP</div>
      <div class="brag-card"><strong>BEP 23 &mdash; Compact Peers</strong>Compact IPv4 and dict model with no_peer_id support</div>
      <div class="brag-card"><strong>BEP 24 &mdash; External IP</strong>Reflects client external IP in every announce response</div>
      <div class="brag-card"><strong>BEP 48 &mdash; Scrape Extension</strong>Multi-hash scrape with flags.min_request_interval</div>
      <div class="brag-card"><strong>gzip Compression</strong>Automatic compression when clients advertise support -- only applied when it actually saves bytes</div>
      <div class="brag-card"><strong>Pure Python</strong>No external dependencies. Runs anywhere Python 3.10+ is available</div>
    </div>
  </div>

  <!-- Footer -->
  <div class="footer">
    <div class="stateless">
      &#128274; This tracker is <strong>stateless</strong>. No peer data, activity logs, or personal
      information is stored to disk. All statistics shown are held in memory only and reset
      when the service restarts.
    </div>
    Powered by <strong>Wildkat Tracker</strong> &nbsp;&#183;&nbsp;
    <a href="https://github.com/HolyRoses/wildkat-tracker" target="_blank">github.com/HolyRoses/wildkat-tracker</a>
  </div>

</div>

<script>
function showTab(name, btn) {{
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('visible'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('visible');
  btn.classList.add('active');
}}

function copyUrl(url, btn) {{
  navigator.clipboard.writeText(url).then(() => {{
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {{ btn.textContent = 'Copy'; btn.classList.remove('copied'); }}, 2000);
  }}).catch(() => {{
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = url;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {{ btn.textContent = 'Copy'; btn.classList.remove('copied'); }}, 2000);
  }});
}}
</script>
</body>
</html>'''


# ─────────────────────────────────────────────────────────────
# HTTP redirect server (port 80 → HTTPS when running TLS)
# ─────────────────────────────────────────────────────────────

class RedirectHandler(BaseHTTPRequestHandler):
    """Redirect plain HTTP → HTTPS."""

    redirect_host = ''  # set at startup

    def do_GET(self):
        target = f'https://{self.redirect_host}{self.path}'
        self.send_response(301)
        self.send_header('Location', target)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # quiet


# ─────────────────────────────────────────────────────────────
# Server wiring & startup
# ─────────────────────────────────────────────────────────────

def build_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    # Modern TLS only
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class IPv6HTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    """HTTPServer variant that binds an AF_INET6 socket.
    IPV6_V6ONLY=1 ensures this socket handles only IPv6 traffic, allowing
    the paired IPv4 socket to coexist on the same port (required on Linux).
    """
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def start_http_server(host: str, port: int, ssl_ctx=None, label='HTTP'):
    server = ThreadingHTTPServer((host, port), TrackerHTTPHandler)
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    log.info('%s tracker listening on %s:%d/announce', label, host or '0.0.0.0', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def start_http6_server(host6: str, port: int, ssl_ctx=None, label='HTTP'):
    """Start an IPv6 HTTP(S) tracker listener."""
    server = IPv6HTTPServer((host6, port, 0, 0), TrackerHTTPHandler)
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    log.info('%s tracker listening on [%s]:%d/announce (IPv6)', label, host6 or '::', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


class IPv6RedirectServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    """IPv6 variant of the HTTP→HTTPS redirect server."""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def start_redirect_server(host: str, port: int, target_host: str):
    # Create a fresh subclass per server so each instance has its own
    # redirect_host without clobbering other redirect servers started on
    # different ports (e.g. tracker HTTP redirect vs web HTTP redirect).
    handler = type('_RH', (RedirectHandler,), {'redirect_host': target_host})
    if ':' in host or host == '::':
        server = IPv6RedirectServer((host, port, 0, 0), handler)
        log.info('HTTP→HTTPS redirect listening on [%s]:%d → %s (IPv6)', host or '::', port, target_host)
    else:
        server = ThreadingHTTPServer((host, port), handler)
        log.info('HTTP→HTTPS redirect listening on %s:%d → %s', host or '0.0.0.0', port, target_host)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server



# ─────────────────────────────────────────────────────────────
# Stats web server
# ─────────────────────────────────────────────────────────────

WEB_CONFIG: dict = {}   # populated at startup by main()



class ManageHandler(BaseHTTPRequestHandler):
    """Handles all /manage/* routes."""

    def _is_https(self) -> bool:
        return isinstance(self.connection, ssl.SSLSocket)

    def _redirect(self, location: str, code: int = 303):
        self.send_response(code)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _send_html(self, html: str, code: int = 200):
        body = html.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self._refresh_csrf_cookie()  # ensure wkcsrf is always current
        self.end_headers()
        self.wfile.write(body)

    def _get_session_token(self) -> str:
        """Return first wksession cookie value (used only for CSRF derivation)."""
        for part in self.headers.get('Cookie', '').split(';'):
            part = part.strip()
            if part.startswith('wksession='):
                return part[10:]
        return ''

    def _get_session_user(self):
        """Return user row from session cookie, or None.
        Tries every wksession cookie; browsers can accumulate stale duplicates
        from prior sessions so we must check all candidates.
        """
        raw_cookie = self.headers.get('Cookie', '')
        log.debug('SESSION cookie_header=%r', raw_cookie[:160] if raw_cookie else '(none)')
        candidates = [p.strip()[10:] for p in raw_cookie.split(';')
                       if p.strip().startswith('wksession=')]
        log.debug('SESSION %d wksession candidate(s): %s',
                  len(candidates), ', '.join(t[:8]+'...' for t in candidates))
        for token in candidates:
            if not token:
                continue
            user = REGISTRATION_DB.get_session_user(token)
            if user is not None:
                log.debug('SESSION valid token=%s... user=%s', token[:8], user['username'])
                self._valid_token = token  # remember for wkcsrf refresh
                return user
        if candidates:
            log.debug('SESSION all %d candidates invalid', len(candidates))
        return None

    def _refresh_csrf_cookie(self) -> None:
        """Re-set the wkcsrf cookie from the currently validated session token.
        Called on every authenticated GET so the cookie is always present and
        current, even if it was evicted or the server was restarted.
        """
        token = getattr(self, '_valid_token', None)
        if not token:
            return
        csrf = _csrf_token(token)
        # Only refresh if browser cookie differs or is absent
        current = ''
        for part in self.headers.get('Cookie', '').split(';'):
            part = part.strip()
            if part.startswith('wkcsrf='):
                current = part[7:]
                break
        if current == csrf:
            return  # already correct, no Set-Cookie needed
        log.debug('CSRF refreshing wkcsrf cookie (was %s... now %s...)',
                  current[:6] if current else 'absent', csrf[:6])
        expires = (datetime.datetime.now() + datetime.timedelta(hours=48)).strftime(
            '%a, %d %b %Y %H:%M:%S GMT')
        self.send_header('Set-Cookie',
            f'wkcsrf={csrf}; Path=/; SameSite=Strict; Expires={expires}; Secure')

    def _set_session_cookie(self, token: str):
        expires = (datetime.datetime.now() + datetime.timedelta(hours=48)).strftime(
            '%a, %d %b %Y %H:%M:%S GMT')
        self.send_header('Set-Cookie',
            f'wksession={token}; Path=/; HttpOnly; SameSite=Strict; '
            f'Expires={expires}; Secure')
        csrf = _csrf_token(token)
        self.send_header('Set-Cookie',
            f'wkcsrf={csrf}; Path=/; SameSite=Strict; Expires={expires}; Secure')

    def _clear_session_cookie(self):
        expired = 'Expires=Thu, 01 Jan 1970 00:00:00 GMT'
        self.send_header('Set-Cookie', f'wksession=; Path=/; HttpOnly; {expired}')
        self.send_header('Set-Cookie', f'wkcsrf=; Path=/; {expired}')

    def _https_redirect(self):
        """Redirect to HTTPS if we're on plain HTTP."""
        host = self.headers.get('Host', '').split(':')[0]
        port = _MANAGE_HTTPS_PORT
        target = f'https://{host}{":" + str(port) if port != 443 else ""}{self.path}'
        self._redirect(target, 301)

    def _require_https(self) -> bool:
        """Returns True if request should proceed, False if redirected."""
        if not self._is_https():
            self._https_redirect()
            return False
        return True

    def _read_body(self) -> bytes:
        if hasattr(self, '_body_cache'):
            return self._body_cache
        length = int(self.headers.get('Content-Length', 0))
        self._body_cache = self.rfile.read(length) if length else b''
        return self._body_cache

    def log_message(self, fmt, *args):
        log.debug('MANAGE %s %s', self.address_string(), fmt % args)

    # ── Routing ──────────────────────────────────────────────

    def do_GET(self):
        if not self._require_https():
            return
        path = urllib.parse.urlparse(self.path).path.rstrip('/')

        if path in ('/manage', ''):
            user = self._get_session_user()
            if user:
                self._redirect('/manage/dashboard')
            else:
                self._send_html(_render_login())
        elif path == '/manage/dashboard':
            self._get_dashboard()
        elif path == '/manage/admin':
            self._get_admin()
        elif path == '/manage/password':
            self._get_password_page()
        elif path == '/manage/logout':
            self._do_logout()
        elif path == '/manage/signup':
            self._get_signup()
        elif path.startswith('/manage/invite/'):
            self._get_invite_signup(path[len('/manage/invite/'):])
        elif path.startswith('/manage/admin/user/'):
            self._get_user_detail(path[len('/manage/admin/user/'):])
        elif path.startswith('/manage/user/'):
            self._get_public_profile(path[len('/manage/user/'):])
        elif path == '/manage/profile':
            self._get_profile()
        elif path == '/robots.txt':
            self._serve_robots()
        elif path == '/manage/search':
            self._get_search()
        elif path.startswith('/manage/torrent/'):
            ih = path[len('/manage/torrent/'):]
            self._get_torrent_detail(ih)
        else:
            self._send_html('<h1>Not Found</h1>', 404)

    def do_POST(self):
        # Clear body cache so Keep-Alive connections never bleed
        # a previous request's body into this one.
        if hasattr(self, '_body_cache'):
            del self._body_cache
        if not self._require_https():
            return
        path = urllib.parse.urlparse(self.path).path.rstrip('/')

        # ── CSRF validation ──────────────────────────────
        # Login and signup have no session yet; everything else must carry
        # the CSRF token derived from whichever session token the browser used.
        # Browsers can hold multiple wksession cookies (stale + current); we try
        # all candidates so the valid one matches regardless of order.
        _no_csrf = ('/manage/login', '/manage/signup', '/manage')
        if path not in _no_csrf:
            raw_cookie = self.headers.get('Cookie', '')
            session_candidates = [p.strip()[10:] for p in raw_cookie.split(';')
                                  if p.strip().startswith('wksession=')]
            if session_candidates:
                body = self._read_body()
                fields, _ = _parse_multipart(self.headers, body)
                submitted = fields.get('_csrf', '')
                # Accept if ANY candidate session produces the right CSRF token
                csrf_ok = any(
                    hmac.compare_digest(_csrf_token(t), submitted)
                    for t in session_candidates if t
                )
                if not csrf_ok:
                    log.warning('CSRF mismatch path=%s candidates=%d submitted_len=%d',
                                path, len(session_candidates), len(submitted))
                    self._redirect('/manage?msg=csrf')
                    return

        if path == '/manage/login':
            self._post_login()
        elif path == '/manage/upload':
            self._post_upload()
        elif path == '/manage/delete-torrent':
            self._post_delete_torrent()
        elif path == '/manage/password':
            self._post_change_password()
        elif path == '/manage/admin/add-user':
            self._post_add_user()
        elif path == '/manage/admin/delete-user':
            self._post_delete_user()
        elif path == '/manage/admin/change-password':
            self._post_admin_change_password()
        elif path == '/manage/admin/unlock':
            self._post_unlock_user()
        elif path == '/manage/admin/disable-user':
            self._post_set_disabled(True)
        elif path == '/manage/admin/enable-user':
            self._post_set_disabled(False)
        elif path == '/manage/admin/set-admin':
            self._post_set_admin()
        elif path == '/manage/admin/set-standard':
            self._post_set_standard()
        elif path == '/manage/admin/tracker-add':
            self._post_tracker_add()
        elif path == '/manage/admin/tracker-delete':
            self._post_tracker_delete()
        elif path == '/manage/admin/tracker-toggle':
            self._post_tracker_toggle()
        elif path == '/manage/admin/tracker-move':
            self._post_tracker_move()
        elif path == '/manage/admin/save-settings':
            self._post_save_settings()
        elif path == '/manage/signup':
            self._post_signup()
        elif path.startswith('/manage/invite/'):
            self._post_invite_signup(path[len('/manage/invite/'):])
        elif path == '/manage/admin/delete-all-torrents':
            self._post_delete_all_torrents_global()
        elif path == '/manage/admin/delete-all-users':
            self._post_delete_all_users()
        elif path == '/manage/admin/generate-invite':
            self._post_admin_generate_invite()
        elif path == '/manage/admin/delete-invite':
            self._post_admin_delete_invite()
        elif path == '/manage/admin/adjust-credits':
            self._post_adjust_credits()
        elif path == '/manage/profile/generate-invite':
            self._post_profile_generate_invite()
        elif path == '/manage/delete-all-torrents-user':
            self._post_delete_all_torrents_user()
        elif path == '/manage/admin/ip-lock':
            self._post_ip_lock()
        elif path == '/manage/admin/ip-lock-remove':
            self._post_ip_lock_remove()
        elif path == '/manage/admin/ip-lock-clear':
            self._post_ip_lock_clear()
        else:
            self._send_html('<h1>Not Found</h1>', 404)

    # ── GET handlers ─────────────────────────────────────────

    def _get_dashboard(self):
        user = self._get_session_user()
        log.debug('DASHBOARD session_found=%s', user is not None)
        if not user:
            return self._redirect('/manage')
        role    = _user_role(user)
        per_page = int(REGISTRATION_DB.get_setting('torrents_per_page', '50'))
        page     = _get_page_param(self.path)
        uid      = None if role in ('super', 'admin', 'standard') else user['id']
        total    = REGISTRATION_DB.count_torrents(user_id=uid)
        torrents = REGISTRATION_DB.list_torrents(user_id=uid, page=page, per_page=per_page)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        self._send_html(_render_dashboard(user, torrents, page=page,
                                          total_pages=total_pages, total=total))

    def _get_admin(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        is_super = user['username'] == SUPER_USER
        if not (user['is_admin'] or is_super):
            return self._redirect('/manage/dashboard')
        qs           = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        per_page     = int(REGISTRATION_DB.get_setting('torrents_per_page', '50'))
        # torrent pagination
        page         = _get_page_param(self.path)
        total        = REGISTRATION_DB.count_torrents()
        all_torrents = REGISTRATION_DB.list_torrents(page=page, per_page=per_page)
        total_pages  = max(1, (total + per_page - 1) // per_page)
        page         = min(page, total_pages)
        # user pagination + search
        uquery       = qs.get('uq', [''])[0].strip()
        upage        = _get_named_page_param(self.path, 'upage')
        users_pp     = 50
        if uquery:
            utotal   = REGISTRATION_DB.count_search_users(uquery)
            all_users = REGISTRATION_DB.search_users(uquery, page=upage, per_page=users_pp)
        else:
            utotal   = REGISTRATION_DB.count_users()
            all_users = REGISTRATION_DB.list_users(page=upage, per_page=users_pp)
        utotal_pages = max(1, (utotal + users_pp - 1) // users_pp)
        upage        = min(upage, utotal_pages)
        events       = REGISTRATION_DB.list_events(100)
        trackers     = REGISTRATION_DB.list_magnet_trackers()
        settings     = REGISTRATION_DB.get_all_settings()
        self._send_html(_render_admin(user, all_torrents, all_users, events, trackers, settings,
                                      page=page, total_pages=total_pages, total=total,
                                      upage=upage, utotal_pages=utotal_pages, utotal=utotal,
                                      uquery=uquery))

    def _get_password_page(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        self._send_html(_render_password_page(user))

    def _do_logout(self):
        cookie_hdr = self.headers.get('Cookie', '')
        # Identify who is logging out before we delete the session
        logout_user = self._get_session_user()
        for part in cookie_hdr.split(';'):
            part = part.strip()
            if part.startswith('wksession='):
                REGISTRATION_DB.delete_session(part[10:])
        if logout_user:
            REGISTRATION_DB._log(logout_user['username'], 'logout',
                                 self.client_address[0])
        self.send_response(303)
        self._clear_session_cookie()
        self.send_header('Location', '/manage')
        self.send_header('Content-Length', '0')
        self.end_headers()

    # ── POST handlers ────────────────────────────────────────

    def _post_login(self):
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        username = fields.get('username', '').strip()
        password = fields.get('password', '')
        log.debug('LOGIN attempt user=%r ip=%s', username, self.client_address[0])
        user = REGISTRATION_DB.authenticate(username, password)
        if user is None:
            log.debug('LOGIN failed user=%r', username)
            REGISTRATION_DB._log(username or '(unknown)', 'login_failed',
                                 self.client_address[0])
            self._send_html(_render_login('Invalid credentials.'))
            return
        token = REGISTRATION_DB.create_session(user['id'])
        REGISTRATION_DB.record_login_ip(user['id'], self.client_address[0])
        REGISTRATION_DB._log(username, 'login', self.client_address[0])
        log.debug('LOGIN success user=%r token=%s...', username, token[:8])
        self.send_response(303)
        try:
            self._set_session_cookie(token)
        except Exception as exc:
            log.error('LOGIN _set_session_cookie failed: %s', exc, exc_info=True)
            raise
        self.send_header('Location', '/manage/dashboard')
        self.send_header('Content-Length', '0')
        self.end_headers()
        log.debug('LOGIN 303 sent for user=%r', username)

    def _post_upload(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        body = self._read_body()
        log.debug('UPLOAD body_len=%d content_type=%r',
                  len(body), self.headers.get('Content-Type', '')[:60])
        fields, files = _parse_multipart(self.headers, body)
        log.debug('UPLOAD fields=%s file_keys=%s', list(fields.keys()), list(files.keys()))
        # files dict may hold a single tuple or list of tuples for multiple uploads
        raw_files = files.get('torrent')
        if not raw_files:
            log.debug('UPLOAD no torrent field found in parsed body')
            torrents = REGISTRATION_DB.list_torrents(user_id=user['id'])
            return self._send_html(_render_dashboard(user, torrents, 'No torrent file received.'))
        # Normalise to list of (filename, data) tuples
        if isinstance(raw_files, tuple):
            file_list = [raw_files]
        else:
            file_list = raw_files
        added, skipped, errors = [], [], []
        for fname, file_data in file_list:
            try:
                ih, name, total_size, meta = parse_torrent(file_data)
            except Exception as e:
                errors.append(f'{fname}: {e}')
                continue
            ok = REGISTRATION_DB.register_torrent(ih, name, total_size, user['id'], user['username'], meta=meta)
            if ok:
                log.info('REGISTRATION torrent registered  ih=%s  name=%s  by=%s', ih, name, user['username'])
                REGISTRATION_DB.check_auto_promote(user['id'])
                REGISTRATION_DB.check_reward_credit(user['id'])
                added.append(name)
            else:
                skipped.append(f'{name} (already registered)')
        parts = []
        if added:   parts.append(f'{len(added)} registered: ' + ', '.join(added))
        if skipped: parts.append(f'{len(skipped)} skipped: ' + ', '.join(skipped))
        if errors:  parts.append(f'{len(errors)} failed: ' + '; '.join(errors))
        msg = ' | '.join(parts) if parts else 'No files processed.'
        msg_type = 'error' if errors and not added else 'success'
        log.debug('UPLOAD result msg=%r msg_type=%r added=%d skipped=%d errors=%d',
                  msg[:80], msg_type, len(added), len(skipped), len(errors))
        torrents = REGISTRATION_DB.list_torrents(user_id=user['id'])
        self._send_html(_render_dashboard(user, torrents, msg, msg_type))

    def _get_torrent_detail(self, ih: str):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        t = REGISTRATION_DB.get_torrent(ih.upper())
        if not t: return self._send_html('<h1>Torrent not found</h1>', 404)
        referer = self.headers.get('Referer', '')
        back = urllib.parse.urlparse(referer).path or '/manage/dashboard'
        if back.startswith('/manage/torrent'): back = '/manage/dashboard'
        self._send_html(_render_torrent_detail(user, t, back_url=back))

    def _post_delete_torrent(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        ih       = fields.get('info_hash', '').strip().upper()
        redirect = fields.get('redirect', '').strip()
        if not ih:
            return self._redirect('/manage/dashboard')
        is_super = user['username'] == SUPER_USER
        is_admin = user['is_admin'] or is_super
        # Check ownership unless admin/super
        if not is_admin:
            t = REGISTRATION_DB.get_torrent(ih)
            if not t or t['uploaded_by_id'] != user['id']:
                return self._redirect('/manage/dashboard')
        REGISTRATION_DB.delete_torrent(ih, user['username'])
        log.info('REGISTRATION torrent deleted  ih=%s  by=%s', ih, user['username'])
        if redirect and redirect.startswith('/manage') and not redirect.startswith('/manage/torrent'):
            self._redirect(redirect)
        elif is_admin:
            self._redirect('/manage/admin')
        else:
            self._redirect('/manage/dashboard')

    def _post_change_password(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        cur  = fields.get('current_password', '')
        new  = fields.get('new_password', '')
        conf = fields.get('confirm_password', '')
        if not _verify_password(cur, user['password_hash'], user['salt']):
            return self._send_html(_render_password_page(user, 'Invalid credentials.'))
        if new != conf:
            return self._send_html(_render_password_page(user, 'New passwords do not match.'))
        pw_settings = REGISTRATION_DB.get_all_settings() if REGISTRATION_DB else {}
        pw_errors = _validate_password(new, pw_settings)
        if pw_errors:
            return self._send_html(_render_password_page(user, 'Password does not meet requirements: ' + '; '.join(pw_errors)))
        REGISTRATION_DB.change_password(user['username'], new, user['username'])
        self._redirect('/manage/dashboard')

    def _post_add_user(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        is_super = user['username'] == SUPER_USER
        is_admin = user['is_admin'] or is_super
        if not is_admin:
            return self._redirect('/manage/dashboard')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        username = fields.get('username', '').strip()
        password = fields.get('password', '')
        # Role: basic/standard/admin (admin only for super)
        role_choice     = fields.get('role', 'basic')
        is_new_admin    = is_super and role_choice == 'admin'
        is_new_standard = role_choice in ('standard', 'admin')
        un_err = _validate_username(username)
        if un_err or not password:
            return self._redirect('/manage/admin')
        pw_settings = REGISTRATION_DB.get_all_settings()
        pw_errors   = _validate_password(password, pw_settings)
        if pw_errors:
            return self._redirect('/manage/admin?msg=pw_error&tab=adduser')
        ok = REGISTRATION_DB.create_user(username, password, is_new_admin, user['username'])
        if ok and is_new_standard and not is_new_admin:
            REGISTRATION_DB.set_standard(username, True, user['username'])
        return self._redirect('/manage/admin?tab=users')

    def _post_delete_user(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        is_super = user['username'] == SUPER_USER
        is_admin = user['is_admin'] or is_super
        if not is_admin:
            return self._redirect('/manage/dashboard')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target = fields.get('username', '').strip()
        if not target or target == SUPER_USER:
            return self._redirect('/manage/admin')
        t_user = REGISTRATION_DB.get_user(target)
        if not t_user:
            return self._redirect('/manage/admin')
        # Admins can only delete standard users; super can delete anyone except super
        if not is_super and t_user['is_admin']:
            return self._redirect('/manage/admin')
        REGISTRATION_DB.delete_user(target, user['username'])
        self._redirect('/manage/admin')

    def _post_admin_change_password(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        is_super = user['username'] == SUPER_USER
        is_admin = user['is_admin'] or is_super
        if not is_admin:
            return self._redirect('/manage/dashboard')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target   = fields.get('username', '').strip()
        new_pass = fields.get('new_password', '')
        if not target or target == SUPER_USER or not new_pass:
            return self._redirect('/manage/admin')
        t_user = REGISTRATION_DB.get_user(target)
        if not t_user:
            return self._redirect('/manage/admin')
        # Admins cannot change other admin passwords
        if not is_super and t_user['is_admin']:
            return self._redirect('/manage/admin')
        pw_settings = REGISTRATION_DB.get_all_settings()
        pw_errors   = _validate_password(new_pass, pw_settings)
        if pw_errors:
            return self._redirect(f'/manage/admin/user/{target}?msg=pw_error')
        REGISTRATION_DB.change_password(target, new_pass, user['username'])
        self._redirect(f'/manage/admin/user/{target}?msg=pw_changed')

    def _post_unlock_user(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        is_super = user['username'] == SUPER_USER
        if not (user['is_admin'] or is_super):
            return self._redirect('/manage/dashboard')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target = fields.get('username', '').strip()
        if target:
            REGISTRATION_DB.set_locked(target, False, user['username'])
        ref = self.headers.get('Referer', '')
        back = urllib.parse.urlparse(ref).path or '/manage/admin'
        if not back.startswith('/manage'): back = '/manage/admin'
        self._redirect(back)

    def _post_set_disabled(self, disabled: bool):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        is_super = user['username'] == SUPER_USER
        if not (user['is_admin'] or is_super):
            return self._redirect('/manage/dashboard')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target = fields.get('username', '').strip()
        if target and target != SUPER_USER:
            REGISTRATION_DB.set_disabled(target, disabled, user['username'])
        ref = self.headers.get('Referer', '')
        back = urllib.parse.urlparse(ref).path or '/manage/admin'
        if not back.startswith('/manage'): back = '/manage/admin'
        self._redirect(back)

    def _post_set_admin(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        if user['username'] != SUPER_USER:
            return self._redirect('/manage/dashboard')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target   = fields.get('username', '').strip()
        is_admin = fields.get('is_admin', '0') == '1'
        if target and target != SUPER_USER:
            REGISTRATION_DB.set_admin(target, is_admin, user['username'])
        ref = self.headers.get('Referer', '')
        back = urllib.parse.urlparse(ref).path or '/manage/admin'
        if not back.startswith('/manage'): back = '/manage/admin'
        self._redirect(back)


    # ── Tracker management handlers ──────────────────────────

    def _post_set_standard(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if not (user['is_admin'] or user['username'] == SUPER_USER): return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target = fields.get('username', '').strip()
        is_std = fields.get('is_standard', '0') == '1'
        if target and target != SUPER_USER:
            REGISTRATION_DB.set_standard(target, is_std, user['username'])
        ref = self.headers.get('Referer', '')
        back = urllib.parse.urlparse(ref).path or '/manage/admin'
        if not back.startswith('/manage'): back = '/manage/admin'
        self._redirect(back)

    def _post_delete_all_users(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if user['username'] != SUPER_USER: return self._redirect('/manage/dashboard')
        count = REGISTRATION_DB.delete_all_users(user['username'], user['username'])
        log.info('DELETE ALL USERS: %d users removed by %s', count, user['username'])
        self._redirect('/manage/admin')

    def _post_delete_all_torrents_global(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if user['username'] != SUPER_USER: return self._redirect('/manage/dashboard')
        REGISTRATION_DB.delete_all_torrents(user['username'])
        self._redirect('/manage/admin')

    def _post_delete_all_torrents_user(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target_username = fields.get('username', '').strip()
        is_super = user['username'] == SUPER_USER
        is_admin = user['is_admin'] or is_super
        # Users can delete their own; admins/super can delete anyone's
        if target_username == user['username'] or is_admin:
            target = REGISTRATION_DB.get_user(target_username) if target_username else user
            if target:
                REGISTRATION_DB.delete_all_torrents_for_user(target['id'], user['username'],
                                                              target_username=target['username'])
        # Redirect back to profile or admin based on context
        referer = fields.get('referer', '')
        if referer.startswith('/manage/admin/user/'):
            self._redirect(referer)
        elif referer == '/manage/profile':
            self._redirect('/manage/profile')
        else:
            self._redirect('/manage/dashboard')

    def _post_ip_lock(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if user['username'] != SUPER_USER: return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target_uid = int(fields.get('user_id', 0))
        ips = fields.get('selected_ips', '').split(',')
        for ip in ips:
            ip = ip.strip()
            if ip:
                REGISTRATION_DB.add_ip_allowlist(target_uid, ip, user['username'])
        target = REGISTRATION_DB.get_user_by_id(target_uid)
        if target:
            self._redirect(f'/manage/admin/user/{target["username"]}')
        else:
            self._redirect('/manage/admin')

    def _post_ip_lock_remove(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if user['username'] != SUPER_USER: return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        entry_id   = int(fields.get('entry_id', 0))
        target_username = fields.get('target_username', '')
        if entry_id:
            REGISTRATION_DB.remove_ip_allowlist(entry_id, user['username'])
        self._redirect(f'/manage/admin/user/{target_username}')

    def _post_ip_lock_clear(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if user['username'] != SUPER_USER: return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target_uid      = int(fields.get('user_id', 0))
        target_username = fields.get('target_username', '')
        if target_uid:
            REGISTRATION_DB.clear_ip_allowlist(target_uid, user['username'])
        self._redirect(f'/manage/admin/user/{target_username}')

    def _get_search(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        query  = params.get('q', [''])[0].strip()[:200]
        page   = max(1, int(params.get('page', ['1'])[0]))
        per_page = int(REGISTRATION_DB.get_setting('torrents_per_page', '50'))
        role   = _user_role(user)
        uid    = None if role in ('super', 'admin', 'standard') else user['id']
        if query:
            total    = REGISTRATION_DB.count_search_torrents(query, user_id=uid)
            torrents = REGISTRATION_DB.search_torrents(query, user_id=uid, page=page, per_page=per_page)
        else:
            total    = REGISTRATION_DB.count_torrents(user_id=uid)
            torrents = REGISTRATION_DB.list_torrents(user_id=uid, page=page, per_page=per_page)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        self._send_html(_render_search(user, torrents, query, page, total_pages, total))

    def _serve_robots(self):
        txt = 'User-agent: *\nDisallow: /manage\n'
        if REGISTRATION_DB:
            try: txt = REGISTRATION_DB.get_setting('robots_txt') or txt
            except Exception: pass
        data = txt.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def _get_public_profile(self, username: str):
        viewer = self._get_session_user()
        if not viewer: return self._redirect('/manage')
        if _user_role(viewer) == 'basic': return self._redirect('/manage/dashboard')
        target = REGISTRATION_DB.get_user(username)
        if not target: return self._redirect('/manage/dashboard')
        per_page = int(REGISTRATION_DB.get_setting('torrents_per_page', '50'))
        page     = _get_page_param(self.path)
        total    = REGISTRATION_DB.count_torrents(user_id=target['id'])
        torrents = REGISTRATION_DB.list_torrents(user_id=target['id'], page=page, per_page=per_page)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        self._send_html(_render_public_profile(viewer, target, torrents,
                                               page=page, total_pages=total_pages, total=total))

    def _get_profile(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        is_super  = user['username'] == SUPER_USER
        per_page  = int(REGISTRATION_DB.get_setting('torrents_per_page', '50'))
        page      = _get_page_param(self.path)
        total     = REGISTRATION_DB.count_torrents(user_id=user['id'])
        torrents  = REGISTRATION_DB.list_torrents(user_id=user['id'], page=page, per_page=per_page)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        history   = REGISTRATION_DB.get_login_history(user['id'], 5)
        allowlist = REGISTRATION_DB.get_ip_allowlist(user['id'])
        self._send_html(_render_user_detail(user, user, torrents, history, is_super,
                                            allowlist=allowlist, is_own_profile=True,
                                            page=page, total_pages=total_pages,
                                            total=total, base_url='/manage/profile'))

    def _post_tracker_add(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if not (user['is_admin'] or user['username'] == SUPER_USER): return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        url = fields.get('url', '').strip()
        if url:
            REGISTRATION_DB.add_magnet_tracker(url, user['username'])
        self._redirect('/manage/admin')

    def _post_tracker_delete(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if not (user['is_admin'] or user['username'] == SUPER_USER): return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        tid = int(fields.get('tid', 0))
        if tid: REGISTRATION_DB.delete_magnet_tracker(tid, user['username'])
        self._redirect('/manage/admin')

    def _post_tracker_toggle(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if not (user['is_admin'] or user['username'] == SUPER_USER): return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        tid = int(fields.get('tid', 0))
        if tid: REGISTRATION_DB.toggle_magnet_tracker(tid, user['username'])
        self._redirect('/manage/admin')

    def _post_tracker_move(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if not (user['is_admin'] or user['username'] == SUPER_USER): return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        tid = int(fields.get('tid', 0))
        direction = int(fields.get('direction', 0))
        if tid and direction in (-1, 1):
            REGISTRATION_DB.move_magnet_tracker(tid, direction, user['username'])
        self._redirect('/manage/admin')

    def _post_save_settings(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if user['username'] != SUPER_USER: return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        form_id = fields.get('form_id', '')
        if form_id == 'complexity':
            for key in ('pw_min_length', 'pw_require_upper', 'pw_require_lower',
                        'pw_require_digit', 'pw_require_symbol'):
                if key == 'pw_min_length':
                    try: val = str(max(6, min(64, int(fields.get(key, '12')))))
                    except: val = '12'
                else:
                    val = '1' if fields.get(key) == '1' else '0'
                REGISTRATION_DB.set_setting(key, val, user['username'])
        elif form_id == 'free_signup':
            val = '1' if fields.get('free_signup') == '1' else '0'
            REGISTRATION_DB.set_setting('free_signup', val, user['username'])
        elif form_id == 'open_tracker':
            global OPEN_TRACKER
            val = '1' if fields.get('open_tracker') == '1' else '0'
            REGISTRATION_DB.set_setting('open_tracker', val, user['username'])
            OPEN_TRACKER = (val == '1')
            log.info('OPEN_TRACKER set to %s by %s', OPEN_TRACKER, user['username'])
        elif form_id == 'robots_txt':
            val = fields.get('robots_txt', 'User-agent: *\nDisallow: /')
            REGISTRATION_DB.set_setting('robots_txt', val[:4000], user['username'])
        elif form_id == 'torrents_per_page':
            try:
                val = str(max(5, min(500, int(fields.get('torrents_per_page', '50')))))
            except Exception:
                val = '50'
            REGISTRATION_DB.set_setting('torrents_per_page', val, user['username'])
        elif form_id == 'auto_promote':
            val = '1' if fields.get('auto_promote_enabled') == '1' else '0'
            REGISTRATION_DB.set_setting('auto_promote_enabled', val, user['username'])
            try:
                threshold = str(max(1, min(9999, int(fields.get('auto_promote_threshold', '25')))))
            except Exception:
                threshold = '25'
            REGISTRATION_DB.set_setting('auto_promote_threshold', threshold, user['username'])
        elif form_id == 'reward':
            global REWARD_ENABLED, REWARD_THRESHOLD
            val = '1' if fields.get('reward_enabled') == '1' else '0'
            REGISTRATION_DB.set_setting('reward_enabled', val, user['username'])
            REWARD_ENABLED = (val == '1')
            try:
                thr = str(max(1, min(99999, int(fields.get('reward_threshold', '200')))))
            except Exception:
                thr = '200'
            REGISTRATION_DB.set_setting('reward_threshold', thr, user['username'])
            REWARD_THRESHOLD = int(thr)
            log.info('REWARD set enabled=%s threshold=%s by %s', REWARD_ENABLED, REWARD_THRESHOLD, user['username'])
        self._redirect('/manage/admin')

    # ── Invite & Credit handlers ─────────────────────────────

    def _post_admin_generate_invite(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if not (user['is_admin'] or user['username'] == SUPER_USER):
            return self._redirect('/manage/dashboard')
        REGISTRATION_DB.create_invite_code(user['username'])
        self._redirect('/manage/admin?tab=invites')

    def _post_admin_delete_invite(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if not (user['is_admin'] or user['username'] == SUPER_USER):
            return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        code = fields.get('code', '')
        if code:
            REGISTRATION_DB.delete_invite_code(code, user['username'])
        self._redirect('/manage/admin?tab=invites')

    def _post_adjust_credits(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if not (user['is_admin'] or user['username'] == SUPER_USER):
            return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target_username = fields.get('username', '')
        try:
            delta = int(fields.get('delta', '0'))
        except Exception:
            delta = 0
        if target_username and delta:
            REGISTRATION_DB.adjust_credits(target_username, delta, user['username'])
        referer = fields.get('referer', '')
        self._redirect(referer if referer.startswith('/manage/') else '/manage/admin')

    def _post_profile_generate_invite(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        token = REGISTRATION_DB.spend_credit_for_invite(user['username'])
        if not token:
            return self._redirect('/manage/profile?msg=nocredits')
        self._redirect('/manage/profile')

    def _get_invite_signup(self, code: str):
        if REGISTRATION_DB is None:
            return self._send_html('<h1>Not Found</h1>', 404)
        invite = REGISTRATION_DB.get_invite_code(code)
        if not invite or invite['consumed_at']:
            return self._send_html(_render_invite_invalid())
        pw_settings = REGISTRATION_DB.get_all_settings()
        self._send_html(_render_signup(pw_settings=pw_settings, invite_code=code,
                                       invited_by=invite['created_by_username']))

    def _post_invite_signup(self, code: str):
        if REGISTRATION_DB is None:
            return self._send_html('<h1>Not Found</h1>', 404)
        invite = REGISTRATION_DB.get_invite_code(code)
        if not invite or invite['consumed_at']:
            return self._send_html(_render_invite_invalid())
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        username = fields.get('username', '').strip()
        password = fields.get('password', '')
        confirm  = fields.get('confirm_password', '')
        pw_settings = REGISTRATION_DB.get_all_settings()
        un_err = _validate_username(username)
        if un_err:
            return self._send_html(_render_signup(un_err, pw_settings=pw_settings,
                                                  invite_code=code, invited_by=invite['created_by_username']))
        if password != confirm:
            return self._send_html(_render_signup('Passwords do not match.', pw_settings=pw_settings,
                                                  invite_code=code, invited_by=invite['created_by_username']))
        pw_errors = _validate_password(password, pw_settings)
        if pw_errors:
            return self._send_html(_render_signup(
                'Password does not meet requirements: ' + '; '.join(pw_errors),
                pw_settings=pw_settings, invite_code=code, invited_by=invite['created_by_username']))
        created_by = f'invite:{invite["created_by_username"]}'
        ok = REGISTRATION_DB.create_user(username, password, False, created_by)
        if not ok:
            return self._send_html(_render_signup(f'Username {username!r} is already taken.',
                                                  pw_settings=pw_settings, invite_code=code,
                                                  invited_by=invite['created_by_username']))
        REGISTRATION_DB.consume_invite_code(code, username)
        user = REGISTRATION_DB.authenticate(username, password)
        token = REGISTRATION_DB.create_session(user['id'])
        REGISTRATION_DB.record_login_ip(user['id'], self.client_address[0])
        REGISTRATION_DB._log(username, 'login', self.client_address[0])
        self.send_response(303)
        self._set_session_cookie(token)
        self.send_header('Location', '/manage/dashboard')
        self.send_header('Content-Length', '0')
        self.end_headers()

    # ── Signup handlers ──────────────────────────────────────

    def _get_user_detail(self, username: str):
        viewer = self._get_session_user()
        if not viewer: return self._redirect('/manage')
        is_super = viewer['username'] == SUPER_USER
        if not (viewer['is_admin'] or is_super): return self._redirect('/manage/dashboard')
        target = REGISTRATION_DB.get_user(username)
        if not target: return self._redirect('/manage/admin')
        per_page = int(REGISTRATION_DB.get_setting('torrents_per_page', '50'))
        page     = _get_page_param(self.path)
        total    = REGISTRATION_DB.count_torrents(user_id=target['id'])
        torrents = REGISTRATION_DB.list_torrents(user_id=target['id'], page=page, per_page=per_page)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        history   = REGISTRATION_DB.get_login_history(target['id'], 5)
        allowlist = REGISTRATION_DB.get_ip_allowlist(target['id'])
        base_url  = f'/manage/admin/user/{username}'
        self._send_html(_render_user_detail(viewer, target, torrents, history, is_super,
                                            allowlist=allowlist,
                                            page=page, total_pages=total_pages,
                                            total=total, base_url=base_url))

    def _get_signup(self):
        if REGISTRATION_DB is None or REGISTRATION_DB.get_setting('free_signup') != '1':
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        pw_settings = REGISTRATION_DB.get_all_settings()
        self._send_html(_render_signup(pw_settings=pw_settings))

    def _post_signup(self):
        if REGISTRATION_DB is None or REGISTRATION_DB.get_setting('free_signup') != '1':
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        username = fields.get('username', '').strip()
        password = fields.get('password', '')
        confirm  = fields.get('confirm_password', '')
        pw_settings = REGISTRATION_DB.get_all_settings()
        un_err = _validate_username(username)
        if un_err:
            return self._send_html(_render_signup(un_err, pw_settings=pw_settings))
        if password != confirm:
            return self._send_html(_render_signup('Passwords do not match.', pw_settings=pw_settings))
        pw_errors = _validate_password(password, pw_settings)
        if pw_errors:
            return self._send_html(_render_signup(
                'Password does not meet requirements: ' + '; '.join(pw_errors), pw_settings=pw_settings))
        ok = REGISTRATION_DB.create_user(username, password, False, 'self')
        if not ok:
            return self._send_html(_render_signup(f'Username {username!r} is already taken.', pw_settings=pw_settings))
        user = REGISTRATION_DB.authenticate(username, password)
        token = REGISTRATION_DB.create_session(user['id'])
        REGISTRATION_DB.record_login_ip(user['id'], self.client_address[0])
        REGISTRATION_DB._log(username, 'login', self.client_address[0])
        self.send_response(303)
        self._set_session_cookie(token)
        self.send_header('Location', '/manage/dashboard')
        self.send_header('Content-Length', '0')
        self.end_headers()

class IPv6ManageServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def start_manage_server(host: str, port: int, ssl_ctx=None, label='MANAGE'):
    server = ThreadingHTTPServer((host, port), ManageHandler)
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    log.info('%s management page listening on %s:%d', label, host or '0.0.0.0', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def start_manage6_server(host6: str, port: int, ssl_ctx=None, label='MANAGE'):
    server = IPv6ManageServer((host6, port, 0, 0), ManageHandler)
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    log.info('%s management page listening on [%s]:%d (IPv6)', label, host6, port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


class StatsWebHandler(ManageHandler):
    """Serves the stats page at / and /manage/* when registration is enabled."""

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith('/manage'):
            if not REGISTRATION_MODE:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            ManageHandler.do_GET(self)
        elif path == '/' or path == '':
            snap = STATS.snapshot()
            _show_manage = False
            if REGISTRATION_MODE and REGISTRATION_DB is not None:
                _show_manage = self._get_session_user() is not None
                WEB_CONFIG['free_signup'] = REGISTRATION_DB.get_setting('free_signup') == '1'
            html = generate_stats_html(snap, WEB_CONFIG, show_manage=_show_manage)
            body = html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(body)
        elif path == '/favicon.ico':
            self.send_response(200)
            self.send_header('Content-Type', 'image/x-icon')
            self.send_header('Content-Length', str(len(FAVICON_ICO)))
            self.send_header('Cache-Control', 'max-age=86400')
            self.end_headers()
            self.wfile.write(FAVICON_ICO)
        elif path == '/robots.txt':
            self._serve_robots()
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '9')
            self.end_headers()
            self.wfile.write(b'Not Found')

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith('/manage'):
            if not REGISTRATION_MODE:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            ManageHandler.do_POST(self)
        else:
            self.send_response(405)
            self.send_header('Content-Length', '0')
            self.end_headers()

    def log_message(self, fmt, *args):
        log.debug('WEB %s %s', self.address_string(), fmt % args)


class IPv6StatsWebServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    """IPv6 variant of the stats web server."""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def start_web_server(host: str, port: int, ssl_ctx=None, label='WEB'):
    server = ThreadingHTTPServer((host, port), StatsWebHandler)
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    log.info('%s stats page listening on %s:%d', label, host or '0.0.0.0', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def start_web6_server(host6: str, port: int, ssl_ctx=None, label='WEB'):
    server = IPv6StatsWebServer((host6, port, 0, 0), StatsWebHandler)
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    log.info('%s stats page listening on [%s]:%d (IPv6)', label, host6 or '::', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# ─────────────────────────────────────────────────────────────
# /manage page HTML generators
# ─────────────────────────────────────────────────────────────

_MANAGE_CSS = '''
  :root {
    --bg: #0a0b10; --card: #12141c; --card2: #191b26; --border: #1e2133;
    --accent: #f5a623; --accent2: #e05b30; --green: #3ecf8e; --red: #e05b30; --blue: #4f8ef7;
    --text: #e8eaf2; --muted: #555878;
    --mono: 'JetBrains Mono', monospace; --sans: 'DM Sans', sans-serif;
    --display: 'Orbitron', sans-serif;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg: #f5f4ef; --card: #ffffff; --card2: #eeede8; --border: #d8d6cc;
      --accent: #c97d0a; --accent2: #c04820; --green: #1a9e65; --red: #c04820; --blue: #2c6fd4;
      --text: #1a1a2a; --muted: #888070;
    }
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--sans);
         font-size: 15px; line-height: 1.6; min-height: 100vh; }
  body::before { content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background: radial-gradient(ellipse 80% 50% at 50% -10%, rgba(245,166,35,0.06) 0%, transparent 70%); }
  .container { max-width: 1280px; margin: 0 auto; padding: 0 32px; position: relative; z-index: 1; }
  .header { padding: 32px 0 24px; border-bottom: 1px solid var(--border); margin-bottom: 32px;
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
  .logo { font-family: var(--display); font-size: 1.4rem; font-weight: 900;
          letter-spacing: 0.12em; color: var(--accent); text-decoration: none; }
  .logo span { color: var(--text); }
  .nav { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  .nav a, .nav-user { font-family: var(--mono); font-size: 0.78rem; color: var(--muted);
                      text-decoration: none; letter-spacing: 0.08em; }
  .nav a:hover { color: var(--accent); }
  .nav-user { color: var(--text); }
  .nav-user:hover .nav-username { color: var(--accent); }
  .nav-username { transition: color 0.15s; }
  .btn { display: inline-block; font-family: var(--mono); font-size: 0.78rem; letter-spacing: 0.08em;
         padding: 8px 18px; border-radius: 6px; border: 1px solid var(--border); cursor: pointer;
         text-decoration: none; transition: all 0.15s; background: transparent; color: var(--text); }
  .btn:hover { border-color: var(--accent); color: var(--accent); }
  .btn-primary { background: var(--accent); border-color: var(--accent); color: #000; }
  .btn-primary:hover { opacity: 0.85; color: #000; }
  .btn-danger { border-color: var(--red); color: var(--red); }
  .btn-danger:hover { background: var(--red); color: #fff; }
  .btn-sm { padding: 4px 12px; font-size: 0.72rem; }
  .btn-green { border-color: var(--green); color: var(--green); }
  .btn-green:hover { background: var(--green); color: #000; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px;
          padding: 24px 28px; margin-bottom: 24px; }
  .card-title { font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.2em;
                text-transform: uppercase; color: var(--muted); margin-bottom: 18px;
                padding-bottom: 10px; border-bottom: 1px solid var(--border); }
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 0.82rem; color: var(--muted);
                      margin-bottom: 6px; font-family: var(--mono); font-size: 0.72rem;
                      letter-spacing: 0.1em; text-transform: uppercase; }
  .form-group input[type=text], .form-group input[type=password],
  .form-group input[type=file] {
    width: 100%; padding: 10px 14px; background: var(--card2); border: 1px solid var(--border);
    border-radius: 6px; color: var(--text); font-family: var(--mono); font-size: 0.88rem;
    outline: none; transition: border-color 0.15s; }
  input:focus { border-color: var(--accent); }
  .alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 18px;
           font-size: 0.88rem; font-family: var(--mono); }
  .alert-error { background: rgba(224,91,48,0.12); border: 1px solid rgba(224,91,48,0.3); color: var(--red); }
  .alert-success { background: rgba(62,207,142,0.10); border: 1px solid rgba(62,207,142,0.3); color: var(--green); }
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  .torrent-table { table-layout: fixed; min-width: 700px; }
  th { font-family: var(--mono); font-size: 0.68rem; letter-spacing: 0.15em; text-transform: uppercase;
       color: var(--muted); padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--card2); }
  .badge { display: inline-block; font-family: var(--mono); font-size: 0.65rem; letter-spacing: 0.1em;
           padding: 2px 8px; border-radius: 4px; font-weight: 600; }
  .badge-admin    { background: rgba(245,166,35,0.15); color: var(--accent); border: 1px solid rgba(245,166,35,0.3); }
  .badge-standard { background: rgba(180,180,200,0.12); color: var(--text); border: 1px solid rgba(180,180,200,0.3); }
  .badge-basic    { background: rgba(62,207,142,0.10); color: var(--green); border: 1px solid rgba(62,207,142,0.3); }
  .user-link { color:var(--text);text-decoration:none;border-bottom:1px solid transparent;transition:color .15s,border-color .15s; }
  .user-link:hover { color:var(--accent);border-bottom-color:var(--accent); }
  .badge-super { background: rgba(79,142,247,0.15); color: var(--blue); border: 1px solid rgba(79,142,247,0.3); }
  .badge-locked { background: rgba(224,91,48,0.15); color: var(--red); border: 1px solid rgba(224,91,48,0.3); }
  .badge-disabled { background: rgba(85,88,120,0.2); color: var(--muted); border: 1px solid var(--border); }

  .hash { font-family: var(--mono); font-size: 0.75rem; color: var(--muted); }
  .tabs { display: flex; gap: 4px; margin-bottom: 24px; background: var(--card);
          border: 1px solid var(--border); border-radius: 10px; padding: 4px; width: fit-content; }
  .tab { font-family: var(--mono); font-size: 0.75rem; letter-spacing: 0.1em; text-transform: uppercase;
         padding: 7px 20px; border-radius: 7px; border: none; background: transparent;
         color: var(--muted); cursor: pointer; transition: color 0.15s; }
  .tab:hover { color: var(--accent); background: rgba(245,166,35,0.08); }
  .tab.tab-danger { color: var(--accent2); }
  .tab.tab-danger:hover { color: #ff7a55; background: rgba(224,91,48,0.12); }
  .tab.active { background: var(--card2); color: var(--accent); border: 1px solid var(--border); }
  .tab.tab-danger.active { color: var(--accent2); }
  .panel { display: none; }
  .panel.visible { display: block; }
  .empty { text-align: center; padding: 32px; color: var(--muted);
           font-family: var(--mono); font-size: 0.85rem; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .page-title { font-family: var(--display); font-size: 1.1rem; color: var(--text);
                letter-spacing: 0.08em; margin-bottom: 4px; }
  .page-sub { font-size: 0.85rem; color: var(--muted); margin-bottom: 28px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
  @media (max-width: 640px) { .two-col { grid-template-columns: 1fr; } }
'''

_MANAGE_HEAD = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} -- Wildkat Tracker</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,{favicon}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;600&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body>
<div class="container">'''

_MANAGE_HEADER = '''
  <div class="header">
    <a class="logo" href="/">&#128008; WILD<span>KAT</span></a>
    <div class="nav">
      {nav_items}
    </div>
  </div>'''

_MANAGE_FOOT = '''
</div>
<script>
function showTab(name, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('visible'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('visible');
  btn.classList.add('active');
}
function confirmAction(msg) {
  return new Promise(function(resolve) {
    var o = document.createElement('div');
    o.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:9999;display:flex;align-items:center;justify-content:center';
    o.innerHTML = '<div style="background:var(--card);border:1px solid var(--border);border-radius:12px;padding:28px 32px;max-width:560px;width:92%;text-align:center">'
      + '<div style="font-family:var(--mono);font-size:0.68rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--muted);margin-bottom:12px">Confirm Action</div>'
      + '<div style="font-size:0.92rem;margin-bottom:24px;line-height:1.5;color:var(--text);word-break:break-word;overflow-wrap:anywhere">' + msg + '</div>'
      + '<div style="display:flex;gap:12px;justify-content:center">'
      + '<button id="_ca_no" class="btn">Cancel</button>'
      + '<button id="_ca_yes" class="btn btn-danger">Confirm</button>'
      + '</div></div>';
    document.body.appendChild(o);
    document.getElementById('_ca_yes').onclick = function(){ document.body.removeChild(o); resolve(true); };
    document.getElementById('_ca_no').onclick  = function(){ document.body.removeChild(o); resolve(false); };
  });
}
// CSRF: inject token from cookie into every POST form before submit
function _getCsrf(){
  var m=document.cookie.match(/(?:^|;[ \t]*)wkcsrf=([^;]+)/);
  return m ? m[1] : '';
}
function _injectCsrf(form){
  if(!form.querySelector('input[name="_csrf"]')){
    var inp=document.createElement('input');
    inp.type='hidden'; inp.name='_csrf'; inp.value=_getCsrf();
    form.appendChild(inp);
  }
}
document.addEventListener('submit', function(e){
  var f = e.target, msg = f.dataset.confirm;
  if(f.method && f.method.toUpperCase()==='POST') _injectCsrf(f);
  if(msg){ e.preventDefault(); confirmAction(msg).then(function(ok){
    if(ok){ _injectCsrf(f); f.submit(); }
  }); }
}, true);
function filterTorrents(input, tableId) {
  var q = input.value.toLowerCase();
  var rows = document.getElementById(tableId).querySelectorAll('tr[data-name]');
  rows.forEach(function(r){ r.style.display = r.dataset.name.indexOf(q) !== -1 ? '' : 'none'; });
}
function copyInvite(btn, path) {
  var url = window.location.protocol + '//' + window.location.host + path;
  navigator.clipboard.writeText(url).then(function() {
    var orig = btn.innerHTML;
    btn.innerHTML = '&#10003; Copied!';
    btn.style.borderColor = 'var(--green)';
    btn.style.color = 'var(--green)';
    btn.style.background = 'transparent';
    setTimeout(function() {
      btn.innerHTML = orig;
      btn.style.borderColor = '';
      btn.style.color = '';
      btn.style.background = '';
    }, 2000);
  }).catch(function() {
    prompt('Copy this invite URL:', url);
  });
}
function copyMagnet(btn, url) {
  navigator.clipboard.writeText(url).then(function() {
    var orig = btn.innerHTML;
    btn.innerHTML = '&#10003; Copied!';
    btn.style.borderColor = 'var(--green)';
    btn.style.color = 'var(--green)';
    btn.style.background = 'transparent';
    setTimeout(function() {
      btn.innerHTML = orig;
      btn.style.borderColor = '';
      btn.style.color = '';
      btn.style.background = '';
    }, 2000);
  }).catch(function() {
    prompt('Copy this magnet link:', url);
  });
}
</script>
</body></html>'''


def _manage_page(title: str, body: str, user=None, msg: str = '', msg_type: str = 'error') -> str:
    fav = urllib.parse.quote(FAVICON_SVG.strip())
    if user:
        role = _user_role(user)
        role_label = role.upper()
        nav = (f'<a href="/manage/profile" class="nav-user" style="text-decoration:none">'
               f'<span class="nav-username">{_h(user["username"])}</span> '
               f'<span class="badge badge-{role}">{role_label}</span></a>'
               f'<a href="/manage/password" class="btn btn-sm">Password</a>'
               f'<a href="/manage/logout" class="btn btn-sm">Logout</a>')
    else:
        nav = ''

    alert = ''
    if msg:
        cls = 'alert-error' if msg_type == 'error' else 'alert-success'
        alert = f'<div class="alert {cls}">{msg}</div>'

    head = _MANAGE_HEAD.format(title=title, favicon=fav, css=_MANAGE_CSS)
    header = _MANAGE_HEADER.format(nav_items=nav)
    return head + header + alert + body + _MANAGE_FOOT


def _pw_requirements_html(settings: dict) -> str:
    """Render password requirements list for display on forms."""
    reqs = [f"At least {settings.get('pw_min_length','12')} characters"]
    if settings.get('pw_require_upper','1') == '1': reqs.append('One uppercase letter')
    if settings.get('pw_require_lower','1') == '1': reqs.append('One lowercase letter')
    if settings.get('pw_require_digit','1') == '1': reqs.append('One digit')
    if settings.get('pw_require_symbol','1') == '1': reqs.append('One symbol (!@#$%^&* etc.)')
    items = ''.join(f'<li>{r}</li>' for r in reqs)
    return (f'<div style="background:var(--card2);border:1px solid var(--border);border-radius:8px;'
            f'padding:12px 16px;margin-bottom:16px;font-size:0.82rem;color:var(--muted)">'
            f'<div style="font-family:var(--mono);font-size:0.68rem;letter-spacing:0.1em;'
            f'text-transform:uppercase;margin-bottom:8px;color:var(--text)">Password Requirements</div>'
            f'<ul style="margin:0;padding-left:18px;line-height:1.8">{items}</ul></div>')


def _render_signup(msg: str = '', pw_settings: dict | None = None,
                   invite_code: str = '', invited_by: str = '') -> str:
    pw_req_html = _pw_requirements_html(pw_settings or {}) if pw_settings else ''
    action = f'/manage/invite/{invite_code}' if invite_code else '/manage/signup'
    invite_note = ''
    if invited_by:
        invite_note = f'<div style="font-size:0.82rem;color:var(--green);margin-bottom:12px">&#127881; You were invited by <strong>{_h(invited_by)}</strong></div>'
    body = f'''
  <div style="max-width:400px;margin:60px auto">
    <div class="page-title">Create Account</div>
    <div class="page-sub">Wildkat Tracker &nbsp;·&nbsp; <a href="/manage" style="color:var(--muted)">Sign In</a></div>
    <div class="card">
      {invite_note}
      <form method="POST" action="{action}">
        <div class="form-group">
          <label>Username</label>
          <input type="text" name="username" autocomplete="username" autofocus required>
        </div>
        {pw_req_html}
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" autocomplete="new-password" required>
        </div>
        <div class="form-group">
          <label>Confirm Password</label>
          <input type="password" name="confirm_password" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;margin-top:8px">Create Account</button>
      </form>
    </div>
  </div>'''
    return _manage_page('Sign Up', body, msg=msg)


def _render_invite_invalid() -> str:
    body = '''<div style="max-width:400px;margin:60px auto">
    <div class="page-title">Invalid Invite</div>
    <div class="page-sub">This invite link is invalid or has already been used.</div>
    <div class="card"><p style="color:var(--muted);font-size:0.9rem">If you believe this is an error,
    contact the person who sent you the link.</p>
    <a href="/manage" class="btn btn-primary" style="margin-top:16px;display:inline-block">Sign In</a></div></div>'''
    return _manage_page('Invalid Invite', body)


def _render_login(msg: str = '') -> str:
    body = '''
  <div style="max-width:380px;margin:60px auto">
    <div class="page-title">Sign In</div>
    <div class="page-sub">Wildkat Tracker Management</div>
    <div class="card">
      <form method="POST" action="/manage/login">
        <div class="form-group">
          <label>Username</label>
          <input type="text" name="username" autocomplete="username" autofocus required>
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" autocomplete="current-password" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;margin-top:8px">Sign In</button>
      </form>
    </div>
  </div>'''
    return _manage_page('Login', body, msg=msg)


def _fmt_size(b: int) -> str:
    """Human-friendly file size."""
    if b == 0: return '--'
    if b < 1024: return f'{b} B'
    if b < 1024**2: return f'{b/1024:.1f} KB'
    if b < 1024**3: return f'{b/1024**2:.1f} MB'
    return f'{b/1024**3:.2f} GB'


def _torrent_header(show_owner: bool = False) -> str:
    if show_owner:
        # 6 cols: 33+27+10+8+10+12 = 100%
        return (
            '<tr>'
            '<th style="width:33%">Name</th>'
            '<th style="width:27%">Info Hash</th>'
            '<th style="width:10%">Owner</th>'
            '<th style="width:8%;white-space:nowrap">Size</th>'
            '<th style="width:10%;white-space:nowrap">Registered</th>'
            '<th style="width:12%;min-width:100px">Action</th>'
            '</tr>'
        )
    # 5 cols: 36+36+8+8+12 = 100%
    return (
        '<tr>'
        '<th style="width:36%">Name</th>'
        '<th style="width:36%">Info Hash</th>'
        '<th style="width:8%;white-space:nowrap">Size</th>'
        '<th style="width:8%;white-space:nowrap">Registered</th>'
        '<th style="width:12%;min-width:100px">Action</th>'
        '</tr>'
    )


def _torrent_row(t, viewer_role: str, viewer_id: int,
                 show_owner: bool = False, show_delete: bool = True) -> str:
    """Render a unified <tr> for any torrent table."""
    is_super   = viewer_role == 'super'
    is_admin   = viewer_role in ('super', 'admin')
    is_owner   = t['uploaded_by_id'] == viewer_id
    ih         = t['info_hash']
    size_str   = _fmt_size(t['total_size'] if 'total_size' in t.keys() else 0)
    reg_date   = t['registered_at'][:10]
    name_esc   = _h(t['name'])
    magnet     = REGISTRATION_DB.build_magnet(ih, t['name'],
                     t['total_size'] if 'total_size' in t.keys() else 0) if REGISTRATION_DB else ''

    # Delete button: super anywhere, owner on profile (show_delete=True only when appropriate)
    del_btn = ''
    if show_delete and (is_super or is_owner or is_admin):
        del_btn = (f'<form method="POST" action="/manage/delete-torrent" style="display:inline"'
                   f' data-confirm="Delete {name_esc}?">'
                   f'<input type="hidden" name="info_hash" value="{ih}">'
                   f'<button class="btn btn-sm btn-danger">Delete</button></form>')

    uname_e  = _h(t['uploaded_by_username']) if t['uploaded_by_username'] else ''
    owner_td = (f'<td><a href="/manage/user/{uname_e}" class="user-link">{uname_e}</a></td>'
                if show_owner else '')
    name_lower = _html_mod.escape(t['name'].lower())

    return (
        f'<tr data-name="{name_lower}">'
        f'<td style="word-break:break-word;overflow-wrap:anywhere"><a href="/manage/torrent/{ih}" class="user-link">{name_esc}</a></td>'
        f'<td class="hash" style="word-break:break-all">{ih}</td>'
        f'{owner_td}'
        f'<td class="hash" style="white-space:nowrap">{size_str}</td>'
        f'<td class="hash">{reg_date}</td>'
        f'<td><div class="actions">'
        f'<button class="btn btn-sm btn-green" onclick="copyMagnet(this,{repr(magnet)})" title="Copy magnet">&#x1F9F2; Magnet</button>'
        f' {del_btn}'
        f'</div></td>'
        f'</tr>'
    )


def _render_search(user, torrents: list, query: str = '',
                   page: int = 1, total_pages: int = 1, total: int = 0) -> str:
    is_admin = _user_role(user) in ('admin', 'super')

    srole = _user_role(user)
    t_rows = ''.join(
        _torrent_row(t, srole, user['id'], show_owner=is_admin, show_delete=False)
        for t in torrents
    )
    if not t_rows:
        cols = 6 if is_admin else 5
        t_rows = f'<tr><td colspan="{cols}" class="empty">No results found</td></tr>'

    q_enc = urllib.parse.quote(query)
    pagination = _pagination_html(page, total_pages, f'/manage/search?q={q_enc}')

    body = f'''
  <div class="page-title">Search Torrents</div>
  <div class="page-sub"><a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#8592; Dashboard</a></div>
  <div class="card" style="margin-bottom:0">
    <form method="GET" action="/manage/search" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
      <div class="form-group" style="flex:1;margin:0;min-width:240px">
        <label>Search by name or info hash</label>
        <input type="text" name="q" value="{query}" placeholder="Enter name or hash..." autofocus
               style="font-size:1rem">
      </div>
      <button type="submit" class="btn btn-primary" style="margin-bottom:1px">Search</button>
    </form>
  </div>
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:12px">
      <div class="card-title" style="margin:0">
        {"Results for &ldquo;" + query + "&rdquo; &mdash; " + str(total) + " found" if query else "All Torrents (" + str(total) + ")"}
      </div>
      <input type="text" placeholder="Filter this page..." oninput="filterTorrents(this,'search-torrent-table')"
       style="padding:6px 12px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem;width:220px">
    </div>
    <div class="table-wrap"><table id="search-torrent-table" class="torrent-table">
      {_torrent_header(show_owner=is_admin)}
      {t_rows}
    </table></div>
    {pagination}
  </div>'''
    return _manage_page('Search', body, user=user)


def _render_dashboard(user, torrents: list, msg: str = '', msg_type: str = 'error',
                      page: int = 1, total_pages: int = 1, total: int = 0) -> str:
    is_super = user['username'] == SUPER_USER
    role = _user_role(user)
    is_admin = role in ('admin','super')
    is_standard = role in ('admin','super','standard')

    viewer_role = _user_role(user)
    torrent_rows = ''.join(
        _torrent_row(t, viewer_role, user['id'], show_owner=is_standard, show_delete=is_super)
        for t in torrents
    )
    if not torrent_rows:
        cols = 6 if is_standard else 5
        torrent_rows = f'<tr><td colspan="{cols}" class="empty">No torrents registered yet</td></tr>'

    admin_link = (
        '<a href="/manage/admin" class="dash-nav-btn">&#9881;&#65039; Admin Panel</a>'
        if is_admin else '')
    search_link = '<a href="/manage/search" class="dash-nav-btn">&#128269; Search</a>'

    body = f'''
  <style>
    .dash-nav-btn {{
      font-family: var(--mono); font-size: 0.75rem; letter-spacing: 0.1em;
      text-transform: uppercase; padding: 7px 20px; border-radius: 7px;
      border: none; background: transparent; color: var(--muted);
      cursor: pointer; transition: color 0.15s, background 0.15s;
      text-decoration: none; display: inline-block;
    }}
    .dash-nav-btn:hover {{
      color: var(--accent); background: rgba(245,166,35,0.08);
    }}
  </style>
  <div class="page-title">Dashboard</div>
  <div class="page-sub">Manage your registered torrents</div>
  {admin_link} {search_link}
  <div class="card" style="margin-top:16px">
    <div class="card-title">Register a Torrent</div>
    <form method="POST" action="/manage/upload" enctype="multipart/form-data">
      <div class="two-col">
        <div class="form-group" style="margin:0">
          <label>Torrent File (.torrent)</label>
          <input type="file" name="torrent" accept=".torrent" multiple required>
        </div>
        <div style="display:flex;align-items:flex-end">
          <button type="submit" class="btn btn-primary">Register</button>
        </div>
      </div>
    </form>
  </div>
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:12px">
      <div class="card-title" style="margin:0">Registered Torrents ({total})</div>
      <input type="text" placeholder="Filter this page..." oninput="filterTorrents(this,'dash-torrent-table')"
       style="padding:6px 12px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem;width:240px">
    </div>
    <div class="table-wrap"><table id="dash-torrent-table" class="torrent-table">
      {_torrent_header(is_standard)}
      {torrent_rows}
    </table></div>
    {_pagination_html(page, total_pages, '/manage/dashboard')}
  </div>'''
    return _manage_page('Dashboard', body, user=user, msg=msg, msg_type=msg_type)


def _render_admin(user, all_torrents: list, all_users: list, events: list,
                  trackers: list, settings: dict,
                  msg: str = '', msg_type: str = 'error',
                  page: int = 1, total_pages: int = 1, total: int = 0,
                  upage: int = 1, utotal_pages: int = 1, utotal: int = 0,
                  uquery: str = '') -> str:
    is_super = user['username'] == SUPER_USER

    # ── Tracker rows ─────────────────────────────────────────────
    tr_rows = ''
    for tr in trackers:
        tid    = tr['id']
        url    = tr['url']
        enabled = tr['is_enabled']
        tog_lbl = 'Disable' if enabled else 'Enable'
        tog_cls = '' if enabled else 'btn-green'
        status_badge = '<span class="badge badge-standard">ON</span>' if enabled else '<span class="badge badge-disabled">OFF</span>'
        tr_rows += f'''
      <tr>
        <td class="hash" style="word-break:break-all">{url}</td>
        <td style="text-align:center">{status_badge}</td>
        <td>
          <div class="actions">
            <form method="POST" action="/manage/admin/tracker-move" style="display:inline">
              <input type="hidden" name="tid" value="{tid}">
              <input type="hidden" name="direction" value="-1">
              <button class="btn btn-sm" title="Move up">&#8593;</button>
            </form>
            <form method="POST" action="/manage/admin/tracker-move" style="display:inline">
              <input type="hidden" name="tid" value="{tid}">
              <input type="hidden" name="direction" value="1">
              <button class="btn btn-sm" title="Move down">&#8595;</button>
            </form>
            <form method="POST" action="/manage/admin/tracker-toggle" style="display:inline">
              <input type="hidden" name="tid" value="{tid}">
              <button class="btn btn-sm {tog_cls}">{tog_lbl}</button>
            </form>
            <form method="POST" action="/manage/admin/tracker-delete" style="display:inline"
                  data-confirm="Remove this tracker?">
              <input type="hidden" name="tid" value="{tid}">
              <button class="btn btn-sm btn-danger">Delete</button>
            </form>
          </div>
        </td>
      </tr>'''
    if not tr_rows:
        tr_rows = '<tr><td colspan="3" class="empty">No trackers configured</td></tr>'

    # ── Settings HTML ─────────────────────────────────────────
    def _checked(k): return 'checked' if settings.get(k,'1') == '1' else ''
    tpp = settings.get('torrents_per_page', '50')
    robots_txt_val = settings.get('robots_txt', 'User-agent: *\nDisallow: /')
    ap_enabled = settings.get('auto_promote_enabled', '0') == '1'
    settings_html = f'''
    <div class="two-col">
      <div class="card">
        <div class="card-title">Password Complexity</div>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="complexity">
          <div class="form-group">
            <label>Minimum Length</label>
            <input type="number" name="pw_min_length" value="{settings.get('pw_min_length','12')}"
                   min="6" max="64" style="width:100px">
          </div>
          <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:16px">
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <input type="checkbox" name="pw_require_upper" value="1" {_checked('pw_require_upper')}> Require uppercase letter
            </label>
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <input type="checkbox" name="pw_require_lower" value="1" {_checked('pw_require_lower')}> Require lowercase letter
            </label>
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <input type="checkbox" name="pw_require_digit" value="1" {_checked('pw_require_digit')}> Require digit
            </label>
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <input type="checkbox" name="pw_require_symbol" value="1" {_checked('pw_require_symbol')}> Require symbol
            </label>
          </div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">Open Tracker</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          When enabled, the tracker accepts announces for <em>any</em> info hash — not just
          torrents registered in the database. User accounts and registration are still required
          to access the web interface.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="open_tracker">
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:16px">
            <input type="checkbox" name="open_tracker" value="1" {'checked' if settings.get('open_tracker','0')=='1' else ''}> Enable open tracker
          </label>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">Reward System</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Award 1 credit for every N torrents uploaded. Users can spend credits to generate
          invite links for new members.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="reward">
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:16px">
            <input type="checkbox" name="reward_enabled" value="1" {'checked' if settings.get('reward_enabled','0')=='1' else ''}> Enable reward system
          </label>
          <div class="form-group">
            <label>Torrent upload threshold per credit</label>
            <input type="number" name="reward_threshold" value="{settings.get('reward_threshold','200')}" min="1" max="99999" style="width:120px">
          </div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">Free Signup</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          When enabled, a Sign Up button appears on the public stats page and anyone can register an account.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="free_signup">
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:16px">
            <input type="checkbox" name="free_signup" value="1" {'checked' if settings.get('free_signup','0')=='1' else ''}> Enable free signup
          </label>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">Torrents Per Page</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Number of torrents shown per page on dashboards and profiles. Default: 50.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="torrents_per_page">
          <div class="form-group">
            <label>Torrents per page</label>
            <input type="number" name="torrents_per_page" value="{tpp}" min="5" max="500"
                   style="width:120px">
          </div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">Auto Promotion</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Automatically promote basic users to standard after reaching an upload threshold.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="auto_promote">
          <div style="display:flex;flex-direction:column;gap:12px;margin-bottom:16px">
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <input type="checkbox" name="auto_promote_enabled" value="1" {'checked' if ap_enabled else ''}> Enable auto-promotion
            </label>
            <div class="form-group" style="margin:0">
              <label>Upload threshold (torrents)</label>
              <input type="number" name="auto_promote_threshold" value="{settings.get('auto_promote_threshold','25')}"
                     min="1" max="9999" style="width:120px">
            </div>
          </div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
    </div>
    <div class="card">
      <div class="card-title">robots.txt</div>
      <p style="font-size:0.88rem;color:var(--muted);margin-bottom:12px">
        Controls how search engines and crawlers interact with your tracker.
        This is served at /robots.txt.
      </p>
      <form method="POST" action="/manage/admin/save-settings">
        <input type="hidden" name="form_id" value="robots_txt">
        <div class="form-group">
          <textarea name="robots_txt" rows="5" style="width:100%;font-family:var(--mono);font-size:0.82rem;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:10px;resize:vertical">{robots_txt_val}</textarea>
        </div>
        <button type="submit" class="btn btn-primary">Save</button>
      </form>
    </div>'''

    # ── Invites HTML ──────────────────────────────────────────
    all_codes = REGISTRATION_DB.list_invite_codes() if REGISTRATION_DB else []
    _inv_rows = ''
    for ic in all_codes:
        code_h = _h(ic['code'])
        by_h   = _h(ic['created_by_username'])
        at_h   = _h((ic['created_at'] or '')[:16])
        if ic['consumed_at']:
            _cu = ic["consumed_by_username"] or "?"
            _cu_link = f'<a href="/manage/user/{_h(_cu)}" class="user-link">{_h(_cu)}</a>'
            status = f'<span style="color:var(--muted)">Used by {_cu_link} {_h((ic["consumed_at"] or "")[:10])}</span>'
            actions = ''
        else:
            # Build the invite URL — use request Host header if possible
            invite_url = f'/manage/invite/{ic["code"]}'
            status = '<span style="color:var(--green)">Pending</span>'
            actions = (
                f'<button class="btn btn-sm btn-green" onclick="copyInvite(this,{repr(invite_url)})" title="Copy invite URL">&#128279; Copy URL</button>'
                + f'<form method="POST" action="/manage/admin/delete-invite" style="display:inline"'
                + f' data-confirm="Delete this invite code?">'
                + f'<input type="hidden" name="code" value="{code_h}">'
                + '<button class="btn btn-sm btn-danger">Delete</button></form>'
            )
        _inv_rows += (
            '<tr>'
            + f'<td class="hash" style="font-size:0.78rem;word-break:break-all">{code_h[:20]}...</td>'
            + f'<td><a href="/manage/user/{by_h}" class="user-link">{by_h}</a></td>'
            + f'<td class="hash">{at_h}</td>'
            + f'<td>{status}</td>'
            + f'<td><div class="actions">{actions}</div></td>'
            + '</tr>'
        )
    if not _inv_rows:
        _inv_rows = '<tr><td colspan="5" class="empty">No invite codes yet</td></tr>'
    invites_html = f'''
    <div class="card" style="margin-bottom:16px">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
        <div class="card-title" style="margin:0">Invite Codes ({len(all_codes)})</div>
        <form method="POST" action="/manage/admin/generate-invite">
          <button class="btn btn-primary">&#43; Generate Invite Code</button>
        </form>
      </div>
    </div>
    <div class="card">
      <table>
        <tr>
          <th>Code</th><th>Created By</th><th>Created At</th><th>Status</th><th>Actions</th>
        </tr>
        {_inv_rows}
      </table>
    </div>'''

    # ── Auto-promote + Danger HTML ───────────────────────────
    danger_html = f'''
    <div class="two-col">
      <div class="card" style="border-color:rgba(224,91,48,0.3)">
        <div class="card-title" style="color:var(--accent2)">Delete All Users</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Permanently deletes every user account except the super-user. All sessions are
          invalidated. This cannot be undone.
        </p>
        <form method="POST" action="/manage/admin/delete-all-users"
              data-confirm="Delete ALL users except super? This CANNOT be undone.">
          <button class="btn btn-danger">Delete All Users</button>
        </form>
      </div>
      <div class="card" style="border-color:rgba(224,91,48,0.3)">
        <div class="card-title" style="color:var(--accent2)">Delete All Torrents</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Permanently removes every registered torrent from the tracker. This cannot be undone.
        </p>
        <form method="POST" action="/manage/admin/delete-all-torrents"
              data-confirm="Delete ALL registered torrents from the tracker? This CANNOT be undone.">
          <button class="btn btn-danger">Delete All Torrents</button>
        </form>
      </div>
    </div>'''



    # ── Torrent table ──────────────────────────────────────────
    admin_role = _user_role(user)
    t_rows = ''.join(
        _torrent_row(t, admin_role, user['id'], show_owner=True, show_delete=True)
        for t in all_torrents
    )
    if not t_rows:
        t_rows = '<tr><td colspan="6" class="empty">No torrents registered</td></tr>'

    # ── User table ─────────────────────────────────────────────
    u_rows = ''
    for u in all_users:
        uname    = u['username']
        uname_h  = _h(uname)          # HTML-safe for output
        u_is_super = (uname == SUPER_USER)
        u_role   = _user_role(u)
        u_is_admin = u['is_admin']
        badges   = ''
        if u_is_super:
            badges += '<span class="badge badge-super">SUPER</span> '
        elif u_is_admin:
            badges += '<span class="badge badge-admin">ADMIN</span> '
        elif u_role == 'standard':
            badges += '<span class="badge badge-standard">STANDARD</span> '
        else:
            badges += '<span class="badge badge-basic">BASIC</span> '
        if u['is_locked']:
            badges += '<span class="badge badge-locked">LOCKED</span> '
        if u['is_disabled']:
            badges += '<span class="badge badge-disabled">DISABLED</span> '

        actions = ''
        # Change password -- anyone except superuser passwd (only super can do that via CLI)
        if not u_is_super:
            actions += f'''
            <form method="POST" action="/manage/admin/change-password" style="display:inline">
              <input type="hidden" name="username" value="{uname_h}">
              <input type="text" name="new_password" placeholder="new password"
                     style="width:120px;padding:3px 8px;margin-right:4px;background:var(--card2);
                            border:1px solid var(--border);border-radius:4px;color:var(--text);
                            font-family:var(--mono);font-size:0.72rem" required>
              <button class="btn btn-sm">Set Passwd</button>
            </form>'''

        # Unlock -- admins and super
        if u['is_locked']:
            actions += f'''
            <form method="POST" action="/manage/admin/unlock" style="display:inline">
              <input type="hidden" name="username" value="{uname_h}">
              <button class="btn btn-sm btn-green">Unlock</button>
            </form>'''

        # Disable/enable -- cannot disable super
        if not u_is_super:
            dis_label = 'Enable' if u['is_disabled'] else 'Disable'
            dis_action = 'enable' if u['is_disabled'] else 'disable'
            actions += f'''
            <form method="POST" action="/manage/admin/{dis_action}-user" style="display:inline"
                  data-confirm="{dis_label} {uname_h}?">
              <input type="hidden" name="username" value="{uname_h}">
              <button class="btn btn-sm {"btn-green" if u["is_disabled"] else ""}">{dis_label}</button>
            </form>'''

        # Promote/demote -- super only, cannot touch other admins or super
        if is_super and not u_is_super:
            if u_is_admin:
                actions += f'''
                <form method="POST" action="/manage/admin/set-admin" style="display:inline"
                      data-confirm="Remove admin from {uname_h}?">
                  <input type="hidden" name="username" value="{uname_h}">
                  <input type="hidden" name="is_admin" value="0">
                  <button class="btn btn-sm">&#8595; To Standard</button>
                </form>'''
            else:
                actions += f'''
                <form method="POST" action="/manage/admin/set-admin" style="display:inline"
                      data-confirm="Promote {uname_h} to admin?">
                  <input type="hidden" name="username" value="{uname_h}">
                  <input type="hidden" name="is_admin" value="1">
                  <button class="btn btn-sm btn-green">&#8593; Admin</button>
                </form>'''

        # Delete -- admin can delete standard users; super can delete admins and users
        # Promote/demote standard -- super and admins can do this for non-admin users
        if not u_is_super and not u_is_admin and (is_super or user['is_admin']):
            if u_role == 'standard':
                actions += f'''
                <form method="POST" action="/manage/admin/set-standard" style="display:inline"
                      data-confirm="Demote {uname_h} to basic?">
                  <input type="hidden" name="username" value="{uname_h}">
                  <input type="hidden" name="is_standard" value="0">
                  <button class="btn btn-sm">&#8595; Demote</button>
                </form>'''
            else:
                actions += f'''
                <form method="POST" action="/manage/admin/set-standard" style="display:inline"
                      data-confirm="Promote {uname_h} to standard?">
                  <input type="hidden" name="username" value="{uname_h}">
                  <input type="hidden" name="is_standard" value="1">
                  <button class="btn btn-sm btn-green">&#8593; Standard</button>
                </form>'''

        can_delete = (not u_is_super and
                      (is_super or (not u_is_admin)))
        if can_delete:
            actions += f'''
            <form method="POST" action="/manage/admin/delete-user" style="display:inline"
                  data-confirm="Delete user {uname_h}? This cannot be undone.">
              <input type="hidden" name="username" value="{uname_h}">
              <button class="btn btn-sm btn-danger">Delete</button>
            </form>'''

        u_rows += f'''
      <tr>
        <td><a href="/manage/admin/user/{uname_h}" class="user-link">{uname_h}</a></td>
        <td>{badges}</td>
        <td class="hash">{u["created_by"] or "--"}</td>
        <td class="hash">{(u["last_login"] or "Never")[:16]}</td>
        <td><div class="actions">{actions}</div></td>
      </tr>'''

    if not u_rows:
        u_rows = '<tr><td colspan="5" class="empty">No users</td></tr>'

    # ── Event log ──────────────────────────────────────────────
    ev_rows = ''
    for e in events:
        ev_rows += f'<tr><td class="hash">{e["timestamp"][:16]}</td><td>{_h(e["actor"])}</td><td>{_h(e["action"])}</td><td>{_h(e["target"])}</td><td class="hash">{_h(e["detail"])}</td></tr>'
    if not ev_rows:
        ev_rows = '<tr><td colspan="5" class="empty">No events yet</td></tr>'

    _tab_settings = ('<button class="tab" onclick="showTab(\'settings\',this)">Settings</button>'
                     if is_super else '')
    _tab_invites  = ('<button class="tab" onclick="showTab(\'invites\',this)">Invites</button>'
                     if (is_super or user['is_admin']) else '')
    _tab_danger   = ('<button class="tab tab-danger" onclick="showTab(\'danger\',this)"'
                     '>Danger</button>'
                     if is_super else '')
    _autotab_js   = ('<script>window.addEventListener("DOMContentLoaded",function(){'
                     'var b=document.querySelector(".tab:nth-child(2)");'
                     'if(b){b.click();}})</script>'
                     if (uquery or upage > 1) else '')

    body = f'''
  <div class="page-title">Admin Panel</div>
  <div class="page-sub">Manage torrents and users &nbsp;·&nbsp; <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none;font-size:0.85rem">← Dashboard</a></div>
  {_autotab_js}
  <div class="tabs">
    <button class="tab active" onclick="showTab('torrents',this)">Torrents</button>
    <button class="tab" onclick="showTab('users',this)">Users</button>
    <button class="tab" onclick="showTab('adduser',this)">Add User</button>
    <button class="tab" onclick="showTab('trackers',this)">Trackers</button>
    {_tab_settings}
    {_tab_invites}
    {_tab_danger}
    <button class="tab" onclick="showTab('events',this)">Event Log</button>
  </div>

  <div class="panel visible" id="panel-torrents">
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:12px">
        <div class="card-title" style="margin:0">All Registered Torrents ({total})</div>
        <input type="text" placeholder="Filter this page..." oninput="filterTorrents(this,'admin-torrent-table')"
         style="padding:6px 12px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem;width:240px">
      </div>
      <div class="table-wrap"><table id="admin-torrent-table" class="torrent-table">
        {_torrent_header(show_owner=True)}
        {t_rows}
      </table></div>
      {_pagination_html(page, total_pages, "/manage/admin")}
    </div>
  </div>

  <div class="panel" id="panel-users">
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:12px">
        <div class="card-title" style="margin:0">Users ({utotal}{"" if not uquery else f" · search: {uquery}"})</div>
        <form method="GET" action="/manage/admin" style="display:flex;gap:8px;align-items:center">
          <input type="text" name="uq" value="{uquery}"
                 placeholder="Search users..."
                 style="padding:6px 12px;background:var(--card2);border:1px solid var(--border);
                        border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem;width:200px">
          <button type="submit" class="btn btn-sm">Search</button>
          {"" if not uquery else '<a href="/manage/admin" class="btn btn-sm">Clear</a>'}
        </form>
      </div>
      <div class="table-wrap"><table>
        <tr><th>Username</th><th>Role / Status</th><th>Created By</th><th>Last Login</th><th>Actions</th></tr>
        {u_rows}
      </table></div>
      {_pagination_html(upage, utotal_pages, '/manage/admin' + (f'?uq={uquery}' if uquery else ''), page_param='upage')}
    </div>
  </div>

  <div class="panel" id="panel-adduser">
    <div class="card" style="max-width:440px">
      <div class="card-title">Add New User</div>
      <form method="POST" action="/manage/admin/add-user">
        <div class="form-group">
          <label>Username</label>
          <input type="text" name="username" required>
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" required>
        </div>
        {"" if not is_super else """
        <div class="form-group">
          <label>Role</label>
          <select name="role" style="width:100%;padding:10px 14px;background:var(--card2);
                  border:1px solid var(--border);border-radius:6px;color:var(--text);
                  font-family:var(--mono);font-size:0.88rem">
            <option value="basic">Basic</option>
            <option value="standard">Standard</option>
            <option value="admin">Admin</option>
          </select>
        </div>"""}
        <button type="submit" class="btn btn-primary">Create User</button>
      </form>
    </div>
  </div>

  <div class="panel" id="panel-trackers">
    <div class="card">
      <div class="card-title">Magnet Link Trackers</div>
      <div class="table-wrap"><table>
        <tr><th>URL</th><th style="text-align:center">Status</th><th>Actions</th></tr>
        {tr_rows}
      </table></div>
    </div>
    <div class="card" style="max-width:600px">
      <div class="card-title">Add Tracker</div>
      <form method="POST" action="/manage/admin/tracker-add" style="display:flex;gap:12px;align-items:flex-end">
        <div class="form-group" style="flex:1;margin:0">
          <label>Tracker URL</label>
          <input type="text" name="url" placeholder="udp://tracker.example.com:6969/announce" required>
        </div>
        <button type="submit" class="btn btn-primary" style="margin-bottom:1px">Add</button>
      </form>
    </div>
  </div>

  {'<div class="panel" id="panel-settings">' + settings_html + '</div>' if is_super else ''}
  {'<div class="panel" id="panel-invites">' + invites_html + '</div>' if (is_super or user['is_admin']) else ''}
  {'<div class="panel" id="panel-danger">' + danger_html + '</div>' if is_super else ''}

  <div class="panel" id="panel-events">
    <div class="card">
      <div class="card-title">Recent Events (last 100)</div>
      <div class="table-wrap"><table>
        <tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr>
        {ev_rows}
      </table></div>
    </div>
  </div>'''
    return _manage_page('Admin Panel', body, user=user, msg=msg, msg_type=msg_type)


def _render_torrent_detail(viewer, t, back_url: str = '/manage/dashboard') -> str:
    """Full detail page for a single torrent."""
    is_super  = viewer['username'] == SUPER_USER
    vrole     = _user_role(viewer)
    is_owner  = t['uploaded_by_id'] == viewer['id']
    can_del   = is_super or vrole == 'admin' or is_owner
    ih        = t['info_hash']
    magnet    = REGISTRATION_DB.build_magnet(ih, t['name'],
                    t['total_size'] if 'total_size' in t.keys() else 0)

    # Parse files JSON
    try:
        files = json.loads(t['files_json']) if 'files_json' in t.keys() else []
    except Exception:
        files = []

    # File list table
    if files:
        file_rows = ''
        for f in files:
            fsize = '{:,}'.format(f.get('size', 0))
            fpath = f.get('path', '?').replace('<', '&lt;')
            file_rows += f'<tr><td style="word-break:break-all">{fpath}</td><td class="hash" style="text-align:right;white-space:nowrap">{fsize} B</td></tr>'
        files_html = (
            '<div class="card-title">Files (' + str(len(files)) + ')</div>'
            '<div class="table-wrap"><table>'
            '<tr><th>Path</th><th style="text-align:right">Size</th></tr>'
            + file_rows + '</table></div>'
        )
    else:
        files_html = '<div class="card-title">Files</div><p style="color:var(--muted)">No file list stored — re-upload torrent to populate.</p>'

    # Piece length human display
    pl = t['piece_length'] if 'piece_length' in t.keys() else 0
    pl_str = _fmt_size(pl) if pl else '--'
    pc = t['piece_count'] if 'piece_count' in t.keys() else 0
    priv = 'Yes' if (t['is_private'] if 'is_private' in t.keys() else 0) else 'No'
    mf   = 'Multi-file' if (t['is_multifile'] if 'is_multifile' in t.keys() else 0) else 'Single-file'

    # Delete button
    del_btn = ''
    if can_del:
        tname = t['name']
        del_btn = (f'<form method="POST" action="/manage/delete-torrent" style="display:inline"'
                   f' data-confirm="Permanently delete {tname}?">'
                   f'<input type="hidden" name="info_hash" value="{ih}">'
                   f'<input type="hidden" name="redirect" value="{back_url}">'
                   f'<button class="btn btn-danger">Delete</button></form>')

    body = f'''
  <div class="page-title">{t["name"]}</div>
  <div class="page-sub">
    <a href="{back_url}" style="color:var(--muted);text-decoration:none">&#8592; Back</a>
    &nbsp;&#183;&nbsp;
    <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#8592; Dashboard</a>
  </div>

  <div class="two-col" style="margin-bottom:0">
    <div class="card">
      <div class="card-title">Torrent Info</div>
      <table style="min-width:unset">
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;width:40%">NAME</td>
            <td style="word-break:break-all">{t["name"]}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em">INFO HASH</td>
            <td class="hash" style="word-break:break-all;font-size:0.82rem">{ih}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em">TYPE</td>
            <td>{mf}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em">TOTAL SIZE</td>
            <td>{_fmt_size(t["total_size"] if "total_size" in t.keys() else 0)}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em">PIECE SIZE</td>
            <td>{pl_str}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em">PIECE COUNT</td>
            <td>{pc:,}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em">PRIVATE</td>
            <td>{priv}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em">REGISTERED BY</td>
            <td><a href="/manage/user/{t["uploaded_by_username"]}" class="user-link">{t["uploaded_by_username"]}</a></td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em">REGISTERED AT</td>
            <td class="hash">{t["registered_at"][:16].replace("T", " ")}</td></tr>
      </table>
    </div>
    <div class="card">
      <div class="card-title">Actions</div>
      <div style="display:flex;flex-direction:column;gap:12px;align-items:flex-start">
        <button class="btn btn-primary" onclick="copyMagnet(this,{repr(magnet)})">&#x1F9F2; Copy Magnet Link</button>
        {del_btn}
      </div>
    </div>
  </div>

  <div class="card">
    {files_html}
  </div>'''

    return _manage_page(t['name'], body, user=viewer)


def _render_public_profile(viewer, target_user, torrents: list,
                            page: int = 1, total_pages: int = 1, total: int = 0) -> str:
    """Public-facing user profile — shows role, join date, torrent count. No sensitive fields."""
    uname     = target_user['username']
    uname_h   = _h(uname)
    vrole     = _user_role(viewer)
    trole     = _user_role(target_user)
    is_super  = viewer['username'] == SUPER_USER
    is_own    = viewer['id'] == target_user['id']

    # If viewer is admin/super, link back to admin view
    admin_link = ''
    if vrole in ('super', 'admin'):
        admin_link = (f' &nbsp;&#183;&nbsp; <a href="/manage/admin/user/{uname_h}" '
                      f'style="color:var(--muted);text-decoration:none">&#9881; Admin View</a>')

    role_badge = f'<span class="badge badge-{trole}">{trole.upper()}</span>'

    # Safe public fields only
    joined    = (target_user['created_at'] or '')[:10] or '--'
    t_rows    = ''.join(
        _torrent_row(t, vrole, viewer['id'], show_owner=False,
                     show_delete=(is_own or vrole in ('super', 'admin')))
        for t in torrents
    )
    if not t_rows:
        t_rows = '<tr><td colspan="5" class="empty">No torrents registered</td></tr>'

    base_url = f'/manage/user/{uname}'

    body = f'''
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;flex-wrap:wrap">
    <div class="page-title">{uname_h}</div>
    {role_badge}
  </div>
  <div class="page-sub" style="margin-bottom:20px">
    Public profile
    &nbsp;&#183;&nbsp; <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#8592; Dashboard</a>
    {admin_link}
  </div>

  <div class="card" style="max-width:400px">
    <div class="card-title">Account</div>
    <table style="min-width:unset">
      <tr>
        <td style="font-family:var(--mono);font-size:0.72rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);padding:10px 24px 10px 0;white-space:nowrap">Member Since</td>
        <td style="padding:10px 0">{joined}</td>
      </tr>
      <tr>
        <td style="font-family:var(--mono);font-size:0.72rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);padding:10px 24px 10px 0;white-space:nowrap">Torrents</td>
        <td style="padding:10px 0">{total}</td>
      </tr>
    </table>
  </div>

  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:12px">
      <div class="card-title" style="margin:0">Registered Torrents ({total})</div>
      <input type="text" placeholder="Filter this page..."
             oninput="filterTorrents(this,'pub-torrent-table')"
             style="padding:6px 12px;background:var(--card2);border:1px solid var(--border);
                    border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem;width:240px">
    </div>
    <div class="table-wrap"><table id="pub-torrent-table" class="torrent-table">
      {_torrent_header(show_owner=False)}
      {t_rows}
    </table></div>
    {_pagination_html(page, total_pages, base_url)}
  </div>'''

    return _manage_page(uname_h, body, user=viewer)


def _render_user_detail(viewer, target_user, torrents, login_history, is_super,
                        allowlist=None, is_own_profile=False,
                        page: int = 1, total_pages: int = 1, total: int = 0, base_url: str = ''):
    uname   = target_user['username']
    uname_h = _h(uname)          # HTML-safe for output
    t_role = _user_role(target_user)
    role_badge = {
        'super':    '<span class="badge badge-super">SUPERUSER</span>',
        'admin':    '<span class="badge badge-admin">ADMIN</span>',
        'standard': '<span class="badge badge-standard">STANDARD</span>',
        'basic':    '<span class="badge badge-basic">BASIC</span>',
    }[t_role]

    status_badges = ''
    if target_user['is_locked']:
        status_badges += ' <span class="badge badge-locked">LOCKED</span>'
    if target_user['is_disabled']:
        status_badges += ' <span class="badge badge-disabled">DISABLED</span>'

    lpc = target_user['last_password_change'] if 'last_password_change' in target_user.keys() else None
    lc  = target_user['login_count']          if 'login_count'          in target_user.keys() else 0

    def row(label, value):
        return (
            '<tr>'
            '<td style="font-family:var(--mono);font-size:0.72rem;letter-spacing:0.1em;'
            'text-transform:uppercase;color:var(--muted);padding:10px 24px 10px 0;'
            'white-space:nowrap;vertical-align:top">' + label + '</td>'
            '<td style="padding:10px 0;vertical-align:top">' + str(value) + '</td>'
            '</tr>'
        )

    credits_val = target_user['credits'] if 'credits' in target_user.keys() else 0
    raw_cb = target_user['created_by'] or '--'
    if raw_cb.startswith('invite:'):
        inviter = _h(raw_cb[7:])
        created_by_display = f'Invited by <strong>{inviter}</strong>'
    else:
        created_by_display = _h(raw_cb)
    info_rows = (
        row('Created',          (target_user['created_at'] or '')[:16] or '--')
        + row('Created By',     created_by_display)
        + row('Last Login',     (target_user['last_login'] or 'Never')[:16])
        + row('Login Count',    str(lc))
        + row('Password Changed', lpc[:16] if lpc else 'Never recorded')
        + row('Failed Attempts', str(target_user['failed_attempts']))
        + row('Credits',        f'<span style="color:var(--accent);font-weight:bold">{credits_val}</span>')
    )

    # ── IP section (superuser only) ───────────────────────────
    ip_html = ''
    if is_super:
        ip_rows = ''
        if login_history:
            for h in login_history:
                ip_h = _h(h['ip_address'])
                ip_rows += (
                    '<tr>'
                    + '<td style="padding:6px 8px"><input type="checkbox" name="ip_check" value="'
                    + ip_h + '"></td>'
                    + '<td class="hash" style="padding:6px 8px">' + h['logged_in_at'][:16] + '</td>'
                    + '<td class="hash" style="word-break:break-all;padding:6px 8px;font-size:0.78rem">' + ip_h + '</td>'
                    + '</tr>'
                )
        else:
            ip_rows = '<tr><td colspan="3" class="empty">No login history yet</td></tr>'

        allowlist = allowlist or (REGISTRATION_DB.get_ip_allowlist(target_user['id']) if REGISTRATION_DB else [])
        al_rows = ''
        for entry in allowlist:
            al_rows += (
                '<tr>'
                + '<td class="hash" style="word-break:break-all;padding:6px 8px;font-size:0.78rem">' + _h(entry['ip_address']) + '</td>'
                + '<td class="hash" style="padding:6px 8px">' + entry['added_at'][:16] + '</td>'
                + '<td style="padding:6px 8px; white-space:nowrap;">'
                + '<form method="POST" action="/manage/admin/ip-lock-remove" style="display:inline">'
                + '<input type="hidden" name="entry_id" value="' + str(entry['id']) + '">'
                + '<input type="hidden" name="target_username" value="' + uname_h + '">'
                + '<button class="btn btn-sm btn-danger">Remove</button>'
                + '</form></td></tr>'
            )
        if not al_rows:
            al_rows = '<tr><td colspan="3" class="empty">No restrictions -- any IP allowed</td></tr>'

        ip_lock_js = (
            '<script>function doIpLock(){'
            + 'var cbs=document.querySelectorAll(\'input[name="ip_check"]:checked\');'
            + 'if(!cbs.length){alert("Select at least one IP.");return;}'
            + 'var ips=Array.from(cbs).map(function(c){return c.value;}).join(",");'
            + 'var f=document.getElementById("ip-lock-form");'
            + 'var h=document.createElement("input");h.type="hidden";h.name="selected_ips";h.value=ips;'
            + 'f.appendChild(h);f.submit();}'
            + '</script>'
        )

        clear_btn = ''
        if allowlist:
            clear_btn = (
                '<form method="POST" action="/manage/admin/ip-lock-clear" style="margin-top:12px"'
                + ' data-confirm="Remove ALL IP restrictions for ' + uname_h + '?">'
                + '<input type="hidden" name="user_id" value="' + str(target_user['id']) + '">'
                + '<input type="hidden" name="target_username" value="' + uname_h + '">'
                + '<button type="submit" class="btn btn-sm btn-danger">Clear All</button></form>'
            )

        ip_html = (
            '<div style="display:flex;flex-direction:column;gap:16px;margin-bottom:16px">'
            + '<div class="card" style="overflow:hidden">'
            + '<div class="card-title">Recent Login IPs</div>'
            + '<form id="ip-lock-form" method="POST" action="/manage/admin/ip-lock">'
            + '<input type="hidden" name="user_id" value="' + str(target_user['id']) + '">'
            + '<div style="overflow-x:auto"><table style="table-layout:fixed;width:100%;border-collapse:collapse">'
            + '<tr><th style="width:28px;padding:6px 8px"></th>'
            + '<th style="width:36%;padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">TIME</th>'
            + '<th style="padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">IP ADDRESS</th></tr>'
            + ip_rows
            + '</table></div>'
            + '<div style="margin-top:12px">'
            + '<button type="button" class="btn btn-sm btn-primary" onclick="doIpLock()">&#128274; IP Lock Selected</button>'
            + '</div></form></div>'
            + '<div class="card" style="overflow:hidden">'
            + '<div class="card-title">IP Allowlist</div>'
            + '<div style="overflow-x:auto"><table style="table-layout:fixed;width:100%;border-collapse:collapse">'
            + '<tr>'
            + '<th style="padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">IP ADDRESS</th>'
            + '<th style="width:50%;padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">ADDED</th>'
            + '<th style="width:120px;padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">ACTION</th>'
            + '</tr>'
            + al_rows
            + '</table></div>'
            + '<div style="overflow:hidden">'
            + clear_btn
            + '</div>'
            + '</div>'
            + '</div>'
            + ip_lock_js
        )

    # ── Delete all torrents card ──────────────────────────────
    viewer_role   = _user_role(viewer)
    can_delete_all = (viewer_role == 'super' or viewer['id'] == target_user['id'])
    delete_all_html = ''
    if can_delete_all and total > 0:
        referer = '/manage/profile' if is_own_profile else '/manage/admin/user/' + uname_h
        delete_all_html = (
            '<div class="card" style="border-color:rgba(224,91,48,0.3);margin-bottom:16px">'
            + '<div class="card-title" style="color:var(--accent2)">Danger Zone</div>'
            + '<p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">Permanently delete all '
            + str(total) + ' torrents registered by ' + uname_h + '. This cannot be undone.</p>'
            + '<form method="POST" action="/manage/delete-all-torrents-user"'
            + ' data-confirm="Delete ALL ' + str(total) + ' torrents for ' + uname_h + '? This cannot be undone.">'
            + '<input type="hidden" name="username" value="' + uname_h + '">'
            + '<input type="hidden" name="referer" value="' + referer + '">'
            + '<button class="btn btn-danger">Delete All Torrents</button>'
            + '</form></div>'
        )

    # ── Torrent list with search ──────────────────────────────
    detail_role = _user_role(viewer)
    t_rows = ''.join(
        _torrent_row(t, detail_role, viewer['id'], show_owner=False,
                     show_delete=(is_own_profile or detail_role in ('super', 'admin')))
        for t in torrents
    )
    if not t_rows:
        t_rows = '<tr><td colspan="5" class="empty">No torrents registered</td></tr>'

    torrent_html = (
        '<div class="card">'
        + '<div style="display:flex;align-items:center;justify-content:space-between;'
        + 'flex-wrap:wrap;gap:12px;margin-bottom:16px">'
        + '<div class="card-title" style="margin:0">Registered Torrents (' + str(total or len(torrents)) + ')</div>'
        + '<input type="text" placeholder="Filter torrents..."'
        + ' oninput="filterTorrents(this,\'detail-torrent-table\')"'
        + ' style="padding:6px 12px;background:var(--card2);border:1px solid var(--border);'
        + 'border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem;width:240px">'
        + '</div>'
        + '<div class="table-wrap"><table id="detail-torrent-table" class="torrent-table">'
        + _torrent_header(show_owner=False)
        + t_rows
        + '</table></div>'
        + _pagination_html(page, total_pages, base_url or '/manage/profile')
        + '</div>'
    )

    # ── Nav ───────────────────────────────────────────────────
    nav_links = ' &nbsp;&#183;&nbsp; <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#8592; Dashboard</a>'
    if not is_own_profile:
        nav_links = (
            ' &nbsp;&#183;&nbsp; <a href="/manage/admin" style="color:var(--muted);text-decoration:none">'
            + '&#8592; Admin Panel</a>'
            + nav_links
        )

    # ── Actions card (admin/super only, not own profile) ────
    actions_card = ''
    viewer_role = _user_role(viewer)
    t_is_super  = (uname == SUPER_USER)
    t_is_admin  = target_user['is_admin']
    if not is_own_profile and viewer_role in ('super', 'admin'):
        hi = '<input type="hidden" name="username" value="' + uname_h + '">'
        pw_form = ''
        if not t_is_super:
            pw_form = (
                '<form method="POST" action="/manage/admin/change-password" style="display:flex;gap:8px;flex-wrap:wrap">'
                + hi
                + '<input type="password" name="new_password" placeholder="new password" style="flex:1;min-width:140px;padding:8px 12px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem" required>'
                + '<button class="btn btn-sm">Set Password</button></form>'
            )
        unlock_btn = ''
        if target_user['is_locked']:
            unlock_btn = (
                '<form method="POST" action="/manage/admin/unlock" style="display:inline">'
                + hi + '<button class="btn btn-sm btn-green">Unlock Account</button></form>'
            )
        dis_btn = ''
        if not t_is_super:
            dis_label  = 'Enable' if target_user['is_disabled'] else 'Disable'
            dis_action = 'enable' if target_user['is_disabled'] else 'disable'
            dis_cls    = 'btn-green' if target_user['is_disabled'] else ''
            dis_btn = (
                f'<form method="POST" action="/manage/admin/{dis_action}-user" style="display:inline" data-confirm="{dis_label} {uname_h}?">'
                + hi + f'<button class="btn btn-sm {dis_cls}">{dis_label}</button></form>'
            )
        role_btns = ''
        if is_super and not t_is_super:
            if t_is_admin:
                role_btns += (
                    f'<form method="POST" action="/manage/admin/set-admin" style="display:inline" data-confirm="Remove admin from {uname_h}?">'
                    + hi + '<input type="hidden" name="is_admin" value="0">'
                    + '<button class="btn btn-sm">&#8595; Demote to Standard</button></form>'
                )
            else:
                role_btns += (
                    f'<form method="POST" action="/manage/admin/set-admin" style="display:inline" data-confirm="Promote {uname_h} to admin?">'
                    + hi + '<input type="hidden" name="is_admin" value="1">'
                    + '<button class="btn btn-sm btn-green">&#8593; Promote to Admin</button></form>'
                )
        if not t_is_super and not t_is_admin and viewer_role in ('super', 'admin'):
            t_std = (_user_role(target_user) == 'standard')
            if t_std:
                role_btns += (
                    f'<form method="POST" action="/manage/admin/set-standard" style="display:inline" data-confirm="Demote {uname_h} to basic?">'
                    + hi + '<input type="hidden" name="is_standard" value="0">'
                    + '<button class="btn btn-sm">&#8595; Demote to Basic</button></form>'
                )
            else:
                role_btns += (
                    f'<form method="POST" action="/manage/admin/set-standard" style="display:inline" data-confirm="Promote {uname_h} to standard?">'
                    + hi + '<input type="hidden" name="is_standard" value="1">'
                    + '<button class="btn btn-sm btn-green">&#8593; Promote to Standard</button></form>'
                )
        del_btn = ''
        if not t_is_super and (is_super or not t_is_admin):
            del_btn = (
                f'<form method="POST" action="/manage/admin/delete-user" style="display:inline" data-confirm="Delete {uname_h}? This cannot be undone.">'
                + hi + '<button class="btn btn-sm btn-danger">Delete User</button></form>'
            )
        hi_referer = '/manage/profile' if is_own_profile else '/manage/admin/user/' + uname_h
        credit_btns = (
            f'<form method="POST" action="/manage/admin/adjust-credits" style="display:inline">'
            + f'<input type="hidden" name="username" value="{uname_h}">'
            + f'<input type="hidden" name="delta" value="1">'
            + f'<input type="hidden" name="referer" value="{hi_referer}">'
            + '<button class="btn btn-sm btn-green">&#43; Credit</button></form>'
            + f'<form method="POST" action="/manage/admin/adjust-credits" style="display:inline">'
            + f'<input type="hidden" name="username" value="{uname_h}">'
            + f'<input type="hidden" name="delta" value="-1">'
            + f'<input type="hidden" name="referer" value="{hi_referer}">'
            + '<button class="btn btn-sm">&#8722; Credit</button></form>'
        )
        actions_card = (
            '<div class="card"><div class="card-title">Actions</div>'
            + '<div style="display:flex;flex-direction:column;gap:14px">'
            + (('<div>' + pw_form + '</div>') if pw_form else '')
            + (('<div style="display:flex;flex-wrap:wrap;gap:8px">' + unlock_btn + dis_btn + role_btns + del_btn + '</div>') if any([unlock_btn, dis_btn, role_btns, del_btn]) else '')
            + '<div style="display:flex;flex-wrap:wrap;gap:8px">'
            + credit_btns
            + '</div>'
            + '</div></div>'
        )

    body = (
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;flex-wrap:wrap">'
        + '<div class="page-title">' + uname_h + '</div>'
        + role_badge + status_badges
        + '</div>'
        + '<div class="page-sub" style="margin-bottom:20px">'
        + ('Your profile' if is_own_profile else 'User profile')
        + nav_links + '</div>'
        + '<div class="two-col">'
        + '<div class="card"><div class="card-title">Account Details</div>'
        + '<table style="min-width:unset">' + info_rows + '</table></div>'
        + actions_card
        + '</div>'
        + _render_invite_section(viewer, target_user, is_own_profile, REGISTRATION_DB)
        + ip_html
        + delete_all_html
        + torrent_html
    )
    return _manage_page(('My Profile' if is_own_profile else 'User: ' + uname_h), body, user=viewer)


def _render_invite_section(viewer, target_user, is_own_profile: bool, db) -> str:
    """Render the invite codes card for profile/user-detail pages."""
    if db is None:
        return ''
    uname = target_user['username']
    viewer_role = _user_role(viewer)
    is_admin_view = viewer_role in ('admin', 'super') and not is_own_profile
    # Only show to the user themselves or an admin
    if not is_own_profile and not is_admin_view:
        return ''

    codes = db.list_invite_codes(created_by_username=uname)
    pending = [c for c in codes if not c['consumed_at']]
    consumed = [c for c in codes if c['consumed_at']]

    credits_val = target_user['credits'] if 'credits' in target_user.keys() else 0

    # Generate button (own profile only, needs credit; admin section has its own flow)
    gen_btn = ''
    if is_own_profile and credits_val > 0:
        gen_btn = (
            '<form method="POST" action="/manage/profile/generate-invite" style="display:inline">'
            + '<button class="btn btn-primary">&#127881; Generate Invite Link'
            + f' ({credits_val} credit{"s" if credits_val != 1 else ""} remaining)</button></form>'
        )
    elif is_own_profile and credits_val == 0:
        gen_btn = (
            '<form method="POST" action="/manage/profile/generate-invite" style="display:inline"'
            + ' data-confirm="You have no credits. Earn credits by uploading torrents.">'
            + '<button class="btn" style="opacity:0.5;cursor:not-allowed" disabled>'
            + '&#127881; Generate Invite Link (0 credits remaining)</button></form>'
        )

    rows = ''
    for c in pending:
        invite_path = f'/manage/invite/{c["code"]}'
        code_h = _h(c['code'])
        rows += (
            '<tr>'
            + f'<td class="hash" style="font-size:0.78rem">{code_h[:20]}...</td>'
            + f'<td class="hash">{_h((c["created_at"] or "")[:10])}</td>'
            + '<td><span style="color:var(--green)">Pending</span></td>'
            + f'<td><div class="actions">'
            + f'<button class="btn btn-sm btn-green" onclick="copyInvite(this,{repr(invite_path)})" title="Copy invite URL">&#128279; Copy URL</button>'
            + '</div></td>'
            + '</tr>'
        )
    for c in consumed:
        rows += (
            '<tr>'
            + f'<td class="hash" style="font-size:0.78rem">{_h(c["code"][:20])}...</td>'
            + f'<td class="hash">{_h((c["created_at"] or "")[:10])}</td>'
            + (lambda cu: f'<td style="color:var(--muted)">Used by <a href="/manage/user/{_h(cu)}" class="user-link">{_h(cu)}</a></td>')(c["consumed_by_username"] or "?")
            + '<td></td>'
            + '</tr>'
        )
    if not rows:
        rows = '<tr><td colspan="4" class="empty">No invite codes</td></tr>'

    return (
        '<div class="card">'
        + '<div style="display:flex;align-items:center;justify-content:space-between;'
        + 'flex-wrap:wrap;gap:12px;margin-bottom:16px">'
        + '<div class="card-title" style="margin:0">Invite Codes</div>'
        + gen_btn
        + '</div>'
        + '<table><tr><th>Code</th><th>Created</th><th>Status</th><th>Actions</th></tr>'
        + rows
        + '</table></div>'
    )


def _render_password_page(user, msg: str = '', msg_type: str = 'error') -> str:
    pw_settings = REGISTRATION_DB.get_all_settings() if REGISTRATION_DB else {}
    pw_req_html = _pw_requirements_html(pw_settings)
    body = f'''
  <div style="max-width:420px;margin:0 auto">
    <div class="page-title">Change Password</div>
    <div class="page-sub">Update your account password</div>
    <div class="card">
      <form method="POST" action="/manage/password">
        <div class="form-group">
          <label>Current Password</label>
          <input type="password" name="current_password" required>
        </div>
        {pw_req_html}
        <div class="form-group">
          <label>New Password</label>
          <input type="password" name="new_password" required>
        </div>
        <div class="form-group">
          <label>Confirm New Password</label>
          <input type="password" name="confirm_password" required>
        </div>
        <button type="submit" class="btn btn-primary">Update Password</button>
        <a href="/manage/dashboard" class="btn" style="margin-left:8px">Cancel</a>
      </form>
    </div>
  </div>'''
    return _manage_page('Change Password', body, user=user, msg=msg, msg_type=msg_type)


# ─────────────────────────────────────────────────────────────
# /manage HTTP request handler
# ─────────────────────────────────────────────────────────────

def _parse_multipart(headers, body: bytes) -> tuple[dict, dict]:
    """Minimal multipart/form-data parser. Returns (fields, files)."""
    content_type = headers.get('Content-Type', '')
    if 'multipart/form-data' not in content_type:
        # plain urlencoded
        fields = {}
        for k, v in urllib.parse.parse_qsl(body.decode('utf-8', errors='replace')):
            fields[k] = v
        return fields, {}

    boundary = None
    for part in content_type.split(';'):
        part = part.strip()
        if part.startswith('boundary='):
            boundary = part[9:].strip('"')
    if not boundary:
        return {}, {}

    fields, files = {}, {}
    delimiter = ('--' + boundary).encode()
    parts = body.split(delimiter)
    for part in parts[1:]:
        if part.strip() in (b'', b'--', b'--\r\n'):
            continue
        if part.startswith(b'\r\n'):
            part = part[2:]
        if b'\r\n\r\n' not in part:
            continue
        raw_headers, content = part.split(b'\r\n\r\n', 1)
        if content.endswith(b'\r\n'):
            content = content[:-2]
        hdr_text = raw_headers.decode('utf-8', errors='replace')
        disposition = ''
        for line in hdr_text.splitlines():
            if line.lower().startswith('content-disposition'):
                disposition = line
        name = ''
        filename = ''
        for segment in disposition.split(';'):
            segment = segment.strip()
            if segment.startswith('name='):
                name = segment[5:].strip('"')
            elif segment.startswith('filename='):
                filename = segment[9:].strip('"')
        if filename:
            entry = (filename, content)
            if name in files:
                if isinstance(files[name], list):
                    files[name].append(entry)
                else:
                    files[name] = [files[name], entry]
            else:
                files[name] = entry
        else:
            fields[name] = content.decode('utf-8', errors='replace')
    return fields, files

def main():
    global DEFAULT_INTERVAL, DEFAULT_MIN_INTERVAL, PEER_TTL, MAX_PEERS_PER_REPLY, \
           DEFAULT_TRACKER_ID, MAX_SCRAPE_HASHES, ALLOW_FULL_SCRAPE, \
           REGISTRATION_MODE, REGISTRATION_DB, OPEN_TRACKER, \
           REWARD_ENABLED, REWARD_THRESHOLD, SUPER_USER, _MANAGE_HTTPS_PORT

    parser = argparse.ArgumentParser(
        description='BitTorrent Tracker Server (HTTP + HTTPS + UDP)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--host', default='',
                        help='Bind address (empty = all interfaces)')
    parser.add_argument('--http-port', type=int, default=DEFAULT_HTTP_PORT,
                        help='HTTP listen port (0 to disable)')
    parser.add_argument('--https-port', type=int, default=0,
                        help='HTTPS listen port (requires --cert and --key)')
    parser.add_argument('--udp-port', type=int, default=DEFAULT_UDP_PORT,
                        help='UDP listen port (0 to disable)')
    parser.add_argument('--cert', default='',
                        help='Path to TLS certificate (e.g. acme.sh fullchain.cer)')
    parser.add_argument('--key', default='',
                        help='Path to TLS private key')
    parser.add_argument('--redirect-http', action='store_true',
                        help='When HTTPS is enabled, redirect HTTP → HTTPS instead of serving on it')
    parser.add_argument('--domain', default='',
                        help='Public domain name (used for HTTP→HTTPS redirect Location header)')
    parser.add_argument('--interval', type=int, default=DEFAULT_INTERVAL,
                        help='Announce interval (seconds)')
    parser.add_argument('--min-interval', type=int, default=DEFAULT_MIN_INTERVAL,
                        help='Minimum re-announce interval (seconds)')
    parser.add_argument('--peer-ttl', type=int, default=PEER_TTL,
                        help='Seconds before an inactive peer is purged')
    parser.add_argument('--max-peers', type=int, default=MAX_PEERS_PER_REPLY,
                        help='Maximum peers returned per announce')
    parser.add_argument('--tracker-id', default=DEFAULT_TRACKER_ID,
                        help='Tracker ID string returned in HTTP announce responses')
    parser.add_argument('--max-scrape-hashes', type=int, default=MAX_SCRAPE_HASHES,
                        help='Maximum number of info_hashes allowed per scrape request')
    parser.add_argument('--full-scrape', action='store_true',
                        help='Allow full scrape (no info_hash returns all torrents). Disabled by default.')
    parser.add_argument('--web-http-port', type=int, default=80,
                        help='Stats web page HTTP port (0 to disable)')
    parser.add_argument('--web-https-port', type=int, default=0,
                        help='Stats web page HTTPS port (0 to disable, uses same cert/key as tracker)')
    parser.add_argument('--web-redirect-http', action='store_true',
                        help='Redirect stats HTTP → HTTPS (requires --web-https-port)')
    parser.add_argument('--ipv6', action='store_true',
                        help='Also listen on IPv6 (binds :: for HTTP and UDP in addition to IPv4)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Debug logging')
    parser.add_argument('--registration', action='store_true',
                        help='Enable registration mode (requires --web-https-port and --cert/--key)')
    parser.add_argument('--db', default='/opt/tracker/tracker.db',
                        help='Path to SQLite database for registration mode')
    parser.add_argument('--super-user', default='',
                        help='Superuser username (required with --registration)')
    parser.add_argument('--super-user-password', default='',
                        help='Set/reset superuser password (service must be stopped)')
    parser.add_argument('--manage-port', type=int, default=0,
                        help='Management HTTPS port (default: same as --web-https-port)')

    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Override globals with CLI args
    DEFAULT_TRACKER_ID  = args.tracker_id
    MAX_SCRAPE_HASHES   = args.max_scrape_hashes
    ALLOW_FULL_SCRAPE   = args.full_scrape
    DEFAULT_INTERVAL    = args.interval
    DEFAULT_MIN_INTERVAL = args.min_interval
    PEER_TTL            = args.peer_ttl
    MAX_PEERS_PER_REPLY = args.max_peers

    servers = []

    # ── Registration mode ────────────────────────────────────────
    if args.registration:
        if not args.super_user:
            print('Error: --registration requires --super-user', file=sys.stderr)
            sys.exit(1)
        if not args.web_https_port and not args.manage_port:
            print('Error: --registration requires --web-https-port or --manage-port (HTTPS required)', file=sys.stderr)
            sys.exit(1)
        REGISTRATION_MODE = True
        SUPER_USER        = args.super_user
        REGISTRATION_DB   = RegistrationDB(args.db)
        _init_csrf_secret(REGISTRATION_DB)
        OPEN_TRACKER = REGISTRATION_DB.get_setting('open_tracker') == '1'
        REWARD_ENABLED = REGISTRATION_DB.get_setting('reward_enabled') == '1'
        try:
            REWARD_THRESHOLD = int(REGISTRATION_DB.get_setting('reward_threshold', '200'))
        except Exception:
            REWARD_THRESHOLD = 200
        log.info('Registration mode enabled  db=%s  super=%s  open_tracker=%s  reward=%s/%s',
                 args.db, args.super_user, OPEN_TRACKER, REWARD_ENABLED, REWARD_THRESHOLD)

    # ── Super-user password reset (run offline, exits) ───────────
    if args.super_user_password:
        if not args.super_user:
            print('Error: --super-user-password requires --super-user', file=sys.stderr)
            sys.exit(1)
        db = RegistrationDB(args.db)
        ph, salt = _hash_password(args.super_user_password)
        conn = sqlite3.connect(args.db)
        conn.execute('INSERT OR REPLACE INTO users '
                     '(username,password_hash,salt,is_admin,created_by,created_at) '
                     'VALUES (?,?,?,0,"cli",datetime("now"))',
                     (args.super_user, ph, salt))
        conn.commit()
        conn.close()
        print(f'Superuser {args.super_user!r} password set.')
        sys.exit(0)

    # ── TLS / HTTPS ──────────────────────────────────────────
    ssl_ctx = None
    if args.https_port:
        if not args.cert or not args.key:
            print('Error: --https-port requires --cert and --key', file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(args.cert):
            print(f'Error: cert file not found: {args.cert}', file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(args.key):
            print(f'Error: key file not found: {args.key}', file=sys.stderr)
            sys.exit(1)
        ssl_ctx = build_ssl_context(args.cert, args.key)
        servers.append(start_http_server(args.host, args.https_port, ssl_ctx, 'HTTPS'))

    # ── HTTP ─────────────────────────────────────────────────
    if args.http_port:
        if ssl_ctx and args.redirect_http:
            # Redirect HTTP → HTTPS
            redirect_host = args.domain or f'localhost:{args.https_port}'
            servers.append(start_redirect_server(args.host, args.http_port, redirect_host))
        else:
            servers.append(start_http_server(args.host, args.http_port, None, 'HTTP'))

    # ── UDP IPv4 ─────────────────────────────────────────────
    if args.udp_port:
        log.info('UDP tracker listening on %s:%d', args.host or '0.0.0.0', args.udp_port)
        t = threading.Thread(
            target=run_udp_server,
            args=(args.host, args.udp_port),
            daemon=True
        )
        t.start()

    # ── HTTP IPv6 ────────────────────────────────────────────
    if args.ipv6:
        if args.http_port:
            if ssl_ctx and args.redirect_http:
                redirect_host = args.domain or f'localhost:{args.https_port}'
                servers.append(start_redirect_server('::', args.http_port, redirect_host))
            else:
                servers.append(start_http6_server('::', args.http_port, None, 'HTTP'))
        if args.https_port and ssl_ctx:
            servers.append(start_http6_server('::', args.https_port, ssl_ctx, 'HTTPS'))

    # ── UDP IPv6 ─────────────────────────────────────────────
    if args.ipv6 and args.udp_port:
        log.info('UDP tracker listening on [%s]:%d (IPv6)', '::', args.udp_port)
        t = threading.Thread(
            target=run_udp6_server,
            args=('::', args.udp_port),
            daemon=True
        )
        t.start()

    # ── Stats web page ──────────────────────────────────────
    # Build announce URL list (only advertise UDP and HTTPS)
    announce_urls = []
    _pub_domain = args.domain.split(':')[0] if args.domain else 'localhost'
    if args.udp_port:
        announce_urls.append(('UDP', f'udp://{_pub_domain}:{args.udp_port}/announce'))
    if args.https_port:
        _https_url = f'https://{_pub_domain}'
        if args.https_port != 443:
            _https_url += f':{args.https_port}'
        announce_urls.append(('HTTPS', f'{_https_url}/announce'))

    WEB_CONFIG['announce_urls'] = announce_urls
    WEB_CONFIG['domain']        = _pub_domain
    if REGISTRATION_DB is not None:
        REGISTRATION_DB._init_defaults(announce_urls)
        WEB_CONFIG['free_signup'] = REGISTRATION_DB.get_setting('free_signup') == '1'

    if args.web_https_port:
        if not ssl_ctx:
            print('Error: --web-https-port requires --cert and --key', file=sys.stderr)
            sys.exit(1)
        servers.append(start_web_server(args.host, args.web_https_port, ssl_ctx, 'HTTPS'))
        if args.ipv6:
            servers.append(start_web6_server('::', args.web_https_port, ssl_ctx, 'HTTPS'))

    if args.web_http_port:
        if ssl_ctx and args.web_redirect_http and args.web_https_port:
            _web_redirect = _pub_domain
            if args.web_https_port != 443:
                _web_redirect += f':{args.web_https_port}'
            servers.append(start_redirect_server(args.host, args.web_http_port, _web_redirect))
            if args.ipv6:
                servers.append(start_redirect_server('::', args.web_http_port, _web_redirect))
        else:
            servers.append(start_web_server(args.host, args.web_http_port, None, 'HTTP'))
            if args.ipv6:
                servers.append(start_web6_server('::', args.web_http_port, None, 'HTTP'))

    # ── Management page ─────────────────────────────────────
    if args.registration:
        _manage_https = args.web_https_port
        _MANAGE_HTTPS_PORT = _manage_https
        if not _manage_https or not ssl_ctx:
            print('Error: registration mode requires --web-https-port with cert/key',
                  file=sys.stderr)
            sys.exit(1)
        log.info('Management page: https://%s%s/manage',
                 _pub_domain, f':{_manage_https}' if _manage_https != 443 else '')

    if not servers and not args.udp_port:
        print('Error: all listeners disabled.', file=sys.stderr)
        sys.exit(1)

    log.info('Tracker running. Press Ctrl-C to stop.')

    # ── Stats loop ───────────────────────────────────────────
    try:
        while True:
            time.sleep(60)
            STATS.check_rollover()
            if REGISTRATION_DB is not None:
                try:
                    REGISTRATION_DB.purge_expired_sessions()
                except Exception as _e:
                    log.warning('purge_expired_sessions failed (non-fatal): %s', _e)
            hashes = REGISTRY.all_hashes()
            total_peers = sum(
                len(REGISTRY._torrents.get(h, {})) for h in hashes
            )
            log.info('Stats: %d torrents  %d peers', len(hashes), total_peers)
    except KeyboardInterrupt:
        log.info('Shutting down.')
        sys.exit(0)


if __name__ == '__main__':
    main()
