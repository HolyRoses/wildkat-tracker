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
    request_queue_size = 128  # default is 5; larger backlog survives SYN floods
    ssl_context = None        # set after construction when HTTPS is needed

    def get_request(self):
        # Accept the raw TCP connection first
        conn, addr = self.socket.accept()
        if self.ssl_context:
            # Set timeout on the raw socket BEFORE the SSL handshake.
            # Without this, a scanner that completes TCP but sends no
            # TLS ClientHello freezes the handshake indefinitely, blocking
            # the entire accept loop. The timeout raises OSError which
            # _handle_request_noblock() silently discards and the loop recovers.
            conn.settimeout(10)
            try:
                conn = self.ssl_context.wrap_socket(conn, server_side=True)
            except Exception:
                conn.close()
                raise
            conn.settimeout(None)  # clear — timeout was only needed for the handshake
        return conn, addr


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


def _session_token_for(user) -> str:
    """Look up the most recent active session token for a user (for CSRF generation in render functions)."""
    if not REGISTRATION_DB:
        return ''
    row = REGISTRATION_DB._conn().execute(
        'SELECT token FROM sessions WHERE user_id=? ORDER BY id DESC LIMIT 1',
        (user['id'],)
    ).fetchone()
    return row[0] if row else ''


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
    prev_btn = (f'<a href="{page_url(current_page-1)}" style="{btn}">&#10094;</a> '
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
        self._restore_lock = threading.Lock()
        self._restore_gen  = 0   # incremented on every restore; forces conn reopen
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        # If a restore happened since this thread last opened, reopen
        if (not getattr(self._local, 'conn', None) or
                getattr(self._local, 'conn_gen', -1) != self._restore_gen):
            old = getattr(self._local, 'conn', None)
            if old:
                try: old.close()
                except Exception: pass
            conn = sqlite3.connect(self._path, check_same_thread=False,
                                   timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA foreign_keys=ON')
            conn.execute('PRAGMA busy_timeout=10000')  # wait up to 10s on lock
            self._local.conn = conn
            self._local.conn_gen = self._restore_gen
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
                credits_awarded       INTEGER NOT NULL DEFAULT 0,
                points                INTEGER NOT NULL DEFAULT 0,
                login_streak          INTEGER NOT NULL DEFAULT 0,
                longest_streak        INTEGER NOT NULL DEFAULT 0,
                last_login_date       TEXT,
                comment_pts_date      TEXT,
                comment_pts_today     INTEGER NOT NULL DEFAULT 0
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
        if 'points' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN points INTEGER NOT NULL DEFAULT 0')
            # migrate existing credits balance into points
            c.execute('UPDATE users SET points = credits WHERE credits > 0')
        if 'login_streak' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN login_streak INTEGER NOT NULL DEFAULT 0')
        if 'longest_streak' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN longest_streak INTEGER NOT NULL DEFAULT 0')
        if 'last_login_date' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN last_login_date TEXT')
        if 'comment_pts_date' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN comment_pts_date TEXT')
        if 'comment_pts_today' not in ucols:
            c.execute('ALTER TABLE users ADD COLUMN comment_pts_today INTEGER NOT NULL DEFAULT 0')
        # comments_locked column (may not exist on older installs)
        tcols = [r[1] for r in c.execute('PRAGMA table_info(torrents)').fetchall()]
        if 'comments_locked' not in tcols:
            c.execute('ALTER TABLE torrents ADD COLUMN comments_locked INTEGER NOT NULL DEFAULT 0')
        c.commit()
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
        # ── Points ledger (migration-safe) ───────────────────
        c.executescript('''
            CREATE TABLE IF NOT EXISTS points_ledger (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id       INTEGER NOT NULL,
                delta         INTEGER NOT NULL,
                balance_after INTEGER NOT NULL,
                reason        TEXT    NOT NULL,
                ref_type      TEXT    NOT NULL DEFAULT '',
                ref_id        TEXT    NOT NULL DEFAULT '',
                created_at    TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        ''')
        c.commit()
        # ── Comments & notifications (migration-safe) ────────
        c.executescript('''
            CREATE TABLE IF NOT EXISTS comments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                info_hash   TEXT    NOT NULL,
                user_id     INTEGER NOT NULL,
                username    TEXT    NOT NULL,
                parent_id   INTEGER,
                body        TEXT    NOT NULL,
                created_at  TEXT    NOT NULL,
                edited_at   TEXT,
                is_deleted  INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id        INTEGER NOT NULL,
                type           TEXT    NOT NULL,
                from_username  TEXT    NOT NULL,
                info_hash      TEXT    NOT NULL,
                torrent_name   TEXT    NOT NULL,
                comment_id     INTEGER NOT NULL,
                created_at     TEXT    NOT NULL,
                is_read        INTEGER NOT NULL DEFAULT 0
            );
        ''')
        c.commit()
        # ── Bounty system (migration-safe) ───────────────────
        c.executescript('''
            CREATE TABLE IF NOT EXISTS bounties (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                created_by       TEXT    NOT NULL,
                description      TEXT    NOT NULL,
                status           TEXT    NOT NULL DEFAULT 'open',
                initial_cost     INTEGER NOT NULL DEFAULT 0,
                total_escrow     INTEGER NOT NULL DEFAULT 0,
                claimed_infohash TEXT,
                claimed_by       TEXT,
                claimed_at       TEXT,
                fulfilled_by     TEXT,
                fulfilled_at     TEXT,
                created_at       TEXT    NOT NULL,
                expires_at       TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bounty_contributions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                bounty_id   INTEGER NOT NULL,
                username    TEXT    NOT NULL,
                amount      INTEGER NOT NULL,
                contributed_at TEXT NOT NULL,
                FOREIGN KEY (bounty_id) REFERENCES bounties(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS bounty_votes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                bounty_id  INTEGER NOT NULL,
                username   TEXT    NOT NULL,
                voted_at   TEXT    NOT NULL,
                UNIQUE(bounty_id, username),
                FOREIGN KEY (bounty_id) REFERENCES bounties(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS bounty_comments (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                bounty_id  INTEGER NOT NULL,
                username   TEXT    NOT NULL,
                body       TEXT    NOT NULL,
                created_at TEXT    NOT NULL,
                FOREIGN KEY (bounty_id) REFERENCES bounties(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS direct_messages (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                sender         TEXT    NOT NULL,
                recipient      TEXT    NOT NULL,
                subject        TEXT    NOT NULL DEFAULT '',
                body           TEXT    NOT NULL,
                sent_at        TEXT    NOT NULL,
                read_at        TEXT,
                del_by_sender  INTEGER NOT NULL DEFAULT 0,
                del_by_recip   INTEGER NOT NULL DEFAULT 0,
                is_broadcast   INTEGER NOT NULL DEFAULT 0,
                reply_to_id    INTEGER
            );
            CREATE TABLE IF NOT EXISTS dm_blocklist (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id          INTEGER NOT NULL,
                blocked_username TEXT    NOT NULL,
                blocked_at       TEXT    NOT NULL,
                UNIQUE(user_id, blocked_username),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        ''')
        c.commit()
        # ── DM opt-out column (migration-safe) ───────────────
        try:
            self._conn().execute('ALTER TABLE users ADD COLUMN allow_dms INTEGER NOT NULL DEFAULT 1')
            self._conn().commit()
        except Exception:
            pass  # column already exists

    def _init_defaults(self, announce_urls: list):
        """Seed magnet_trackers and settings if not already present."""
        c = self._conn()
        # Seed settings
        defaults = {
            'free_signup':           '0',
            'auto_promote_enabled':   '0',
            'auto_promote_threshold': '100',
            'torrents_per_page':       '50',
            'robots_txt':              'User-agent: *\nDisallow: /announce\nDisallow: /scrape\nDisallow: /manage\n',
            'pw_min_length':     '12',
            'pw_require_upper':  '1',
            'pw_require_lower':  '1',
            'pw_require_digit':  '1',
            'pw_require_symbol': '1',
            'open_tracker':       '0',
            'comments_enabled':   '1',
            # ── Points economy ────────────────────────────────
            'points_login_daily':       '1',
            'points_streak_7day':       '1',
            'points_streak_30day':      '4',
            'points_upload':            '25',
            'points_comment':           '1',
            'points_comment_cap':       '10',
            'points_penalty_torrent':   '25',
            'points_penalty_comment':   '1',
            'points_invite_cost':       '1000',
            'points_transfer_fee_pct':  '25',
            # ── Bounty system ─────────────────────────────────
            'bounty_min_cost':          '50',
            'bounty_refund_pct':        '25',
            'bounty_claimer_pct':       '70',
            'bounty_uploader_pct':      '15',
            'bounty_reject_penalty':    '10',
            'bounty_expiry_days':       '90',
            'bounty_confirm_votes':     '3',
            'bounty_pending_hours':     '48',
            # ── Leaderboard ───────────────────────────────────
            'leaderboard_top_n':        '10',
            # ── Admin ─────────────────────────────────────────
            'admin_max_point_grant':    '1000',
            # ── Direct messages ───────────────────────────────
            'dm_enabled':           '1',
            'dm_cost':              '5',
            'dm_daily_limit':       '10',
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

    # ── Direct Message DB Methods ────────────────────────────

    def send_dm(self, sender: str, recipient: str, subject: str, body: str,
                is_broadcast: bool = False, reply_to_id: int = None) -> int:
        """Insert a DM. Returns new message id."""
        c = self._conn()
        c.execute(
            "INSERT INTO direct_messages (sender,recipient,subject,body,sent_at,is_broadcast,reply_to_id)"
            " VALUES (?,?,?,?,?,?,?)",
            (sender, recipient, subject[:200], body[:5000],
             self._ts(), 1 if is_broadcast else 0, reply_to_id)
        )
        c.commit()
        return c.execute("SELECT last_insert_rowid()").fetchone()[0]

    def get_dm_inbox(self, username: str, limit: int = 100) -> list:
        return self._conn().execute(
            "SELECT * FROM direct_messages WHERE recipient=? AND del_by_recip=0"
            " ORDER BY id DESC LIMIT ?",
            (username, limit)
        ).fetchall()

    def get_dm_sent(self, username: str, limit: int = 100) -> list:
        return self._conn().execute(
            "SELECT * FROM direct_messages WHERE sender=? AND del_by_sender=0"
            " AND is_broadcast=0 ORDER BY id DESC LIMIT ?",
            (username, limit)
        ).fetchall()

    def get_dm(self, msg_id: int) -> object:
        return self._conn().execute(
            "SELECT * FROM direct_messages WHERE id=?", (msg_id,)
        ).fetchone()

    def get_dm_thread(self, msg_id: int, username: str) -> list:
        """Get a message and all replies in the thread visible to username."""
        root = self.get_dm(msg_id)
        if not root:
            return []
        # Walk up to find root
        while root["reply_to_id"]:
            parent = self.get_dm(root["reply_to_id"])
            if not parent:
                break
            root = parent
        # Get all messages in thread (root + replies)
        def collect(mid):
            msg = self.get_dm(mid)
            if not msg:
                return []
            result = [msg]
            children = self._conn().execute(
                "SELECT id FROM direct_messages WHERE reply_to_id=? ORDER BY id",
                (mid,)
            ).fetchall()
            for row in children:
                result.extend(collect(row[0]))
            return result
        return collect(root["id"])

    def get_unread_dm_count(self, username: str) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) FROM direct_messages WHERE recipient=? AND read_at IS NULL AND del_by_recip=0",
            (username,)
        ).fetchone()[0]

    def mark_dm_read(self, msg_id: int, username: str):
        c = self._conn()
        c.execute(
            "UPDATE direct_messages SET read_at=? WHERE id=? AND recipient=? AND read_at IS NULL",
            (self._ts(), msg_id, username)
        )
        c.commit()

    def mark_all_dm_read(self, username: str):
        c = self._conn()
        c.execute(
            "UPDATE direct_messages SET read_at=? WHERE recipient=? AND read_at IS NULL",
            (self._ts(), username)
        )
        c.commit()

    def delete_dm_sender(self, msg_id: int, username: str):
        c = self._conn()
        c.execute("UPDATE direct_messages SET del_by_sender=1 WHERE id=? AND sender=?",
                  (msg_id, username))
        c.commit()

    def delete_dm_recip(self, msg_id: int, username: str):
        c = self._conn()
        c.execute("UPDATE direct_messages SET del_by_recip=1 WHERE id=? AND recipient=?",
                  (msg_id, username))
        c.commit()

    def get_dm_sent_today(self, username: str) -> int:
        today = self._ts()[:10]
        return self._conn().execute(
            "SELECT COUNT(*) FROM direct_messages WHERE sender=? AND sent_at>=? AND is_broadcast=0",
            (username, today)
        ).fetchone()[0]

    def dm_blocklist_add(self, user_id: int, blocked_username: str):
        c = self._conn()
        c.execute(
            "INSERT OR IGNORE INTO dm_blocklist (user_id,blocked_username,blocked_at) VALUES (?,?,?)",
            (user_id, blocked_username, self._ts())
        )
        c.commit()

    def dm_blocklist_remove(self, user_id: int, blocked_username: str):
        c = self._conn()
        c.execute("DELETE FROM dm_blocklist WHERE user_id=? AND blocked_username=?",
                  (user_id, blocked_username))
        c.commit()

    def dm_blocklist_get(self, user_id: int) -> list:
        return self._conn().execute(
            "SELECT * FROM dm_blocklist WHERE user_id=? ORDER BY blocked_at DESC",
            (user_id,)
        ).fetchall()

    def dm_is_blocked(self, sender: str, recipient_id: int) -> bool:
        """Returns True if recipient has blocked sender."""
        row = self._conn().execute(
            "SELECT 1 FROM dm_blocklist WHERE user_id=? AND blocked_username=?",
            (recipient_id, sender)
        ).fetchone()
        return row is not None

    def dm_toggle_setting(self, user_id: int, allow: bool):
        """Store per-user DM opt-out in settings-like user field."""
        # We use the users table — add allow_dms column via migration
        c = self._conn()
        c.execute("UPDATE users SET allow_dms=? WHERE id=?", (1 if allow else 0, user_id))
        c.commit()

    def broadcast_dm(self, sender: str, subject: str, body: str) -> int:
        """Send a DM to every non-disabled user. Returns count sent."""
        users = self._conn().execute(
            "SELECT username FROM users WHERE is_disabled=0 AND username!=?",
            (sender,)
        ).fetchall()
        count = 0
        for row in users:
            self.send_dm(sender, row[0], subject, body, is_broadcast=True)
            count += 1
        self._log(sender, 'broadcast_dm', '', f'subject={subject[:60]!r} recipients={count}')
        return count

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
        """Promote basic→standard if points threshold reached. Returns True if promoted."""
        if self.get_setting('auto_promote_enabled') != '1':
            return False
        user = self.get_user_by_id(user_id)
        if not user or user['is_standard'] or user['is_admin']:
            return False
        threshold = int(self.get_setting('auto_promote_threshold', '100'))
        pts = user['points'] if 'points' in user.keys() else 0
        if pts >= threshold:
            self._conn().execute('UPDATE users SET is_standard=1 WHERE id=?', (user_id,))
            self._conn().commit()
            self._log('system', 'auto_promote', user['username'],
                      f'promoted to standard after reaching {pts} points')
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

    # ── Points Engine ─────────────────────────────────────────

    def award_points(self, user_id: int, delta: int, reason: str,
                     ref_type: str = '', ref_id: str = '') -> int:
        """Award (positive) or deduct (negative) points. Points can go negative.
        Writes a ledger entry and returns the new balance."""
        c = self._conn()
        c.execute('UPDATE users SET points = points + ? WHERE id = ?', (delta, user_id))
        c.commit()
        row = c.execute('SELECT points FROM users WHERE id=?', (user_id,)).fetchone()
        balance = row[0] if row else 0
        c.execute(
            'INSERT INTO points_ledger (user_id,delta,balance_after,reason,ref_type,ref_id,created_at)'
            ' VALUES (?,?,?,?,?,?,?)',
            (user_id, delta, balance, reason, ref_type, ref_id, self._ts())
        )
        c.commit()
        return balance

    def spend_points(self, user_id: int, amount: int, reason: str,
                     ref_type: str = '', ref_id: str = '') -> bool:
        """Spend points only if balance >= amount. Returns True on success."""
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        pts = user['points'] if 'points' in user.keys() else 0
        if pts < amount:
            return False
        self.award_points(user_id, -amount, reason, ref_type, ref_id)
        return True

    def adjust_points(self, username: str, delta: int, actor: str) -> int:
        """Admin manual point adjustment (can be positive or negative). Returns new balance."""
        user = self.get_user(username)
        if not user:
            return 0
        reason = f'Admin adjustment by {actor} ({delta:+d})'
        new_bal = self.award_points(user['id'], delta, reason, 'admin', actor)
        action = 'points_add' if delta > 0 else 'points_remove'
        self._log(actor, action, username, f'delta={delta:+d} balance={new_bal}')
        self.check_auto_promote(user['id'])
        return new_bal

    def daily_login_check(self, user_id: int) -> int:
        """Award daily login + streak bonus points. Returns points awarded (0 if already done today)."""
        today = datetime.date.today().isoformat()
        user = self.get_user_by_id(user_id)
        if not user:
            return 0
        last_date = user['last_login_date'] if 'last_login_date' in user.keys() else None
        if last_date == today:
            return 0  # already awarded today
        # Calculate streak
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        current_streak = user['login_streak'] if 'login_streak' in user.keys() else 0
        new_streak = (current_streak + 1) if last_date == yesterday else 1
        longest = max(user['longest_streak'] if 'longest_streak' in user.keys() else 0, new_streak)
        c = self._conn()
        c.execute(
            'UPDATE users SET last_login_date=?, login_streak=?, longest_streak=? WHERE id=?',
            (today, new_streak, longest, user_id)
        )
        c.commit()
        # Compute points to award
        daily = int(self.get_setting('points_login_daily', '1'))
        s7    = int(self.get_setting('points_streak_7day',  '1'))
        s30   = int(self.get_setting('points_streak_30day', '4'))
        total = daily
        parts = ['daily login']
        if new_streak % 7 == 0:
            total += s7
            parts.append(f'7-day streak (day {new_streak})')
        if new_streak % 30 == 0:
            total += s30
            parts.append(f'30-day streak (day {new_streak})')
        self.award_points(user_id, total, ' + '.join(parts), 'login', today)
        self.check_auto_promote(user_id)
        return total

    def award_upload_points(self, user_id: int, torrent_name: str, info_hash: str) -> int:
        """Award points for a new torrent upload. Returns points awarded."""
        pts = int(self.get_setting('points_upload', '25'))
        bal = self.award_points(user_id, pts, f'upload: {torrent_name}', 'torrent', info_hash)
        self.check_auto_promote(user_id)
        return pts

    def award_comment_points(self, user_id: int, comment_id: int) -> int:
        """Award comment points (up to daily cap). Returns points awarded (0 if cap reached)."""
        pts_each = int(self.get_setting('points_comment', '1'))
        cap      = int(self.get_setting('points_comment_cap', '10'))
        today    = datetime.date.today().isoformat()
        user = self.get_user_by_id(user_id)
        if not user:
            return 0
        # Reset daily counter if date changed
        c_date  = user['comment_pts_date']  if 'comment_pts_date'  in user.keys() else None
        c_today = user['comment_pts_today'] if 'comment_pts_today' in user.keys() else 0
        if c_date != today:
            c_today = 0
        if c_today >= cap:
            return 0
        c = self._conn()
        c.execute(
            'UPDATE users SET comment_pts_date=?, comment_pts_today=? WHERE id=?',
            (today, c_today + pts_each, user_id)
        )
        c.commit()
        self.award_points(user_id, pts_each, 'comment posted', 'comment', str(comment_id))
        self.check_auto_promote(user_id)
        return pts_each

    def penalize_torrent_owner(self, info_hash: str, actor: str):
        """Deduct points from the torrent owner when an admin deletes their torrent."""
        row = self._conn().execute(
            'SELECT uploaded_by_id, uploaded_by_username FROM torrents WHERE info_hash=?',
            (info_hash.upper(),)
        ).fetchone()
        if not row or not row['uploaded_by_id']:
            return
        owner_id = row['uploaded_by_id']
        owner_un = row['uploaded_by_username']
        # Only penalize if actor is not the owner (i.e. admin removal)
        if owner_un == actor:
            return
        pts = int(self.get_setting('points_penalty_torrent', '25'))
        self.award_points(owner_id, -pts, f'torrent removed by {actor}', 'penalty_torrent',
                          info_hash.upper())
        self._log(actor, 'points_penalty', owner_un, f'-{pts} pts (torrent removed)')

    def penalize_comment_author(self, comment_id: int, actor: str):
        """Deduct points from comment author when an admin deletes their comment."""
        row = self._conn().execute(
            'SELECT user_id, username FROM comments WHERE id=?', (comment_id,)
        ).fetchone()
        if not row:
            return
        if row['username'] == actor:
            return  # self-delete: no penalty
        pts = int(self.get_setting('points_penalty_comment', '1'))
        self.award_points(row['user_id'], -pts, f'comment removed by {actor}', 'penalty_comment',
                          str(comment_id))

    def spend_points_for_invite(self, username: str) -> str | None:
        """Spend invite cost in points to generate an invite. Returns token or None."""
        cost = int(self.get_setting('points_invite_cost', '1000'))
        user = self.get_user(username)
        if not user:
            return None
        pts = user['points'] if 'points' in user.keys() else 0
        if pts < cost:
            return None
        self.spend_points(user['id'], cost, f'invite code purchased ({cost} pts)',
                          'invite', '')
        return self.create_invite_code(username)

    def transfer_points(self, from_username: str, to_username: str, amount: int) -> tuple[bool, str]:
        """Transfer points between users with configurable fee. Returns (success, message)."""
        if from_username == to_username:
            return False, 'Cannot transfer to yourself.'
        sender = self.get_user(from_username)
        recipient = self.get_user(to_username)
        if not sender:
            return False, 'Sender not found.'
        if not recipient:
            return False, f'User @{to_username} not found.'
        sender_pts = sender['points'] if 'points' in sender.keys() else 0
        if sender_pts < amount:
            return False, f'Insufficient points. You have {sender_pts} pts.'
        fee_pct = int(self.get_setting('points_transfer_fee_pct', '25'))
        fee  = max(1, round(amount * fee_pct / 100))
        received = amount - fee
        self.spend_points(sender['id'], amount,
                          f'transfer to @{to_username} ({fee} pts fee)',
                          'transfer', to_username)
        self.award_points(recipient['id'], received,
                          f'transfer from @{from_username} ({fee} pts fee deducted)',
                          'transfer', from_username)
        self._log(from_username, 'transfer_points', to_username,
                  f'sent={amount} fee={fee} received={received}')
        self.check_auto_promote(recipient['id'])
        return True, f'Transferred {received} pts to @{to_username} ({fee} pts fee).'

    def get_points_ledger(self, user_id: int, limit: int = 50) -> list:
        """Return most recent ledger entries for a user."""
        return self._conn().execute(
            'SELECT * FROM points_ledger WHERE user_id=? ORDER BY id DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()

    def get_economy_stats(self) -> dict:
        """Return economy-wide statistics for the admin dashboard."""
        c = self._conn()
        def _q(sql, *args):
            row = c.execute(sql, args).fetchone()
            return row[0] if row and row[0] is not None else 0
        total_positive  = _q('SELECT SUM(points) FROM users WHERE points > 0')
        total_debt      = _q('SELECT SUM(points) FROM users WHERE points < 0')
        total_generated = _q('SELECT SUM(delta) FROM points_ledger WHERE delta > 0')
        total_destroyed = _q('SELECT SUM(delta) FROM points_ledger WHERE delta < 0')
        in_escrow       = _q("SELECT SUM(total_escrow) FROM bounties WHERE status IN ('open','pending')")
        cutoff30 = (datetime.datetime.now() - datetime.timedelta(days=30)).isoformat()
        gen_30d  = _q('SELECT SUM(delta) FROM points_ledger WHERE delta > 0 AND created_at > ?', cutoff30)
        burn_30d = _q('SELECT SUM(delta) FROM points_ledger WHERE delta < 0 AND created_at > ?', cutoff30)
        open_bounties     = _q("SELECT COUNT(*) FROM bounties WHERE status='open'")
        pending_bounties  = _q("SELECT COUNT(*) FROM bounties WHERE status='pending'")
        fulfilled_bounties= _q("SELECT COUNT(*) FROM bounties WHERE status='fulfilled'")
        expired_bounties  = _q("SELECT COUNT(*) FROM bounties WHERE status='expired'")
        rows = c.execute(
            'SELECT ref_type, SUM(delta) as net FROM points_ledger GROUP BY ref_type ORDER BY ref_type'
        ).fetchall()
        breakdown = {r['ref_type'] or 'other': r['net'] for r in rows}
        return {
            'in_circulation':  total_positive,
            'in_debt':         abs(total_debt),
            'in_escrow':       in_escrow,
            'total_generated': total_generated,
            'total_destroyed': abs(total_destroyed),
            'net_all_time':    total_generated + total_destroyed,
            'gen_30d':         gen_30d,
            'burn_30d':        abs(burn_30d),
            'net_30d':         gen_30d + burn_30d,
            'breakdown':       breakdown,
            'open_bounties':     open_bounties,
            'pending_bounties':  pending_bounties,
            'fulfilled_bounties':fulfilled_bounties,
            'expired_bounties':  expired_bounties,
        }

    def create_invite_code(self, created_by_username: str) -> str:
        token = secrets.token_urlsafe(32)
        self._conn().execute(
            'INSERT INTO invite_codes (code, created_by_username, created_at) VALUES (?,?,?)',
            (token, created_by_username, self._ts())
        )
        self._conn().commit()
        self._log(created_by_username, 'create_invite', token[:12] + '...')
        return token

    # ── Bounty System ─────────────────────────────────────────

    def create_bounty(self, username: str, description: str) -> tuple[bool, str]:
        """Create a new bounty. Spends points. Returns (ok, message_or_id)."""
        min_cost = int(self.get_setting('bounty_min_cost', '50'))
        ok = self.spend_points(
            self.get_user(username)['id'], min_cost,
            f'bounty created: {description[:40]}', 'bounty', ''
        )
        if not ok:
            return False, f'Insufficient points. Minimum bounty cost is {min_cost} pts.'
        expiry = (datetime.datetime.now() +
                  datetime.timedelta(days=int(self.get_setting('bounty_expiry_days', '90')))
                  ).date().isoformat()
        c = self._conn()
        cur = c.execute(
            'INSERT INTO bounties (created_by, description, status, initial_cost, total_escrow, created_at, expires_at)'
            ' VALUES (?,?,?,?,?,?,?)',
            (username, description, 'open', min_cost, min_cost, self._ts(), expiry)
        )
        c.commit()
        bid = cur.lastrowid
        # Record the contribution
        c.execute('INSERT INTO bounty_contributions (bounty_id,username,amount,contributed_at) VALUES (?,?,?,?)',
                  (bid, username, min_cost, self._ts()))
        c.commit()
        self._log(username, 'bounty_create', str(bid), description[:60])
        return True, str(bid)

    def contribute_to_bounty(self, bounty_id: int, username: str, amount: int) -> tuple[bool, str]:
        """Add points to an existing open bounty."""
        b = self.get_bounty(bounty_id)
        if not b:
            return False, 'Bounty not found.'
        if b['status'] not in ('open', 'pending'):
            return False, 'Bounty is no longer active.'
        user = self.get_user(username)
        if not user:
            return False, 'User not found.'
        if amount < 1:
            return False, 'Amount must be at least 1.'
        ok = self.spend_points(user['id'], amount,
                               f'contributed {amount} pts to bounty #{bounty_id}',
                               'bounty_contrib', str(bounty_id))
        if not ok:
            return False, 'Insufficient points.'
        c = self._conn()
        c.execute('UPDATE bounties SET total_escrow=total_escrow+? WHERE id=?', (amount, bounty_id))
        c.execute('INSERT INTO bounty_contributions (bounty_id,username,amount,contributed_at) VALUES (?,?,?,?)',
                  (bounty_id, username, amount, self._ts()))
        c.commit()
        # Notify bounty creator
        creator = b['created_by']
        if creator != username:
            self._notify_bounty(creator, 'bounty_contribution', username, bounty_id,
                                b['description'], amount)
        self._log(username, 'bounty_contribute', str(bounty_id), f'+{amount} pts')
        return True, 'Contributed successfully.'

    def claim_bounty(self, bounty_id: int, claimer: str, info_hash: str) -> tuple[bool, str]:
        """Submit an infohash as fulfillment. First valid submission wins."""
        b = self.get_bounty(bounty_id)
        if not b:
            return False, 'Bounty not found.'
        if b['status'] != 'open':
            return False, 'Bounty is not open for claims.'
        if b['created_by'] == claimer:
            return False, 'You cannot claim your own bounty.'
        ih = info_hash.strip().upper()
        torrent = self.get_torrent(ih)
        if not torrent:
            return False, 'No torrent with that info hash is registered on this tracker.'
        now = datetime.datetime.now()
        expiry_dt = datetime.datetime.fromisoformat(b['expires_at'] + 'T23:59:59')
        if now > expiry_dt:
            return False, 'This bounty has expired.'
        pending_until = (now + datetime.timedelta(
            hours=int(self.get_setting('bounty_pending_hours', '48'))
        )).isoformat()
        c = self._conn()
        c.execute(
            'UPDATE bounties SET status=?,claimed_infohash=?,claimed_by=?,claimed_at=? WHERE id=?',
            ('pending', ih, claimer, self._ts(), bounty_id)
        )
        c.commit()
        self._log(claimer, 'bounty_claim', str(bounty_id), f'ih={ih} torrent={torrent["name"]}')
        # Notify all contributors
        contributors = self._get_bounty_contributor_usernames(bounty_id)
        for u in contributors:
            if u != claimer:
                self._notify_bounty(u, 'bounty_claimed', claimer, bounty_id,
                                    b['description'], 0, ih)
        return True, 'Claim submitted. Awaiting confirmation.'

    def confirm_bounty(self, bounty_id: int, confirmer: str) -> tuple[bool, str]:
        """Requestor confirms fulfillment. Pays out escrow."""
        b = self.get_bounty(bounty_id)
        if not b:
            return False, 'Bounty not found.'
        if b['status'] != 'pending':
            return False, 'No pending claim to confirm.'
        if b['created_by'] != confirmer:
            return False, 'Only the bounty creator can confirm.'
        return self._fulfill_bounty(bounty_id, refund_requestor=True)

    def reject_bounty_claim(self, bounty_id: int, rejecter: str) -> tuple[bool, str]:
        """Requestor rejects the claim. Bounty returns to open. Claimer penalised."""
        b = self.get_bounty(bounty_id)
        if not b:
            return False, 'Bounty not found.'
        if b['status'] != 'pending':
            return False, 'No pending claim to reject.'
        if b['created_by'] != rejecter:
            return False, 'Only the bounty creator can reject a claim.'
        claimer = b['claimed_by']
        penalty = int(self.get_setting('bounty_reject_penalty', '10'))
        claimer_user = self.get_user(claimer)
        if claimer_user:
            self.award_points(claimer_user['id'], -penalty,
                              f'bounty #{bounty_id} claim rejected', 'bounty_reject', str(bounty_id))
        c = self._conn()
        c.execute(
            'UPDATE bounties SET status=?,claimed_infohash=NULL,claimed_by=NULL,claimed_at=NULL WHERE id=?',
            ('open', bounty_id)
        )
        c.commit()
        self._log(rejecter, 'bounty_reject', str(bounty_id), f'claimer={claimer}')
        if claimer_user:
            self._notify_bounty(claimer, 'bounty_rejected', rejecter, bounty_id,
                                b['description'], 0)
        return True, 'Claim rejected. Bounty is open again.'

    def vote_bounty_fulfilled(self, bounty_id: int, voter: str) -> tuple[bool, str]:
        """Community vote that a pending claim is legitimate."""
        b = self.get_bounty(bounty_id)
        if not b:
            return False, 'Bounty not found.'
        if b['status'] != 'pending':
            return False, 'No pending claim to vote on.'
        if b['created_by'] == voter or b['claimed_by'] == voter:
            return False, 'Requestor and claimer cannot vote.'
        c = self._conn()
        try:
            c.execute('INSERT INTO bounty_votes (bounty_id,username,voted_at) VALUES (?,?,?)',
                      (bounty_id, voter, self._ts()))
            c.commit()
        except sqlite3.IntegrityError:
            return False, 'You have already voted.'
        # Check if threshold reached
        vote_count = c.execute('SELECT COUNT(*) FROM bounty_votes WHERE bounty_id=?',
                               (bounty_id,)).fetchone()[0]
        threshold = int(self.get_setting('bounty_confirm_votes', '3'))
        if vote_count >= threshold:
            self._fulfill_bounty(bounty_id, refund_requestor=False)
        return True, 'Vote recorded.'

    def _fulfill_bounty(self, bounty_id: int, refund_requestor: bool) -> tuple[bool, str]:
        """Internal: pay out escrow and close bounty as fulfilled."""
        b = self.get_bounty(bounty_id)
        claimer  = b['claimed_by']
        ih       = b['claimed_infohash']
        escrow   = b['total_escrow']
        torrent  = self.get_torrent(ih) if ih else None
        uploader = torrent['uploaded_by_username'] if torrent else None

        claimer_pct  = int(self.get_setting('bounty_claimer_pct',  '70')) / 100
        uploader_pct = int(self.get_setting('bounty_uploader_pct', '15')) / 100

        claimer_pay  = int(escrow * claimer_pct)
        if uploader and uploader != claimer:
            uploader_pay = int(escrow * uploader_pct)
        else:
            uploader_pay = 0
            claimer_pay  = int(escrow * (claimer_pct + uploader_pct))

        # Pay claimer
        claimer_user = self.get_user(claimer)
        if claimer_user:
            self.award_points(claimer_user['id'], claimer_pay,
                              f'bounty #{bounty_id} fulfilled (claimer share)',
                              'bounty_payout', str(bounty_id))
        # Pay uploader if different
        if uploader_pay > 0:
            up_user = self.get_user(uploader)
            if up_user:
                self.award_points(up_user['id'], uploader_pay,
                                  f'your torrent fulfilled bounty #{bounty_id}',
                                  'bounty_payout', str(bounty_id))
                self._notify_bounty(uploader, 'bounty_uploader_payout', claimer, bounty_id,
                                    b['description'], uploader_pay, ih)
        # Refund requestor their initial cost % if confirming themselves
        if refund_requestor:
            refund_pct = int(self.get_setting('bounty_refund_pct', '25')) / 100
            refund_amt = int(b['initial_cost'] * refund_pct)
            if refund_amt > 0:
                req_user = self.get_user(b['created_by'])
                if req_user:
                    self.award_points(req_user['id'], refund_amt,
                                      f'bounty #{bounty_id} confirmed — partial refund',
                                      'bounty_refund', str(bounty_id))

        c = self._conn()
        c.execute(
            'UPDATE bounties SET status=?,fulfilled_by=?,fulfilled_at=? WHERE id=?',
            ('fulfilled', claimer, self._ts(), bounty_id)
        )
        c.commit()
        self._log('system', 'bounty_fulfilled', str(bounty_id),
                  f'claimer={claimer} escrow={escrow} refund={refund_requestor}')
        if claimer_user:
            self._notify_bounty(claimer, 'bounty_fulfilled', b['created_by'], bounty_id,
                                b['description'], claimer_pay, ih)
        return True, 'Bounty fulfilled.'

    def expire_bounties(self):
        """Called periodically to expire stale bounties and destroy their escrow."""
        today = datetime.date.today().isoformat()
        c = self._conn()
        expired = c.execute(
            "SELECT * FROM bounties WHERE status IN ('open','pending') AND expires_at <= ?",
            (today,)
        ).fetchall()
        for b in expired:
            c.execute("UPDATE bounties SET status='expired' WHERE id=?", (b['id'],))
            c.commit()
            contributors = self._get_bounty_contributor_usernames(b['id'])
            for u in contributors:
                self._notify_bounty(u, 'bounty_expired', 'system', b['id'],
                                    b['description'], 0)
            self._log('system', 'bounty_expired', str(b['id']),
                      f'{b["total_escrow"]} pts destroyed')

    def get_bounty(self, bounty_id: int):
        return self._conn().execute(
            'SELECT * FROM bounties WHERE id=?', (bounty_id,)
        ).fetchone()

    def list_bounties(self, status: str | None = None, sort: str = 'points',
                      page: int = 1, per_page: int = 20) -> tuple[list, int]:
        c = self._conn()
        where = ''
        args: list = []
        if status:
            where = 'WHERE status=?'
            args.append(status)
        order = {
            'points':  'total_escrow DESC',
            'newest':  'created_at DESC',
            'oldest':  'created_at ASC',
        }.get(sort, 'total_escrow DESC')
        total = c.execute(f'SELECT COUNT(*) FROM bounties {where}', args).fetchone()[0]
        offset = (page - 1) * per_page
        rows = c.execute(
            f'SELECT * FROM bounties {where} ORDER BY {order} LIMIT ? OFFSET ?',
            args + [per_page, offset]
        ).fetchall()
        return rows, total

    def get_bounty_contributions(self, bounty_id: int) -> list:
        return self._conn().execute(
            'SELECT * FROM bounty_contributions WHERE bounty_id=? ORDER BY contributed_at',
            (bounty_id,)
        ).fetchall()

    def get_bounty_votes(self, bounty_id: int) -> list:
        return self._conn().execute(
            'SELECT * FROM bounty_votes WHERE bounty_id=? ORDER BY voted_at',
            (bounty_id,)
        ).fetchall()

    def get_bounty_comments(self, bounty_id: int) -> list:
        return self._conn().execute(
            'SELECT * FROM bounty_comments WHERE bounty_id=? ORDER BY created_at',
            (bounty_id,)
        ).fetchall()

    def add_bounty_comment(self, bounty_id: int, username: str, body: str) -> int:
        c = self._conn()
        cur = c.execute(
            'INSERT INTO bounty_comments (bounty_id,username,body,created_at) VALUES (?,?,?,?)',
            (bounty_id, username, body, self._ts())
        )
        c.commit()
        return cur.lastrowid

    def get_leaderboard(self, top_n: int = 10) -> dict:
        """Return ranked lists for each leaderboard category."""
        c = self._conn()
        def _rows(sql, *args):
            return [dict(r) for r in c.execute(sql, args).fetchall()]

        holders = _rows(
            'SELECT username, points FROM users WHERE is_standard=1 OR is_admin=1 '
            'ORDER BY points DESC LIMIT ?', top_n)

        earners = _rows(
            'SELECT u.username, COALESCE(SUM(pl.delta),0) AS total_earned '
            'FROM users u LEFT JOIN points_ledger pl ON pl.user_id=u.id AND pl.delta>0 '
            'WHERE u.is_standard=1 OR u.is_admin=1 '
            'GROUP BY u.id ORDER BY total_earned DESC LIMIT ?', top_n)

        uploaders = _rows(
            'SELECT uploaded_by_username AS username, COUNT(*) AS torrent_count '
            'FROM torrents GROUP BY uploaded_by_username '
            'ORDER BY torrent_count DESC LIMIT ?', top_n)

        bounty_hunters = _rows(
            'SELECT fulfilled_by AS username, COUNT(*) AS fulfilled_count '
            "FROM bounties WHERE status='fulfilled' AND fulfilled_by IS NOT NULL "
            'GROUP BY fulfilled_by ORDER BY fulfilled_count DESC LIMIT ?', top_n)

        streaks = _rows(
            'SELECT username, login_streak FROM users '
            'WHERE (is_standard=1 OR is_admin=1) AND login_streak > 0 '
            'ORDER BY login_streak DESC LIMIT ?', top_n)

        chatty = _rows(
            'SELECT u.username, COUNT(cm.id) AS comment_count '
            'FROM users u JOIN comments cm ON cm.username=u.username '
            'WHERE u.is_standard=1 OR u.is_admin=1 '
            'GROUP BY u.username ORDER BY comment_count DESC LIMIT ?', top_n)

        return {
            'holders':       holders,
            'earners':       earners,
            'uploaders':     uploaders,
            'bounty_hunters':bounty_hunters,
            'streaks':       streaks,
            'chatty':        chatty,
        }

    def list_bounties_by_user(self, username: str) -> dict:
        """Return dicts of created and fulfilled bounties for profile display."""
        c = self._conn()
        created   = c.execute(
            'SELECT * FROM bounties WHERE created_by=? ORDER BY created_at DESC', (username,)
        ).fetchall()
        fulfilled = c.execute(
            'SELECT * FROM bounties WHERE fulfilled_by=? ORDER BY fulfilled_at DESC', (username,)
        ).fetchall()
        return {'created': created, 'fulfilled': fulfilled}

    def _get_bounty_contributor_usernames(self, bounty_id: int) -> list[str]:
        rows = self._conn().execute(
            'SELECT DISTINCT username FROM bounty_contributions WHERE bounty_id=?', (bounty_id,)
        ).fetchall()
        return [r['username'] for r in rows]

    def _notify_bounty(self, recipient: str, ntype: str, actor: str,
                       bounty_id: int, description: str, amount: int,
                       info_hash: str = '') -> None:
        """Insert a notification for bounty events. Reuses notifications table with bounty ref."""
        user = self.get_user(recipient)
        if not user:
            return
        # We store bounty_id in comment_id field, info_hash as info_hash,
        # description in torrent_name, amount in comment_id (overloaded).
        # Use a special info_hash prefix "BOUNTY:" to distinguish from torrent notifs.
        self._conn().execute(
            'INSERT INTO notifications (user_id,type,from_username,info_hash,torrent_name,'
            'comment_id,created_at,is_read) VALUES (?,?,?,?,?,?,?,0)',
            (user['id'], ntype, actor,
             f'BOUNTY:{bounty_id}',
             description[:120],
             amount, self._ts())
        )
        self._conn().commit()

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
        spaces so 'ubuntu server' matches 'Ubuntu.Server.2025...'
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
        ih_upper = ih.upper()
        # Fetch name before deleting so we can log it
        row = self._conn().execute(
            'SELECT name FROM torrents WHERE info_hash=?', (ih_upper,)
        ).fetchone()
        torrent_name = row['name'] if row else ih_upper
        for attempt in range(5):
            try:
                c = self._conn()
                # Expunge all comments and notifications tied to this torrent
                c.execute('DELETE FROM comments WHERE info_hash=?', (ih_upper,))
                c.execute('DELETE FROM notifications WHERE info_hash=?', (ih_upper,))
                c.execute('DELETE FROM torrents WHERE info_hash=?', (ih_upper,))
                c.commit()
                self._log(actor, 'delete_torrent', ih_upper, torrent_name)
                return
            except sqlite3.OperationalError as e:
                if 'locked' in str(e) and attempt < 4:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                raise

    def backup_to_bytes(self) -> bytes:
        """Return a gzip-compressed snapshot of the live DB as raw bytes."""
        import io, gzip, tempfile, os
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tf:
            tmp_path = tf.name
        try:
            dst = sqlite3.connect(tmp_path)
            self._conn().backup(dst)
            dst.close()
            with open(tmp_path, 'rb') as f:
                raw = f.read()
        finally:
            os.unlink(tmp_path)
        gz_buf = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buf, mode='wb', compresslevel=9) as gz:
            gz.write(raw)
        return gz_buf.getvalue()

    def restore_from_bytes(self, gz_data: bytes, actor: str) -> None:
        """Replace the live DB with a gzip-compressed SQLite backup."""
        import gzip, tempfile, os, shutil
        try:
            raw = gzip.decompress(gz_data)
        except Exception:
            raise ValueError('Not a valid gzip file')
        if not raw.startswith(b'SQLite format 3\x00'):
            raise ValueError('File is not a valid SQLite database')
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tf:
            tf.write(raw)
            tmp_path = tf.name
        try:
            # Validate integrity before touching the live DB
            check = sqlite3.connect(tmp_path)
            result = check.execute('PRAGMA integrity_check').fetchone()
            check.close()
            if result[0] != 'ok':
                raise ValueError('Backup database failed integrity check')
            with self._restore_lock:
                # Close this thread's connection and flush WAL
                conn = getattr(self._local, 'conn', None)
                if conn:
                    try:
                        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                        conn.close()
                    except Exception:
                        pass
                    self._local.conn = None
                # Overwrite the DB file on disk
                shutil.copy2(tmp_path, self._path)
                # Remove any stale WAL / SHM files so they don't override the restore
                for ext in ('-wal', '-shm'):
                    sidecar = self._path + ext
                    if os.path.exists(sidecar):
                        try: os.unlink(sidecar)
                        except Exception: pass
                # Bump generation — every thread will reopen on next DB call
                self._restore_gen += 1
        finally:
            os.unlink(tmp_path)
        # Log using the freshly-reopened connection
        self._log(actor, 'db_restore', '', 'Database restored from backup')

    def delete_all_comments_global(self, actor: str) -> int:
        """Hard-delete every comment and notification in the system."""
        count = self._conn().execute('SELECT COUNT(*) FROM comments').fetchone()[0]
        self._conn().execute('DELETE FROM comments')
        self._conn().execute('DELETE FROM notifications')
        self._conn().commit()
        self._log(actor, 'delete_all_comments_global', '', f'{count} comment(s) removed')
        return count

    def system_wipe(self, actor: str):
        """Wipe all data except the super user account and system settings."""
        c = self._conn()
        c.execute('DELETE FROM users WHERE username != ?', (actor,))
        c.execute('DELETE FROM torrents')
        c.execute('DELETE FROM comments')
        c.execute('DELETE FROM notifications')
        c.execute('DELETE FROM invite_codes')
        c.execute('DELETE FROM sessions WHERE user_id NOT IN (SELECT id FROM users)')
        c.execute('DELETE FROM events')
        c.execute('DELETE FROM ip_allowlist WHERE user_id NOT IN (SELECT id FROM users)')
        c.execute('DELETE FROM login_history WHERE user_id NOT IN (SELECT id FROM users)')
        c.commit()
        self._log(actor, 'SYSTEM_WIPE', '', 'All data wiped except super account')

    def delete_all_comments(self, ih: str, actor: str) -> int:
        """Hard-delete every comment and associated notifications for a torrent.
        Returns number of comments deleted."""
        count = self._conn().execute(
            'SELECT COUNT(*) FROM comments WHERE info_hash=?', (ih.upper(),)
        ).fetchone()[0]
        self._conn().execute('DELETE FROM comments WHERE info_hash=?', (ih.upper(),))
        self._conn().execute('DELETE FROM notifications WHERE info_hash=?', (ih.upper(),))
        self._conn().commit()
        self._log(actor, 'delete_all_comments', ih.upper(), f'{count} comment(s) removed')
        return count

    def set_comments_locked(self, ih: str, locked: bool, actor: str):
        self._conn().execute(
            'UPDATE torrents SET comments_locked=? WHERE info_hash=?',
            (1 if locked else 0, ih.upper())
        )
        self._conn().commit()
        action = 'lock_comments' if locked else 'unlock_comments'
        self._log(actor, action, ih.upper())

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

    # ── Comments ──────────────────────────────────────────────

    def add_comment(self, info_hash: str, user_id: int, username: str,
                    body: str, parent_id: int | None = None) -> int:
        c = self._conn()
        cur = c.execute(
            'INSERT INTO comments (info_hash,user_id,username,parent_id,body,created_at)'
            ' VALUES (?,?,?,?,?,?)',
            (info_hash.upper(), user_id, username, parent_id, body, self._ts())
        )
        c.commit()
        return cur.lastrowid

    def get_comments(self, info_hash: str) -> list:
        return self._conn().execute(
            'SELECT * FROM comments WHERE info_hash=? ORDER BY id ASC',
            (info_hash.upper(),)
        ).fetchall()

    def get_comment(self, comment_id: int):
        return self._conn().execute(
            'SELECT * FROM comments WHERE id=?', (comment_id,)
        ).fetchone()

    def edit_comment(self, comment_id: int, user_id: int, body: str, is_admin: bool) -> bool:
        row = self.get_comment(comment_id)
        if not row or row['is_deleted']:
            return False
        if not is_admin and row['user_id'] != user_id:
            return False
        self._conn().execute(
            'UPDATE comments SET body=?, edited_at=? WHERE id=?',
            (body, self._ts(), comment_id)
        )
        self._conn().commit()
        return True

    def delete_comment(self, comment_id: int, user_id: int, is_admin: bool) -> bool:
        row = self.get_comment(comment_id)
        if not row:
            return False
        if not is_admin and row['user_id'] != user_id:
            return False
        parent_id = row['parent_id']
        # Hard delete if no replies exist, soft delete if replies must be preserved
        has_replies = self._conn().execute(
            'SELECT COUNT(*) FROM comments WHERE parent_id=?', (comment_id,)
        ).fetchone()[0]
        if has_replies:
            self._conn().execute(
                'UPDATE comments SET is_deleted=1, body=? WHERE id=?',
                ('[deleted]', comment_id)
            )
        else:
            self._conn().execute('DELETE FROM comments WHERE id=?', (comment_id,))
            # If this was a reply, check if the parent is a soft-deleted comment
            # with no remaining replies — if so, clean it up too
            if parent_id:
                parent = self.get_comment(parent_id)
                if parent and parent['is_deleted']:
                    remaining = self._conn().execute(
                        'SELECT COUNT(*) FROM comments WHERE parent_id=?', (parent_id,)
                    ).fetchone()[0]
                    if not remaining:
                        self._conn().execute(
                            'DELETE FROM comments WHERE id=?', (parent_id,)
                        )
        self._conn().commit()
        return True

    # ── Notifications ──────────────────────────────────────────

    def add_notification(self, user_id: int, ntype: str, from_username: str,
                         info_hash: str, torrent_name: str, comment_id: int):
        c = self._conn()
        c.execute(
            'INSERT INTO notifications'
            ' (user_id,type,from_username,info_hash,torrent_name,comment_id,created_at)'
            ' VALUES (?,?,?,?,?,?,?)',
            (user_id, ntype, from_username, info_hash.upper(),
             torrent_name, comment_id, self._ts())
        )
        c.commit()
        # Prune to 100 per user
        c.execute(
            'DELETE FROM notifications WHERE user_id=? AND id NOT IN'
            ' (SELECT id FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100)',
            (user_id, user_id)
        )
        c.commit()

    def get_unread_notifications(self, user_id: int, limit: int = 5) -> list:
        return self._conn().execute(
            'SELECT * FROM notifications WHERE user_id=? AND is_read=0'
            ' ORDER BY id DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()

    def get_all_notifications(self, user_id: int) -> list:
        return self._conn().execute(
            'SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100',
            (user_id,)
        ).fetchall()

    def get_unread_count(self, user_id: int) -> int:
        return self._conn().execute(
            'SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0',
            (user_id,)
        ).fetchone()[0]

    def mark_notification_read(self, notif_id: int, user_id: int):
        self._conn().execute(
            'UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?',
            (notif_id, user_id)
        )
        self._conn().commit()

    def mark_all_notifications_read(self, user_id: int):
        self._conn().execute(
            'UPDATE notifications SET is_read=1 WHERE user_id=?', (user_id,)
        )
        self._conn().commit()

    def get_notification(self, notif_id: int, user_id: int):
        return self._conn().execute(
            'SELECT * FROM notifications WHERE id=? AND user_id=?',
            (notif_id, user_id)
        ).fetchone()

    # ── Events ─────────────────────────────────────────────────

    def list_events(self, limit: int = 200,
                    q_actor: str = '', q_action: str = '',
                    q_target: str = '', q_any: str = '',
                    offset: int = 0) -> tuple:
        """Search events with optional filters. Returns (rows, total) newest-first."""
        clauses = []
        params  = []
        if q_any:
            like = f'%{q_any}%'
            clauses.append('(actor LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ?)')
            params += [like, like, like, like]
        if q_actor:
            clauses.append('actor LIKE ?');  params.append(f'%{q_actor}%')
        if q_action:
            clauses.append('action LIKE ?'); params.append(f'%{q_action}%')
        if q_target:
            clauses.append('target LIKE ?'); params.append(f'%{q_target}%')
        where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
        rows = self._conn().execute(
            f'SELECT * FROM events {where} ORDER BY id DESC LIMIT ? OFFSET ?',
            params + [limit, offset]
        ).fetchall()
        total = self._conn().execute(
            f'SELECT COUNT(*) FROM events {where}', params
        ).fetchone()[0]
        return [dict(r) for r in rows], total




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

APPLE_TOUCH_ICON_B64 = 'iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAYAAAA9zQYyAAAPnElEQVR42u2de3BU5RnGn7O7SYAQFgJIuIQ7AduqhDsCMk4V2mKhyiXh0nFqZ1qtl1qxilVHB0RQQEAwXG21pU1nyiUwBhTHqbcqARzAKkW5idxEMDFZEhLYS/8IC7t7vnPN3s7H8/wDOWf37Hn3/e1znu87Z/coSKByWrULgaJi5Ks5pyRq2woBpmQCXCHIlExgKwSZkglshSBTMoHtIsxUusoOay7CTMkEtUKQKZkiiIswUzK5tYswUzJB7eJbRMkkF92ZksmlXYSZkglqF2GmZIKaGZqSN0PTnSmnuzQdmpLToenOlAwuTYem5HNoujMli0vToSk5MzRFEWiKSjMpzM8UHZqiCDRFEWiKItAUgaYoAk1RBJqiCDRFEWiKQFMUgaYoAk1RBJqiCDRFoCmKQFMUgaYoAk1RBJq6JuSRubhvVnrL7T43797qcazPeZLmS7JNaa4TIJC9vmseaAsNrrSx+dxUAyB7fQTaXKMrE/jSuclovOz1EWj9JptpcJWNl2xjFwA7zZe9PgJtv9Gi5lbbeGmvBQhsN172+gi0fqMrTTS4OoG75TUBQK6ZxsteH4HWb7ZRo42aHC8H01pv2PjIpsteH4G25lpGjU6mgxk13sxMglT1pQPYaQG0CdeqakKTa2zsUqsmNN8M2NLWl2qoUw60Acx6jlVtocE+C7uUYwEArwlHy5W8vrSCOqVAx8Bs1rWqDZosam6phd2aagBBKwuN7yV5fZpunSqoUwa0DsxarlVtssmGzc27tzpyP6xCoNf8yI0NkLw+Q7dOBdQpAdoEzHquZbvRsc222HSzjfeagNnp9Rm5dcqgTjrQFmHWci2fjUOtsNk2mh7b/JyYpt8qeX16bp1yqF0Ogbkmkc02s14nt/oi9vFWyeurMYhLVaL6k3GlYNKBbiLM4TfWd/mNLkV6KLwvPgATJK/PJ4hEaQe1KwUww2azYbfRZt3JhouFNUPy+kRubRZqJBPqVHxjpdJGs9PFsa7l+kojsnXO5f1vFVGXN+b/VZczdSVMXn/tCIc2mGuGBM2WvT4R2EZOrfUhT7hLu5IIs96hWAaYZazPLtQpix7JjBx6h2KtTNlkWcmNNdVnr7zRdaW9x7E+Q/kE8QOpjB4Jm4fWuUZDy71iTyiUJqvhkY2OlU7jZa/PjMJ5Oqww1N6Yf4XXtSRifjpZ03Zm3CvuzU6zo4+T6zMTPfTGDVUmxhiOAtqo4BoJm30t1KeVp6tTtTMJydAaMxtVqS5WS6287cdZzJiy1xfvD7UwS3+z0lse79iRyl9OSrh7WT2REG785Teb9Vlz6dj56ci56aSJv21HSaW4A53MC1FSpHJik768JNqhzU5lOXWwJHt98RocJm22g5GDYuSgKAJNUQSaogg0RaApikBTFIGmKCcDHb7+NXw9bOx1suHrZ3Mg/omqdJfs9VlR5LXRlq6LTmugZb1dWIRkry+pijcvjBwUI0eclPDDst1LJON0aaXs9ZmNG84HOuYwopUzZYkdMtaXCONS5Wcnf6cwZS7G+lI6GJQ2clhxMSc2Xfb6zMBsyZ0dB7SFw0msi0W+WU6JHTLWZwbmSFly50TNhiUzcphxschDc0oGTk0YMMlen9bRRvRhTYk7JxxonU+h1okIp+VN2euzkptF9bZJpjsnxaE1Zjz0Ds1OhlrG+qzCrHf0SviJt1TMcugdmvWa7pTGy1rfVJMwpyRqJBVoC9FDr+m2B1Jmc2MT8uU6yevTu9+K0b1WkhI1ku7QOtHDStPTzc0iXWuz5PXZgTnpNw5KauRoItRNcjMjd4rTXaL+LXl9aQ0zwPsUWm0271PI+xTahjq20byTbHrVxzvJWoDarJsZNd+Su+kc6nmvb2NXTjnMKQdaALVZN9NqfGzz9SDQkugsXiuNx3p1/taatpKtPlWNqfySR8qBNgG1npvpNV4PACO1Mljv1Vmm6VrXQn2p/sZSWgCtAbVe4+02vynyGiwzA7LU9aXD1+/SBmgLbm2m8U2FwGthvegkgqZryV4fgbbv1rGNT7aDGTZaq9my10egrYGt1XwRAPF0sDYajxVGCzONlr0+Ah2/xhtBYKQ2Jh4Tt0bLXh+Bttd8swDYleYgL55Nlr0+Am2v8U2FwNQlj4lstOz1Eej4AWBbqWyw7PUR6ARD4ITmyl4fgaauefG37SgCTVEEmqIINEURaIpAUxSBpigCTVEEmqIINEWgKYpAUxSBpqiEyGPnSRke4NBiL7IyopfPKr2A1967KHzObTd4sO7+bNXyh/96Af/8SPycOwozsPa3LaKWBYJA30dqcL6+8SLBmws82PiIersz113A3z+M3q6VxxpJa1sA4A8C/kAIdQ3A93UhnK0J4quzQew7FsC7+/048m3Q1GuMGjkC5eVlquUPPvQHvP66+Bd8u3TujPLyMvTo0V21buXKNXjs8T9pw+Dx4MsvPkO7dm2F6wcOGo6DBw+plu/bu0v4enY1pWg63nxze/Ic+pIf2POVX7V8aG/tz8fQXuJ1w3q7NZ8zRLBu/4nAFZjT1iVcQLMMBbktFfS8zoWhvT0oGp6J54ub46PZOSibma37XtlVfn4+tm3bIoSrpGSVLswAMGbMbZowA8DUqUXyRo6KQ4Emw9m4XLuxw/p4TL2u0zSsjwdlM7Px9F3NoCjx2WbXrvnYtnUzunXrqlq3bFkJZj3xlOE2jIAtLpoEJV47nH5Aqx26YxsXuuS6hBGlfzcxuD2vc6FdjvpNys5S8IMu6g9BxWG/FFlPUYD7x2Rh/tTmTd5W9+7d8Oa2LejaNV+1bunS5XjyqWcMt9G6dWv8ZOwY3cd06dIFt4waKV+GBoBdhwMIhgCXEus+bqyviM6Ihd3cqrwdG1XK91yKWjaopxsewcdt56H0Bjqcx90uwNtCQY/2Lozq58HdozPRsbW6oLtvycSBUwH85d2Ltl6vZ88eKC8vQ+dOnVTrXlq8FM8++5yp7UyaeCeysjJNuPgUvPf+B1HLbuo/WPPxS5YsxD2/ulttfp26o7a2Nn0c2lcfwv4TAVMRInbZicqgYRwRbefYuSDOVDvjG2OBIFB5PoRPjgawZFsDhj99HusrLgkf++QvmqFNtvVDee/evbBt6xYhzAsWLjYNcxhUlXns3KVaNmHCz9GiRQv5IgcA7DwsytEew8FiyfYGwwGjKI9XHHJu3Ki/FMJDr9Xh3f3qGlo2U/CbH2dZ2l5BQR9sLd+Mjh3zVOteeHER5sx53tIHY/DgQeoZqIcfRVVV9O/YZGdnY/z4O+QEesdBdXP65Lmi3EZRgME93VEzJKUfXUJ13VWn/VFXN5pnXn1OhhsY0MMtiBvOHhAGQ8Az6+sREhxkftrffPrrW1CA8jfKkJfXQbVu3vwFmDt3vqX9Eg0GP//8f/js8/3YsqXclJtLAbTIMRUFGBLhuAUd3WgdAfjeYwFcuBjC7iOBqGmugREA3xADuAwOHdYXpwLYf1L9wezXyY32rczFjgceuA8dOlynWj537nzMm/eixcGpguKiSarlGzZsvPzvJtW60beMEsYcxwN9pjqEY+fUJwmG9nFHxAl3TExphHJHDJxDIyKGKLZU1YZw6EwQMmjPV+IjTedc++2YPXsuXnhxkeXnjRo5Avn56tmRjZsa71L3wYf/wdmz56KhcblQVDRZPqC1XDMyM8cO7sLzyBUxcWVI1HMEceOwX3iodqLO+cSF5La0N8e7Z89evLT4ZVvPFcWNvXv34ciRo42D20AAZZu3OCZ2xAFotdvc2NWNZhmKynlDoasOvedYAA0Rg/6BPdxwX96bIb3kPKFy5U2P87mJwsL+WL5sCVwua+1s3rw5JkxQD/A2bCyLduuYvwGgb98CFBb2lw9o0cAwPKjL87qQ3/bqS3x5OoDva0NXBoeRp89bNms8kdInzyV0qp2H/NIALTqRBADf+ewfgmbMmGoZ6vHj70DLli3VcWPj5qi/P/64AqdPf6N63PRpRfIBffhMUNiIYX3cUVkaACpipvliXXdob7fwdHfDJWDf1/I4dGF38WUAJyvNjRFE88NhqF9ZvtQ01NMEsWHXrt04fvx49OxMMIiyMnXsmDjxLmRkZKTVexuXK2QqDvvxs/7RhQ3p5UG7nKCuyzbm76yIAaQH9X7RIMqPS5IY9A+7uHF9ZzXQB04FNLN1rP627h/YuGkz5s9TnziZPr0YigL87v7fIxjU/oB06tQRo0ffolo+ePAg1FSfNbUfbdvmYuzY2/HGG1vlcehGUNXuOainG8NjHHrHwejH7TocQCAYPTAUn1CRw53dLmD25GbCddv2WvvElpSswuOznhQ777RilLyi79RFUyZbztzCQWVxeg0O4wL0jkPis1+RTnS6Kqg65e2rD0XNyXbwKlGZO/II4HS1yFJQck8LjOirPiierw9h9TsNlre5YsVqzUtCp00rxoqSlzWhLS6Oz7Tb2LG3Izc3Vy6gP/s6gLqGkEEsCZh296j8FgJ2H3aeQ7sUoHW2ggE93HhkXBY+np2DCYPEeXNuWT2qau0NCFeuXIM/PvaE2D2nFgmhLizsj+uv7xeXOjMzMzFp4p1yZWh/EPjkaACj+nkszYaE3f3Xt2pf5XXgVAA1FxI7Ab1oRnMsmmF8GecvX6nF2//1x2VbYb3+/kXbV9qFtWrVWoRCwMIF84RQK4qCe+978EqmniaYe25ouIievfrB59O/y/IH77+Dm266MeY1pmD1mlflcWgzOVfLiSsO+m09z+kKBIHnNtVjVumFuGxv9eq1ePTRWRrxYgpWrlgGl8uFjIwMTBQ46lvbtxvCDADrBafCBw4cgIKCPrIBrQ1mzYUQDpwSg/ltTQhHzwZtbdeJCoaA7Z9ewvgF57H8rYa4nv1cveZVzJz5uCbUq1Yux9ixtwu/ZrX+XxtNvcaG9ZsQEux0upw5jNsX2z45GoA/COFF+bsvfxlAE9qDfvRon2nL+dPVfQNBoK4hhO/rQjhTHcSxs0Hs+zqA7Z/6cfy7xF2TsmbtnwEACxfOV31dqqhoMkaMvFn1nNraWry1/W1T2z9x8iQqKnZh2LAhqm3PmTNPd6owGeI9ViipxN/loAg0RRFoiiLQFEWgKQJNUQSaogg0RRFoiiLQ1DUJtK/mnMK3gZJBvppzCh2aYuSgKAJNUckCmjmakiE/06EpeSMHXZpyujvToSm5B4V0acrJ7kyHpuR2aLo05WR31nRoQk05EWbdyEGoKafBzAxNyZ+h6dKUU93ZlEMTasopMAOAJVj5s2FUuoJsK0PTral0htnWoJBQU+kKs+XIwQhCpSvIcQGaYFPpAnJcgSbYVKpBTgjQBJxK9Tjs/5f98Az5meLjAAAAAElFTkSuQmCC'

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
        manage_btn = f'<div style="text-align:right;margin-bottom:8px"><a href="/manage/dashboard" style="{_btn_style}">&#9881;&#65039; Manage</a></div>'
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
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
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
    request_queue_size = 128
    ssl_context = None
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def get_request(self):
        conn, addr = self.socket.accept()
        if self.ssl_context:
            conn.settimeout(10)
            try:
                conn = self.ssl_context.wrap_socket(conn, server_side=True)
            except Exception:
                conn.close()
                raise
            conn.settimeout(None)  # clear — timeout was only needed for the handshake
        return conn, addr


def start_http_server(host: str, port: int, ssl_ctx=None, label='HTTP'):
    server = ThreadingHTTPServer((host, port), TrackerHTTPHandler)
    if ssl_ctx:
        # Store context for get_request() — handshake timeout applied per-connection
        server.ssl_context = ssl_ctx
    log.info('%s tracker listening on %s:%d/announce', label, host or '0.0.0.0', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def start_http6_server(host6: str, port: int, ssl_ctx=None, label='HTTP'):
    """Start an IPv6 HTTP(S) tracker listener."""
    server = IPv6HTTPServer((host6, port, 0, 0), TrackerHTTPHandler)
    if ssl_ctx:
        server.ssl_context = ssl_ctx
    log.info('%s tracker listening on [%s]:%d/announce (IPv6)', label, host6 or '::', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


class IPv6RedirectServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 128
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
        elif path.startswith('/manage/admin/set-password/'):
            self._get_admin_set_password(path[len('/manage/admin/set-password/'):])
        elif path == '/manage/admin/db-backup':
            self._get_db_backup()
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
        elif path == '/manage/notifications':
            self._get_notifications()
        elif path == '/manage/messages':
            self._get_messages()
        elif path.startswith('/manage/messages/'):
            self._get_message_thread(path[len('/manage/messages/'):])
        elif path == '/manage/bounty':
            self._get_bounty_board()
        elif path == '/manage/leaderboard':
            self._get_leaderboard()
        elif path.startswith('/manage/bounty/'):
            bid_str = path[len('/manage/bounty/'):]
            if bid_str.isdigit():
                self._get_bounty_detail(int(bid_str))
            else:
                self._send_html('<h1>Not Found</h1>', 404)
        elif path.startswith('/manage/torrent/lock/'):
            ih = path[len('/manage/torrent/lock/'):]
            self._get_toggle_comments_lock(ih, True)
        elif path.startswith('/manage/torrent/unlock/'):
            ih = path[len('/manage/torrent/unlock/'):]
            self._get_toggle_comments_lock(ih, False)
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
        elif path == '/manage/admin/set-password':
            self._post_admin_set_password()
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
        elif path == '/manage/comment/post':
            self._post_comment()
        elif path == '/manage/comment/edit':
            self._post_comment_edit()
        elif path == '/manage/comment/delete':
            self._post_comment_delete()
        elif path.startswith('/manage/notifications/read/'):
            nid = path[len('/manage/notifications/read/'):]
            self._post_notification_read(nid)
        elif path == '/manage/notifications/read-all':
            self._post_notification_read_all()
        elif path == '/manage/messages/send':
            self._post_dm_send()
        elif path == '/manage/messages/reply':
            self._post_dm_reply()
        elif path == '/manage/messages/delete':
            self._post_dm_delete()
        elif path == '/manage/messages/mark-read':
            self._post_dm_mark_read()
        elif path == '/manage/messages/block':
            self._post_dm_block()
        elif path == '/manage/messages/unblock':
            self._post_dm_unblock()
        elif path == '/manage/messages/broadcast':
            self._post_dm_broadcast()
        elif path == '/manage/messages/toggle-dms':
            self._post_dm_toggle()

        elif path == '/manage/comment/delete-all':
            self._post_delete_all_comments()
        elif path == '/manage/admin/delete-all-comments-global':
            self._post_delete_all_comments_global()
        elif path == '/manage/admin/system-wipe':
            self._post_system_wipe()
        elif path == '/manage/admin/db-restore':
            self._post_db_restore()
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
        elif path == '/manage/bounty/create':
            self._post_bounty_create()
        elif path == '/manage/bounty/contribute':
            self._post_bounty_contribute()
        elif path == '/manage/bounty/claim':
            self._post_bounty_claim()
        elif path == '/manage/bounty/confirm':
            self._post_bounty_confirm()
        elif path == '/manage/bounty/reject':
            self._post_bounty_reject()
        elif path == '/manage/bounty/vote':
            self._post_bounty_vote()
        elif path == '/manage/bounty/comment':
            self._post_bounty_comment()
        elif path == '/manage/points/transfer':
            self._post_points_transfer()
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
        events, ev_total = REGISTRATION_DB.list_events(
            limit=200,
            q_any=qs.get('eq', [''])[0].strip(),
            q_actor=qs.get('eactor', [''])[0].strip(),
            q_action=qs.get('eaction', [''])[0].strip(),
            q_target=qs.get('etarget', [''])[0].strip(),
        )
        trackers     = REGISTRATION_DB.list_magnet_trackers()
        settings     = REGISTRATION_DB.get_all_settings()
        msg      = urllib.parse.unquote(qs.get('msg',      [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        tab      = qs.get('tab',      [''])[0]
        self._send_html(_render_admin(user, all_torrents, all_users, events, trackers, settings,
                                      page=page, total_pages=total_pages, total=total,
                                      upage=upage, utotal_pages=utotal_pages, utotal=utotal,
                                      uquery=uquery, msg=msg, msg_type=msg_type, tab=tab,
                                      new_username=urllib.parse.unquote(qs.get('new_username',[''])[0]),
                                      ev_total=ev_total,
                                      eq=qs.get('eq',[''])[0],
                                      eactor=qs.get('eactor',[''])[0],
                                      eaction=qs.get('eaction',[''])[0],
                                      etarget=qs.get('etarget',[''])[0]))

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
        REGISTRATION_DB.daily_login_check(user['id'])
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
                REGISTRATION_DB.award_upload_points(user['id'], name, ih)
                REGISTRATION_DB.check_auto_promote(user['id'])
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

    def _get_notifications(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        self._send_html(_render_notifications_page(user))

    def _get_bounty_board(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) == 'basic': return self._redirect('/manage/dashboard')
        qs   = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        sort = qs.get('sort', ['points'])[0]
        filt = qs.get('status', [''])[0]
        page = max(1, int(qs.get('page', ['1'])[0]) if qs.get('page', ['1'])[0].isdigit() else 1)
        per_page = 20
        status_filter = filt if filt in ('open', 'pending', 'fulfilled', 'expired') else None
        bounties, total = REGISTRATION_DB.list_bounties(
            status=status_filter, sort=sort, page=page, per_page=per_page)
        total_pages = max(1, (total + per_page - 1) // per_page)
        msg      = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        self._send_html(_render_bounty_board(user, bounties, total, page, total_pages,
                                             sort=sort, status=filt,
                                             msg=msg, msg_type=msg_type))

    def _get_leaderboard(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) == 'basic': return self._redirect('/manage/dashboard')
        top_n = int(REGISTRATION_DB.get_setting('leaderboard_top_n', '10'))
        data  = REGISTRATION_DB.get_leaderboard(top_n)
        self._send_html(_render_leaderboard(user, data, top_n))

    def _get_bounty_detail(self, bounty_id: int):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) == 'basic': return self._redirect('/manage/dashboard')
        bounty = REGISTRATION_DB.get_bounty(bounty_id)
        if not bounty: return self._send_html('<h1>Bounty Not Found</h1>', 404)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg      = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        contributions = REGISTRATION_DB.get_bounty_contributions(bounty_id)
        votes         = REGISTRATION_DB.get_bounty_votes(bounty_id)
        comments      = REGISTRATION_DB.get_bounty_comments(bounty_id)
        torrent = None
        if bounty['claimed_infohash']:
            torrent = REGISTRATION_DB.get_torrent(bounty['claimed_infohash'])
        threshold = int(REGISTRATION_DB.get_setting('bounty_confirm_votes', '3'))
        self._send_html(_render_bounty_detail(user, bounty, contributions, votes,
                                              comments, torrent, threshold,
                                              msg=msg, msg_type=msg_type))


    def _post_comment(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        ih     = fields.get('info_hash', '').strip().upper()
        text   = fields.get('body', '').strip()[:2000]
        parent = fields.get('parent_id', '').strip()
        parent_id = int(parent) if parent.isdigit() else None
        if not ih or not text:
            return self._redirect(f'/manage/torrent/{ih.lower()}')
        t = REGISTRATION_DB.get_torrent(ih)
        if not t: return self._redirect('/manage/dashboard')
        # Block if comments system is disabled globally
        if REGISTRATION_DB.get_setting('comments_enabled', '1') != '1':
            return self._redirect(f'/manage/torrent/{ih.lower()}')
        # Block posting if comments are locked on this torrent
        if t['comments_locked']:
            return self._redirect(f'/manage/torrent/{ih.lower()}?msg=locked')
        uname = user['username']
        tname = t['name']
        # Validate @mentions — warn on unknowns but still post
        mentioned = set(_MENTION_RE.findall(text))
        unknown = [m for m in mentioned
                   if m != uname and not REGISTRATION_DB.get_user(m)]
        if unknown:
            unknown_list = ', '.join(f'@{u}' for u in sorted(unknown))
            warn_param = urllib.parse.quote(unknown_list)
            # Still save the comment; just notify the poster
            cid = REGISTRATION_DB.add_comment(ih, user['id'], uname, text, parent_id)
            REGISTRATION_DB.award_comment_points(user['id'], cid)
            _deliver_notifications(cid, ih, tname, uname, text, parent_id)
            return self._redirect(
                f'/manage/torrent/{ih.lower()}?warn={warn_param}#comment-{cid}')
        cid = REGISTRATION_DB.add_comment(ih, user['id'], uname, text, parent_id)
        REGISTRATION_DB.award_comment_points(user['id'], cid)
        _deliver_notifications(cid, ih, tname, uname, text, parent_id)
        self._redirect(f'/manage/torrent/{ih.lower()}#comment-{cid}')

    def _post_comment_edit(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        cid    = fields.get('comment_id', '').strip()
        ih     = fields.get('info_hash', '').strip().upper()
        text   = fields.get('body', '').strip()[:2000]
        if not cid.isdigit() or not text:
            return self._redirect(f'/manage/torrent/{ih.lower()}')
        role = _user_role(user)
        REGISTRATION_DB.edit_comment(int(cid), user['id'], text, role in ('super','admin'))
        # Validate @mentions — warn on unknowns the same as post
        uname = user['username']
        mentioned = set(_MENTION_RE.findall(text))
        unknown = [m for m in mentioned
                   if m != uname and not REGISTRATION_DB.get_user(m)]
        if unknown:
            unknown_list = ', '.join(f'@{u}' for u in sorted(unknown))
            warn_param = urllib.parse.quote(unknown_list)
            return self._redirect(
                f'/manage/torrent/{ih.lower()}?warn={warn_param}#comment-{cid}')
        self._redirect(f'/manage/torrent/{ih.lower()}#comment-{cid}')

    def _post_comment_delete(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        cid    = fields.get('comment_id', '').strip()
        ih     = fields.get('info_hash', '').strip().upper()
        if not cid.isdigit():
            return self._redirect(f'/manage/torrent/{ih.lower()}')
        role = _user_role(user)
        REGISTRATION_DB.delete_comment(int(cid), user['id'], role in ('super','admin'))
        self._redirect(f'/manage/torrent/{ih.lower()}')

    def _post_notification_read(self, nid_str: str):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if nid_str.isdigit():
            n = REGISTRATION_DB.get_notification(int(nid_str), user['id'])
            if n:
                REGISTRATION_DB.mark_notification_read(int(nid_str), user['id'])
                return self._redirect(
                    f'/manage/torrent/{n["info_hash"].lower()}#comment-{n["comment_id"]}')
        self._redirect('/manage/notifications')

    def _post_delete_all_comments_global(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) not in ('super', 'admin'):
            return self._redirect('/manage/dashboard')
        count = REGISTRATION_DB.delete_all_comments_global(user['username'])
        self._redirect('/manage/admin?tab=danger&msg=' +
                       urllib.parse.quote(f'{count} comment(s) and all notifications deleted'))

    def _post_system_wipe(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) != 'super':
            return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        # Double-check the confirmation token server-side
        if fields.get('confirm_token', '').strip() != 'SYSTEMWIPE':
            self._redirect('/manage/admin?tab=danger&msg=' +
                           urllib.parse.quote('System wipe cancelled — confirmation token mismatch'))
            return
        REGISTRATION_DB.system_wipe(user['username'])
        # Invalidate all other sessions; keep the super session alive
        self._redirect('/manage/admin?tab=danger&msg=' +
                       urllib.parse.quote('System wipe complete. All data removed except your account.'))

    def _post_delete_all_comments(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) not in ('super', 'admin'):
            return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        ih = fields.get('info_hash', '').strip().upper()
        if not ih: return self._redirect('/manage/dashboard')
        count = REGISTRATION_DB.delete_all_comments(ih, user['username'])
        msg = urllib.parse.quote(f'{count} comment(s) deleted')
        self._redirect(f'/manage/torrent/{ih.lower()}?msg={msg}&msg_type=success')

    def _post_notification_read_all(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        REGISTRATION_DB.mark_all_notifications_read(user['id'])
        self._redirect('/manage/notifications')

    def _get_toggle_comments_lock(self, ih: str, lock: bool):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) not in ('super', 'admin'):
            return self._redirect(f'/manage/torrent/{ih.lower()}')
        t = REGISTRATION_DB.get_torrent(ih.upper())
        if not t: return self._redirect('/manage/dashboard')
        REGISTRATION_DB.set_comments_locked(ih, lock, user['username'])
        self._redirect(f'/manage/torrent/{ih.lower()}')

    def _get_torrent_detail(self, ih: str):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        t = REGISTRATION_DB.get_torrent(ih.upper())
        if not t: return self._send_html('<h1>Torrent not found</h1>', 404)
        referer = self.headers.get('Referer', '')
        back = urllib.parse.urlparse(referer).path or '/manage/dashboard'
        if back.startswith('/manage/torrent'): back = '/manage/dashboard'
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg      = urllib.parse.unquote(qs.get('msg',      [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        warn     = urllib.parse.unquote(qs.get('warn',     [''])[0])
        self._send_html(_render_torrent_detail(user, t, back_url=back,
                                               msg=msg, msg_type=msg_type, warn=warn))

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
            err = urllib.parse.quote('Password does not meet requirements: ' + '; '.join(pw_errors))
            un  = urllib.parse.quote(username)
            return self._redirect(f'/manage/admin?tab=adduser&msg={err}&msg_type=error&new_username={un}')
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

    def _get_db_backup(self):
        user = self._get_session_user()
        if not user or user['username'] != SUPER_USER:
            return self._redirect('/manage/admin')
        try:
            gz_data = REGISTRATION_DB.backup_to_bytes()
        except Exception as e:
            logging.error('DB backup failed: %s', e)
            return self._redirect('/manage/admin?tab=database&msg='
                                  + urllib.parse.quote('Backup failed: ' + str(e)))
        import datetime
        stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        fname = f'tracker-backup-{stamp}.db.gz'
        REGISTRATION_DB._log(user['username'], 'db_backup', '', 'Database backup downloaded')
        self.send_response(200)
        self.send_header('Content-Type', 'application/gzip')
        self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
        self.send_header('Content-Length', str(len(gz_data)))
        self.end_headers()
        self.wfile.write(gz_data)

    def _post_db_restore(self):
        user = self._get_session_user()
        if not user or user['username'] != SUPER_USER:
            return self._redirect('/manage/admin')
        body = self._read_body()
        fields, files = _parse_multipart(self.headers, body)
        file_entry = files.get('db_file')
        if not file_entry:
            return self._redirect('/manage/admin?tab=database&msg='
                                  + urllib.parse.quote('No file received.'))
        # _parse_multipart stores files as (filename, bytes)
        gz_data = file_entry[1] if isinstance(file_entry, tuple) else file_entry
        try:
            REGISTRATION_DB.restore_from_bytes(gz_data, user['username'])
        except ValueError as e:
            return self._redirect('/manage/admin?tab=database&msg='
                                  + urllib.parse.quote(str(e)) + '&msg_type=error')
        except Exception as e:
            logging.error('DB restore failed: %s', e)
            return self._redirect('/manage/admin?tab=database&msg='
                                  + urllib.parse.quote('Restore failed: ' + str(e)) + '&msg_type=error')
        self._redirect('/manage/admin?tab=database&msg='
                       + urllib.parse.quote('Database restored successfully. Please verify the site.')
                       + '&msg_type=success')

    def _get_admin_set_password(self, target_username: str):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if not (user['is_admin'] or user['username'] == SUPER_USER):
            return self._redirect('/manage/dashboard')
        target = REGISTRATION_DB.get_user(target_username)
        if not target or target['username'] == SUPER_USER:
            return self._redirect('/manage/admin')
        # Admins cannot change other admin passwords
        if user['username'] != SUPER_USER and target['is_admin']:
            return self._redirect('/manage/admin')
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg      = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        self._send_html(_render_admin_set_password_page(
            user, target, msg=msg, msg_type=msg_type))

    def _post_admin_set_password(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        is_super = user['username'] == SUPER_USER
        if not (user['is_admin'] or is_super):
            return self._redirect('/manage/dashboard')
        body   = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target   = fields.get('username', '').strip()
        new_pass = fields.get('new_password', '')
        conf     = fields.get('confirm_password', '')
        back_url = f'/manage/admin/set-password/{urllib.parse.quote(target)}'
        if not target or target == SUPER_USER:
            return self._redirect('/manage/admin')
        t_user = REGISTRATION_DB.get_user(target)
        if not t_user:
            return self._redirect('/manage/admin')
        if not is_super and t_user['is_admin']:
            return self._redirect('/manage/admin')
        if new_pass != conf:
            err = urllib.parse.quote('Passwords do not match.')
            return self._redirect(f'{back_url}?msg={err}&msg_type=error')
        pw_settings = REGISTRATION_DB.get_all_settings()
        pw_errors   = _validate_password(new_pass, pw_settings)
        if pw_errors:
            err = urllib.parse.quote('Password does not meet requirements: ' + '; '.join(pw_errors))
            return self._redirect(f'{back_url}?msg={err}&msg_type=error')
        REGISTRATION_DB.change_password(target, new_pass, user['username'])
        ok = urllib.parse.quote(f'Password changed for {target}.')
        self._redirect(f'/manage/admin/user/{urllib.parse.quote(target)}?msg={ok}&msg_type=success')

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
        ledger    = REGISTRATION_DB.get_points_ledger(user['id'], 50)
        bounty_data = REGISTRATION_DB.list_bounties_by_user(user['username'])
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg      = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        self._send_html(_render_user_detail(user, user, torrents, history, is_super,
                                            allowlist=allowlist, is_own_profile=True,
                                            page=page, total_pages=total_pages,
                                            total=total, base_url='/manage/profile',
                                            ledger=ledger, bounty_data=bounty_data,
                                            msg=msg, msg_type=msg_type))

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
        elif form_id == 'comments_enabled':
            val = '1' if fields.get('comments_enabled') == '1' else '0'
            REGISTRATION_DB.set_setting('comments_enabled', val, user['username'])
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
            # Legacy reward form — no-op, superseded by points_earn
            pass
        elif form_id == 'points_earn':
            for key, default, lo, hi in [
                ('points_login_daily',  '1',  0, 999),
                ('points_streak_7day',  '1',  0, 999),
                ('points_streak_30day', '4',  0, 999),
                ('points_upload',       '25', 0, 9999),
                ('points_comment',      '1',  0, 999),
                ('points_comment_cap',  '10', 0, 999),
            ]:
                try: v = str(max(lo, min(hi, int(fields.get(key, default)))))
                except: v = default
                REGISTRATION_DB.set_setting(key, v, user['username'])
        elif form_id == 'points_spend':
            for key, default, lo, hi in [
                ('points_invite_cost',       '1000', 1, 99999),
                ('points_transfer_fee_pct',  '25',   0, 99),
                ('auto_promote_threshold',   '100',  1, 99999),
                ('points_penalty_torrent',   '25',   0, 9999),
                ('points_penalty_comment',   '1',    0, 999),
            ]:
                try: v = str(max(lo, min(hi, int(fields.get(key, default)))))
                except: v = default
                REGISTRATION_DB.set_setting(key, v, user['username'])
            val = '1' if fields.get('auto_promote_enabled') == '1' else '0'
            REGISTRATION_DB.set_setting('auto_promote_enabled', val, user['username'])
        elif form_id == 'bounty_settings':
            for key, default, lo, hi in [
                ('bounty_min_cost',       '50',  1, 99999),
                ('bounty_refund_pct',     '25',  0, 100),
                ('bounty_claimer_pct',    '70',  1, 100),
                ('bounty_uploader_pct',   '15',  0, 100),
                ('bounty_reject_penalty', '10',  0, 9999),
                ('bounty_expiry_days',    '90',  1, 3650),
                ('bounty_confirm_votes',  '3',   1, 999),
                ('bounty_pending_hours',  '48',  1, 720),
            ]:
                try: v = str(max(lo, min(hi, int(fields.get(key, default)))))
                except: v = default
                REGISTRATION_DB.set_setting(key, v, user['username'])
        elif form_id == 'leaderboard_settings':
            try: v = str(max(3, min(100, int(fields.get('leaderboard_top_n', '10')))))
            except: v = '10'
            REGISTRATION_DB.set_setting('leaderboard_top_n', v, user['username'])
        elif form_id == 'admin_grant_settings':
            try: v = str(max(1, min(999999, int(fields.get('admin_max_point_grant', '1000')))))
            except: v = '1000'
            REGISTRATION_DB.set_setting('admin_max_point_grant', v, user['username'])
        elif form_id == 'dm_settings':
            val = '1' if fields.get('dm_enabled') == '1' else '0'
            REGISTRATION_DB.set_setting('dm_enabled', val, user['username'])
            for key, default, lo, hi in [
                ('dm_cost',        '5',  0, 9999),
                ('dm_daily_limit', '10', 1, 999),
            ]:
                try: v = str(max(lo, min(hi, int(fields.get(key, default)))))
                except: v = default
                REGISTRATION_DB.set_setting(key, v, user['username'])
        self._redirect('/manage/admin?tab=economy' if form_id in ('points_earn','points_spend','bounty_settings','leaderboard_settings','admin_grant_settings','dm_settings') else '/manage/admin')

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
            max_grant = int(REGISTRATION_DB.get_setting('admin_max_point_grant', '1000'))
            delta = max(-max_grant, min(max_grant, delta))
            REGISTRATION_DB.adjust_points(target_username, delta, user['username'])
        referer = fields.get('referer', '')
        self._redirect(referer if referer.startswith('/manage/') else '/manage/admin')

    def _post_bounty_create(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) == 'basic': return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        description = fields.get('description', '').strip()[:500]
        if not description:
            return self._redirect('/manage/bounty?msg=empty')
        ok, result = REGISTRATION_DB.create_bounty(user['username'], description)
        if not ok:
            return self._redirect(f'/manage/bounty?msg={urllib.parse.quote(result)}')
        self._redirect(f'/manage/bounty/{result}')

    def _post_bounty_contribute(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) == 'basic': return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        try:
            bounty_id = int(fields.get('bounty_id', '0'))
            amount    = int(fields.get('amount', '0'))
        except ValueError:
            return self._redirect('/manage/bounty')
        ok, msg = REGISTRATION_DB.contribute_to_bounty(bounty_id, user['username'], amount)
        q = urllib.parse.quote(msg)
        self._redirect(f'/manage/bounty/{bounty_id}?msg={q}&msg_type={"success" if ok else "error"}')

    def _post_bounty_claim(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) == 'basic': return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        try:
            bounty_id = int(fields.get('bounty_id', '0'))
        except ValueError:
            return self._redirect('/manage/bounty')
        info_hash = fields.get('info_hash', '').strip()
        ok, msg = REGISTRATION_DB.claim_bounty(bounty_id, user['username'], info_hash)
        q = urllib.parse.quote(msg)
        self._redirect(f'/manage/bounty/{bounty_id}?msg={q}&msg_type={"success" if ok else "error"}')

    def _post_bounty_confirm(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        try:
            bounty_id = int(fields.get('bounty_id', '0'))
        except ValueError:
            return self._redirect('/manage/bounty')
        ok, msg = REGISTRATION_DB.confirm_bounty(bounty_id, user['username'])
        q = urllib.parse.quote(msg)
        self._redirect(f'/manage/bounty/{bounty_id}?msg={q}&msg_type={"success" if ok else "error"}')

    def _post_bounty_reject(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        try:
            bounty_id = int(fields.get('bounty_id', '0'))
        except ValueError:
            return self._redirect('/manage/bounty')
        ok, msg = REGISTRATION_DB.reject_bounty_claim(bounty_id, user['username'])
        q = urllib.parse.quote(msg)
        self._redirect(f'/manage/bounty/{bounty_id}?msg={q}&msg_type={"success" if ok else "error"}')

    def _post_bounty_vote(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) == 'basic': return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        try:
            bounty_id = int(fields.get('bounty_id', '0'))
        except ValueError:
            return self._redirect('/manage/bounty')
        ok, msg = REGISTRATION_DB.vote_bounty_fulfilled(bounty_id, user['username'])
        q = urllib.parse.quote(msg)
        self._redirect(f'/manage/bounty/{bounty_id}?msg={q}&msg_type={"success" if ok else "error"}')

    def _post_bounty_comment(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if _user_role(user) == 'basic': return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        try:
            bounty_id = int(fields.get('bounty_id', '0'))
        except ValueError:
            return self._redirect('/manage/bounty')
        text = fields.get('body', '').strip()[:2000]
        if text:
            cid = REGISTRATION_DB.add_bounty_comment(bounty_id, user['username'], text)
            REGISTRATION_DB.award_comment_points(user['id'], cid)
        self._redirect(f'/manage/bounty/{bounty_id}#bc-{bounty_id}')

    def _post_points_transfer(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        to_user = fields.get('to_username', '').strip()
        try:
            amount = int(fields.get('amount', '0'))
        except ValueError:
            amount = 0
        if not to_user or amount < 1:
            return self._redirect('/manage/profile?msg=invalid_transfer&msg_type=error')
        ok, msg = REGISTRATION_DB.transfer_points(user['username'], to_user, amount)
        q = urllib.parse.quote(msg)
        self._redirect(f'/manage/profile?msg={q}&msg_type={"success" if ok else "error"}')

    # ── DM Handlers ─────────────────────────────────────────

    def _get_messages(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        role = _user_role(user)
        if role == 'basic': return self._redirect('/manage/dashboard')
        qs   = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        tab      = qs.get('tab', ['inbox'])[0]
        msg      = qs.get('msg',  [''])[0]
        msg_type = qs.get('msg_type', ['info'])[0]
        compose_to = qs.get('to', [''])[0]   # pre-fill recipient from profile Send DM link
        if compose_to:
            tab = 'compose'
        inbox     = REGISTRATION_DB.get_dm_inbox(user['username'])
        sent      = REGISTRATION_DB.get_dm_sent(user['username'])
        blocklist = REGISTRATION_DB.dm_blocklist_get(user['id'])
        self._send_html(_render_messages_page(user, inbox, sent, blocklist,
                                              tab=tab, msg=msg, msg_type=msg_type,
                                              compose_to=compose_to))

    def _get_message_thread(self, msg_id_str: str):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        role = _user_role(user)
        if role == 'basic': return self._redirect('/manage/dashboard')
        if not msg_id_str.isdigit():
            return self._redirect('/manage/messages')
        msg_id = int(msg_id_str)
        thread = REGISTRATION_DB.get_dm_thread(msg_id, user['username'])
        if not thread:
            return self._redirect('/manage/messages')
        uname = user['username']
        if not any(m['sender'] == uname or m['recipient'] == uname for m in thread):
            return self._redirect('/manage/messages')
        for m in thread:
            if m['recipient'] == uname and not m['read_at']:
                REGISTRATION_DB.mark_dm_read(m['id'], uname)
        qs       = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg      = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['info'])[0]
        self._send_html(_render_message_thread(user, thread, msg_id, msg=msg, msg_type=msg_type))

    def _post_dm_send(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        role = _user_role(user)
        if role == 'basic': return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        recipient_raw = fields.get('recipient', '').strip()
        subject       = fields.get('subject', '').strip()[:200]
        text          = fields.get('body', '').strip()[:5000]
        uname         = user['username']
        is_admin_or_super = role in ('admin', 'super')

        if not recipient_raw or not text:
            return self._redirect('/manage/messages?tab=compose&msg=Missing+recipient+or+body&msg_type=error')

        # Check DMs enabled globally
        if REGISTRATION_DB.get_setting('dm_enabled', '1') != '1' and not is_admin_or_super:
            return self._redirect('/manage/messages?msg=DMs+are+disabled&msg_type=error')

        # Split recipients on semicolons, strip whitespace, deduplicate, drop self
        recipients = [r.strip() for r in recipient_raw.replace(',', ';').split(';')]
        recipients = list(dict.fromkeys(r for r in recipients if r and r != uname))
        if not recipients:
            return self._redirect('/manage/messages?tab=compose&msg=No+valid+recipients&msg_type=error')

        # Pre-validate all recipients before spending any points
        errors = []
        valid  = []
        for recip in recipients:
            recip_user = REGISTRATION_DB.get_user(recip)
            if not recip_user:
                errors.append(f'{recip}: not found')
                continue
            if not is_admin_or_super:
                allow = recip_user['allow_dms'] if 'allow_dms' in recip_user.keys() else 1
                if not allow:
                    errors.append(f'{recip}: has disabled DMs')
                    continue
                if REGISTRATION_DB.dm_is_blocked(uname, recip_user['id']):
                    errors.append(f'{recip}: not accepting messages')
                    continue
            valid.append(recip_user)

        if not valid:
            msg = urllib.parse.quote('; '.join(errors))
            return self._redirect(f'/manage/messages?tab=compose&msg={msg}&msg_type=error')

        if not is_admin_or_super:
            daily_limit = int(REGISTRATION_DB.get_setting('dm_daily_limit', '10'))
            sent_today  = REGISTRATION_DB.get_dm_sent_today(uname)
            remaining   = daily_limit - sent_today
            if remaining <= 0:
                return self._redirect(f'/manage/messages?tab=compose&msg=Daily+DM+limit+reached+%28{daily_limit}%2Fday%29&msg_type=error')
            if len(valid) > remaining:
                valid = valid[:remaining]
                errors.append(f'daily limit reached — only sent to first {remaining}')
            cost = int(REGISTRATION_DB.get_setting('dm_cost', '5'))
            total_cost = cost * len(valid)
            if total_cost > 0:
                ok = REGISTRATION_DB.spend_points(user['id'], total_cost,
                                                   f'DM to {len(valid)} recipients', 'dm', recipient_raw[:60])
                if not ok:
                    return self._redirect(f'/manage/messages?tab=compose&msg=Insufficient+points+%28need+{total_cost}+pts%29&msg_type=error')

        last_id = None
        for recip_user in valid:
            last_id = REGISTRATION_DB.send_dm(uname, recip_user['username'], subject, text)
            REGISTRATION_DB._log(uname, 'dm_send', recip_user['username'], f'subject={subject[:40]!r}')

        sent_count = len(valid)
        if errors:
            skipped = urllib.parse.quote(f'Sent to {sent_count}. Skipped: ' + '; '.join(errors))
            return self._redirect(f'/manage/messages/{last_id}?msg={skipped}&msg_type=info')

        if sent_count == 1:
            self._redirect(f'/manage/messages/{last_id}?msg=Message+sent&msg_type=success')
        else:
            self._redirect(f'/manage/messages/{last_id}?msg=Message+sent+to+{sent_count}+recipients&msg_type=success')

    def _post_dm_reply(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        role = _user_role(user)
        if role == 'basic': return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        reply_to  = fields.get('reply_to_id', '').strip()
        text      = fields.get('body', '').strip()[:5000]
        uname     = user['username']
        is_admin_or_super = role in ('admin', 'super')

        if not reply_to.isdigit() or not text:
            return self._redirect('/manage/messages')
        orig = REGISTRATION_DB.get_dm(int(reply_to))
        if not orig:
            return self._redirect('/manage/messages')
        # Only sender or recipient of original can reply
        if orig['sender'] != uname and orig['recipient'] != uname:
            return self._redirect('/manage/messages')

        # Recipient of the reply is the other party
        recipient = orig['sender'] if orig['recipient'] == uname else orig['recipient']
        recip_user = REGISTRATION_DB.get_user(recipient)

        if not is_admin_or_super:
            if REGISTRATION_DB.get_setting('dm_enabled', '1') != '1':
                return self._redirect(f'/manage/messages/{reply_to}?msg=DMs+are+disabled&msg_type=error')
            if recip_user:
                allow = recip_user['allow_dms'] if 'allow_dms' in recip_user.keys() else 1
                if not allow:
                    return self._redirect(f'/manage/messages/{reply_to}?msg=User+has+disabled+DMs&msg_type=error')
                if REGISTRATION_DB.dm_is_blocked(uname, recip_user['id']):
                    return self._redirect(f'/manage/messages/{reply_to}?msg=This+user+is+not+accepting+messages+at+this+time&msg_type=error')
            daily_limit = int(REGISTRATION_DB.get_setting('dm_daily_limit', '10'))
            if REGISTRATION_DB.get_dm_sent_today(uname) >= daily_limit:
                return self._redirect(f'/manage/messages/{reply_to}?msg=Daily+DM+limit+reached&msg_type=error')
            cost = int(REGISTRATION_DB.get_setting('dm_cost', '5'))
            if cost > 0:
                ok = REGISTRATION_DB.spend_points(user['id'], cost, f'DM reply to {recipient}', 'dm', recipient)
                if not ok:
                    return self._redirect(f'/manage/messages/{reply_to}?msg=Insufficient+points&msg_type=error')

        subject = ('Re: ' + orig['subject']) if not orig['subject'].startswith('Re: ') else orig['subject']
        msg_id = REGISTRATION_DB.send_dm(uname, recipient, subject, text, reply_to_id=int(reply_to))
        self._redirect(f'/manage/messages/{msg_id}?msg=Reply+sent&msg_type=success')

    def _post_dm_delete(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        msg_id = fields.get('msg_id', '').strip()
        if not msg_id.isdigit(): return self._redirect('/manage/messages')
        msg = REGISTRATION_DB.get_dm(int(msg_id))
        if not msg: return self._redirect('/manage/messages')
        uname = user['username']
        if msg['sender'] == uname:
            REGISTRATION_DB.delete_dm_sender(int(msg_id), uname)
        elif msg['recipient'] == uname:
            REGISTRATION_DB.delete_dm_recip(int(msg_id), uname)
        self._redirect('/manage/messages?msg=Message+deleted&msg_type=success')

    def _post_dm_mark_read(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        REGISTRATION_DB.mark_all_dm_read(user['username'])
        self._redirect('/manage/messages?msg=All+marked+read&msg_type=success')

    def _post_dm_block(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target = fields.get('username', '').strip()
        if target and target != user['username']:
            REGISTRATION_DB.dm_blocklist_add(user['id'], target)
        self._redirect('/manage/messages?tab=blocked&msg=User+blocked&msg_type=success')

    def _post_dm_unblock(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target = fields.get('username', '').strip()
        REGISTRATION_DB.dm_blocklist_remove(user['id'], target)
        self._redirect('/manage/messages?tab=blocked&msg=User+unblocked&msg_type=success')

    def _post_dm_broadcast(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        if user['username'] != SUPER_USER: return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        subject = fields.get('subject', '').strip()[:200]
        text    = fields.get('body', '').strip()[:5000]
        if not subject or not text:
            return self._redirect('/manage/messages?tab=broadcast&msg=Subject+and+body+required&msg_type=error')
        count = REGISTRATION_DB.broadcast_dm(user['username'], subject, text)
        self._redirect(f'/manage/messages?tab=sent&msg=Broadcast+sent+to+{count}+users&msg_type=success')

    def _post_dm_toggle(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        allow = fields.get('allow_dms', '0') == '1'
        REGISTRATION_DB.dm_toggle_setting(user['id'], allow)
        msg = 'DMs+enabled' if allow else 'DMs+disabled'
        self._redirect(f'/manage/profile?msg={msg}&msg_type=success')

    def _post_profile_generate_invite(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        token = REGISTRATION_DB.spend_points_for_invite(user['username'])
        if not token:
            cost = REGISTRATION_DB.get_setting('points_invite_cost', '1000')
            pts  = user['points'] if 'points' in user.keys() else 0
            return self._redirect(f'/manage/profile?msg=Insufficient+points+%28need+{cost}%2C+have+{pts}%29&msg_type=error')
        self._redirect('/manage/profile?msg=Invite+link+created&msg_type=success')

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
    request_queue_size = 128
    ssl_context = None
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def get_request(self):
        conn, addr = self.socket.accept()
        if self.ssl_context:
            conn.settimeout(10)
            try:
                conn = self.ssl_context.wrap_socket(conn, server_side=True)
            except Exception:
                conn.close()
                raise
            conn.settimeout(None)  # clear — timeout was only needed for the handshake
        return conn, addr


def start_manage_server(host: str, port: int, ssl_ctx=None, label='MANAGE'):
    server = ThreadingHTTPServer((host, port), ManageHandler)
    if ssl_ctx:
        server.ssl_context = ssl_ctx
    log.info('%s management page listening on %s:%d', label, host or '0.0.0.0', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def start_manage6_server(host6: str, port: int, ssl_ctx=None, label='MANAGE'):
    server = IPv6ManageServer((host6, port, 0, 0), ManageHandler)
    if ssl_ctx:
        server.ssl_context = ssl_ctx
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
        elif path in ('/apple-touch-icon.png', '/apple-touch-icon-precomposed.png'):
            import base64 as _b64
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Cache-Control', 'public, max-age=86400')
            data = _b64.b64decode(APPLE_TOUCH_ICON_B64)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
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
    request_queue_size = 128
    ssl_context = None
    """IPv6 variant of the stats web server."""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def get_request(self):
        conn, addr = self.socket.accept()
        if self.ssl_context:
            conn.settimeout(10)
            try:
                conn = self.ssl_context.wrap_socket(conn, server_side=True)
            except Exception:
                conn.close()
                raise
            conn.settimeout(None)  # clear — timeout was only needed for the handshake
        return conn, addr


def start_web_server(host: str, port: int, ssl_ctx=None, label='WEB'):
    server = ThreadingHTTPServer((host, port), StatsWebHandler)
    if ssl_ctx:
        server.ssl_context = ssl_ctx
    log.info('%s stats page listening on %s:%d', label, host or '0.0.0.0', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def start_web6_server(host6: str, port: int, ssl_ctx=None, label='WEB'):
    server = IPv6StatsWebServer((host6, port, 0, 0), StatsWebHandler)
    if ssl_ctx:
        server.ssl_context = ssl_ctx
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
            display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 16px; }
  .nav-center { display: flex; gap: 8px; align-items: center; justify-content: center; flex-wrap: wrap; }
  .nav-user-area { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
  .nav-btn { display: inline-flex; align-items: center; gap: 5px; font-family: var(--mono);
             font-size: 0.78rem; letter-spacing: 0.06em; padding: 7px 14px; border-radius: 6px;
             border: 1px solid var(--border); cursor: pointer; text-decoration: none;
             transition: all 0.15s; background: transparent; color: var(--text); white-space: nowrap; }
  .nav-btn:hover { border-color: var(--accent); color: var(--accent); }
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
  .pw-wrap { position:relative; display:block; }
  .pw-wrap input { width:100%; padding-right:44px; box-sizing:border-box; }
  .pw-eye { position:absolute; right:0; top:0; bottom:0; width:40px;
            background:none; border:none; cursor:pointer; color:var(--muted);
            display:flex; align-items:center; justify-content:center;
            padding:0; transition:color 0.15s; }
  .pw-eye:hover { color:var(--text); }
  .pw-eye svg { width:18px; height:18px; flex-shrink:0; }
  .form-group label { display: block; font-size: 0.82rem; color: var(--muted);
                      margin-bottom: 6px; font-family: var(--mono); font-size: 0.72rem;
                      letter-spacing: 0.1em; text-transform: uppercase; }
  .form-group input[type=text], .form-group input[type=password],
  .form-group input[type=file] {
    width: 100%; padding: 10px 14px; background: var(--card2); border: 1px solid var(--border);
    border-radius: 6px; color: var(--text); font-family: var(--mono); font-size: 0.88rem;
    outline: none; transition: border-color 0.15s; }
  input:focus { border-color: var(--accent); }
  .skip-link { position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden; }
  .skip-link:focus { position:fixed;top:12px;left:12px;width:auto;height:auto;padding:10px 18px;background:var(--accent);color:#000;font-weight:600;border-radius:6px;z-index:99999;text-decoration:none; }
  @media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
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
  @media (max-width: 900px) { .lb-grid { grid-template-columns: 1fr 1fr !important; } }
  @media (max-width: 560px) { .lb-grid { grid-template-columns: 1fr !important; } }
  /* ── Comments ── */
  .comment-card { background:var(--card); border:1px solid var(--border); border-radius:12px;
                  padding:16px 20px; margin-bottom:16px; }
  /* tree node wrapper — carries the anchor id */
  .comment-node { position:relative; }
  .comment-node:target > .comment-inner {
    border-color:var(--accent); animation:highlight-fade 2s ease forwards; }
  @keyframes highlight-fade { 0%{background:rgba(245,166,35,0.10)} 100%{background:transparent} }
  /* inner bubble */
  .comment-inner { border-radius:8px; padding:12px 16px;
                   border:1px solid var(--border); background:var(--card); }
  /* depth backgrounds — each level slightly darker */
  .comment-depth-0 > .comment-inner { background:var(--card); }
  .comment-depth-1 > .comment-inner { background:var(--card2); }
  .comment-depth-2 > .comment-inner { background:var(--bg); border-color:var(--border); }
  .comment-depth-3 > .comment-inner { background:var(--bg); opacity:0.92; }
  /* branch connector: indented children sit inside a left-bordered container */
  .comment-children {
    margin-left:20px;
    padding-left:14px;
    border-left:2px solid var(--border);
    margin-top:6px;
    display:flex;
    flex-direction:column;
    gap:6px;
  }
  .comment-children .comment-node { padding-top:0; }
  .comment-header { display:flex; align-items:center; gap:10px; margin-bottom:10px;
                    flex-wrap:wrap; }
  .comment-ts { font-family:var(--mono); font-size:0.68rem; color:var(--muted); }
  .comment-edited { font-family:var(--mono); font-size:0.65rem; color:var(--muted); font-style:italic; }
  .comment-body { font-size:0.9rem; line-height:1.65; color:var(--text); white-space:pre-wrap;
                  word-break:break-word; }
  .comment-deleted { font-size:0.9rem; color:var(--muted); font-style:italic; }
  .comment-actions { display:flex; gap:8px; margin-top:10px; flex-wrap:wrap; align-items:center; }
  .comment-reply-form { margin-top:10px; display:none; }
  .comment-reply-form.open { display:block; }
  .comment-edit-form { display:none; margin-top:10px; }
  .comment-edit-form.open { display:block; }
  .comment-textarea { width:100%; padding:10px 14px; background:var(--card2);
                      border:1px solid var(--border); border-radius:6px; color:var(--text);
                      font-family:var(--sans); font-size:0.9rem; resize:vertical;
                      outline:none; transition:border-color 0.15s; min-height:80px; }
  .comment-textarea:focus { border-color:var(--accent); }
  .btn-ghost { background:transparent; border:none; font-family:var(--mono); font-size:0.72rem;
               letter-spacing:0.06em; color:var(--muted); cursor:pointer; padding:2px 6px;
               border-radius:4px; transition:color 0.15s; }
  .btn-ghost:hover { color:var(--accent); }
  .btn-ghost-danger { color:var(--muted); }
  .btn-ghost-danger:hover { color:var(--red); }
  /* ── Notification bell ── */
  .sr-only { position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0; }
  .notif-wrap { position:relative; display:inline-flex; align-items:center; }
  .notif-bell-btn { background:transparent; border:none; cursor:pointer; font-size:1.1rem;
                    padding:4px 6px; border-radius:6px; transition:opacity 0.15s;
                    display:flex; align-items:center; gap:5px; line-height:1; }
  .notif-bell-btn:hover { opacity:0.75; }
  .notif-bell-btn .notif-count { font-family:var(--mono); font-size:0.65rem; letter-spacing:0.05em;
                                  background:var(--accent); color:#000; border-radius:10px;
                                  padding:1px 6px; font-weight:700; }
  .notif-bell-inactive { opacity:0.35; }
  .notif-dropdown { position:absolute; right:0; top:calc(100% + 8px); width:340px;
                    background:var(--card); border:1px solid var(--border); border-radius:12px;
                    box-shadow:0 8px 32px rgba(0,0,0,0.4); z-index:1000; display:none;
                    overflow:hidden; }
  .notif-dropdown.open { display:block; }
  .notif-dropdown-header { padding:12px 16px; border-bottom:1px solid var(--border);
                           display:flex; justify-content:space-between; align-items:center; }
  .notif-dropdown-title { font-family:var(--mono); font-size:0.68rem; letter-spacing:0.15em;
                          text-transform:uppercase; color:var(--muted); }
  .notif-item { display:block; padding:12px 16px; border-bottom:1px solid var(--border);
                text-decoration:none; color:var(--text); transition:background 0.1s; cursor:pointer;
                background:transparent; border:none; width:100%; text-align:left; }
  .notif-item:last-child { border-bottom:none; }
  .notif-item:hover { background:var(--card2); }
  .notif-item-type { font-family:var(--mono); font-size:0.65rem; color:var(--muted);
                     margin-bottom:3px; letter-spacing:0.08em; }
  .notif-item-text { font-size:0.85rem; color:var(--text); line-height:1.4; }
  .notif-item-ts { font-family:var(--mono); font-size:0.65rem; color:var(--muted); margin-top:3px; }
  .notif-empty { padding:24px 16px; text-align:center; font-family:var(--mono);
                 font-size:0.78rem; color:var(--muted); }
  .notif-footer { padding:10px 16px; border-top:1px solid var(--border); text-align:center; }
  .notif-footer a { font-family:var(--mono); font-size:0.72rem; color:var(--accent);
                    text-decoration:none; letter-spacing:0.08em; }
  .notif-footer a:hover { opacity:0.8; }
  /* ── Notifications page ── */
  .notif-page-item { background:var(--card); border:1px solid var(--border); border-radius:10px;
                     padding:16px 20px; margin-bottom:12px; display:flex;
                     justify-content:space-between; align-items:flex-start; gap:16px; }
  .notif-page-item.unread { border-left:3px solid var(--accent); }
  .notif-page-meta { font-family:var(--mono); font-size:0.68rem; color:var(--muted); margin-top:4px; }
'''

_MANAGE_HEAD = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} -- Wildkat Tracker</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,{favicon}">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;600&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>
<div class="container">'''

_MANAGE_HEADER = '''
  <header>
  <div class="header">
    <a class="logo" href="/">&#128008; WILD<span>KAT</span></a>
    <nav class="nav-center" aria-label="Site navigation">
      {center_nav}
    </nav>
    <nav class="nav-user-area" aria-label="User navigation">
      {nav_items}
    </nav>
  </div>
  </header>
  <main id="main-content">'''

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
function initiateSystemWipe() {
  // Step 1: type SYSTEMWIPE
  var o = document.createElement('div');
  o.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center';
  o.setAttribute('role','alertdialog');
  o.setAttribute('aria-modal','true');
  o.setAttribute('aria-labelledby','_sw1_title');
  o.innerHTML = '<div style="background:var(--card);border:2px solid var(--red);border-radius:12px;padding:32px;max-width:480px;width:92%">'
    + '<div id="_sw1_title" style="font-family:var(--mono);font-size:0.7rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--red);margin-bottom:12px">&#9762; System Wipe — Step 1 of 2</div>'
    + '<p style="font-size:0.9rem;color:var(--text);margin-bottom:18px;line-height:1.6">'
    + 'This will permanently delete <strong>all users, torrents, comments, notifications, invites, and logs</strong> except your super account.<br><br>'
    + 'Type <strong style="color:var(--red);font-family:var(--mono)">SYSTEMWIPE</strong> to continue:</p>'
    + '<input id="_sw_input" type="text" autocomplete="off" spellcheck="false"'
    + ' style="width:100%;padding:10px 14px;background:var(--card2);border:1px solid var(--border);'
    + 'border-radius:6px;color:var(--text);font-family:var(--mono);font-size:1rem;outline:none;margin-bottom:18px"'
    + ' aria-label="Type SYSTEMWIPE to confirm" placeholder="Type SYSTEMWIPE">'
    + '<div style="display:flex;gap:12px;justify-content:flex-end">'
    + '<button id="_sw1_cancel" class="btn">Cancel</button>'
    + '<button id="_sw1_ok" class="btn btn-danger">Continue</button>'
    + '</div></div>';
  document.body.appendChild(o);
  var inp = document.getElementById('_sw_input');
  inp.focus();
  inp.addEventListener('input', function() {
    document.getElementById('_sw1_ok').disabled = inp.value !== 'SYSTEMWIPE';
  });
  document.getElementById('_sw1_ok').disabled = true;
  document.getElementById('_sw1_cancel').onclick = function() { document.body.removeChild(o); };
  document.getElementById('_sw1_ok').onclick = function() {
    if (inp.value !== 'SYSTEMWIPE') return;
    document.body.removeChild(o);
    // Step 2: final confirmation
    var o2 = document.createElement('div');
    o2.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:9999;display:flex;align-items:center;justify-content:center';
    o2.setAttribute('role','alertdialog');
    o2.setAttribute('aria-modal','true');
    o2.setAttribute('aria-labelledby','_sw2_title');
    o2.innerHTML = '<div style="background:var(--card);border:2px solid var(--red);border-radius:12px;padding:32px;max-width:480px;width:92%;text-align:center">'
      + '<div id="_sw2_title" style="font-family:var(--mono);font-size:0.7rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--red);margin-bottom:16px">&#9762; System Wipe — Step 2 of 2</div>'
      + '<p style="font-size:1rem;color:var(--text);margin-bottom:24px;line-height:1.7">'
      + '<strong style="color:var(--red)">This is your last chance.</strong><br>'
      + 'All data will be permanently destroyed.<br>'
      + 'This action <strong>cannot</strong> be undone.</p>'
      + '<div style="display:flex;gap:12px;justify-content:center">'
      + '<button id="_sw2_cancel" class="btn" style="min-width:100px">Cancel</button>'
      + '<button id="_sw2_ok" class="btn btn-danger" style="min-width:140px">Wipe Everything</button>'
      + '</div></div>';
    document.body.appendChild(o2);
    document.getElementById('_sw2_cancel').onclick = function() { document.body.removeChild(o2); };
    document.getElementById('_sw2_ok').focus();
    document.getElementById('_sw2_ok').onclick = function() {
      document.body.removeChild(o2);
      // Submit hidden form with CSRF + token
      var f = document.createElement('form');
      f.method = 'POST';
      f.action = '/manage/admin/system-wipe';
      var ct = document.createElement('input'); ct.type='hidden'; ct.name='confirm_token'; ct.value='SYSTEMWIPE';
      f.appendChild(ct);
      var csrf = document.createElement('input'); csrf.type='hidden'; csrf.name='_csrf';
      csrf.value = (document.cookie.match(/wkcsrf=([^;]+)/) || [])[1] || '';
      f.appendChild(csrf);
      document.body.appendChild(f);
      f.submit();
    };
    o2.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') document.body.removeChild(o2);
    });
  };
  o.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') document.body.removeChild(o);
    if (e.key === 'Enter' && inp.value === 'SYSTEMWIPE') document.getElementById('_sw1_ok').click();
  });
}
function togglePwVis(btn) {
  var inp = btn.previousElementSibling;
  var showing = inp.type === 'text';
  inp.type = showing ? 'password' : 'text';
  btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
  // swap eye-open / eye-off icon
  btn.querySelector('.eye-open').style.display = showing ? '' : 'none';
  btn.querySelector('.eye-off').style.display  = showing ? 'none' : '';
}
function showWarnModal(msg) {
  var o = document.createElement('div');
  o.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:9999;display:flex;align-items:center;justify-content:center';
  o.setAttribute('role','alertdialog');
  o.setAttribute('aria-modal','true');
  o.setAttribute('aria-labelledby','_wm_title');
  o.setAttribute('aria-describedby','_wm_body');
  o.innerHTML = '<div style="background:var(--card);border:1px solid rgba(224,91,48,0.4);border-radius:12px;padding:28px 32px;max-width:480px;width:92%;text-align:center">'
    + '<div id="_wm_title" style="font-family:var(--mono);font-size:0.68rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--red);margin-bottom:12px">&#9888; Notice</div>'
    + '<div id="_wm_body" style="font-size:0.9rem;margin-bottom:24px;line-height:1.6;color:var(--text)">' + msg + '</div>'
    + '<button id="_wm_ok" class="btn btn-primary" autofocus>OK</button>'
    + '</div>';
  document.body.appendChild(o);
  var ok = document.getElementById('_wm_ok');
  ok.focus();
  ok.onclick = function(){ document.body.removeChild(o); };
  o.addEventListener('keydown', function(e){
    if(e.key==='Escape'||e.key==='Enter') document.body.removeChild(o);
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
function copyHash(el, hash) {
  navigator.clipboard.writeText(hash).then(function() {
    var orig = el.textContent;
    var origStyle = el.style.cssText;
    el.textContent = '✓ Copied!';
    el.style.color = 'var(--green)';
    el.style.borderColor = 'var(--green)';
    setTimeout(function() {
      el.textContent = orig;
      el.style.cssText = origStyle;
    }, 2000);
  });
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
function toggleNotifDropdown(e) {
  e.stopPropagation();
  var d = document.getElementById('notif-dropdown');
  if (d) d.classList.toggle('open');
}
document.addEventListener('click', function() {
  var d = document.getElementById('notif-dropdown');
  if (d) d.classList.remove('open');
});
function readNotif(id, url) {
  fetch('/manage/notifications/read/' + id, {method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'_csrf=' + encodeURIComponent(document.cookie.match(/wkcsrf=([^;]+)/)?.[1] || '')
  }).then(function() { window.location = url; });
}
function toggleReplyForm(id, mentionUser) {
  // Close any other open reply forms first
  document.querySelectorAll('.comment-reply-form.open').forEach(function(el) {
    if (el.id !== 'reply-form-' + id) {
      el.classList.remove('open');
      var ta = el.querySelector('textarea');
      if (ta) ta.value = '';
    }
  });
  var f = document.getElementById('reply-form-' + id);
  if (!f) return;
  var opening = !f.classList.contains('open');
  f.classList.toggle('open');
  if (opening) {
    var ta = f.querySelector('textarea');
    if (ta) {
      if (mentionUser && ta.value === '') {
        ta.value = '@' + mentionUser + ' ';
      }
      ta.focus();
      ta.setSelectionRange(ta.value.length, ta.value.length);
    }
  }
}
function toggleEditForm(id) {
  var b = document.getElementById('comment-body-' + id);
  var f = document.getElementById('edit-form-' + id);
  if (!b || !f) return;
  var editing = f.classList.contains('open');
  if (editing) { f.classList.remove('open'); b.style.display = ''; }
  else { f.classList.add('open'); b.style.display = 'none'; f.querySelector('textarea').focus(); }
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
</main>
</body></html>'''


def _manage_page(title: str, body: str, user=None, msg: str = '', msg_type: str = 'error') -> str:
    fav = urllib.parse.quote(FAVICON_SVG.strip())
    if user:
        role = _user_role(user)
        role_label = role.upper()
        _comments_on = (REGISTRATION_DB.get_setting('comments_enabled','1') == '1') if REGISTRATION_DB else False
        unread = REGISTRATION_DB.get_unread_count(user['id']) if (REGISTRATION_DB and _comments_on) else 0
        bell_cls = 'notif-bell-btn' if unread else 'notif-bell-btn notif-bell-inactive'
        badge_html = (f'<span class="notif-count">{unread}</span>' if unread else '')
        unread_items = REGISTRATION_DB.get_unread_notifications(user['id'], 5) if REGISTRATION_DB else []
        dropdown_items = ''
        for n in unread_items:
            is_bounty = str(n['info_hash']).upper().startswith('BOUNTY:')
            if is_bounty:
                bid = str(n['info_hash']).split(':',1)[1]
                ntype = n['type']
                icon, label = {
                    'bounty_claimed':          ('🎯', 'claimed your bounty'),
                    'bounty_rejected':         ('✗',  'rejected your claim on'),
                    'bounty_fulfilled':        ('✅', 'fulfilled bounty'),
                    'bounty_contribution':     ('➕', 'added points to your bounty'),
                    'bounty_expired':          ('⏰', 'bounty expired:'),
                    'bounty_uploader_payout':  ('💰', 'fulfilled a bounty using your upload:'),
                }.get(ntype, ('🔔', 'bounty update on'))
                tname_h = _h(n['torrent_name'][:40] + ('…' if len(n['torrent_name']) > 40 else ''))
                from_h  = _h(n['from_username'])
                ts_h    = _h((n['created_at'] or '')[:16].replace('T', ' '))
                n_id    = n['id']
                dropdown_items += (
                    f'<button class="notif-item" '
                    f'onclick="readNotif({n_id},\'/manage/bounty/{bid}\')"'
                    f' aria-label="bounty notification from {from_h}">'
                    f'<div class="notif-item-type">{icon} <strong>{from_h}</strong> {label}</div>'
                    f'<div class="notif-item-text"><em>{tname_h}</em></div>'
                    f'<div class="notif-item-ts">{ts_h}</div>'
                    f'</button>'
                )
            else:
                icon = '💬' if n['type'] == 'reply' else '@'
                label = 'replied to your comment' if n['type'] == 'reply' else 'mentioned you'
                tname_h = _h(n['torrent_name'][:40] + ('…' if len(n['torrent_name']) > 40 else ''))
                from_h = _h(n['from_username'])
                ts_h = _h((n['created_at'] or '')[:16].replace('T', ' '))
                n_id   = n['id']
                n_hash = n['info_hash'].lower()
                n_cid  = n['comment_id']
                dropdown_items += (
                    f'<button class="notif-item" '
                    f'onclick="readNotif({n_id},\'/manage/torrent/{n_hash}#comment-{n_cid}\')"'
                    f' aria-label="{label} by {from_h} on {tname_h}">'
                    f'<div class="notif-item-type">{icon} <strong>{from_h}</strong> {label}</div>'
                    f'<div class="notif-item-text">on <em>{tname_h}</em></div>'
                    f'<div class="notif-item-ts">{ts_h}</div>'
                    f'</button>'
                )
        if not dropdown_items:
            dropdown_items = '<div class="notif-empty">No unread notifications</div>'
        bell_html = (
            f'<div class="notif-wrap">'
            f'<button class="{bell_cls}" onclick="toggleNotifDropdown(event)" aria-label="Notifications">'
            f'🔔{badge_html}</button>'
            f'<div class="notif-dropdown" id="notif-dropdown">'
            f'<div class="notif-dropdown-header">'
            f'<span class="notif-dropdown-title">Notifications</span>'
            f'</div>'
            f'{dropdown_items}'
            f'<div class="notif-footer"><a href="/manage/notifications">View all notifications</a></div>'
            f'</div></div>'
        )
        unread_dm = REGISTRATION_DB.get_unread_dm_count(user['username']) if REGISTRATION_DB else 0
        dm_badge  = f'<span class="notif-count">{unread_dm}</span>' if unread_dm else ''
        dm_cls    = 'notif-bell-btn' if unread_dm else 'notif-bell-btn notif-bell-inactive'
        mail_html = (f'<a href="/manage/messages" class="{dm_cls}" '
                     f'style="text-decoration:none" aria-label="Messages">'
                     f'📬{dm_badge}</a>') if role != 'basic' else ''
        nav = (f'<a href="/manage/profile" class="nav-user" style="text-decoration:none">'
               f'<span class="nav-username">{_h(user["username"])}</span> '
               f'<span class="badge badge-{role}">{role_label}</span></a>'
               + mail_html + bell_html +
               f'<a href="/manage/logout" class="btn btn-sm">Logout</a>')
        center_nav = (
            '<a href="/manage/dashboard" class="nav-btn">🖥 Dashboard</a>'
            '<a href="/manage/search" class="nav-btn">🔍 Search</a>'
            + ('' if role == 'basic' else
               '<a href="/manage/bounty" class="nav-btn">🎯 Bounties</a>'
               '<a href="/manage/leaderboard" class="nav-btn">🏆 Leaderboard</a>')
        )
    else:
        nav = ''
        center_nav = ''

    alert = ''
    if msg:
        cls = 'alert-error' if msg_type == 'error' else 'alert-success'
        prefix = '⚠ ' if msg_type == 'error' else '✓ '
        alert = f'<div class="alert {cls}" role="alert">{prefix}{msg}</div>'

    head = _MANAGE_HEAD.format(title=title, favicon=fav, css=_MANAGE_CSS)
    header = _MANAGE_HEADER.format(nav_items=nav, center_nav=center_nav)
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
          <label for="signup-username">Username</label>
          <input id="signup-username" type="text" name="username" autocomplete="username" autofocus required>
        </div>
        {pw_req_html}
        <div class="form-group">
          <label for="signup-password">Password</label>
          <div class="pw-wrap"><input id="signup-password" type="password" name="password" autocomplete="new-password" required><button type="button" class="pw-eye" onclick="togglePwVis(this)" aria-label="Show password" tabindex="-1"><svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button></div>
        </div>
        <div class="form-group">
          <label for="signup-confirm">Confirm Password</label>
          <div class="pw-wrap"><input id="signup-confirm" type="password" name="confirm_password" autocomplete="new-password" required><button type="button" class="pw-eye" onclick="togglePwVis(this)" aria-label="Show password" tabindex="-1"><svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button></div>
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
          <label for="login-username">Username</label>
          <input id="login-username" type="text" name="username" autocomplete="username" autofocus required>
        </div>
        <div class="form-group">
          <label for="login-password">Password</label>
          <input id="login-password" type="password" name="password" autocomplete="current-password" required>
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
            '<th scope="col" style="width:33%">Name</th>'
            '<th scope="col" style="width:27%">Info Hash</th>'
            '<th scope="col" style="width:10%">Owner</th>'
            '<th scope="col" style="width:8%;white-space:nowrap">Size</th>'
            '<th scope="col" style="width:10%;white-space:nowrap">Registered</th>'
            '<th scope="col" style="width:12%;min-width:100px">Action</th>'
            '</tr>'
        )
    # 5 cols: 36+36+8+8+12 = 100%
    return (
        '<tr>'
        '<th scope="col" style="width:36%">Name</th>'
        '<th scope="col" style="width:36%">Info Hash</th>'
        '<th scope="col" style="width:8%;white-space:nowrap">Size</th>'
        '<th scope="col" style="width:8%;white-space:nowrap">Registered</th>'
        '<th scope="col" style="width:12%;min-width:100px">Action</th>'
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
        f'<button class="btn btn-sm btn-green" onclick="copyMagnet(this,{repr(magnet)})">&#x1F9F2; Magnet</button>'
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
  <div class="page-title">🔍 Search Torrents</div>
  <div class="page-sub"><a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a></div>
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
  <div class="page-title">🖥 Dashboard</div>
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
                  uquery: str = '', tab: str = '', new_username: str = '',
                  ev_total: int = 0, eq: str = '', eactor: str = '',
                  eaction: str = '', etarget: str = '') -> str:
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
              <button class="btn btn-sm">&#8593;</button>
            </form>
            <form method="POST" action="/manage/admin/tracker-move" style="display:inline">
              <input type="hidden" name="tid" value="{tid}">
              <input type="hidden" name="direction" value="1">
              <button class="btn btn-sm">&#8595;</button>
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
        <div class="card-title">Comments &amp; Notifications</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Enable or disable the comment and notification system site-wide.
          When disabled, comments cannot be posted and the notification bell is hidden.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="comments_enabled">
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:16px">
            <input type="checkbox" name="comments_enabled" value="1" {'checked' if settings.get('comments_enabled','1')=='1' else ''}> Enable comments &amp; notifications
          </label>
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
                f'<button class="btn btn-sm btn-green" onclick="copyInvite(this,{repr(invite_url)})">&#128279; Copy URL</button>'
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
          <th scope="col">Code</th><th scope="col">Created By</th><th scope="col">Created At</th><th scope="col">Status</th><th scope="col">Actions</th>
        </tr>
        {_inv_rows}
      </table>
    </div>'''

    # ── Database Management HTML ─────────────────────────────
    import os as _os
    try:
        _db_size = _os.path.getsize(REGISTRATION_DB._path)
        _db_size_str = (f'{_db_size / 1048576:.2f} MB' if _db_size >= 1048576
                        else f'{_db_size / 1024:.1f} KB')
    except Exception:
        _db_size_str = 'unknown'
    database_html = f'''
    <div class="two-col">
      <div class="card">
        <div class="card-title">Backup Database</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:8px">
          Download a complete gzip-compressed snapshot of the live database.
          Current size: <strong style="color:var(--text)">{_db_size_str}</strong>
        </p>
        <p style="font-size:0.82rem;color:var(--muted);margin-bottom:16px">
          The backup is taken using SQLite&rsquo;s online backup API &mdash;
          safe to run while the tracker is live.
        </p>
        <a href="/manage/admin/db-backup" class="btn btn-primary"
           aria-label="Download database backup">&#11015; Download Backup</a>
      </div>
      <div class="card">
        <div class="card-title">Restore Database</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:8px">
          Upload a <code>.db.gz</code> backup file to replace the live database.
        </p>
        <p style="font-size:0.82rem;color:var(--red);margin-bottom:16px">
          <strong>Warning:</strong> This replaces all current data immediately.
          Make sure you have a recent backup before restoring.
        </p>
        <form method="POST" action="/manage/admin/db-restore"
              enctype="multipart/form-data"
              data-confirm="Replace the live database with this backup? All current data will be overwritten.">
          <div class="form-group">
            <label for="db-restore-file">Backup File (.db.gz)</label>
            <input id="db-restore-file" type="file" name="db_file"
                   accept=".gz,.db.gz" required
                   style="display:block;margin-top:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem">
          </div>
          <button type="submit" class="btn btn-danger"
                  aria-label="Restore database from backup file">&#11014; Restore from Backup</button>
        </form>
      </div>
    </div>'''

    # ── Economy HTML ──────────────────────────────────────────
    _eco = REGISTRATION_DB.get_economy_stats() if REGISTRATION_DB else {}
    def _eset(k, default=''):
        return settings.get(k, default)
    economy_html = f'''
    <div class="card" style="margin-bottom:16px">
      <div class="card-title">📊 Economy Dashboard</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:12px">
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:var(--accent)">{_eco.get("in_circulation",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">In Circulation</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:var(--accent)">{_eco.get("in_escrow",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">In Escrow</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:var(--danger)">{_eco.get("in_debt",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">In Debt</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:var(--green)">{_eco.get("total_generated",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Total Generated</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:var(--danger)">{_eco.get("total_destroyed",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Total Destroyed</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:var(--text)">{_eco.get("net_all_time",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Net All Time</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:var(--green)">{_eco.get("gen_30d",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Generated (30d)</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:var(--danger)">{_eco.get("burn_30d",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Destroyed (30d)</div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.3rem;font-weight:700;color:var(--green)">{_eco.get("open_bounties",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Open Bounties</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.3rem;font-weight:700;color:var(--accent)">{_eco.get("pending_bounties",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Pending</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.3rem;font-weight:700;color:var(--muted)">{_eco.get("fulfilled_bounties",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Fulfilled</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.3rem;font-weight:700;color:var(--danger)">{_eco.get("expired_bounties",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Expired</div>
        </div>
      </div>
    </div>
    <div class="two-col">
      <div class="card">
        <div class="card-title">Points Earning</div>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="points_earn">
          <div class="form-group"><label>Login (daily)</label>
            <input type="number" name="points_login_daily" value="{_eset('points_login_daily','1')}" min="0" max="999" style="width:80px"></div>
          <div class="form-group"><label>7-day streak bonus</label>
            <input type="number" name="points_streak_7day" value="{_eset('points_streak_7day','1')}" min="0" max="999" style="width:80px"></div>
          <div class="form-group"><label>30-day streak bonus</label>
            <input type="number" name="points_streak_30day" value="{_eset('points_streak_30day','4')}" min="0" max="999" style="width:80px"></div>
          <div class="form-group"><label>Upload torrent</label>
            <input type="number" name="points_upload" value="{_eset('points_upload','25')}" min="0" max="9999" style="width:80px"></div>
          <div class="form-group"><label>Post comment</label>
            <input type="number" name="points_comment" value="{_eset('points_comment','1')}" min="0" max="999" style="width:80px"></div>
          <div class="form-group"><label>Max comment points/day</label>
            <input type="number" name="points_comment_cap" value="{_eset('points_comment_cap','10')}" min="0" max="999" style="width:80px"></div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">Points Spending &amp; Penalties</div>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="points_spend">
          <div class="form-group"><label>Invite code cost</label>
            <input type="number" name="points_invite_cost" value="{_eset('points_invite_cost','1000')}" min="1" max="99999" style="width:100px"></div>
          <div class="form-group"><label>Transfer fee %</label>
            <input type="number" name="points_transfer_fee_pct" value="{_eset('points_transfer_fee_pct','25')}" min="0" max="99" style="width:80px"></div>
          <div class="form-group"><label>Standard promotion threshold (pts)</label>
            <input type="number" name="auto_promote_threshold" value="{_eset('auto_promote_threshold','100')}" min="1" max="99999" style="width:100px"></div>
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:16px">
            <input type="checkbox" name="auto_promote_enabled" value="1" {'checked' if _eset('auto_promote_enabled')=='1' else ''}> Enable auto-promotion
          </label>
          <div class="form-group"><label>Penalty — admin removes torrent</label>
            <input type="number" name="points_penalty_torrent" value="{_eset('points_penalty_torrent','25')}" min="0" max="9999" style="width:80px"></div>
          <div class="form-group"><label>Penalty — admin deletes comment</label>
            <input type="number" name="points_penalty_comment" value="{_eset('points_penalty_comment','1')}" min="0" max="999" style="width:80px"></div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">Bounty Settings</div>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="bounty_settings">
          <div class="form-group"><label>Minimum bounty cost (pts)</label>
            <input type="number" name="bounty_min_cost" value="{_eset('bounty_min_cost','50')}" min="1" max="99999" style="width:100px"></div>
          <div class="form-group"><label>Requestor refund % (on confirm)</label>
            <input type="number" name="bounty_refund_pct" value="{_eset('bounty_refund_pct','25')}" min="0" max="100" style="width:80px"></div>
          <div class="form-group"><label>Claimer payout %</label>
            <input type="number" name="bounty_claimer_pct" value="{_eset('bounty_claimer_pct','70')}" min="1" max="100" style="width:80px"></div>
          <div class="form-group"><label>Uploader payout %</label>
            <input type="number" name="bounty_uploader_pct" value="{_eset('bounty_uploader_pct','15')}" min="0" max="100" style="width:80px"></div>
          <div class="form-group"><label>Rejection penalty (pts)</label>
            <input type="number" name="bounty_reject_penalty" value="{_eset('bounty_reject_penalty','10')}" min="0" max="9999" style="width:80px"></div>
          <div class="form-group"><label>Expiry (days)</label>
            <input type="number" name="bounty_expiry_days" value="{_eset('bounty_expiry_days','90')}" min="1" max="3650" style="width:100px"></div>
          <div class="form-group"><label>Auto-confirm vote threshold</label>
            <input type="number" name="bounty_confirm_votes" value="{_eset('bounty_confirm_votes','3')}" min="1" max="999" style="width:80px"></div>
          <div class="form-group"><label>Pending confirmation window (hours)</label>
            <input type="number" name="bounty_pending_hours" value="{_eset('bounty_pending_hours','48')}" min="1" max="720" style="width:80px"></div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">🏆 Leaderboard</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Controls how many entries appear in each leaderboard category.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="leaderboard_settings">
          <div class="form-group"><label>Top N per category</label>
            <input type="number" name="leaderboard_top_n" value="{_eset('leaderboard_top_n','10')}" min="3" max="100" style="width:80px">
          </div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">&#x2709; Direct Messages</div>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="dm_settings">
          <div class="form-group">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input type="checkbox" name="dm_enabled" value="1" {'checked' if _eset('dm_enabled','1')=='1' else ''}> Enable DM system
            </label>
          </div>
          <div style="display:flex;gap:16px;flex-wrap:wrap">
            <div class="form-group"><label>Point cost per DM (0 = free)</label>
              <input type="number" name="dm_cost" value="{_eset('dm_cost','5')}" min="0" max="9999" style="width:100px"></div>
            <div class="form-group"><label>Daily send limit per user</label>
              <input type="number" name="dm_daily_limit" value="{_eset('dm_daily_limit','10')}" min="1" max="999" style="width:100px"></div>
          </div>
          <p style="color:var(--muted);font-size:0.8rem;margin:0 0 10px">Admins and Super are exempt from cost and daily limits. Super can broadcast to all users.</p>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
            <div class="card">
        <div class="card-title">⚡ Admin Point Grants</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Maximum points an admin can grant or remove per transaction on a user's profile.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="admin_grant_settings">
          <div class="form-group"><label>Max grant / removal per transaction</label>
            <input type="number" name="admin_max_point_grant" value="{_eset('admin_max_point_grant','1000')}" min="1" max="999999" style="width:100px">
          </div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
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
          <button class="btn btn-danger" aria-label="Delete all user accounts">Delete All Users</button>
        </form>
      </div>
      <div class="card" style="border-color:rgba(224,91,48,0.3)">
        <div class="card-title" style="color:var(--accent2)">Delete All Torrents</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Permanently removes every registered torrent from the tracker. This cannot be undone.
        </p>
        <form method="POST" action="/manage/admin/delete-all-torrents"
              data-confirm="Delete ALL registered torrents from the tracker? This CANNOT be undone.">
          <button class="btn btn-danger" aria-label="Delete all torrents">Delete All Torrents</button>
        </form>
      </div>
      <div class="card" style="border-color:rgba(224,91,48,0.3)">
        <div class="card-title" style="color:var(--accent2)">Delete All Comments &amp; Notifications</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Permanently removes every comment and notification across the entire system.
          Torrent lock states are preserved. This cannot be undone.
        </p>
        <form method="POST" action="/manage/admin/delete-all-comments-global"
              data-confirm="Delete ALL comments and notifications system-wide? This CANNOT be undone.">
          <button class="btn btn-danger" aria-label="Delete all comments and notifications">Delete All Comments &amp; Notifications</button>
        </form>
      </div>
      <div class="card" style="border-color:rgba(224,91,48,0.6)">
        <div class="card-title" style="color:var(--red);font-size:0.78rem">&#9762; System Wipe</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          <strong style="color:var(--red)">EXTREME DANGER.</strong>
          Wipes <em>all</em> users (except your super account), torrents, comments,
          notifications, invite codes, sessions, and event logs.
          Returns tracker to near-factory state. This <strong>absolutely cannot</strong> be undone.
        </p>
        <button class="btn btn-danger" onclick="initiateSystemWipe()"
                aria-label="Initiate system wipe — requires typed confirmation">&#9762; System Wipe</button>
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
            actions += (f'<a href="/manage/admin/set-password/{uname_h}"'
                        f' class="btn btn-sm">Set Password</a>')

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
        # Color-code by action type
        action = e['action']
        if 'delete' in action or 'ban' in action or 'lock' in action or 'penalty' in action:
            acolor = 'var(--danger)'
        elif 'login' in action or 'register' in action or 'award' in action or 'promote' in action:
            acolor = 'var(--green)'
        elif 'bounty' in action or 'points' in action or 'spend' in action:
            acolor = 'var(--accent)'
        else:
            acolor = 'var(--text)'
        actor_h  = _h(e['actor'])
        target_h = _h(e['target'])
        ev_rows += (
            f'<tr>'
            f'<td class="hash" style="white-space:nowrap">{e["timestamp"][:16].replace("T"," ")}</td>'
            f'<td><a href="/manage/user/{actor_h}" class="user-link">{actor_h}</a></td>'
            f'<td style="color:{acolor};font-family:var(--mono);font-size:0.78rem">{_h(action)}</td>'
            f'<td style="color:var(--muted)">{target_h}</td>'
            f'<td class="hash" style="font-size:0.75rem">{_h(e["detail"])}</td>'
            f'</tr>'
        )
    if not ev_rows:
        ev_rows = '<tr><td colspan="5" class="empty">No matching events</td></tr>'

    _tab_settings  = ('<button class="tab" onclick="showTab(\'settings\',this)">Settings</button>'
                      if is_super else '')
    _tab_database  = ('<button class="tab" onclick="showTab(\'database\',this)">Database</button>'
                      if is_super else '')
    _tab_economy   = ('<button class="tab" onclick="showTab(\'economy\',this)">Economy</button>'
                      if is_super else '')
    _tab_invites   = ('<button class="tab" onclick="showTab(\'invites\',this)">Invites</button>'
                      if (is_super or user['is_admin']) else '')
    _tab_danger    = ('<button class="tab tab-danger" onclick="showTab(\'danger\',this)"'
                      '>Danger</button>'
                      if is_super else '')
    _tab_names = ['torrents','users','adduser','trackers','settings','database','economy','invites','danger','events']
    if tab and tab in _tab_names:
        _safe_tab = tab.replace("'", '')
        _autotab_js = (
            '<script>window.addEventListener("DOMContentLoaded",function(){'
            'var els=document.querySelectorAll(".tab");'
            'for(var i=0;i<els.length;i++){'
            'var oc=els[i].getAttribute("onclick")||"";'
            f'if(oc.indexOf("showTab(\'{_safe_tab}\'")!==-1){{els[i].click();break;}}'
            '}})</script>'
        )
    elif uquery or upage > 1:
        _autotab_js = ('<script>window.addEventListener("DOMContentLoaded",function(){'
                       'var b=document.querySelector(".tab:nth-child(2)");'
                       'if(b){b.click();}})</script>')
    else:
        _autotab_js = ''

    body = f'''
  <div class="page-title">Admin Panel</div>
  <div class="page-sub">Manage torrents and users &nbsp;·&nbsp; <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none;font-size:0.85rem">&#10094; Dashboard</a></div>
  {_autotab_js}
  <div class="tabs">
    <button class="tab active" onclick="showTab('torrents',this)">Torrents</button>
    <button class="tab" onclick="showTab('users',this)">Users</button>
    <button class="tab" onclick="showTab('adduser',this)">Add User</button>
    <button class="tab" onclick="showTab('trackers',this)">Trackers</button>
    {_tab_settings}
    {_tab_database}
    {_tab_economy}
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
        <tr><th scope="col">Username</th><th scope="col">Role / Status</th><th scope="col">Created By</th><th scope="col">Last Login</th><th scope="col">Actions</th></tr>
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
          <input type="text" name="username" value="{_h(new_username)}" required>
        </div>
        <div class="form-group">
          <label for="adduser-pw">Password</label>
          <div class="pw-wrap"><input id="adduser-pw" type="password" name="password" required autocomplete="new-password"><button type="button" class="pw-eye" onclick="togglePwVis(this)" aria-label="Show password" tabindex="-1"><svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button></div>
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
        <tr><th scope="col">URL</th><th scope="col" style="text-align:center">Status</th><th scope="col">Actions</th></tr>
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
  {'<div class="panel" id="panel-database">' + database_html + '</div>' if is_super else ''}
  {'<div class="panel" id="panel-economy">' + economy_html + '</div>' if is_super else ''}
  {'<div class="panel" id="panel-invites">' + invites_html + '</div>' if (is_super or user['is_admin']) else ''}
  {'<div class="panel" id="panel-danger">' + danger_html + '</div>' if is_super else ''}

  <div class="panel" id="panel-events">
    <div class="card">
      <div class="card-title">Event Log
        <span style="color:var(--muted);font-size:0.78rem;font-weight:400;margin-left:8px">
          {ev_total} matching · showing up to 200
        </span>
      </div>
      <form method="GET" action="/manage/admin" style="margin-bottom:16px">
        <input type="hidden" name="tab" value="events">
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
          <div class="form-group" style="margin:0;flex:1;min-width:160px">
            <label style="font-size:0.75rem">Search all fields</label>
            <input type="text" name="eq" value="{_h(eq)}" placeholder="e.g. sally, bounty, 10000"
                   style="width:100%;padding:7px 10px;background:var(--card2);border:1px solid var(--border);
                          border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem">
          </div>
          <div class="form-group" style="margin:0;min-width:120px">
            <label style="font-size:0.75rem">Actor</label>
            <input type="text" name="eactor" value="{_h(eactor)}" placeholder="e.g. tracy"
                   style="width:100%;padding:7px 10px;background:var(--card2);border:1px solid var(--border);
                          border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem">
          </div>
          <div class="form-group" style="margin:0;min-width:140px">
            <label style="font-size:0.75rem">Action</label>
            <input type="text" name="eaction" value="{_h(eaction)}" placeholder="e.g. award_points"
                   style="width:100%;padding:7px 10px;background:var(--card2);border:1px solid var(--border);
                          border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem">
          </div>
          <div class="form-group" style="margin:0;min-width:120px">
            <label style="font-size:0.75rem">Target</label>
            <input type="text" name="etarget" value="{_h(etarget)}" placeholder="e.g. jason"
                   style="width:100%;padding:7px 10px;background:var(--card2);border:1px solid var(--border);
                          border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.82rem">
          </div>
          <button type="submit" class="btn btn-primary" style="white-space:nowrap">🔍 Search</button>
          <a href="/manage/admin?tab=events" class="btn" style="white-space:nowrap">✕ Clear</a>
        </div>
      </form>
      <div class="table-wrap"><table>
        <thead><tr>
          <th scope="col" style="white-space:nowrap">Time</th>
          <th scope="col">Actor</th>
          <th scope="col">Action</th>
          <th scope="col">Target</th>
          <th scope="col">Detail</th>
        </tr></thead>
        <tbody>{ev_rows}</tbody>
      </table></div>
    </div>
  </div>'''
    return _manage_page('Admin Panel', body, user=user, msg=msg, msg_type=msg_type)


def _deliver_notifications(cid: int, ih: str, tname: str,
                           uname: str, text: str, parent_id):
    """Send reply and @mention notifications for a newly posted comment."""
    if not REGISTRATION_DB:
        return
    if parent_id:
        parent_row = REGISTRATION_DB.get_comment(parent_id)
        if parent_row and parent_row['user_id'] != REGISTRATION_DB.get_user(uname)['id']:
            REGISTRATION_DB.add_notification(
                parent_row['user_id'], 'reply', uname, ih, tname, cid)
    mentioned = set(_MENTION_RE.findall(text))
    poster = REGISTRATION_DB.get_user(uname)
    poster_id = poster['id'] if poster else -1
    for mname in mentioned:
        if mname == uname: continue
        muser = REGISTRATION_DB.get_user(mname)
        if muser and muser['id'] != poster_id:
            REGISTRATION_DB.add_notification(
                muser['id'], 'mention', uname, ih, tname, cid)

_MENTION_RE = re.compile(r'@([a-zA-Z0-9._-]+)')

def _render_comment_body(body: str) -> str:
    """HTML-escape body then linkify @mentions."""
    escaped = _h(body)
    def _linkify(m):
        u = m.group(1)
        return f'<a href="/manage/user/{_h(u)}" class="user-link">@{_h(u)}</a>'
    return _MENTION_RE.sub(_linkify, escaped)


def _render_comments(info_hash: str, viewer, torrent_name: str, locked: bool = False) -> str:
    if not REGISTRATION_DB:
        return ''
    all_comments = REGISTRATION_DB.get_comments(info_hash)
    role   = _user_role(viewer)
    is_mod = role in ('super', 'admin')
    ih_h   = _h(info_hash)

    # Build parent->children map  (0 = top-level)
    children_map: dict = {}
    for c in all_comments:
        pid = c['parent_id'] or 0
        children_map.setdefault(pid, []).append(c)

    def _node(c, depth: int = 0) -> str:
        cid      = c['id']
        uname    = _h(c['username'])
        ts       = _h((c['created_at'] or '')[:16].replace('T', ' '))
        is_own   = (c['user_id'] == viewer['id'])
        can_del  = is_mod or is_own
        can_edit = is_own and not c['is_deleted']

        edited_html = ''
        if c['edited_at']:
            et = _h((c['edited_at'] or '')[:16].replace('T', ' '))
            edited_html = f' <span class="comment-edited">(edited {et})</span>'

        header = (
            f'<div class="comment-header">'
            f'<a href="/manage/user/{uname}" class="user-link">{uname}</a>'
            f'<span class="comment-ts">{ts}</span>'
            f'{edited_html}'
            f'</div>'
        )

        if c['is_deleted']:
            body_html    = '<div class="comment-deleted">[deleted]</div>'
            actions_html = ''
            reply_form   = ''
            edit_form    = ''
        else:
            body_html = (
                f'<div class="comment-body" id="comment-body-{cid}">'
                f'{_render_comment_body(c["body"])}</div>'
            )

            uname_js = uname.replace("'", "\\'")
            reply_onclick = 'toggleReplyForm(' + str(cid) + ', \'' + uname_js + '\')'  
            action_btns = []
            if not locked:
                action_btns.append(
                    f'<button class="btn-ghost" onclick="{reply_onclick}"'
                    f' aria-label="Reply to {uname}">&#x21A9; Reply</button>'
                )
            if can_edit and not locked:
                action_btns.append(
                    f'<button class="btn-ghost"'
                    f' onclick="toggleEditForm({cid})"'
                    f' aria-label="Edit your comment">&#x270E; Edit</button>'
                )
            if can_del:
                action_btns.append(
                    f'<form method="POST" action="/manage/comment/delete"'
                    f' style="display:inline">'
                    f'<input type="hidden" name="comment_id" value="{cid}">'
                    f'<input type="hidden" name="info_hash" value="{ih_h}">'
                    f'<button type="submit" class="btn-ghost btn-ghost-danger"'
                    f' aria-label="Delete comment">&#x2715; Delete</button>'
                    f'</form>'
                )
            actions_html = (
                f'<div class="comment-actions">{"".join(action_btns)}</div>'
            )

            edit_form = (
                f'<div class="comment-edit-form" id="edit-form-{cid}">'
                f'<form method="POST" action="/manage/comment/edit">'
                f'<input type="hidden" name="comment_id" value="{cid}">'
                f'<input type="hidden" name="info_hash" value="{ih_h}">'
                f'<label for="edit-ta-{cid}" class="sr-only">Edit comment</label>'
                f'<textarea id="edit-ta-{cid}" class="comment-textarea" name="body"'
                f' maxlength="2000" aria-label="Edit comment">{_h(c["body"])}</textarea>'
                f'<div style="display:flex;gap:8px;margin-top:8px">'
                f'<button type="submit" class="btn btn-primary btn-sm">Save</button>'
                f'<button type="button" class="btn btn-sm"'
                f' onclick="toggleEditForm({cid})">Cancel</button>'
                f'</div></form></div>'
            )

            # Reply form sits directly below this comment, before children
            reply_form = '' if locked else (
                f'<div class="comment-reply-form" id="reply-form-{cid}">'
                f'<form method="POST" action="/manage/comment/post">'
                f'<input type="hidden" name="info_hash" value="{ih_h}">'
                f'<input type="hidden" name="parent_id" value="{cid}">'
                f'<label for="reply-ta-{cid}" class="sr-only">Reply to {uname}</label>'
                f'<textarea id="reply-ta-{cid}" class="comment-textarea" name="body"'
                f' maxlength="2000" placeholder="Replying to {uname}&#8230;"'
                f' aria-label="Reply to {uname}"></textarea>'
                f'<div style="display:flex;gap:8px;margin-top:8px">'
                f'<button type="submit" class="btn btn-primary btn-sm">Post Reply</button>'
                f'<button type="button" class="btn btn-sm"'
                f' onclick="toggleReplyForm({cid})">Cancel</button>'
                f'</div></form></div>'
            )

        # Render children recursively, indented beneath this node
        children = children_map.get(cid, [])
        children_html = ''
        if children:
            child_items = ''.join(_node(ch, depth + 1) for ch in children)
            children_html = f'<div class="comment-children">{child_items}</div>'

        depth_cls = f'comment-depth-{min(depth, 3)}'
        return (
            f'<div class="comment-node {depth_cls}" id="comment-{cid}">'
            f'<div class="comment-inner">'
            f'{header}{body_html}{edit_form}{actions_html}{reply_form}'
            f'</div>'
            f'{children_html}'
            f'</div>'
        )

    top_level = children_map.get(0, [])
    cards_html = ''
    for c in top_level:
        cards_html += (
            f'<div class="comment-card">{_node(c, depth=0)}</div>'
        )

    if locked:
        add_form = (
            f'<div class="card" style="border-color:rgba(224,91,48,0.3)">'
            f'<div role="status" aria-live="polite"'
            f' style="display:flex;align-items:center;gap:10px;color:var(--muted);'
            f'font-family:var(--mono);font-size:0.82rem">'
            f'&#x1F512; Comments are locked for this torrent.'
            f'</div></div>'
        )
    else:
        add_form = (
            f'<div class="card">'
            f'<div class="card-title">Add Comment</div>'
            f'<form method="POST" action="/manage/comment/post">'
            f'<input type="hidden" name="info_hash" value="{ih_h}">'
            f'<div class="form-group">'
            f'<label for="new-comment-body" class="sr-only">Write a comment</label>'
            f'<textarea id="new-comment-body" class="comment-textarea" name="body"'
            f' maxlength="2000"'
            f' placeholder="Write a comment&#8230; use @username to mention someone"'
            f' aria-label="Write a comment" style="min-height:100px"></textarea>'
            f'</div>'
            f'<button type="submit" class="btn btn-primary">Post Comment</button>'
            f'</form></div>'
        )

    count = len(all_comments)
    lock_badge = (
        ' <span style="font-size:0.75rem;color:var(--red);'
        'font-family:var(--mono);font-weight:400">&#x1F512; Locked</span>'
        if locked else ''
    )
    count_html = (
        f' <span style="color:var(--muted);font-weight:400">({count})</span>'
        if count else ''
    )
    return (
        f'<div id="comments-section">'
        f'<div class="card-title" style="margin-bottom:20px">'
        f'Comments{count_html}{lock_badge}'
        f'</div>'
        f'{cards_html}{add_form}'
        f'</div>'
    )


    @staticmethod
    def get_setting(k,d=''): return d
    @staticmethod
    def get_dm_sent_today(u): return 0
    @staticmethod
    def dm_blocklist_get(uid): return []

def _render_messages_page(viewer, inbox, sent, blocklist,
                           tab='inbox', msg='', msg_type='info', compose_to=''):
    uname    = viewer['username']
    role     = _user_role(viewer)
    is_super = (role == 'super')
    cost     = int(REGISTRATION_DB.get_setting('dm_cost', '5'))
    daily    = int(REGISTRATION_DB.get_setting('dm_daily_limit', '10'))
    sent_today = REGISTRATION_DB.get_dm_sent_today(uname)
    allow    = viewer['allow_dms'] if 'allow_dms' in viewer.keys() else 1
    msg_html = ''
    if msg:
        clr = 'var(--green)' if msg_type == 'success' else 'var(--red)'
        msg_html = (f'<div style="background:{clr}22;border:1px solid {clr};'
                    f'color:{clr};padding:10px 14px;border-radius:6px;margin-bottom:16px">'
                    f'{_h(msg)}</div>')

    def _row(m, mode='inbox'):
        is_unread = (not m['read_at']) and mode == 'inbox'
        other = m['sender'] if mode == 'inbox' else m['recipient']
        subj  = _h(((m['subject'] if 'subject' in m.keys() else '') or '')[:60] or '(no subject)')
        ts    = _h(((m['sent_at'] if 'sent_at' in m.keys() else '') or '')[:16].replace('T', ' '))
        bold  = 'font-weight:700;' if is_unread else ''
        badge = ('<span style="background:var(--accent);color:#000;font-size:0.65rem;'
                 'padding:1px 5px;border-radius:3px;margin-left:6px">NEW</span>') if is_unread else ''
        bcast = ('<span style="background:var(--blue);color:#fff;font-size:0.65rem;'
                 'padding:1px 5px;border-radius:3px;margin-left:4px">BROADCAST</span>') if (m['is_broadcast'] if 'is_broadcast' in m.keys() else 0) else ''
        return (f'<tr style="cursor:pointer" onclick="location.href=\'/manage/messages/{m["id"]}\'">'
                f'<td style="{bold}padding:8px 10px">{_h(other)}{bcast}</td>'
                f'<td style="{bold}padding:8px 10px">{subj}{badge}</td>'
                f'<td style="padding:8px 10px;color:var(--muted);white-space:nowrap">{ts}</td>'
                f'</tr>')

    inbox_rows = (''.join(_row(m, 'inbox') for m in inbox)
                  or '<tr><td colspan="3" style="padding:20px;text-align:center;'
                     'color:var(--muted)">No messages</td></tr>')
    sent_rows  = (''.join(_row(m, 'sent') for m in sent)
                  or '<tr><td colspan="3" style="padding:20px;text-align:center;'
                     'color:var(--muted)">No sent messages</td></tr>')

    def _msg_table(rows, header1):
        return (f'<table style="width:100%;border-collapse:collapse">'
                f'<thead><tr style="border-bottom:1px solid var(--border)">'
                f'<th style="text-align:left;padding:8px 10px;color:var(--muted);'
                f'font-size:0.8rem">{header1}</th>'
                f'<th style="text-align:left;padding:8px 10px;color:var(--muted);'
                f'font-size:0.8rem">Subject</th>'
                f'<th style="text-align:left;padding:8px 10px;color:var(--muted);'
                f'font-size:0.8rem">Date</th>'
                f'</tr></thead><tbody>{rows}</tbody></table>')

    inbox_html = _msg_table(inbox_rows, 'From')
    sent_html  = _msg_table(sent_rows, 'To')
    unread_count = sum(1 for m in inbox if not m['read_at'])

    block_rows = ''
    for b in blocklist:
        bu = _h(b['blocked_username'])
        block_rows += (
            f'<tr><td style="padding:8px 10px">{bu}</td>'
            f'<td style="padding:8px 10px">'
            f'<form method="POST" action="/manage/messages/unblock" style="display:inline">'
            f'<input type="hidden" name="username" value="{bu}">'
            f'<button class="btn btn-sm btn-green">Unblock</button>'
            f'</form></td></tr>')
    blocked_html = (
        f'<table style="width:100%;border-collapse:collapse"><tbody>{block_rows}</tbody></table>'
        if blocklist else
        '<div style="color:var(--muted);padding:20px">No blocked users</div>')

    compose_html = (
        f'<div style="max-width:600px">'
        f'<form method="POST" action="/manage/messages/send">'
        
        f'<div style="margin-bottom:12px">'
        f'<label style="display:block;margin-bottom:4px;color:var(--muted);font-size:0.85rem">To (username, or multiple separated by ;)</label>'
        f'<input type="text" name="recipient" required value="{_h(compose_to)}" placeholder="e.g. cathy; bob; john" style="width:100%;background:var(--card2);'
        f'border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;box-sizing:border-box">'
        f'</div>'
        f'<div style="margin-bottom:12px">'
        f'<label style="display:block;margin-bottom:4px;color:var(--muted);font-size:0.85rem">Subject</label>'
        f'<input type="text" name="subject" maxlength="200" style="width:100%;background:var(--card2);'
        f'border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;box-sizing:border-box">'
        f'</div>'
        f'<div style="margin-bottom:12px">'
        f'<label style="display:block;margin-bottom:4px;color:var(--muted);font-size:0.85rem">Message</label>'
        f'<textarea name="body" required rows="6" maxlength="5000" style="width:100%;background:var(--card2);'
        f'border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;'
        f'box-sizing:border-box;resize:vertical"></textarea>'
        f'</div>'
        f'<button type="submit" class="btn">📩 Send</button>'
        f'</form>')
    if role not in ('admin', 'super') and cost > 0:
        compose_html += (f'<p style="color:var(--muted);font-size:0.83rem;margin-top:8px">'
                         f'Costs {cost} pts per message &middot; {sent_today}/{daily} sent today</p>')
    compose_html += '</div>'

    broadcast_html = ''
    if is_super:
        broadcast_html = (
            f'<div style="max-width:600px">'
            f'<div style="background:var(--accent)22;border:1px solid var(--accent);border-radius:6px;'
            f'padding:12px;margin-bottom:16px;font-size:0.85rem;color:var(--accent)">'
            f'&#x1F4E2; Broadcast sends to ALL non-disabled users. No point cost.</div>'
            f'<form method="POST" action="/manage/messages/broadcast">'
            
            f'<div style="margin-bottom:12px">'
            f'<label style="display:block;margin-bottom:4px;color:var(--muted);font-size:0.85rem">Subject</label>'
            f'<input type="text" name="subject" required maxlength="200" style="width:100%;background:var(--card2);'
            f'border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;box-sizing:border-box">'
            f'</div>'
            f'<div style="margin-bottom:12px">'
            f'<label style="display:block;margin-bottom:4px;color:var(--muted);font-size:0.85rem">Message</label>'
            f'<textarea name="body" required rows="6" maxlength="5000" style="width:100%;background:var(--card2);'
            f'border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;'
            f'box-sizing:border-box;resize:vertical"></textarea>'
            f'</div>'
            f'<button type="submit" class="btn" style="background:var(--accent)22;border-color:var(--accent);'
            f'color:var(--accent)" onclick="return confirm(\'Send broadcast DM to all users?\')">'
            f'&#x1F4E2; Send Broadcast</button>'
            f'</form></div>')

    tabs = [('inbox',   f'&#x1F4E5; Inbox{" (" + str(unread_count) + ")" if unread_count else ""}'),
            ('sent',    '&#x1F4E4; Sent'),
            ('compose', '✍️ Compose'),
            ('blocked', '&#x1F6AB; Blocked')]
    if is_super:
        tabs.append(('broadcast', '&#x1F4E2; Broadcast'))

    content_map = {
        'inbox':     inbox_html,
        'sent':      sent_html,
        'compose':   compose_html,
        'blocked':   blocked_html,
        'broadcast': broadcast_html,
    }
    tab_buttons = ''
    tab_contents = ''
    for tid, tlabel in tabs:
        tab_cls = ' active' if tid == tab else ''
        tab_buttons += f'<button class="tab{tab_cls}" onclick="showTab(\'{tid}\',this)">{tlabel}</button>'
        tab_contents += f'<div id="panel-{tid}" class="panel{" visible" if tid == tab else ""}">{content_map.get(tid,"")}</div>'

    allow_checked = 'checked' if allow else ''
    toggle_html = (
        f'<form method="POST" action="/manage/messages/toggle-dms" style="margin-top:8px">'
        
        f'<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.9rem">'
        f'<input type="checkbox" name="allow_dms" value="1" {allow_checked} onchange="this.form.submit()">'
        f' Allow others to send me DMs</label></form>')

    mark_all = ''
    if unread_count:
        mark_all = (f'<form method="POST" action="/manage/messages/mark-read" style="display:inline;margin-top:4px">'
                    
                    f'<button class="btn btn-sm">&#x2713; Mark all read</button></form>')

    body = (
        f'<div class="page-title">📬 Messages</div>'
        f'<div class="page-sub"><a href="/manage/dashboard" style="color:var(--muted);'
        f'text-decoration:none">&#10094; Dashboard</a></div>'
        f'{msg_html}'
        f'{toggle_html}'
        f'{mark_all}'
        f'<div class="card" style="margin-top:16px">'
        f'<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">{tab_buttons}</div>'
        f'{tab_contents}</div>')
    return _manage_page('📬 Messages', body, user=viewer)


def _render_message_thread(viewer, thread, focus_id, msg='', msg_type='info'):
    uname = viewer['username']
    role  = _user_role(viewer)
    other_party = None
    for m in thread:
        if m['sender'] != uname:
            other_party = m['sender']
            break
        if m['recipient'] != uname:
            other_party = m['recipient']
            break

    bubbles = ''
    for m in thread:
        is_mine = m['sender'] == uname
        align   = 'flex-end' if is_mine else 'flex-start'
        bg      = 'var(--accent)22' if is_mine else 'var(--card2)'
        border  = 'var(--accent)' if is_mine else 'var(--border)'
        ts      = _h(((m['sent_at'] if 'sent_at' in m.keys() else '') or '')[:16].replace('T', ' '))
        subj    = _h(((m['subject'] if 'subject' in m.keys() else '') or '')[:80])
        bcast_badge = ('<span style="background:var(--blue);color:#fff;font-size:0.65rem;'
                       'padding:1px 5px;border-radius:3px;margin-left:4px">BROADCAST</span>'
                       ) if (m['is_broadcast'] if 'is_broadcast' in m.keys() else 0) else ''
        del_form = (
            f'<form method="POST" action="/manage/messages/delete" style="display:inline;margin-left:8px">'
            
            f'<input type="hidden" name="msg_id" value="{m["id"]}">'
            f'<button class="btn btn-sm" style="font-size:0.7rem;background:var(--red)22;'
            f'color:var(--red);border-color:var(--red)" '
            f'onclick="return confirm(\'Delete this message?\')">&#x1F5D1;</button></form>')
        bubbles += (
            f'<div style="display:flex;justify-content:{align};margin-bottom:12px">'
            f'<div style="max-width:75%;background:{bg};border:1px solid {border};'
            f'border-radius:10px;padding:10px 14px">'
            f'<div style="font-size:0.75rem;color:var(--muted);margin-bottom:4px">'
            f'<strong>{_h(m["sender"])}</strong> &#x2192; '
            f'<strong>{_h(m["recipient"])}</strong>{bcast_badge} &middot; {ts}'
            f'{del_form}</div>'
            + (f'<div style="font-size:0.82rem;color:var(--muted);margin-bottom:4px">{subj}</div>' if subj else '')
            + f'<div style="white-space:pre-wrap;word-break:break-word">{_h(m["body"])}</div>'
            f'</div></div>')

    last_msg  = thread[-1]
    reply_html = (
        f'<div class="card" style="margin-top:16px">'
        f'<div class="card-title" style="font-size:0.9rem">Reply</div>'
        f'<form method="POST" action="/manage/messages/reply">'
        
        f'<input type="hidden" name="reply_to_id" value="{last_msg["id"]}">'
        f'<textarea name="body" rows="4" maxlength="5000" placeholder="Write a reply..." '
        f'style="width:100%;background:var(--card2);border:1px solid var(--border);'
        f'color:var(--text);padding:8px 12px;border-radius:6px;box-sizing:border-box;'
        f'resize:vertical;margin-bottom:8px"></textarea>'
        f'<button type="submit" class="btn btn-sm">&#x21A9; Send Reply</button>'
        f'</form></div>')

    block_html = ''
    if other_party:
        other_user = REGISTRATION_DB.get_user(other_party) if REGISTRATION_DB else None
        other_role = _user_role(other_user) if other_user else 'basic'
        # Anyone can block regular users. No one can block admin/super.
        if other_role not in ('admin', 'super'):
            blocklist = REGISTRATION_DB.dm_blocklist_get(viewer['id'])
            already_blocked = any(b['blocked_username'] == other_party for b in blocklist)
            opu = _h(other_party)
            if already_blocked:
                block_html = (
                    f' &nbsp;&#183;&nbsp; '
                    f'<form method="POST" action="/manage/messages/unblock" style="display:inline">'
                    f'<input type="hidden" name="username" value="{opu}">'
                    f'<button class="btn btn-sm btn-green">'
                    f'Unblock {opu}</button></form>')
            else:
                block_html = (
                    f' &nbsp;&#183;&nbsp; '
                    f'<form method="POST" action="/manage/messages/block" style="display:inline">'
                    f'<input type="hidden" name="username" value="{opu}">'
                    f'<button class="btn btn-sm btn-danger" onclick="return confirm(\'Block {opu}?\')">'
                    f'&#x1F6AB; Block {opu}</button></form>')

    profile_link = ''
    if other_party:
        opu = _h(other_party)
        profile_link = (f' &nbsp;&#183;&nbsp; '
                        f'<a href="/manage/user/{opu}" class="btn btn-sm" '
                        f'style="text-decoration:none">👤 {opu}\'s Profile</a>')

    msg_html = ''
    if msg:
        clr = 'var(--green)' if msg_type == 'success' else 'var(--red)'
        msg_html = (f'<div style="background:{clr}22;border:1px solid {clr};color:{clr};'
                    f'padding:10px 14px;border-radius:6px;margin:12px 0">{_h(msg)}</div>')

    body = (
        f'<div class="page-title">📬 Conversation</div>'
        f'<div class="page-sub" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">'
        f'<a href="/manage/messages" style="color:var(--muted);text-decoration:none">&#10094; Messages</a>'
        f'{profile_link}'
        f'{block_html}</div>'
        f'{msg_html}'
        f'<div style="margin-top:16px">{bubbles}</div>'
        f'{reply_html}')
    return _manage_page('📬 Conversation', body, user=viewer)


def _render_notifications_page(viewer) -> str:
    if not REGISTRATION_DB:
        return _manage_page('Notifications', '<p>Unavailable</p>', user=viewer)
    notifs = REGISTRATION_DB.get_all_notifications(viewer['id'])
    unread_count = sum(1 for n in notifs if not n['is_read'])

    rows = ''
    for n in notifs:
        is_bounty = str(n['info_hash']).upper().startswith('BOUNTY:')
        ts_h = _h((n['created_at'] or '')[:16].replace('T', ' '))
        from_h = _h(n['from_username'])
        tname_h = _h(n['torrent_name'])
        unread_cls = '' if n['is_read'] else ' unread'
        n_id = n['id']

        if is_bounty:
            bid = str(n['info_hash']).split(':',1)[1]
            ntype = n['type']
            icon, label = {
                'bounty_claimed':          ('🎯', 'claimed your bounty'),
                'bounty_rejected':         ('✗',  'rejected your claim on'),
                'bounty_fulfilled':        ('✅', 'fulfilled bounty'),
                'bounty_contribution':     ('➕', 'added points to your bounty'),
                'bounty_expired':          ('⏰', 'bounty expired:'),
                'bounty_uploader_payout':  ('💰', 'fulfilled a bounty using your upload:'),
            }.get(ntype, ('🔔', 'bounty update on'))
            url = f'/manage/bounty/{bid}'
            read_js = f"readNotif({n_id},'{url}')"
            rows += (
                f'<div class="notif-page-item{unread_cls}">'
                f'<div>'
                f'<div style="font-size:0.9rem"><span style="margin-right:6px">{icon}</span>'
                f'<a href="/manage/user/{from_h}" class="user-link">{from_h}</a>'
                f' {label} '
                f'<a href="{url}" onclick="event.preventDefault();{read_js}" style="color:var(--accent);text-decoration:none">{tname_h}</a></div>'
                f'<div class="notif-page-meta">{ts_h}</div>'
                f'</div>'
                f'<button class="btn btn-sm" style="white-space:nowrap" onclick="{read_js}">View →</button>'
                f'</div>'
            )
        else:
            icon  = '💬' if n['type'] == 'reply' else '@ '
            label = 'replied to your comment' if n['type'] == 'reply' else 'mentioned you'
            url   = f'/manage/torrent/{n["info_hash"].lower()}#comment-{n["comment_id"]}'
            read_js = f"readNotif({n_id},'{url}')"
            rows += (
                f'<div class="notif-page-item{unread_cls}">'
                f'<div>'
                f'<div style="font-size:0.9rem"><span style="margin-right:6px">{icon}</span>'
                f'<a href="/manage/user/{from_h}" class="user-link">{from_h}</a>'
                f' {label} on '
                f'<a href="{url}" onclick="event.preventDefault();{read_js}" style="color:var(--accent);text-decoration:none">{tname_h}</a></div>'
                f'<div class="notif-page-meta">{ts_h}</div>'
                f'</div>'
                f'<button class="btn btn-sm" style="white-space:nowrap" onclick="{read_js}" aria-label="View notification from {from_h}">View →</button>'
                f'</div>'
            )

    if not rows:
        rows = '<div style="text-align:center;padding:48px;color:var(--muted);font-family:var(--mono);font-size:0.85rem">No notifications yet</div>'

    mark_all = ''
    if unread_count:
        mark_all = (
            f'<form method="POST" action="/manage/notifications/read-all" style="display:inline">'
            f'<button class="btn btn-sm">✓ Mark all read</button>'
            f'</form>'
        )

    body = (
        f'<div class="page-title">Notifications</div>'
        f'<div class="page-sub" style="display:flex;justify-content:space-between;align-items:center">'
        f'<span><a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a></span>'
        f'{mark_all}'
        f'</div>'
        f'{rows}'
    )
    return _manage_page('Notifications', body, user=viewer)


def _render_torrent_detail(viewer, t, back_url: str = '/manage/dashboard', msg: str = '', msg_type: str = 'error', warn: str = '') -> str:
    """Full detail page for a single torrent."""
    is_super  = viewer['username'] == SUPER_USER
    vrole     = _user_role(viewer)
    is_owner  = t['uploaded_by_id'] == viewer['id']
    can_del   = is_super or vrole == 'admin' or is_owner
    ih        = t['info_hash']

    # ── Dynamic back link label ───────────────────────────────
    import re as _re
    _back_path = back_url.split('?')[0]
    _bounty_m  = _re.match(r'^/manage/bounty/(\d+)$', _back_path)
    if _bounty_m:
        _back_label = f'Bounty #{_bounty_m.group(1)}'
    else:
        _back_label = {
            '/manage/dashboard': 'Dashboard',
            '/manage/search':    'Search',
            '/manage/bounty':    'Bounty Board',
            '/manage/admin':     'Admin Panel',
        }.get(_back_path, 'Back')
    _back_html = (
        f'<a href="{back_url}" style="color:var(--muted);text-decoration:none">&#10094; {_back_label}</a>'
        + ('' if _back_path == '/manage/dashboard' else
           ' &nbsp;&#183;&nbsp; <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a>')
    )
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
            '<tr><th scope="col">Path</th><th scope="col" style="text-align:right">Size</th></tr>'
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
                   f'<button class="btn btn-danger" aria-label="Delete torrent {tname}">Delete</button></form>')

    # Lock/unlock comments button (admin/super only)
    role = _user_role(viewer)
    lock_btn = ''
    del_comments_btn = ''
    if role in ('super', 'admin'):
        locked = t['comments_locked'] if 'comments_locked' in t.keys() else 0
        if locked:
            lock_btn = (f'<a href="/manage/torrent/unlock/{ih.lower()}" class="btn btn-sm"'
                        f' aria-label="Unlock comments for this torrent">&#x1F513; Unlock Comments</a>')
        else:
            lock_btn = (f'<a href="/manage/torrent/lock/{ih.lower()}" class="btn btn-sm btn-danger"'
                        f' aria-label="Lock comments for this torrent">&#x1F512; Lock Comments</a>')
        tname_esc = t['name'].replace('"', '&quot;').replace("'", '&#39;')
        del_comments_btn = (
            f'<form method="POST" action="/manage/comment/delete-all" style="display:inline"'
            f' data-confirm="Delete ALL comments on {tname_esc}? This cannot be undone.">'
            f'<input type="hidden" name="info_hash" value="{ih}">'
            f'<button type="submit" class="btn btn-sm btn-danger"'
            f' aria-label="Delete all comments on this torrent">&#x1F5D1; Delete All Comments</button>'
            f'</form>'
        )

    body = f'''
  <div class="page-title">{t["name"]}</div>
  <div class="page-sub">
    {_back_html}
  </div>

  <div class="two-col" style="margin-bottom:0">
    <div class="card">
      <div class="card-title">Torrent Info</div>
      <table style="min-width:unset">
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;width:40%">NAME</td>
            <td style="word-break:break-all">{t["name"]}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em">INFO HASH</td>
            <td class="hash" style="word-break:break-all;font-size:0.82rem">
              <span onclick="copyHash(this,'{ih}')"
                    title="Click to copy"
                    style="cursor:pointer;border-bottom:1px dashed var(--muted)">{ih}</span>
            </td></tr>
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
        {lock_btn}
        {del_comments_btn}
      </div>
    </div>
  </div>

  <div class="card">
    {files_html}
  </div>'''

    is_locked = bool(t['comments_locked']) if 'comments_locked' in t.keys() else False
    _comments_globally_on = (
        REGISTRATION_DB.get_setting('comments_enabled', '1') == '1'
    ) if REGISTRATION_DB else True
    comments_html = (
        _render_comments(ih, viewer, t['name'], locked=is_locked)
        if _comments_globally_on else ''
    )
    warn_script = ''
    if warn:
        names = _h(warn)
        warn_script = (
            f'<script>document.addEventListener("DOMContentLoaded",function(){{'
            f'showWarnModal("The following @mention(s) were not delivered because '
            f'those usernames do not exist:<br><br><strong>{names}</strong>");'
            f'}});</script>'
        )
    return _manage_page(t['name'], body + comments_html + warn_script,
                        user=viewer, msg=msg, msg_type=msg_type)


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
                      f'style="color:var(--muted);text-decoration:none">&#9881;&#65039; Admin View</a>')

    role_badge = f'<span class="badge badge-{trole}">{trole.upper()}</span>'

    # Safe public fields only
    joined    = (target_user['created_at'] or '')[:10] or '--'
    pts_val   = target_user['points']       if 'points'       in target_user.keys() else 0
    streak    = target_user['login_streak'] if 'login_streak' in target_user.keys() else 0
    pts_color = 'var(--danger)' if pts_val < 0 else 'var(--accent)'

    def _pub_row(label, value):
        return (f'<tr>'
                f'<td style="font-family:var(--mono);font-size:0.72rem;letter-spacing:0.1em;'
                f'text-transform:uppercase;color:var(--muted);padding:10px 24px 10px 0;white-space:nowrap">{label}</td>'
                f'<td style="padding:10px 0">{value}</td>'
                f'</tr>')
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
    &nbsp;&#183;&nbsp; <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a>
    {admin_link}
    {'&nbsp;&#183;&nbsp; <a href="/manage/messages?to=' + uname_h + '" class="btn btn-sm">📬 Send DM</a>' if (not is_own and vrole != 'basic' and REGISTRATION_DB and REGISTRATION_DB.get_setting('dm_enabled','1') == '1' and not target_user['is_disabled']) else ''}
  </div>

  <div class="card" style="max-width:400px">
    <div class="card-title">Account</div>
    <table style="min-width:unset">
      {_pub_row('Member Since', joined)}
      {_pub_row('Points', f'<span style="color:{pts_color};font-weight:bold">{pts_val}</span>'
                          + (f' <span style="color:var(--muted);font-size:0.8rem">🔥 {streak}-day streak</span>'
                             if streak > 1 else ''))}
      {_pub_row('Torrents', str(total))}
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
                        page: int = 1, total_pages: int = 1, total: int = 0, base_url: str = '',
                        ledger=None, bounty_data=None,
                        msg: str = '', msg_type: str = 'error'):
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
    pts_val     = target_user['points']  if 'points'  in target_user.keys() else 0
    streak_val  = target_user['login_streak'] if 'login_streak' in target_user.keys() else 0
    raw_cb = target_user['created_by'] or '--'
    if raw_cb.startswith('invite:'):
        inviter = _h(raw_cb[7:])
        created_by_display = f'Invited by <strong>{inviter}</strong>'
    else:
        created_by_display = _h(raw_cb)
    pts_color = 'var(--danger)' if pts_val < 0 else 'var(--accent)'
    info_rows = (
        row('Created',          (target_user['created_at'] or '')[:16] or '--')
        + row('Created By',     created_by_display)
        + row('Last Login',     (target_user['last_login'] or 'Never')[:16])
        + row('Login Count',    str(lc))
        + row('Password Changed', lpc[:16] if lpc else 'Never recorded')
        + row('Failed Attempts', str(target_user['failed_attempts']))
        + row('Points',         f'<span style="color:{pts_color};font-weight:bold">{pts_val}</span>'
                                + (f' <span style="color:var(--muted);font-size:0.8rem">(🔥 {streak_val}-day streak)</span>'
                                   if streak_val > 1 else ''))
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
            '<div class="two-col">'
            + '<div class="card" style="overflow:hidden">'
            + '<div class="card-title">Recent Login IPs</div>'
            + '<form id="ip-lock-form" method="POST" action="/manage/admin/ip-lock">'
            + '<input type="hidden" name="user_id" value="' + str(target_user['id']) + '">'
            + '<div style="overflow-x:auto"><table style="table-layout:fixed;width:100%;border-collapse:collapse">'
            + '<tr><th scope="col" style="width:28px;padding:6px 8px"></th>'
            + '<th scope="col" style="width:36%;padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">TIME</th>'
            + '<th scope="col" style="padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">IP ADDRESS</th></tr>'
            + ip_rows
            + '</table></div>'
            + '<div style="margin-top:12px">'
            + '<button type="button" class="btn btn-sm btn-primary" onclick="doIpLock()">&#128274; IP Lock Selected</button>'
            + '</div></form></div>'
            + '<div class="card" style="overflow:hidden">'
            + '<div class="card-title">IP Allowlist</div>'
            + '<div style="overflow-x:auto"><table style="table-layout:fixed;width:100%;border-collapse:collapse">'
            + '<tr>'
            + '<th scope="col" style="padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">IP ADDRESS</th>'
            + '<th scope="col" style="width:50%;padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">ADDED</th>'
            + '<th scope="col" style="width:120px;padding:6px 8px;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);text-align:left">ACTION</th>'
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
            '<div class="card" style="border-color:rgba(224,91,48,0.3)">'
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
    nav_links = ' &nbsp;&#183;&nbsp; <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a>'
    if not is_own_profile:
        nav_links = (
            ' &nbsp;&#183;&nbsp; <a href="/manage/admin" style="color:var(--muted);text-decoration:none">'
            + '&#10094; Admin Panel</a>'
            + nav_links
        )

    # ── Actions card (admin/super only, not own profile) ────
    actions_card = ''
    viewer_role = _user_role(viewer)
    t_is_super  = (uname == SUPER_USER)
    t_is_admin  = target_user['is_admin']
    if is_own_profile:
        # Build invite section inline for right column
        _invite_html = _render_invite_section(viewer, target_user, True, REGISTRATION_DB)
        # Build send points inline for right column
        _points_top  = _render_points_section(viewer, target_user, True, ledger, bounty_data, part='top')
        actions_card = (
            '<div style="display:flex;flex-direction:column;gap:24px">'
            '<div class="card"><div class="card-title">Actions</div>'
            '<div style="display:flex;flex-direction:column;gap:14px">'
            '<div>'
            '<a href="/manage/password" class="btn btn-primary">Change Password</a>'
            '</div>'
            '</div>'
            '<div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--border)">'
            '<div style="font-size:0.85rem;color:var(--muted);margin-bottom:8px">Messaging</div>'
            '<form method="POST" action="/manage/messages/toggle-dms" style="display:flex;align-items:center;gap:10px">'
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.9rem">'
            '<input type="checkbox" name="allow_dms" value="1" '
            + ('checked' if ('allow_dms' in viewer.keys() and viewer['allow_dms']) else '')
            + '> Allow others to send me DMs</label>'
            '<button type="submit" class="btn btn-sm">Save</button>'
            '</form>'
            '</div>'
            '</div></div>'
            + _invite_html
            + _points_top
            + '</div>'
        )
    elif viewer_role in ('super', 'admin'):
        hi = '<input type="hidden" name="username" value="' + uname_h + '">'
        pw_form = ''
        if not t_is_super:
            pw_form = (
                '<a href="/manage/admin/set-password/' + uname_h + '" class="btn btn-sm">Set Password</a>'
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
        max_grant  = int(REGISTRATION_DB.get_setting('admin_max_point_grant', '1000')) if REGISTRATION_DB else 1000
        credit_btns = (
            f'<form method="POST" action="/manage/admin/adjust-credits" '
            f'style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">'
            f'<input type="hidden" name="username" value="{uname_h}">'
            f'<input type="hidden" name="referer" value="{hi_referer}">'
            f'<input type="number" name="delta" value="10" min="-{max_grant}" max="{max_grant}" '
            f'style="width:90px;padding:6px 10px;background:var(--card2);border:1px solid var(--border);'
            f'border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.85rem" '
            f'title="Positive adds points, negative removes. Max ±{max_grant}.">'
            f'<button type="submit" class="btn btn-sm btn-green" '
            f'onclick="var v=parseInt(this.form.delta.value)||0;this.form.delta.value=Math.abs(v)">＋ Grant</button>'
            f'<button type="submit" class="btn btn-sm btn-danger" '
            f'onclick="var v=parseInt(this.form.delta.value)||0;this.form.delta.value=-Math.abs(v)">－ Remove</button>'
            f'</form>'
            f'<div style="display:flex;gap:6px;margin-top:4px">'
            f'<form method="POST" action="/manage/admin/adjust-credits" style="display:inline">'
            f'<input type="hidden" name="username" value="{uname_h}">'
            f'<input type="hidden" name="delta" value="10">'
            f'<input type="hidden" name="referer" value="{hi_referer}">'
            f'<button class="btn btn-sm">Quick +10</button></form>'
            f'<form method="POST" action="/manage/admin/adjust-credits" style="display:inline">'
            f'<input type="hidden" name="username" value="{uname_h}">'
            f'<input type="hidden" name="delta" value="-10">'
            f'<input type="hidden" name="referer" value="{hi_referer}">'
            f'<button class="btn btn-sm">Quick −10</button></form>'
            f'</div>'
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
    # Send DM button — show on other users' profiles (Standard+ only, if DMs enabled)
    dm_btn = ''
    if (not is_own_profile
            and REGISTRATION_DB
            and REGISTRATION_DB.get_setting('dm_enabled', '1') == '1'
            and _user_role(viewer) not in ('basic',)
            and not target_user['is_disabled']):
        dm_btn = (f' &nbsp;&#183;&nbsp; <a href="/manage/messages?tab=compose&to={uname_h}" '
                  f'class="btn btn-sm">📬 Send DM</a>')

    body = (
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;flex-wrap:wrap">'
        + '<div class="page-title">' + uname_h + '</div>'
        + role_badge + status_badges
        + '</div>'
        + '<div class="page-sub" style="margin-bottom:20px">'
        + ('Your profile' if is_own_profile else 'User profile')
        + nav_links
        + dm_btn + '</div>'
        + '<div style="display:flex;flex-direction:column;gap:24px">'
        + '<div class="two-col">'
        + '<div class="card"><div class="card-title">Account Details</div>'
        + '<table style="min-width:unset">' + info_rows + '</table></div>'
        + actions_card
        + '</div>'
        + _render_points_section(viewer, target_user, is_own_profile, ledger, bounty_data, part='rest')
        + ip_html
        + delete_all_html
        + torrent_html
        + '</div>'
    )
    # Profile-level msg banner
    if msg:
        col = 'var(--green)' if msg_type == 'success' else 'var(--danger)'
        msg_card = (f'<div style="background:{col};color:#fff;padding:10px 16px;'
                    f'border-radius:8px;margin-bottom:16px;font-size:0.9rem">{_h(msg)}</div>')
        body = msg_card + body
    return _manage_page(('My Profile' if is_own_profile else 'User: ' + uname_h), body, user=viewer)



def _render_points_section(viewer, target_user, is_own_profile: bool,
                            ledger, bounty_data, part: str = 'all') -> str:
    """Points ledger, transfer form, bounty history, and Basic sandbox teaser.
       part='top'  — Send Points card only (for two-col placement)
       part='rest' — bounty tables + ledger (full-width)
       part='all'  — everything (legacy)
    """
    if not is_own_profile or not REGISTRATION_DB:
        return ''

    role  = _user_role(target_user)
    pts   = target_user['points'] if 'points' in target_user.keys() else 0
    uname = target_user['username']
    out   = ''

    # Basic sandbox teaser
    if role == 'basic':
        threshold  = int(REGISTRATION_DB.get_setting('auto_promote_threshold', '100'))
        ap_enabled = REGISTRATION_DB.get_setting('auto_promote_enabled', '0') == '1'
        if ap_enabled:
            pct = min(100, int(pts / threshold * 100)) if threshold > 0 else 0
            out += (
                f'''<div class="card" style="border:1px solid var(--accent)">'''
                + f'<div class="card-title" style="color:var(--accent)">🔒 Basic Member — Unlock More Features</div>'
                + f'<p style="color:var(--muted);font-size:0.88rem;margin-bottom:12px">'
                + f'Reach <strong>{threshold} points</strong> to unlock <strong>Standard</strong> membership:</p>'
                + '<ul style="color:var(--muted);font-size:0.88rem;margin:0 0 16px 20px;line-height:1.8">'
                + '<li>🎯 <strong>Bounty Board</strong> — post requests, claim rewards</li>'
                + '<li>🏆 <strong>Leaderboard</strong> — compete for top holder, earner, uploader & streak rankings</li>'
                + '<li>👥 <strong>Public Profiles</strong> — view other members</li>'
                + '<li>💸 <strong>Point Transfers</strong> — send points to friends</li>'
                + '<li>✅ <strong>Bounty Voting</strong> — vote on fulfillment claims</li></ul>'
                + f'<div style="background:var(--card2);border-radius:8px;overflow:hidden;height:12px;margin-bottom:8px">'
                + f'<div style="background:var(--accent);height:100%;width:{pct}%;transition:width 0.3s"></div></div>'
                + f'<div style="font-size:0.82rem;color:var(--muted)">{pts} / {threshold} points ({pct}%)'
                + ' — earn by logging in daily, uploading torrents, and commenting</div></div>'
            )
        return out

    # Transfer form (Standard+)
    fee_pct = int(REGISTRATION_DB.get_setting('points_transfer_fee_pct', '25'))
    out += (
        '<div class="card">'
        + '<div class="card-title">💸 Send Points</div>'
        + f'<p style="color:var(--muted);font-size:0.85rem;margin-bottom:12px">'
        + f'Transfer points. A <strong>{fee_pct}%</strong> fee is destroyed. Balance: <strong>{pts} pts</strong></p>'
        + '<form method="POST" action="/manage/points/transfer">'
        + '<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">'
        + '<div class="form-group" style="margin:0"><label>Recipient</label>'
        + '<input type="text" name="to_username" maxlength="32" required '
        + 'style="padding:8px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text)"></div>'
        + '<div class="form-group" style="margin:0"><label>Amount</label>'
        + f'<input type="number" name="amount" min="1" max="{max(0,pts)}" required '
        + 'style="width:100px;padding:8px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text)"></div>'
        + f'<button type="submit" class="btn btn-primary" data-confirm="Send? {fee_pct}% fee destroyed.">Send</button>'
        + '</div></form></div>'
    )

    if part == 'top':
        return out
    elif part == 'rest':
        out = ''  # reset — only return the sections below

    # Bounty history
    if bounty_data:
        def _brow(b):
            bid  = b['id']
            desc = _h(b['description'][:60] + ('\u2026' if len(b['description']) > 60 else ''))
            badge = _bounty_status_badge(b['status'])
            p    = f'<span style="color:var(--accent)">{b["total_escrow"]} pts</span>'
            return (f'<tr><td><a href="/manage/bounty/{bid}">{desc}</a></td>'
                    f'<td style="text-align:center">{badge}</td>'
                    f'<td style="text-align:center">{p}</td></tr>')

        cr = ''.join(_brow(b) for b in bounty_data['created'][:10])
        ff = ''.join(_brow(b) for b in bounty_data['fulfilled'][:10])
        hdr = '<thead><tr><th>Description</th><th>Status</th><th>Points</th></tr></thead>'
        if cr or ff:
            if cr and ff:
                out += '<div class="two-col">'
            if cr:
                out += ('<div class="card"><div class="card-title">My Bounties</div>'
                        + '<div class="table-wrap"><table class="torrent-table">'
                        + hdr + f'<tbody>{cr}</tbody></table></div>'
                        + '<a href="/manage/bounty" class="btn btn-sm" style="margin-top:8px">View All →</a></div>')
            if ff:
                out += ('<div class="card"><div class="card-title">Bounties I Fulfilled</div>'
                        + '<div class="table-wrap"><table class="torrent-table">'
                        + hdr + f'<tbody>{ff}</tbody></table></div></div>')
            if cr and ff:
                out += '</div>'

    # Points ledger
    if ledger:
        rows = ''
        for e in ledger:
            d = e['delta']; color = 'var(--green)' if d > 0 else 'var(--danger)'
            sign = '+' if d > 0 else ''
            rows += (f'<tr style="border-top:1px solid var(--border)">'
                     f'<td class="hash" style="padding:8px 12px 8px 0;white-space:nowrap;font-size:0.8rem">{_h((e["created_at"] or "")[:16])}</td>'
                     f'<td style="padding:8px 12px 8px 0;color:{color};font-weight:700;white-space:nowrap">{sign}{d}</td>'
                     f'<td style="padding:8px 12px 8px 0;color:var(--accent);white-space:nowrap">{e["balance_after"]}</td>'
                     f'<td style="padding:8px 0;word-break:break-word">{_h(e["reason"])}</td></tr>')
        out += ('<div class="card"><div class="card-title">Points History (last 50)</div>'
                + '<table style="width:100%;border-collapse:collapse">'
                + '<thead><tr>'
                + '<th style="text-align:left;padding:6px 12px 6px 0;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);white-space:nowrap">Date</th>'
                + '<th style="text-align:left;padding:6px 12px 6px 0;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);white-space:nowrap">Change</th>'
                + '<th style="text-align:left;padding:6px 12px 6px 0;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);white-space:nowrap">Balance</th>'
                + '<th style="text-align:left;padding:6px 0;font-family:var(--mono);font-size:0.7rem;letter-spacing:0.1em;color:var(--muted);width:99%">Reason</th>'
                + '</tr></thead>'
                + f'<tbody>{rows}</tbody></table></div>')

    return out


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

    pts_val   = target_user['points'] if 'points' in target_user.keys() else 0
    inv_cost  = int(db.get_setting('points_invite_cost', '1000')) if db else 1000

    # Generate button (own profile only, explicit purchase with points)
    gen_btn = ''
    if is_own_profile:
        can_afford = pts_val >= inv_cost
        if can_afford:
            gen_btn = (
                f'<form method="POST" action="/manage/profile/generate-invite" style="display:inline">'
                f'<button class="btn btn-primary"'
                f' data-confirm="Purchase an invite link for {inv_cost} points?">'
                f'🎟 Purchase Invite Link ({inv_cost} pts)</button></form>'
            )
        else:
            gen_btn = (
                f'<button class="btn" style="opacity:0.5;cursor:not-allowed" disabled>'
                f'🎟 Purchase Invite Link ({inv_cost} pts required · you have {pts_val})</button>'
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
            + f'<button class="btn btn-sm btn-green" onclick="copyInvite(this,{repr(invite_path)})">&#128279; Copy URL</button>'
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
        + '<table><tr><th scope="col">Code</th><th scope="col">Created</th><th scope="col">Status</th><th scope="col">Actions</th></tr>'
        + rows
        + '</table></div>'
    )


def _render_admin_set_password_page(viewer, target_user, msg: str = '', msg_type: str = 'error') -> str:
    """Admin-only page to set another user's password — no current password required."""
    pw_settings = REGISTRATION_DB.get_all_settings() if REGISTRATION_DB else {}
    pw_req_html = _pw_requirements_html(pw_settings)
    tname_h = _h(target_user['username'])
    cancel_url = f'/manage/admin/user/{tname_h}'
    body = f'''
  <div style="max-width:420px;margin:0 auto">
    <div class="page-title">Set Password</div>
    <div class="page-sub">Changing password for <strong>{tname_h}</strong></div>
    <div class="card">
      <form method="POST" action="/manage/admin/set-password">
        <input type="hidden" name="username" value="{tname_h}">
        {pw_req_html}
        <div class="form-group">
          <label for="asp-new">New Password</label>
          <div class="pw-wrap"><input id="asp-new" type="password" name="new_password" required autocomplete="new-password"><button type="button" class="pw-eye" onclick="togglePwVis(this)" aria-label="Show password" tabindex="-1"><svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button></div>
        </div>
        <div class="form-group">
          <label for="asp-conf">Confirm New Password</label>
          <div class="pw-wrap"><input id="asp-conf" type="password" name="confirm_password" required autocomplete="new-password"><button type="button" class="pw-eye" onclick="togglePwVis(this)" aria-label="Show password" tabindex="-1"><svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button></div>
        </div>
        <button type="submit" class="btn btn-primary">Set Password</button>
        <a href="{cancel_url}" class="btn" style="margin-left:8px">Cancel</a>
      </form>
    </div>
  </div>'''
    return _manage_page('Set Password', body, user=viewer, msg=msg, msg_type=msg_type)


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
          <label for="cp-cur">Current Password</label>
          <div class="pw-wrap"><input id="cp-cur" type="password" name="current_password" required autocomplete="current-password"><button type="button" class="pw-eye" onclick="togglePwVis(this)" aria-label="Show password" tabindex="-1"><svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button></div>
        </div>
        {pw_req_html}
        <div class="form-group">
          <label for="cp-new">New Password</label>
          <div class="pw-wrap"><input id="cp-new" type="password" name="new_password" required autocomplete="new-password"><button type="button" class="pw-eye" onclick="togglePwVis(this)" aria-label="Show password" tabindex="-1"><svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button></div>
        </div>
        <div class="form-group">
          <label for="cp-conf">Confirm New Password</label>
          <div class="pw-wrap"><input id="cp-conf" type="password" name="confirm_password" required autocomplete="new-password"><button type="button" class="pw-eye" onclick="togglePwVis(this)" aria-label="Show password" tabindex="-1"><svg class="eye-open" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg></button></div>
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
                try:
                    REGISTRATION_DB.expire_bounties()
                except Exception as _e:
                    log.warning('expire_bounties failed (non-fatal): %s', _e)
            hashes = REGISTRY.all_hashes()
            total_peers = sum(
                len(REGISTRY._torrents.get(h, {})) for h in hashes
            )
            log.info('Stats: %d torrents  %d peers', len(hashes), total_peers)
    except KeyboardInterrupt:
        log.info('Shutting down.')
        sys.exit(0)



# ── Bounty Board ──────────────────────────────────────────────

def _bounty_status_badge(status: str) -> str:
    colors = {
        'open':      'var(--green)',
        'pending':   'var(--accent)',
        'fulfilled': 'var(--muted)',
        'expired':   'var(--danger)',
    }
    c = colors.get(status, 'var(--muted)')
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
            f'background:{c};color:#fff;font-size:0.75rem;font-weight:700;'
            f'text-transform:uppercase">{_h(status)}</span>')


def _render_leaderboard(viewer, data: dict, top_n: int) -> str:
    """Render the five-category leaderboard page."""

    def _lb_table(rows, cols):
        """cols: list of (header, key, formatter_fn) — _rank and _user are special keys"""
        if not rows:
            return '<p style="color:var(--muted);font-size:0.85rem">No data yet.</p>'
        # Find the value col (everything that isn't _rank or _user)
        val_cols = [(h, k, f) for h, k, f in cols if k not in ('_rank', '_user')]
        tbody = ''
        for i, row in enumerate(rows):
            rank  = i + 1
            medal = {1: '🥇', 2: '🥈', 3: '🥉'}.get(rank, f'<span style="color:var(--muted);font-size:0.8rem;font-family:var(--mono)">{rank}.</span>')
            uname   = row.get('username') or '—'
            uname_h = _h(uname)
            u_link  = (f'<a href="/manage/user/{uname_h}" class="user-link">{uname_h}</a>'
                       if uname != '—' else '—')
            val_cells = ''.join(
                f'<td style="text-align:right;padding:9px 4px;overflow:hidden;'
                f'text-overflow:ellipsis;white-space:nowrap;border-bottom:1px solid var(--border)">'
                f'{f(row.get(k, 0))}</td>'
                for _, k, f in val_cols
            )
            tbody += (f'<tr>'
                      f'<td style="width:28px;text-align:center;padding:9px 4px;'
                      f'border-bottom:1px solid var(--border)">{medal}</td>'
                      f'<td style="padding:9px 6px;overflow:hidden;text-overflow:ellipsis;'
                      f'white-space:nowrap;border-bottom:1px solid var(--border)">{u_link}</td>'
                      f'{val_cells}'
                      f'</tr>')
        val_headers = ''.join(
            f'<th style="text-align:right;white-space:nowrap;padding:6px 4px;'
            f'font-family:var(--mono);font-size:0.7rem;letter-spacing:0.08em;'
            f'color:var(--muted);text-transform:uppercase">{h}</th>'
            for h, k, f in val_cols
        )
        thead = (f'<tr>'
                 f'<th style="width:28px;padding:6px 4px"></th>'
                 f'<th style="text-align:left;padding:6px 4px;font-family:var(--mono);'
                 f'font-size:0.7rem;letter-spacing:0.08em;color:var(--muted);text-transform:uppercase">Member</th>'
                 f'{val_headers}</tr>')
        return (f'<table style="width:100%;border-collapse:collapse;table-layout:fixed">'
                f'<colgroup><col style="width:28px"><col><col style="width:95px"></colgroup>'
                f'<thead style="border-bottom:1px solid var(--border)">{thead}</thead>'
                f'<tbody>{tbody}</tbody></table>')

    def pts(v):
        color = 'var(--danger)' if int(v) < 0 else 'var(--accent)'
        return f'<span style="color:{color};font-weight:700">{v:+} pts</span>'
    def plain_pts(v):
        color = 'var(--danger)' if int(v) < 0 else 'var(--accent)'
        return f'<span style="color:{color};font-weight:700">{v} pts</span>'
    def count(suffix):
        return lambda v: f'<span style="color:var(--text);font-weight:600">{v}</span> <span style="color:var(--muted)">{suffix}</span>'
    def streak_fmt(v):
        return f'<span style="color:var(--accent);font-weight:700">🔥 {v} days</span>'

    cols_holders  = [('Balance',      'points',         plain_pts)]
    cols_earners  = [('Total Earned', 'total_earned',   plain_pts)]
    cols_uploaders= [('Torrents',     'torrent_count',  count('torrents'))]
    cols_hunters  = [('Fulfilled',    'fulfilled_count',count('bounties'))]
    cols_streaks  = [('Streak',       'login_streak',   streak_fmt)]
    cols_chatty   = [('Comments',     'comment_count',  count('comments'))]

    def _card(title, icon, rows, cols, desc):
        return (f'<div class="card">'
                f'<div class="card-title">{icon} {title}</div>'
                f'<p style="color:var(--muted);font-size:0.82rem;margin-bottom:12px">{desc}</p>'
                + _lb_table(rows, cols) +
                f'</div>')

    uname = viewer['username']

    card_holders   = _card("Top Holders",      "💰", data["holders"],        cols_holders,
                           "Who's sitting on the most points right now.")
    card_earners   = _card("All-Time Earners", "📈", data["earners"],        cols_earners,
                           "Most points ever generated — spending doesn't hurt your rank.")
    card_uploaders = _card("Top Uploaders",    "📦", data["uploaders"],      cols_uploaders,
                           "Most torrents registered on the tracker.")
    card_hunters   = _card("Bounty Hunters",   "🎯", data["bounty_hunters"], cols_hunters,
                           "Most bounties successfully fulfilled.")
    card_streaks   = _card("Login Streaks",    "🔥", data["streaks"],        cols_streaks,
                           "Longest consecutive daily login streak.")
    card_chatty    = _card("Most Chatty",      "💬", data["chatty"],         cols_chatty,
                           "Most comments posted — the voices of the community.")

    body = f'''
    <div class="page-title">🏆 Leaderboard</div>
    <div class="page-sub">
      <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a>
    </div>
    <p style="color:var(--muted);font-size:0.85rem;margin-bottom:24px">
      Top {top_n} in each category. Updated in real time.
    </p>
    <div class="lb-grid" style="display:grid;grid-template-columns:repeat(3,minmax(0,340px));gap:20px;max-width:1080px">
      {card_holders}
      {card_earners}
      {card_uploaders}
      {card_hunters}
      {card_streaks}
      {card_chatty}
    </div>'''

    return _manage_page('Leaderboard', body, user=viewer)


def _render_bounty_board(viewer, bounties: list, total: int, page: int, total_pages: int,
                          sort: str = 'points', status: str = '',
                          msg: str = '', msg_type: str = 'error') -> str:
    if not REGISTRATION_DB:
        return _manage_page('Bounty Board', '<p>Unavailable</p>', user=viewer)

    role    = _user_role(viewer)
    pts     = viewer['points'] if 'points' in viewer.keys() else 0
    min_cost= int(REGISTRATION_DB.get_setting('bounty_min_cost', '50'))

    msg_html = ''
    if msg:
        col = 'var(--green)' if msg_type == 'success' else 'var(--danger)'
        msg_html = (f'<div style="background:{col};color:#fff;padding:10px 16px;'
                    f'border-radius:8px;margin-bottom:16px;font-size:0.9rem">{_h(msg)}</div>')

    # Sort/filter controls
    def _sort_link(s, label):
        cls = 'btn btn-sm btn-primary' if sort == s else 'btn btn-sm'
        return f'<a href="/manage/bounty?sort={s}&status={_h(status)}" class="{cls}">{label}</a>'
    def _stat_link(s, label):
        cls = 'btn btn-sm btn-primary' if status == s else 'btn btn-sm'
        return f'<a href="/manage/bounty?sort={_h(sort)}&status={s}" class="{cls}">{label}</a>'

    controls = (
        '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px">'
        '<span style="color:var(--muted);font-size:0.82rem">Sort:</span>'
        + _sort_link('points',  '🏆 Highest Points')
        + _sort_link('newest',  '🆕 Newest')
        + '&nbsp;&nbsp;<span style="color:var(--muted);font-size:0.82rem">Filter:</span>'
        + _stat_link('',          'All')
        + _stat_link('open',      'Open')
        + _stat_link('pending',   'Pending')
        + _stat_link('fulfilled', 'Fulfilled')
        + _stat_link('expired',   'Expired')
        + '</div>'
    )

    # Bounty rows
    rows = ''
    for b in bounties:
        bid   = b['id']
        desc  = _h(b['description'][:80] + ('…' if len(b['description']) > 80 else ''))
        badge = _bounty_status_badge(b['status'])
        pts_disp = f'<span style="color:var(--accent);font-weight:700">{b["total_escrow"]} pts</span>'
        by    = _h(b['created_by'])
        exp   = _h((b['expires_at'] or '')[:10])
        ff    = _h(b['fulfilled_by'] or '')
        rows += (
            f'<tr>'
            f'<td><a href="/manage/bounty/{bid}" style="color:var(--text)">{desc}</a></td>'
            f'<td style="text-align:center">{pts_disp}</td>'
            f'<td style="text-align:center">{badge}</td>'
            f'<td class="hash"><a href="/manage/user/{by}" class="user-link">{by}</a></td>'
            f'<td class="hash">{ff if ff else "—"}</td>'
            f'<td class="hash">{exp}</td>'
            f'<td><a href="/manage/bounty/{bid}" class="btn btn-sm">View →</a></td>'
            f'</tr>'
        )
    if not rows:
        rows = '<tr><td colspan="7" class="empty">No bounties found</td></tr>'

    table = f'''<div class="table-wrap"><table class="torrent-table">
      <thead><tr>
        <th>Description</th><th style="text-align:center">Points</th>
        <th style="text-align:center">Status</th><th>Posted By</th>
        <th>Fulfilled By</th><th>Expires</th><th></th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table></div>'''

    # Pagination
    def _plink(p):
        return f'/manage/bounty?sort={sort}&status={status}&page={p}'
    pag = _pagination_html(page, total_pages, f'/manage/bounty?sort={sort}&status={status}')

    # Create bounty form
    create_html = ''
    if role != 'basic':
        can_afford = pts >= min_cost
        afford_note = (
            f'<span style="color:var(--muted);font-size:0.82rem">'
            f'Costs {min_cost} pts. Your balance: <strong>{pts} pts</strong>.'
            f'{"" if can_afford else " You need more points."}</span>'
        )
        create_html = f'''
    <div class="card" style="margin-bottom:16px">
      <div class="card-title">Post a Bounty Request</div>
      {afford_note}
      <form method="POST" action="/manage/bounty/create" style="margin-top:12px">
        <div class="form-group">
          <label for="bdesc">What are you looking for?</label>
          <textarea id="bdesc" name="description" rows="3" maxlength="500" required
            placeholder="Describe the content you want (name, format, quality, etc.)"
            style="width:100%;background:var(--card2);border:1px solid var(--border);
                   border-radius:6px;color:var(--text);padding:10px;resize:vertical;
                   font-family:inherit;font-size:0.9rem"></textarea>
        </div>
        <button type="submit" class="btn btn-primary" {'disabled' if not can_afford else ''}
                data-confirm="Post this bounty for {min_cost} points?">
          🎯 Post Bounty ({min_cost} pts)
        </button>
      </form>
    </div>'''

    body_html = f'''
    <div class="page-title">🎯 Bounty Board</div>
    <div class="page-sub">
      <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a>
    </div>
    {msg_html}
    {create_html}
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;
                  flex-wrap:wrap;gap:12px;margin-bottom:12px">
        <div class="card-title" style="margin:0">Bounty Board ({total})</div>
      </div>
      {controls}
      {table}
      {pag}
    </div>'''
    return _manage_page('Bounty Board', body_html, user=viewer)


def _render_bounty_detail(viewer, bounty, contributions: list, votes: list,
                           comments: list, torrent, threshold: int,
                           msg: str = '', msg_type: str = 'error') -> str:
    if not REGISTRATION_DB:
        return _manage_page('Bounty', '<p>Unavailable</p>', user=viewer)

    bid      = bounty['id']
    role     = _user_role(viewer)
    uname    = viewer['username']
    pts      = viewer['points'] if 'points' in viewer.keys() else 0
    is_owner = uname == bounty['created_by']
    is_claimer = uname == bounty['claimed_by']
    status   = bounty['status']

    msg_html = ''
    if msg:
        col = 'var(--green)' if msg_type == 'success' else 'var(--danger)'
        msg_html = (f'<div style="background:{col};color:#fff;padding:10px 16px;'
                    f'border-radius:8px;margin-bottom:16px;font-size:0.9rem">{_h(msg)}</div>')

    # Contributors list
    contrib_rows = ''
    for c in contributions:
        contrib_rows += (
            f'<tr><td><a href="/manage/user/{_h(c["username"])}" class="user-link">'
            f'{_h(c["username"])}</a></td>'
            f'<td style="color:var(--accent)">{c["amount"]} pts</td>'
            f'<td class="hash">{_h((c["contributed_at"] or "")[:16])}</td></tr>'
        )
    if not contrib_rows:
        contrib_rows = '<tr><td colspan="3" class="empty">No contributions</td></tr>'

    contrib_html = f'''
    <div class="card">
      <div class="card-title">Contributors ({len(contributions)})</div>
      <div class="table-wrap"><table class="torrent-table">
        <thead><tr><th>User</th><th>Amount</th><th>Date</th></tr></thead>
        <tbody>{contrib_rows}</tbody>
      </table></div>
    </div>'''

    # Contribute form — anyone active (including owner) can add points
    contribute_form = ''
    if status in ('open', 'pending'):
        contribute_form = f'''
    <div class="card">
      <div class="card-title">Add Points to Bounty</div>
      <p style="color:var(--muted);font-size:0.85rem">
        Raise the stakes. Points are not refunded. Your balance: <strong>{pts} pts</strong>
      </p>
      <form method="POST" action="/manage/bounty/contribute">
        <input type="hidden" name="bounty_id" value="{bid}">
        <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
          <input type="number" name="amount" min="1" max="{pts}" value="10"
                 style="width:100px;padding:8px;background:var(--card2);
                        border:1px solid var(--border);border-radius:6px;color:var(--text)">
          <button type="submit" class="btn btn-primary"
                  data-confirm="Add points to this bounty? This is not refundable.">
            ➕ Add Points
          </button>
        </div>
      </form>
    </div>'''

    # Claim form
    claim_form = ''
    if status == 'open' and not is_owner:
        claim_form = f'''
    <div class="card">
      <div class="card-title">Claim This Bounty</div>
      <p style="color:var(--muted);font-size:0.85rem">
        Found a registered torrent that fulfills this request?
        Enter its info hash below. First valid claim wins.
      </p>
      <form method="POST" action="/manage/bounty/claim">
        <input type="hidden" name="bounty_id" value="{bid}">
        <div class="form-group">
          <label>Info Hash (40 hex characters)</label>
          <input type="text" name="info_hash" maxlength="40" required
                 placeholder="e.g. A1B2C3D4..."
                 style="width:100%;font-family:var(--mono);padding:8px;
                        background:var(--card2);border:1px solid var(--border);
                        border-radius:6px;color:var(--text);font-size:0.88rem">
        </div>
        <button type="submit" class="btn btn-primary"
                data-confirm="Submit this claim? The bounty will enter pending state.">
          🎯 Submit Claim
        </button>
      </form>
    </div>'''

    # Pending confirmation section
    pending_html = ''
    if status == 'pending':
        ih_h  = _h(bounty['claimed_infohash'] or '')
        cl_h  = _h(bounty['claimed_by'] or '')
        t_name = _h(torrent['name'] if torrent else 'Unknown torrent')
        t_link = (f'<a href="/manage/torrent/{(bounty["claimed_infohash"] or "").lower()}"'
                  f' style="color:var(--accent)">{t_name}</a>'
                  if torrent else t_name)

        vote_count  = len(votes)
        already_voted = any(v['username'] == uname for v in votes)
        can_vote = (not is_owner and not is_claimer and not already_voted
                    and role not in ('basic',))

        vote_btn = ''
        if can_vote:
            vote_btn = (f'<form method="POST" action="/manage/bounty/vote" style="display:inline">'
                        f'<input type="hidden" name="bounty_id" value="{bid}">'
                        f'<button class="btn btn-green">✓ Vote Fulfilled ({vote_count}/{threshold})</button>'
                        f'</form>')
        elif already_voted:
            vote_btn = f'<span class="btn btn-sm" style="opacity:.6">You voted ✓ ({vote_count}/{threshold})</span>'
        else:
            vote_btn = f'<span style="color:var(--muted);font-size:0.85rem">Community votes: {vote_count}/{threshold}</span>'

        confirm_btn = ''
        reject_btn  = ''
        if is_owner:
            confirm_btn = (f'<form method="POST" action="/manage/bounty/confirm" style="display:inline">'
                           f'<input type="hidden" name="bounty_id" value="{bid}">'
                           f'<button class="btn btn-green"'
                           f' data-confirm="Confirm this bounty is fulfilled? You\'ll receive a partial refund.">✅ Confirm Fulfilled</button>'
                           f'</form>')
            reject_btn  = (f'<form method="POST" action="/manage/bounty/reject" style="display:inline">'
                           f'<input type="hidden" name="bounty_id" value="{bid}">'
                           f'<button class="btn btn-danger"'
                           f' data-confirm="Reject this claim? The claimer will be penalised.">✗ Reject Claim</button>'
                           f'</form>')

        pending_html = f'''
    <div class="card" style="border:1px solid var(--accent)">
      <div class="card-title" style="color:var(--accent)">⏳ Pending Confirmation</div>
      <p style="margin-bottom:8px">
        Claimed by <a href="/manage/user/{cl_h}" class="user-link">{cl_h}</a>
        · Torrent: {t_link}
        · Hash: <span class="hash">{ih_h}</span>
      </p>
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
        {confirm_btn}
        {reject_btn}
        {vote_btn}
      </div>
    </div>'''

    # Fulfilled section
    fulfilled_html = ''
    if status == 'fulfilled':
        ih_h = _h(bounty['claimed_infohash'] or '')
        ff_h = _h(bounty['fulfilled_by'] or '')
        t_name = _h(torrent['name'] if torrent else 'Unknown')
        t_link = (f'<a href="/manage/torrent/{(bounty["claimed_infohash"] or "").lower()}"'
                  f' style="color:var(--green)">{t_name}</a>'
                  if torrent else t_name)

        # Reconstruct payout breakdown
        escrow       = bounty['total_escrow']
        initial_cost = bounty['initial_cost']
        claimer_pct  = int(REGISTRATION_DB.get_setting('bounty_claimer_pct',  '70')) / 100
        uploader_pct = int(REGISTRATION_DB.get_setting('bounty_uploader_pct', '15')) / 100
        refund_pct   = int(REGISTRATION_DB.get_setting('bounty_refund_pct',   '25')) / 100
        house_pct    = 1 - claimer_pct - uploader_pct

        claimer       = bounty['fulfilled_by'] or ''
        uploader      = torrent['uploaded_by_username'] if torrent else None
        same_person   = uploader == claimer

        claimer_pay   = int(escrow * (claimer_pct + (uploader_pct if same_person else 0)))
        uploader_pay  = 0 if same_person else int(escrow * uploader_pct)
        house_cut     = escrow - claimer_pay - uploader_pay
        refund_amt    = int(initial_cost * refund_pct)

        def _prow(label, username, amount, color, note=''):
            u_link = (f'<a href="/manage/user/{_h(username)}" class="user-link">{_h(username)}</a>'
                      if username else '—')
            note_html = f' <span style="color:var(--muted);font-size:0.78rem">{_h(note)}</span>' if note else ''
            return (f'<tr>'
                    f'<td>{label}</td>'
                    f'<td>{u_link}</td>'
                    f'<td style="text-align:right;color:{color};font-weight:700">{amount:+} pts</td>'
                    f'<td>{note_html}</td>'
                    f'</tr>')

        payout_rows = _prow('Claimer', claimer, claimer_pay, 'var(--green)',
                            f'{int((claimer_pct + (uploader_pct if same_person else 0))*100)}% of escrow'
                            + (' (claimer + uploader combined)' if same_person else ''))
        if not same_person and uploader:
            payout_rows += _prow('Uploader', uploader, uploader_pay, 'var(--green)',
                                 f'{int(uploader_pct*100)}% of escrow · torrent bonus')
        payout_rows += _prow('House cut', None, -house_cut, 'var(--danger)',
                             f'{int(house_pct*100)}% destroyed')
        payout_rows += _prow('Requestor refund', bounty['created_by'], refund_amt, 'var(--accent)',
                             f'{int(refund_pct*100)}% of initial {initial_cost} pts · returned from escrow')

        fulfilled_html = f'''
    <div class="card" style="border:1px solid var(--green)">
      <div class="card-title" style="color:var(--green)">✅ Fulfilled</div>
      <p style="margin-bottom:12px">
        Fulfilled by <a href="/manage/user/{ff_h}" class="user-link">{ff_h}</a>
        · Torrent: {t_link}
      </p>
      <div class="card-title" style="font-size:0.85rem;margin-bottom:8px">Payout Breakdown
        <span style="color:var(--muted);font-size:0.78rem;font-weight:400">
          · Total escrow: <strong style="color:var(--accent)">{escrow} pts</strong>
        </span>
      </div>
      <div class="table-wrap"><table class="torrent-table">
        <thead><tr><th>Role</th><th>Recipient</th><th style="text-align:right">Amount</th><th>Note</th></tr></thead>
        <tbody>{payout_rows}</tbody>
      </table></div>
    </div>'''

    # Comments
    comment_rows = ''
    for c in comments:
        un_h = _h(c['username'])
        bd_h = _h(c['body'])
        at_h = _h((c['created_at'] or '')[:16])
        comment_rows += f'''
      <div style="padding:12px 0;border-top:1px solid var(--border)">
        <div style="display:flex;gap:12px;align-items:baseline;margin-bottom:4px">
          <a href="/manage/user/{un_h}" class="user-link" style="font-weight:600">{un_h}</a>
          <span class="hash" style="font-size:0.78rem">{at_h}</span>
        </div>
        <div style="white-space:pre-wrap;word-break:break-word">{bd_h}</div>
      </div>'''

    comment_form = ''
    if status not in ('expired',) and role != 'basic':
        comment_form = f'''
      <form method="POST" action="/manage/bounty/comment" style="margin-top:12px">
        <input type="hidden" name="bounty_id" value="{bid}">
        <div class="form-group">
          <textarea name="body" rows="3" maxlength="2000" required
            placeholder="Ask for clarification, discuss details..."
            style="width:100%;background:var(--card2);border:1px solid var(--border);
                   border-radius:6px;color:var(--text);padding:10px;resize:vertical;
                   font-family:inherit;font-size:0.9rem"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Post Comment</button>
      </form>'''

    comments_html = f'''
    <div class="card" id="bc-{bid}">
      <div class="card-title">Discussion ({len(comments)})</div>
      {comment_rows or '<p style="color:var(--muted);font-size:0.88rem">No comments yet.</p>'}
      {comment_form}
    </div>'''

    # Info card
    by_h  = _h(bounty['created_by'])
    ca_h  = _h((bounty['created_at'] or '')[:16])
    exp_h = _h(bounty['expires_at'] or '')
    payout_pct = int(REGISTRATION_DB.get_setting('bounty_claimer_pct', '70'))
    upload_pct = int(REGISTRATION_DB.get_setting('bounty_uploader_pct', '15'))
    refund_pct = int(REGISTRATION_DB.get_setting('bounty_refund_pct', '25'))
    escrow = bounty['total_escrow']

    info_card = f'''
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
        <div>
          <div class="card-title" style="font-size:1.1rem;margin-bottom:8px">
            {_h(bounty["description"])}
          </div>
          <div style="color:var(--muted);font-size:0.85rem;display:flex;gap:16px;flex-wrap:wrap">
            <span>By <a href="/manage/user/{by_h}" class="user-link">{by_h}</a></span>
            <span>Posted {ca_h}</span>
            <span>Expires {exp_h}</span>
          </div>
        </div>
        <div style="text-align:right">
          {_bounty_status_badge(status)}
          <div style="color:var(--accent);font-size:1.4rem;font-weight:700;margin-top:4px">
            {escrow} pts
          </div>
          <div style="color:var(--muted);font-size:0.78rem;margin-top:2px">
            Claimer: {payout_pct}% · Uploader: {upload_pct}% · Requestor refund: {refund_pct}% of initial
          </div>
        </div>
      </div>
    </div>'''

    body_html = f'''
    <div class="page-title">Bounty #{bid}</div>
    <div class="page-sub">
      <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a>
      &nbsp;&#183;&nbsp;
      <a href="/manage/bounty" style="color:var(--muted);text-decoration:none">&#10094; Bounty Board</a>
    </div>
    {msg_html}
    {info_card}
    {pending_html}
    {fulfilled_html}
    {contribute_form}
    {claim_form}
    {contrib_html}
    {comments_html}'''

    return _manage_page(f'Bounty #{bid}', body_html, user=viewer)


if __name__ == '__main__':
    main()
