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
import base64
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
import shlex
import socket
import ssl
import string
import struct
import subprocess
import sys
import threading
import time
import queue
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

_BENIGN_SOCKET_EXC = (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)

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

    def handle_error(self, request, client_address):
        exc_type = sys.exc_info()[0]
        if exc_type in _BENIGN_SOCKET_EXC:
            log.debug('WEB connection reset from %s', client_address[0])
            return
        super().handle_error(request, client_address)


# ─────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────

DEFAULT_HTTP_PORT   = 6969
DEFAULT_HTTPS_PORT  = None   # disabled unless cert+key supplied
DEFAULT_UDP_PORT    = 6969
DEFAULT_INTERVAL    = 1800   # seconds
DEFAULT_MIN_INTERVAL = 60
PEER_SCRAPE_MIN_INTERVAL_SECONDS = 3 * 60 * 60
ACCOUNT_DELETE_CHALLENGE_TTL_MINUTES = 5
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

    def get_active_ip_last_seen(self, ih_hex: str) -> list[tuple[str, float]]:
        """Return unique active peer IPs for a torrent with most recent seen time."""
        with self._lock:
            self._ensure(ih_hex)
            self._purge_stale(ih_hex)
            peers = list(self._torrents[ih_hex].values())
        ip_latest: dict[str, float] = {}
        for p in peers:
            ip = p.get('ip', '')
            if not ip:
                continue
            seen = float(p.get('last_seen', 0))
            prev = ip_latest.get(ip, 0.0)
            if seen > prev:
                ip_latest[ip] = seen
        return sorted(ip_latest.items(), key=lambda x: x[1], reverse=True)

    def snapshot_active_ips_by_hash(self) -> dict[str, dict[str, float]]:
        """Return {info_hash: {ip: last_seen}} for all active torrents."""
        with self._lock:
            out: dict[str, dict[str, float]] = {}
            for ih_hex in list(self._torrents.keys()):
                self._ensure(ih_hex)
                self._purge_stale(ih_hex)
                if not self._torrents[ih_hex]:
                    continue
                ip_latest: dict[str, float] = {}
                for p in self._torrents[ih_hex].values():
                    ip = p.get('ip', '')
                    if not ip:
                        continue
                    seen = float(p.get('last_seen', 0))
                    prev = ip_latest.get(ip, 0.0)
                    if seen > prev:
                        ip_latest[ip] = seen
                if ip_latest:
                    out[ih_hex] = ip_latest
            return out

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
PEER_UPDATE_QUEUE  = None   # background queue for async peer snapshot refresh

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


def _nested_get(obj, path: list[str], default=''):
    cur = obj
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default


def _coinbase_extract_refs(payload: dict) -> dict:
    """Extract likely Coinbase webhook references for order matching."""
    refs = {
        'event_id': str(payload.get('id') or payload.get('event_id') or ''),
        'event_type': str(payload.get('type') or payload.get('event') or _nested_get(payload, ['event', 'type'], '')),
        'order_uuid': '',
        'order_id': '',
        'checkout_id': '',
        'charge_id': '',
        'hosted_url': '',
    }
    metadata = {}
    for path in (
        ['metadata'],
        ['data', 'metadata'],
        ['event', 'metadata'],
        ['event', 'data', 'metadata'],
    ):
        val = _nested_get(payload, path, {})
        if isinstance(val, dict) and val:
            metadata = val
            break
    refs['order_uuid'] = str(metadata.get('order_uuid') or metadata.get('topup_order_uuid') or '')
    refs['order_id'] = str(metadata.get('order_id') or '')
    refs['checkout_id'] = str(
        _nested_get(payload, ['data', 'code'], '')
        or _nested_get(payload, ['data', 'checkout_id'], '')
        or _nested_get(payload, ['event', 'data', 'code'], '')
        or _nested_get(payload, ['event', 'data', 'checkout_id'], '')
        or _nested_get(payload, ['event', 'data', 'payment_link', 'id'], '')
    )
    refs['charge_id'] = str(
        _nested_get(payload, ['data', 'id'], '')
        or _nested_get(payload, ['event', 'data', 'id'], '')
        or _nested_get(payload, ['data', 'charge_id'], '')
        or _nested_get(payload, ['event', 'data', 'charge_id'], '')
    )
    refs['hosted_url'] = str(
        _nested_get(payload, ['data', 'hosted_url'], '')
        or _nested_get(payload, ['event', 'data', 'hosted_url'], '')
        or _nested_get(payload, ['data', 'url'], '')
        or _nested_get(payload, ['event', 'data', 'url'], '')
    )
    return refs


def _verify_coinbase_signature(secret: str, raw_body: bytes, header_value: str) -> bool:
    """Best-effort verifier supporting plain hex and key=value signature formats."""
    if not secret:
        return True
    if not header_value:
        return False
    expected = hmac.new(secret.encode('utf-8'), raw_body, hashlib.sha256).hexdigest().lower()
    hv = header_value.strip().lower()
    if hmac.compare_digest(expected, hv):
        return True
    candidates = []
    for part in hv.split(','):
        part = part.strip()
        if not part:
            continue
        if '=' in part:
            _, val = part.split('=', 1)
            candidates.append(val.strip())
        else:
            candidates.append(part)
    for cand in candidates:
        if hmac.compare_digest(expected, cand):
            return True
    return False


def _paypal_extract_refs(payload: dict) -> dict:
    """Extract useful PayPal webhook references for order matching."""
    refs = {
        'event_id': str(payload.get('id') or ''),
        'event_type': str(payload.get('event_type') or payload.get('type') or ''),
        'order_uuid': '',
        'order_id': '',
        'checkout_id': '',
        'capture_id': '',
    }
    resource = payload.get('resource') if isinstance(payload.get('resource'), dict) else {}
    refs['checkout_id'] = str(resource.get('supplementary_data', {}).get('related_ids', {}).get('order_id', '')
                              if isinstance(resource.get('supplementary_data'), dict) else '') or str(resource.get('id') or '')
    refs['capture_id'] = str(resource.get('id') or '')
    custom_id = str(resource.get('custom_id') or '')
    if custom_id:
        # custom_id uses order_uuid in current create flow
        refs['order_uuid'] = custom_id
    invoice_id = str(resource.get('invoice_id') or '')
    if invoice_id.startswith('wk-topup-'):
        refs['order_uuid'] = invoice_id[len('wk-topup-'):]
    return refs


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
                comment_pts_today     INTEGER NOT NULL DEFAULT 0,
                gravatar_opt_in       INTEGER NOT NULL DEFAULT 0,
                gravatar_hash         TEXT
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
            CREATE TABLE IF NOT EXISTS account_delete_challenges (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id               INTEGER NOT NULL,
                status                TEXT    NOT NULL DEFAULT 'challenged',
                created_at            TEXT    NOT NULL,
                expires_at            TEXT    NOT NULL,
                completed_at          TEXT,
                canceled_at           TEXT,
                requested_ip          TEXT    NOT NULL DEFAULT '',
                requested_user_agent  TEXT    NOT NULL DEFAULT '',
                consumed_ip           TEXT    NOT NULL DEFAULT '',
                consumed_user_agent   TEXT    NOT NULL DEFAULT '',
                attempt_count         INTEGER NOT NULL DEFAULT 0,
                last_attempt_at       TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_delete_challenges_user_status
              ON account_delete_challenges(user_id, status, id DESC);
            CREATE INDEX IF NOT EXISTS idx_delete_challenges_expires
              ON account_delete_challenges(status, expires_at);
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
        if 'peer_seeders' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN peer_seeders INTEGER')
        if 'peer_leechers' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN peer_leechers INTEGER')
        if 'peer_downloaded' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN peer_downloaded INTEGER')
        if 'peer_last_updated' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN peer_last_updated TEXT')
        if 'peer_last_tracker' not in cols:
            c.execute('ALTER TABLE torrents ADD COLUMN peer_last_tracker TEXT')
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
        # ── Top-up system (migration-safe) ───────────────────
        c.executescript('''
            CREATE TABLE IF NOT EXISTS topup_orders (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                order_uuid              TEXT    NOT NULL UNIQUE,
                user_id                 INTEGER NOT NULL,
                provider                TEXT    NOT NULL DEFAULT 'coinbase',
                provider_env            TEXT    NOT NULL DEFAULT 'sandbox',
                provider_checkout_id    TEXT    NOT NULL DEFAULT '',
                provider_charge_id      TEXT    NOT NULL DEFAULT '',
                provider_reference      TEXT    NOT NULL DEFAULT '',
                status                  TEXT    NOT NULL DEFAULT 'created',
                status_reason           TEXT    NOT NULL DEFAULT '',
                status_detail           TEXT    NOT NULL DEFAULT '',
                amount_usd_cents        INTEGER NOT NULL,
                currency                TEXT    NOT NULL DEFAULT 'USD',
                base_rate_pts_per_usd   INTEGER NOT NULL,
                multiplier_bp           INTEGER NOT NULL,
                quoted_points           INTEGER NOT NULL,
                credited_points         INTEGER NOT NULL DEFAULT 0,
                credits_ledger_id       INTEGER,
                created_at              TEXT    NOT NULL,
                updated_at              TEXT    NOT NULL,
                expires_at              TEXT,
                confirmed_at            TEXT,
                credited_at             TEXT,
                last_webhook_at         TEXT,
                created_by_admin_id     INTEGER
            );
            CREATE TABLE IF NOT EXISTS topup_webhook_events (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                provider          TEXT    NOT NULL DEFAULT 'coinbase',
                event_id          TEXT    NOT NULL DEFAULT '',
                event_type        TEXT    NOT NULL DEFAULT '',
                signature_valid   INTEGER NOT NULL DEFAULT 0,
                payload_json      TEXT    NOT NULL DEFAULT '',
                headers_json      TEXT    NOT NULL DEFAULT '',
                received_at       TEXT    NOT NULL,
                processed_at      TEXT,
                process_status    TEXT    NOT NULL DEFAULT 'received',
                process_error     TEXT    NOT NULL DEFAULT '',
                linked_order_id   INTEGER,
                idempotency_key   TEXT    NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS topup_reconciliation_actions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id      INTEGER NOT NULL,
                actor_user_id INTEGER NOT NULL,
                action        TEXT    NOT NULL,
                note          TEXT    NOT NULL DEFAULT '',
                old_status    TEXT    NOT NULL,
                new_status    TEXT    NOT NULL,
                created_at    TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_topup_orders_user_created
              ON topup_orders(user_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_topup_orders_status_created
              ON topup_orders(status, id DESC);
            CREATE INDEX IF NOT EXISTS idx_topup_orders_provider_ref
              ON topup_orders(provider, provider_reference);
            CREATE INDEX IF NOT EXISTS idx_topup_orders_checkout
              ON topup_orders(provider_checkout_id);
            CREATE INDEX IF NOT EXISTS idx_topup_webhook_event_id
              ON topup_webhook_events(provider, event_id);
            CREATE INDEX IF NOT EXISTS idx_topup_webhook_order
              ON topup_webhook_events(linked_order_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_topup_webhook_status
              ON topup_webhook_events(process_status, id DESC);
            CREATE INDEX IF NOT EXISTS idx_topup_recon_order_created
              ON topup_reconciliation_actions(order_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_topup_recon_actor_created
              ON topup_reconciliation_actions(actor_user_id, id DESC);
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
            CREATE TABLE IF NOT EXISTS user_follows (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                follower_user_id  INTEGER NOT NULL,
                followed_user_id  INTEGER NOT NULL,
                created_at        TEXT    NOT NULL,
                UNIQUE(follower_user_id, followed_user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_user_follows_follower
              ON user_follows(follower_user_id, followed_user_id);
            CREATE INDEX IF NOT EXISTS idx_user_follows_followed
              ON user_follows(followed_user_id, follower_user_id);
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
        try:
            self._conn().execute('ALTER TABLE users ADD COLUMN last_seen TEXT')
            self._conn().commit()
        except Exception:
            pass  # column already exists
        # ── conversation_id migration ────────────────────────────────────────
        try:
            self._conn().execute(
                'ALTER TABLE direct_messages ADD COLUMN conversation_id INTEGER')
            self._conn().commit()
        except Exception:
            pass  # column already exists
        # Backfill: top-level messages own their conversation
        self._conn().execute(
            'UPDATE direct_messages SET conversation_id=id WHERE reply_to_id IS NULL AND conversation_id IS NULL')
        self._conn().commit()
        # Backfill replies: walk up reply chain to find root, assign its id
        max_depth = 20
        for _ in range(max_depth):
            changed = self._conn().execute(
                '''UPDATE direct_messages SET conversation_id=(
                       SELECT COALESCE(p.conversation_id, p.id)
                       FROM direct_messages p WHERE p.id=direct_messages.reply_to_id
                   )
                   WHERE reply_to_id IS NOT NULL AND conversation_id IS NULL'''
            ).rowcount
            self._conn().commit()
            if not changed:
                break
        # Any still-null replies (broken chains) get their own id as fallback
        self._conn().execute(
            'UPDATE direct_messages SET conversation_id=id WHERE conversation_id IS NULL')
        self._conn().commit()
        try:
            self._conn().execute('ALTER TABLE users ADD COLUMN show_online INTEGER NOT NULL DEFAULT 1')
            self._conn().commit()
        except Exception:
            pass  # column already exists
        try:
            self._conn().execute('ALTER TABLE users ADD COLUMN bounty_alerts INTEGER NOT NULL DEFAULT 1')
            self._conn().commit()
        except Exception:
            pass  # column already exists
        try:
            self._conn().execute('ALTER TABLE users ADD COLUMN link_torrent_activity INTEGER NOT NULL DEFAULT 1')
            self._conn().commit()
        except Exception:
            pass  # column already exists
        try:
            self._conn().execute('ALTER TABLE users ADD COLUMN allow_follow_visibility INTEGER NOT NULL DEFAULT 1')
            self._conn().commit()
        except Exception:
            pass  # column already exists
        try:
            self._conn().execute('ALTER TABLE users ADD COLUMN gravatar_opt_in INTEGER NOT NULL DEFAULT 0')
            self._conn().commit()
        except Exception:
            pass  # column already exists
        try:
            self._conn().execute('ALTER TABLE users ADD COLUMN gravatar_hash TEXT')
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
            'upload_max_content_mb':  '100',
            'upload_max_files':       '1000',
            'upload_max_file_mb':     '10',
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
            'activity_link_max_login_age_days': '30',
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
            'gravatar_enabled':     '0',
            # ── Top-ups (Coinbase-only v1) ───────────────────
            'topup_enabled':                '0',
            'topup_rollout_mode':           'admin_only',
            'topup_provider':               'coinbase',
            'topup_coinbase_enabled':       '1',
            'topup_coinbase_env':           'sandbox',
            'topup_coinbase_api_key':       '',
            'topup_coinbase_webhook_secret':'',
            'topup_coinbase_api_key_sandbox': '',
            'topup_coinbase_api_key_live':    '',
            'topup_coinbase_webhook_secret_sandbox': '',
            'topup_coinbase_webhook_secret_live':    '',
            'topup_coinbase_create_url':    'https://api.commerce.coinbase.com/charges',
            'topup_provider_request_timeout_sec': '15',
            'topup_coinbase_request_timeout_sec': '15',
            'topup_auto_redirect_checkout': '1',
            'topup_pending_sla_minutes':    '180',
            'topup_paypal_enabled':         '0',
            'topup_paypal_webhook_enforce': '1',
            'topup_paypal_env':             'sandbox',
            'topup_paypal_client_id':       '',
            'topup_paypal_client_secret':   '',
            'topup_paypal_webhook_id':      '',
            'topup_paypal_client_id_sandbox':     '',
            'topup_paypal_client_id_live':        '',
            'topup_paypal_client_secret_sandbox': '',
            'topup_paypal_client_secret_live':    '',
            'topup_paypal_webhook_id_sandbox':    '',
            'topup_paypal_webhook_id_live':       '',
            'topup_base_rate_pts_per_usd':  '200',
            'topup_fixed_amounts_json':     '[5,10,25,50,100]',
            'topup_multiplier_bands_json':  '[{"min_usd":5,"multiplier_bp":10000},{"min_usd":10,"multiplier_bp":12500},{"min_usd":25,"multiplier_bp":14000},{"min_usd":50,"multiplier_bp":15500},{"min_usd":100,"multiplier_bp":17500}]',
            # ── Torrent peer scrape (manual refresh) ─────────
            'peer_query_enabled':           '0',
            'peer_query_tracker':           'http://tracker.opentrackr.org:1337/announce',
            'peer_query_tool':              '/opt/tracker/tracker_query.py',
            'peer_query_args':              '-o json -s -r -H {hash} -t {tracker}',
            'peer_query_retries':           '3',
            'peer_query_retry_wait_sec':    '2',
            'peer_query_auto_on_upload':    '0',
            'peer_query_auto_upload_cap':   '5',
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
                is_broadcast: bool = False, reply_to_id: int = None,
                conversation_id: int = None) -> int:
        """Insert a DM. Returns new message id.
        conversation_id: pass the root message id to keep replies in same thread.
        If None and reply_to_id given, it is looked up from the parent.
        If None and no reply_to_id, the new message becomes its own conversation root.
        """
        c = self._conn()
        # Resolve conversation_id for replies if not explicitly given
        if conversation_id is None and reply_to_id is not None:
            parent = c.execute(
                'SELECT conversation_id, id FROM direct_messages WHERE id=?',
                (reply_to_id,)
            ).fetchone()
            if parent:
                conversation_id = parent['conversation_id'] or parent['id']
        c.execute(
            "INSERT INTO direct_messages (sender,recipient,subject,body,sent_at,is_broadcast,reply_to_id,conversation_id)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (sender, recipient, subject[:200], body[:5000],
             self._ts(), 1 if is_broadcast else 0, reply_to_id, conversation_id)
        )
        c.commit()
        new_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
        # New top-level message: set its own id as conversation_id
        if conversation_id is None:
            c.execute('UPDATE direct_messages SET conversation_id=? WHERE id=?',
                      (new_id, new_id))
            c.commit()
        return new_id

    def get_dm_inbox(self, username: str, limit: int = 100) -> list:
        """Return one row per conversation the user is a recipient in.
        Row is the root message of each conversation (lowest id with that conversation_id),
        annotated with total message count and unread count."""
        rows = self._conn().execute(
            '''SELECT m.*, COUNT(all_m.id) as msg_count,
                      SUM(CASE WHEN all_m.recipient=? AND all_m.read_at IS NULL
                               AND all_m.del_by_recip=0 THEN 1 ELSE 0 END) as unread_count,
                      MAX(all_m.sent_at) as last_activity
               FROM direct_messages m
               JOIN direct_messages all_m ON all_m.conversation_id=m.conversation_id
               WHERE m.id=m.conversation_id
               AND EXISTS (
                   SELECT 1 FROM direct_messages r
                   WHERE r.conversation_id=m.conversation_id
                   AND r.recipient=? AND r.del_by_recip=0
               )
               GROUP BY m.conversation_id
               ORDER BY last_activity DESC LIMIT ?''',
            (username, username, limit)
        ).fetchall()
        return rows

    def get_dm_sent(self, username: str, limit: int = 100) -> list:
        """Return one row per conversation the user initiated (is sender of root)."""
        rows = self._conn().execute(
            '''SELECT m.*, COUNT(all_m.id) as msg_count,
                      MAX(all_m.sent_at) as last_activity
               FROM direct_messages m
               JOIN direct_messages all_m ON all_m.conversation_id=m.conversation_id
               WHERE m.id=m.conversation_id
               AND m.sender=? AND m.del_by_sender=0 AND m.is_broadcast=0
               GROUP BY m.conversation_id
               ORDER BY last_activity DESC LIMIT ?''',
            (username, limit)
        ).fetchall()
        return rows

    def get_dm(self, msg_id: int) -> object:
        return self._conn().execute(
            "SELECT * FROM direct_messages WHERE id=?", (msg_id,)
        ).fetchone()

    def get_dm_thread(self, conversation_id: int, username: str) -> list:
        """Return all messages in a conversation ordered chronologically.
        The conversation_id IS the id of the root message.
        Only returns messages where the user is sender or recipient and has not deleted."""
        return self._conn().execute(
            '''SELECT * FROM direct_messages
               WHERE conversation_id=?
               AND (
                   (sender=? AND del_by_sender=0)
                   OR (recipient=? AND del_by_recip=0)
               )
               ORDER BY id ASC''',
            (conversation_id, username, username)
        ).fetchall()

    def get_unread_dm_count(self, username: str) -> int:
        """Count conversations with at least one unread message for this user."""
        return self._conn().execute(
            '''SELECT COUNT(DISTINCT conversation_id) FROM direct_messages
               WHERE recipient=? AND read_at IS NULL AND del_by_recip=0''',
            (username,)
        ).fetchone()[0]

    def mark_dm_read(self, conversation_id: int, username: str):
        """Mark all unread messages in a conversation as read for this user."""
        c = self._conn()
        c.execute(
            '''UPDATE direct_messages SET read_at=?
               WHERE conversation_id=? AND recipient=? AND read_at IS NULL''',
            (self._ts(), conversation_id, username)
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

    def delete_dm_conversation(self, conversation_id: int, username: str):
        """Soft-delete an entire conversation for this user only.
        Sets del_by_sender on messages they sent, del_by_recip on messages they received.
        Then hard-deletes any rows where both sides have deleted (fully orphaned).
        The other party's view is completely unaffected.
        """
        c = self._conn()
        c.execute(
            """UPDATE direct_messages SET del_by_sender=1
               WHERE conversation_id=? AND sender=?""",
            (conversation_id, username)
        )
        c.execute(
            """UPDATE direct_messages SET del_by_recip=1
               WHERE conversation_id=? AND recipient=?""",
            (conversation_id, username)
        )
        # Hard-delete rows that both parties have now flagged — no orphan data
        c.execute(
            """DELETE FROM direct_messages
               WHERE conversation_id=? AND del_by_sender=1 AND del_by_recip=1""",
            (conversation_id,)
        )
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

    def get_peer_query_config(self) -> dict:
        settings = self.get_all_settings()
        tracker = (settings.get('peer_query_tracker', '') or '').strip()
        tool = (settings.get('peer_query_tool', '') or '').strip()
        args = (settings.get('peer_query_args', '') or '').strip()
        try:
            retries = max(1, min(10, int(settings.get('peer_query_retries', '3') or '3')))
        except Exception:
            retries = 3
        try:
            wait_sec = max(0, min(30, int(settings.get('peer_query_retry_wait_sec', '2') or '2')))
        except Exception:
            wait_sec = 2
        auto_on_upload = settings.get('peer_query_auto_on_upload', '0') == '1'
        try:
            auto_upload_cap = max(1, min(50, int(settings.get('peer_query_auto_upload_cap', '5') or '5')))
        except Exception:
            auto_upload_cap = 5
        enabled = settings.get('peer_query_enabled', '0') == '1'
        # Only considered active if fully configured.
        active = bool(
            enabled and tracker and tool and args
            and ('{hash}' in args) and ('{tracker}' in args)
        )
        return {
            'enabled': enabled,
            'active': active,
            'tracker': tracker,
            'tool': tool,
            'args': args,
            'retries': retries,
            'retry_wait_sec': wait_sec,
            'auto_on_upload': auto_on_upload,
            'auto_upload_cap': auto_upload_cap,
            'min_interval_sec': PEER_SCRAPE_MIN_INTERVAL_SECONDS,
        }

    def update_torrent_peer_snapshot(self, ih: str, seeds: int, peers: int,
                                     downloaded: int | None, tracker: str, actor: str):
        ih_upper = ih.upper()
        for attempt in range(8):
            try:
                c = self._conn()
                c.execute(
                    '''UPDATE torrents
                       SET peer_seeders=?, peer_leechers=?, peer_downloaded=?,
                           peer_last_updated=?, peer_last_tracker=?
                       WHERE info_hash=?''',
                    (int(seeds), int(peers),
                     (None if downloaded is None else int(downloaded)),
                     self._ts(), tracker[:255], ih_upper)
                )
                c.commit()
                break
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower() and attempt < 7:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                raise
        self._log(actor, 'update_peer_stats', ih_upper,
                  f'seeds={int(seeds)} peers={int(peers)}')

    # ── Top-up system ────────────────────────────────────────

    def topup_enabled_for_user(self, user) -> bool:
        if not user:
            return False
        if self.get_setting('topup_enabled', '0') != '1':
            return False
        rollout = self.get_setting('topup_rollout_mode', 'admin_only')
        if rollout == 'all_users':
            return True
        return bool(user['is_admin'] or user['username'] == SUPER_USER)

    def get_topup_config(self) -> dict:
        settings = self.get_all_settings()
        base_rate = int(settings.get('topup_base_rate_pts_per_usd', '200') or '200')
        base_rate = max(1, min(100000, base_rate))
        try:
            fixed_raw = json.loads(settings.get('topup_fixed_amounts_json', '[5,10,25,50,100]'))
            fixed_amounts = sorted({max(1, min(100000, int(v))) for v in fixed_raw})
        except Exception:
            fixed_amounts = [5, 10, 25, 50, 100]
        try:
            bands_raw = json.loads(settings.get('topup_multiplier_bands_json', '[]'))
            bands = []
            for row in bands_raw:
                min_usd = max(1, min(100000, int(row.get('min_usd', 1))))
                bp = max(1000, min(100000, int(row.get('multiplier_bp', 10000))))
                bands.append({'min_usd': min_usd, 'multiplier_bp': bp})
            bands.sort(key=lambda x: x['min_usd'])
        except Exception:
            bands = []
        if not bands:
            bands = [
                {'min_usd': 5, 'multiplier_bp': 10000},
                {'min_usd': 10, 'multiplier_bp': 12500},
                {'min_usd': 25, 'multiplier_bp': 14000},
                {'min_usd': 50, 'multiplier_bp': 15500},
                {'min_usd': 100, 'multiplier_bp': 17500},
            ]
        env = settings.get('topup_coinbase_env', 'sandbox')
        if env not in ('sandbox', 'live'):
            env = 'sandbox'
        coinbase_enabled = settings.get('topup_coinbase_enabled', '1') == '1'
        provider = settings.get('topup_provider', 'coinbase') or 'coinbase'
        try:
            timeout_raw = (settings.get('topup_provider_request_timeout_sec', '')
                           or settings.get('topup_coinbase_request_timeout_sec', '15')
                           or '15')
            timeout_sec = max(3, min(120, int(timeout_raw)))
        except Exception:
            timeout_sec = 15
        try:
            pending_sla = max(5, min(10080, int(settings.get('topup_pending_sla_minutes', '180') or '180')))
        except Exception:
            pending_sla = 180
        paypal_env = settings.get('topup_paypal_env', 'sandbox')
        if paypal_env not in ('sandbox', 'live'):
            paypal_env = 'sandbox'
        paypal_enabled = settings.get('topup_paypal_enabled', '0') == '1'
        paypal_webhook_enforce = settings.get('topup_paypal_webhook_enforce', '1') == '1'
        coinbase_api_key_sandbox = settings.get('topup_coinbase_api_key_sandbox', '')
        coinbase_api_key_live = settings.get('topup_coinbase_api_key_live', '')
        coinbase_webhook_secret_sandbox = settings.get('topup_coinbase_webhook_secret_sandbox', '')
        coinbase_webhook_secret_live = settings.get('topup_coinbase_webhook_secret_live', '')
        paypal_client_id_sandbox = settings.get('topup_paypal_client_id_sandbox', '')
        paypal_client_id_live = settings.get('topup_paypal_client_id_live', '')
        paypal_client_secret_sandbox = settings.get('topup_paypal_client_secret_sandbox', '')
        paypal_client_secret_live = settings.get('topup_paypal_client_secret_live', '')
        paypal_webhook_id_sandbox = settings.get('topup_paypal_webhook_id_sandbox', '')
        paypal_webhook_id_live = settings.get('topup_paypal_webhook_id_live', '')
        legacy_coinbase_key = settings.get('topup_coinbase_api_key', '')
        legacy_coinbase_secret = settings.get('topup_coinbase_webhook_secret', '')
        legacy_paypal_client_id = settings.get('topup_paypal_client_id', '')
        legacy_paypal_client_secret = settings.get('topup_paypal_client_secret', '')
        legacy_paypal_webhook_id = settings.get('topup_paypal_webhook_id', '')

        # Backfill env-specific values from legacy single fields for existing installs.
        if legacy_coinbase_key and not (coinbase_api_key_sandbox or coinbase_api_key_live):
            if env == 'live':
                coinbase_api_key_live = legacy_coinbase_key
            else:
                coinbase_api_key_sandbox = legacy_coinbase_key
        if legacy_coinbase_secret and not (coinbase_webhook_secret_sandbox or coinbase_webhook_secret_live):
            if env == 'live':
                coinbase_webhook_secret_live = legacy_coinbase_secret
            else:
                coinbase_webhook_secret_sandbox = legacy_coinbase_secret
        if legacy_paypal_client_id and not (paypal_client_id_sandbox or paypal_client_id_live):
            if paypal_env == 'live':
                paypal_client_id_live = legacy_paypal_client_id
            else:
                paypal_client_id_sandbox = legacy_paypal_client_id
        if legacy_paypal_client_secret and not (paypal_client_secret_sandbox or paypal_client_secret_live):
            if paypal_env == 'live':
                paypal_client_secret_live = legacy_paypal_client_secret
            else:
                paypal_client_secret_sandbox = legacy_paypal_client_secret
        if legacy_paypal_webhook_id and not (paypal_webhook_id_sandbox or paypal_webhook_id_live):
            if paypal_env == 'live':
                paypal_webhook_id_live = legacy_paypal_webhook_id
            else:
                paypal_webhook_id_sandbox = legacy_paypal_webhook_id

        # Active credentials are resolved from the selected environment; legacy
        # single-value keys remain as fallback for existing deployments.
        coinbase_api_key_active = (
            coinbase_api_key_sandbox if env == 'sandbox' else coinbase_api_key_live
        ) or legacy_coinbase_key
        coinbase_webhook_secret_active = (
            coinbase_webhook_secret_sandbox if env == 'sandbox' else coinbase_webhook_secret_live
        ) or legacy_coinbase_secret
        paypal_client_id_active = (
            paypal_client_id_sandbox if paypal_env == 'sandbox' else paypal_client_id_live
        ) or legacy_paypal_client_id
        paypal_client_secret_active = (
            paypal_client_secret_sandbox if paypal_env == 'sandbox' else paypal_client_secret_live
        ) or legacy_paypal_client_secret
        paypal_webhook_id_active = (
            paypal_webhook_id_sandbox if paypal_env == 'sandbox' else paypal_webhook_id_live
        ) or legacy_paypal_webhook_id
        providers = []
        if coinbase_enabled:
            providers.append('coinbase')
        if paypal_enabled:
            providers.append('paypal')
        if not providers:
            # keep stable behavior when all processors disabled
            providers = ['coinbase']
        if provider not in providers:
            provider = providers[0]
        return {
            'enabled': settings.get('topup_enabled', '0') == '1',
            'rollout_mode': settings.get('topup_rollout_mode', 'admin_only'),
            'provider': provider,
            'providers': providers,
            'coinbase_enabled': coinbase_enabled,
            'coinbase_env': env,
            'coinbase_api_key': coinbase_api_key_active,
            'coinbase_webhook_secret': coinbase_webhook_secret_active,
            'coinbase_api_key_sandbox': coinbase_api_key_sandbox,
            'coinbase_api_key_live': coinbase_api_key_live,
            'coinbase_webhook_secret_sandbox': coinbase_webhook_secret_sandbox,
            'coinbase_webhook_secret_live': coinbase_webhook_secret_live,
            'coinbase_create_url': settings.get('topup_coinbase_create_url', 'https://api.commerce.coinbase.com/charges'),
            'provider_request_timeout_sec': timeout_sec,
            'coinbase_request_timeout_sec': timeout_sec,
            'auto_redirect_checkout': settings.get('topup_auto_redirect_checkout', '1') == '1',
            'pending_sla_minutes': pending_sla,
            'paypal_enabled': paypal_enabled,
            'paypal_webhook_enforce': paypal_webhook_enforce,
            'paypal_env': paypal_env,
            'paypal_client_id': paypal_client_id_active,
            'paypal_client_secret': paypal_client_secret_active,
            'paypal_webhook_id': paypal_webhook_id_active,
            'paypal_client_id_sandbox': paypal_client_id_sandbox,
            'paypal_client_id_live': paypal_client_id_live,
            'paypal_client_secret_sandbox': paypal_client_secret_sandbox,
            'paypal_client_secret_live': paypal_client_secret_live,
            'paypal_webhook_id_sandbox': paypal_webhook_id_sandbox,
            'paypal_webhook_id_live': paypal_webhook_id_live,
            'base_rate_pts_per_usd': base_rate,
            'fixed_amounts_usd': fixed_amounts,
            'multiplier_bands': bands,
        }

    def quote_topup_points(self, amount_usd: int) -> dict:
        cfg = self.get_topup_config()
        amount_usd = max(1, int(amount_usd))
        amount_cents = amount_usd * 100
        multiplier_bp = 10000
        for band in cfg['multiplier_bands']:
            if amount_usd >= band['min_usd']:
                multiplier_bp = band['multiplier_bp']
            else:
                break
        # integer math: floor(usd * rate * multiplier)
        points = (amount_cents * cfg['base_rate_pts_per_usd'] * multiplier_bp) // 1000000
        return {
            'amount_usd': amount_usd,
            'amount_usd_cents': amount_cents,
            'base_rate_pts_per_usd': cfg['base_rate_pts_per_usd'],
            'multiplier_bp': multiplier_bp,
            'quoted_points': int(points),
            'provider': cfg['provider'],
            'provider_env': cfg['coinbase_env'],
        }

    def create_topup_order(self, user_id: int, amount_usd: int, actor: str = '',
                           provider: str = 'coinbase'):
        q = self.quote_topup_points(amount_usd)
        provider = (provider or 'coinbase').strip().lower()
        if provider not in ('coinbase', 'paypal'):
            provider = 'coinbase'
        order_uuid = secrets.token_urlsafe(18)
        c = self._conn()
        c.execute(
            '''INSERT INTO topup_orders (
                   order_uuid,user_id,provider,provider_env,status,
                   amount_usd_cents,currency,base_rate_pts_per_usd,multiplier_bp,quoted_points,
                   created_at,updated_at,created_by_admin_id
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (order_uuid, user_id, provider, q['provider_env'], 'created',
             q['amount_usd_cents'], 'USD', q['base_rate_pts_per_usd'], q['multiplier_bp'], q['quoted_points'],
             self._ts(), self._ts(), None)
        )
        order_id = c.execute('SELECT last_insert_rowid()').fetchone()[0]
        c.commit()
        if actor:
            self._log(actor, 'topup_order_create', str(order_id),
                      f'user_id={user_id} amount_usd={amount_usd} quote={q["quoted_points"]}')
        return self.get_topup_order(order_id)

    def get_topup_order(self, order_id: int):
        return self._conn().execute(
            'SELECT * FROM topup_orders WHERE id=?', (order_id,)
        ).fetchone()

    def get_topup_order_by_uuid(self, order_uuid: str):
        return self._conn().execute(
            'SELECT * FROM topup_orders WHERE order_uuid=?', (order_uuid,)
        ).fetchone()

    def get_topup_order_by_provider_checkout_id(self, checkout_id: str):
        return self._conn().execute(
            'SELECT * FROM topup_orders WHERE provider_checkout_id=?',
            (checkout_id,)
        ).fetchone()

    def get_topup_order_by_provider_charge_id(self, charge_id: str):
        return self._conn().execute(
            'SELECT * FROM topup_orders WHERE provider_charge_id=?',
            (charge_id,)
        ).fetchone()

    def get_topup_order_by_provider_reference(self, provider_reference: str):
        return self._conn().execute(
            'SELECT * FROM topup_orders WHERE provider_reference=?',
            (provider_reference,)
        ).fetchone()

    def set_topup_provider_refs(self, order_id: int, provider_checkout_id: str = '',
                                provider_charge_id: str = '', provider_reference: str = '',
                                actor: str = '') -> None:
        self._conn().execute(
            '''UPDATE topup_orders
               SET provider_checkout_id=?,
                   provider_charge_id=?,
                   provider_reference=?,
                   updated_at=?
               WHERE id=?''',
            (provider_checkout_id[:255], provider_charge_id[:255], provider_reference[:1000], self._ts(), order_id)
        )
        self._conn().commit()
        if actor:
            self._log(actor, 'topup_provider_ref_set', str(order_id),
                      f'checkout_id={provider_checkout_id[:32]} charge_id={provider_charge_id[:32]}')

    def create_coinbase_checkout_for_order(self, order_id: int, user, actor: str = '') -> tuple[bool, dict]:
        order = self.get_topup_order(order_id)
        if not order:
            return False, {'error': 'order_not_found', 'message': 'Order not found.'}
        cfg = self.get_topup_config()
        api_key = cfg.get('coinbase_api_key', '')
        create_url = (cfg.get('coinbase_create_url', '') or '').strip()
        if not api_key:
            return False, {'error': 'missing_api_key', 'message': 'Coinbase API key is not configured.'}
        if not create_url:
            return False, {'error': 'missing_create_url', 'message': 'Coinbase create URL is not configured.'}
        amount_usd = f'{order["amount_usd_cents"] / 100:.2f}'
        payload = {
            'name': f'Wildkat Points Top-up #{order["id"]}',
            'description': f'{order["quoted_points"]} points for user @{user["username"]}',
            'pricing_type': 'fixed_price',
            'local_price': {'amount': amount_usd, 'currency': 'USD'},
            'metadata': {
                'order_uuid': order['order_uuid'],
                'topup_order_uuid': order['order_uuid'],
                'order_id': str(order['id']),
                'user_id': str(order['user_id']),
                'username': user['username'],
            },
        }
        req_data = json.dumps(payload).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            # Commerce API commonly uses X-CC-Api-Key; keep Authorization too for compatibility.
            'X-CC-Api-Key': api_key,
            'Authorization': f'Bearer {api_key}',
        }
        req = urllib.request.Request(create_url, data=req_data, headers=headers, method='POST')
        timeout = cfg.get('provider_request_timeout_sec', cfg.get('coinbase_request_timeout_sec', 15))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                status_code = getattr(resp, 'status', 200)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='replace')
            return False, {'error': 'provider_http_error', 'status': e.code, 'message': err_body[:500]}
        except Exception as e:
            return False, {'error': 'provider_request_error', 'message': str(e)[:500]}
        try:
            data = json.loads(body or '{}')
        except Exception:
            data = {}
        root = data.get('data') if isinstance(data.get('data'), dict) else data
        hosted_url = ''
        for key in ('hosted_url', 'url', 'checkout_url', 'redirect_url'):
            val = root.get(key) if isinstance(root, dict) else None
            if isinstance(val, str) and val.startswith('http'):
                hosted_url = val
                break
        charge_id = ''
        checkout_id = ''
        if isinstance(root, dict):
            charge_id = str(root.get('id') or root.get('charge_id') or '')
            checkout_id = str(root.get('code') or root.get('checkout_id') or root.get('payment_link_id') or '')
        if not hosted_url:
            return False, {'error': 'missing_checkout_url', 'status': status_code, 'message': body[:500]}
        self.set_topup_provider_refs(order_id, provider_checkout_id=checkout_id,
                                     provider_charge_id=charge_id,
                                     provider_reference=hosted_url, actor=actor)
        self.update_topup_status(order_id, 'pending', actor=actor or 'system',
                                 reason='awaiting_payment',
                                 detail='Checkout generated; awaiting Coinbase confirmation')
        return True, {
            'checkout_url': hosted_url,
            'checkout_id': checkout_id,
            'charge_id': charge_id,
            'status': status_code,
        }

    def _paypal_api_base(self, cfg: dict) -> str:
        return 'https://api-m.paypal.com' if cfg.get('paypal_env') == 'live' else 'https://api-m.sandbox.paypal.com'

    def _paypal_access_token(self, cfg: dict) -> tuple[bool, dict]:
        client_id = cfg.get('paypal_client_id', '')
        client_secret = cfg.get('paypal_client_secret', '')
        if not client_id or not client_secret:
            return False, {'error': 'missing_paypal_credentials', 'message': 'PayPal client id/secret not configured.'}
        token_url = self._paypal_api_base(cfg) + '/v1/oauth2/token'
        creds = f'{client_id}:{client_secret}'.encode('utf-8')
        auth = base64.b64encode(creds).decode('ascii')
        data = b'grant_type=client_credentials'
        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'en_US',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {auth}',
        }
        req = urllib.request.Request(token_url, data=data, headers=headers, method='POST')
        timeout = cfg.get('provider_request_timeout_sec', cfg.get('coinbase_request_timeout_sec', 15))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='replace')
            return False, {'error': 'paypal_oauth_http_error', 'status': e.code, 'message': err_body[:500]}
        except Exception as e:
            return False, {'error': 'paypal_oauth_request_error', 'message': str(e)[:500]}
        try:
            payload = json.loads(body or '{}')
        except Exception:
            payload = {}
        token = payload.get('access_token', '')
        if not token:
            return False, {'error': 'paypal_oauth_no_token', 'message': body[:500]}
        return True, {'access_token': token}

    def create_paypal_checkout_for_order(self, order_id: int, user, return_url: str,
                                         cancel_url: str, actor: str = '') -> tuple[bool, dict]:
        order = self.get_topup_order(order_id)
        if not order:
            return False, {'error': 'order_not_found', 'message': 'Order not found.'}
        cfg = self.get_topup_config()
        log.debug('PAYPAL create start order_id=%s order_uuid=%s user_id=%s env=%s actor=%s amount_usd=%.2f',
                  order['id'], str(order['order_uuid'])[:12], order['user_id'], cfg.get('paypal_env', 'sandbox'),
                  actor or 'system', order['amount_usd_cents'] / 100.0)
        ok_tok, tok = self._paypal_access_token(cfg)
        if not ok_tok:
            log.warning('PAYPAL create oauth_failed order_id=%s err=%s',
                        order['id'], tok.get('error') or tok.get('message') or 'unknown')
            return False, tok
        api_base = self._paypal_api_base(cfg)
        create_url = api_base + '/v2/checkout/orders'
        amount_usd = f'{order["amount_usd_cents"] / 100:.2f}'
        payload = {
            'intent': 'CAPTURE',
            'purchase_units': [{
                'reference_id': str(order['id']),
                'custom_id': order['order_uuid'],
                'invoice_id': f'wk-topup-{order["order_uuid"]}',
                'description': f'Wildkat Points Top-up ({order["quoted_points"]} pts)',
                'amount': {'currency_code': 'USD', 'value': amount_usd},
            }],
            'application_context': {
                'brand_name': 'Wildkat Tracker',
                'user_action': 'PAY_NOW',
                'return_url': return_url,
                'cancel_url': cancel_url,
            },
        }
        req_data = json.dumps(payload).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {tok["access_token"]}',
            'PayPal-Request-Id': f'wk-topup-{order["order_uuid"]}',
        }
        req = urllib.request.Request(create_url, data=req_data, headers=headers, method='POST')
        timeout = cfg.get('provider_request_timeout_sec', cfg.get('coinbase_request_timeout_sec', 15))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='replace')
            log.warning('PAYPAL create http_error order_id=%s status=%s body=%r',
                        order['id'], e.code, err_body[:220])
            return False, {'error': 'paypal_create_http_error', 'status': e.code, 'message': err_body[:500]}
        except Exception as e:
            log.warning('PAYPAL create request_error order_id=%s err=%s', order['id'], e)
            return False, {'error': 'paypal_create_request_error', 'message': str(e)[:500]}
        try:
            data = json.loads(body or '{}')
        except Exception:
            data = {}
        paypal_order_id = str(data.get('id') or '')
        approve_url = ''
        links = data.get('links') if isinstance(data.get('links'), list) else []
        for link in links:
            if isinstance(link, dict) and link.get('rel') == 'approve' and isinstance(link.get('href'), str):
                approve_url = link['href']
                break
        if not paypal_order_id or not approve_url:
            log.warning('PAYPAL create missing_fields order_id=%s paypal_order_id=%r approve_present=%s body=%r',
                        order['id'], paypal_order_id[:24], bool(approve_url), body[:220])
            return False, {'error': 'paypal_create_missing_fields', 'message': body[:500]}
        log.debug('PAYPAL create ok order_id=%s paypal_order_id=%s approve_url=%s',
                  order['id'], paypal_order_id[:24], approve_url[:180])
        self.set_topup_provider_refs(order_id,
                                     provider_checkout_id=paypal_order_id,
                                     provider_charge_id='',
                                     provider_reference=approve_url,
                                     actor=actor)
        self.update_topup_status(order_id, 'pending', actor=actor or 'system',
                                 reason='awaiting_payment',
                                 detail='PayPal order created; awaiting payer approval/capture')
        return True, {'checkout_id': paypal_order_id, 'checkout_url': approve_url}

    def capture_paypal_order(self, order_id: int, actor: str = 'system') -> tuple[bool, dict]:
        order = self.get_topup_order(order_id)
        if not order:
            return False, {'error': 'order_not_found', 'message': 'Order not found.'}
        if order['status'] == 'credited':
            log.debug('PAYPAL capture skipped order_id=%s reason=already_credited actor=%s',
                      order_id, actor)
            return True, {'already_credited': True, 'status': 'CREDITED'}
        if order['status'] == 'refunded':
            log.debug('PAYPAL capture skipped order_id=%s reason=already_refunded actor=%s',
                      order_id, actor)
            return False, {'error': 'order_refunded', 'message': 'Order already refunded.'}
        paypal_order_id = order['provider_checkout_id'] or ''
        if not paypal_order_id:
            return False, {'error': 'missing_paypal_order_id', 'message': 'No PayPal order ID on top-up order.'}
        cfg = self.get_topup_config()
        log.debug('PAYPAL capture start order_id=%s paypal_order_id=%s actor=%s env=%s status=%s',
                  order['id'], paypal_order_id[:24], actor, cfg.get('paypal_env', 'sandbox'),
                  order['status'])
        ok_tok, tok = self._paypal_access_token(cfg)
        if not ok_tok:
            log.warning('PAYPAL capture oauth_failed order_id=%s err=%s',
                        order['id'], tok.get('error') or tok.get('message') or 'unknown')
            return False, tok
        capture_url = self._paypal_api_base(cfg) + f'/v2/checkout/orders/{urllib.parse.quote(paypal_order_id)}/capture'
        req = urllib.request.Request(
            capture_url,
            data=b'{}',
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': f'Bearer {tok["access_token"]}',
                'PayPal-Request-Id': f'wk-topup-capture-{order["order_uuid"]}',
            },
            method='POST'
        )
        timeout = cfg.get('provider_request_timeout_sec', cfg.get('coinbase_request_timeout_sec', 15))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='replace')
            log.warning('PAYPAL capture http_error order_id=%s status=%s body=%r',
                        order['id'], e.code, err_body[:220])
            return False, {'error': 'paypal_capture_http_error', 'status': e.code, 'message': err_body[:500]}
        except Exception as e:
            log.warning('PAYPAL capture request_error order_id=%s err=%s', order['id'], e)
            return False, {'error': 'paypal_capture_request_error', 'message': str(e)[:500]}
        try:
            data = json.loads(body or '{}')
        except Exception:
            data = {}
        status = str(data.get('status') or '')
        text_blob = json.dumps(data).lower()
        capture_id = ''
        pu = data.get('purchase_units') if isinstance(data.get('purchase_units'), list) else []
        for unit in pu:
            payments = unit.get('payments') if isinstance(unit, dict) else {}
            captures = payments.get('captures') if isinstance(payments, dict) else []
            if captures and isinstance(captures[0], dict):
                capture_id = str(captures[0].get('id') or '')
                break
        if status in ('COMPLETED', 'APPROVED') or '"status":"completed"' in text_blob:
            log.debug('PAYPAL capture provider_ok order_id=%s paypal_order_id=%s status=%s capture_id=%s',
                      order['id'], paypal_order_id[:24], status, capture_id[:24])
            self.set_topup_provider_refs(order_id,
                                         provider_checkout_id=paypal_order_id,
                                         provider_charge_id=capture_id or order['provider_charge_id'],
                                         provider_reference=order['provider_reference'],
                                         actor=actor)
            self.update_topup_status(order_id, 'confirmed', actor=actor,
                                     reason='provider_confirmed', detail='PayPal order captured')
            ok_credit, msg_credit = self.credit_topup_order(order_id, actor=actor)
            if not ok_credit:
                # Webhook may have credited moments before return capture.
                # Treat that as idempotent success to avoid false user-facing errors.
                if 'already credited' in (msg_credit or '').lower():
                    log.debug('PAYPAL capture already_credited order_id=%s status=%s capture_id=%s',
                              order['id'], status, capture_id[:24])
                    return True, {'status': status, 'capture_id': capture_id, 'already_credited': True}
                log.warning('PAYPAL capture credit_failed order_id=%s msg=%s', order['id'], msg_credit)
                return False, {'error': 'credit_failed', 'message': msg_credit}
            log.debug('PAYPAL capture credited order_id=%s status=%s capture_id=%s',
                      order['id'], status, capture_id[:24])
            return True, {'status': status, 'capture_id': capture_id}
        log.warning('PAYPAL capture not_completed order_id=%s provider_status=%s body=%r',
                    order['id'], status, body[:220])
        return False, {'error': 'paypal_capture_not_completed', 'message': body[:500]}

    def verify_paypal_webhook_signature(self, payload: dict, headers) -> tuple[bool, str]:
        """Verify PayPal webhook signature using PayPal verify endpoint.
        Returns (is_valid, detail). Enforce mode controls fail-closed behavior."""
        cfg = self.get_topup_config()
        webhook_id = cfg.get('paypal_webhook_id', '')
        enforce = bool(cfg.get('paypal_webhook_enforce', True))
        if not webhook_id:
            if enforce:
                log.warning('PAYPAL webhook verify failed: webhook_id_not_configured (env=%s enforce=1)',
                            cfg.get('paypal_env', 'sandbox'))
                return False, 'webhook_id_not_configured'
            log.warning('PAYPAL webhook verify bypassed: webhook_id_not_configured (env=%s enforce=0, INSECURE)',
                        cfg.get('paypal_env', 'sandbox'))
            return True, 'skipped_no_webhook_id_enforce_off'
        required = {
            'transmission_id': headers.get('paypal-transmission-id', ''),
            'transmission_time': headers.get('paypal-transmission-time', ''),
            'cert_url': headers.get('paypal-cert-url', ''),
            'auth_algo': headers.get('paypal-auth-algo', ''),
            'transmission_sig': headers.get('paypal-transmission-sig', ''),
        }
        if not all(required.values()):
            log.warning('PAYPAL webhook verify missing headers id=%s time=%s algo=%s cert=%s sig=%s',
                        bool(required['transmission_id']), bool(required['transmission_time']),
                        bool(required['auth_algo']), bool(required['cert_url']),
                        bool(required['transmission_sig']))
            return False, 'missing_signature_headers'
        ok_tok, tok = self._paypal_access_token(cfg)
        if not ok_tok:
            log.warning('PAYPAL webhook verify oauth_failed err=%s', tok.get('error') or tok.get('message') or 'unknown')
            return False, tok.get('error') or 'oauth_failed'
        verify_url = self._paypal_api_base(cfg) + '/v1/notifications/verify-webhook-signature'
        body = {
            'transmission_id': required['transmission_id'],
            'transmission_time': required['transmission_time'],
            'cert_url': required['cert_url'],
            'auth_algo': required['auth_algo'],
            'transmission_sig': required['transmission_sig'],
            'webhook_id': webhook_id,
            'webhook_event': payload,
        }
        req = urllib.request.Request(
            verify_url,
            data=json.dumps(body).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': f'Bearer {tok["access_token"]}',
            },
            method='POST'
        )
        timeout = cfg.get('provider_request_timeout_sec', cfg.get('coinbase_request_timeout_sec', 15))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode('utf-8', errors='replace')
        except Exception as e:
            log.warning('PAYPAL webhook verify request_error err=%s', e)
            return False, f'verify_request_failed:{str(e)[:120]}'
        try:
            data = json.loads(raw or '{}')
        except Exception:
            data = {}
        status = str(data.get('verification_status') or '').upper()
        log.debug('PAYPAL webhook verify result status=%s webhook_id=%s transmission_id=%s',
                  status, webhook_id[:20], required['transmission_id'][:20])
        return (status == 'SUCCESS'), (status or 'unknown')

    def list_topup_orders(self, user_id: int | None = None, status: str = '',
                          limit: int = 200) -> list:
        limit = max(1, min(500, int(limit)))
        if user_id is None:
            if status:
                return self._conn().execute(
                    'SELECT * FROM topup_orders WHERE status=? ORDER BY id DESC LIMIT ?',
                    (status, limit)
                ).fetchall()
            return self._conn().execute(
                'SELECT * FROM topup_orders ORDER BY id DESC LIMIT ?',
                (limit,)
            ).fetchall()
        if status:
            return self._conn().execute(
                'SELECT * FROM topup_orders WHERE user_id=? AND status=? ORDER BY id DESC LIMIT ?',
                (user_id, status, limit)
            ).fetchall()
        return self._conn().execute(
            'SELECT * FROM topup_orders WHERE user_id=? ORDER BY id DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()

    def get_topup_user_sequence(self, user_id: int, order_id: int) -> int:
        """1-based sequence number of this order within a user's own top-up history."""
        row = self._conn().execute(
            'SELECT COUNT(*) FROM topup_orders WHERE user_id=? AND id<=?',
            (user_id, order_id)
        ).fetchone()
        return int(row[0] if row and row[0] is not None else 0)

    def update_topup_status(self, order_id: int, new_status: str, actor: str = '',
                            reason: str = '', detail: str = '') -> bool:
        allowed = {'created', 'pending', 'confirmed', 'credited', 'expired', 'failed', 'exception', 'refunded'}
        if new_status not in allowed:
            return False
        old = self.get_topup_order(order_id)
        if not old:
            return False
        old_status = old['status']
        if old_status == new_status:
            return False
        transitions = {
            'created':   {'pending', 'confirmed', 'failed', 'expired', 'exception'},
            'pending':   {'confirmed', 'failed', 'expired', 'exception'},
            'confirmed': {'credited', 'failed', 'expired', 'exception'},
            'failed':    set(),
            'expired':   set(),
            'exception': set(),
            'credited':  {'refunded'},
            'refunded':  set(),
        }
        if new_status not in transitions.get(old_status, set()):
            return False
        c = self._conn()
        c.execute(
            'UPDATE topup_orders SET status=?,status_reason=?,status_detail=?,updated_at=? WHERE id=?',
            (new_status, reason, detail[:400], self._ts(), order_id)
        )
        if new_status == 'confirmed':
            c.execute('UPDATE topup_orders SET confirmed_at=COALESCE(confirmed_at,?) WHERE id=?',
                      (self._ts(), order_id))
        c.commit()
        if actor:
            self._log(actor, 'topup_status_change', str(order_id),
                      f'{old["status"]}->{new_status} reason={reason}')
        return True

    def record_topup_webhook_event(self, provider: str, event_type: str,
                                   payload_json: str, headers_json: str = '',
                                   signature_valid: bool = False, event_id: str = '',
                                   linked_order_id: int | None = None,
                                   idempotency_key: str = '') -> int:
        c = self._conn()
        c.execute(
            '''INSERT INTO topup_webhook_events (
                   provider,event_id,event_type,signature_valid,payload_json,headers_json,
                   received_at,linked_order_id,idempotency_key
               ) VALUES (?,?,?,?,?,?,?,?,?)''',
            (provider, event_id[:120], event_type[:120], 1 if signature_valid else 0,
             payload_json[:50000], headers_json[:50000], self._ts(), linked_order_id, idempotency_key[:200])
        )
        event_id_db = c.execute('SELECT last_insert_rowid()').fetchone()[0]
        c.commit()
        return event_id_db

    def get_topup_webhook_event(self, provider: str, event_id: str):
        if not event_id:
            return None
        return self._conn().execute(
            'SELECT * FROM topup_webhook_events WHERE provider=? AND event_id=? ORDER BY id DESC LIMIT 1',
            (provider, event_id[:120])
        ).fetchone()

    def mark_topup_webhook_processed(self, webhook_event_id: int, status: str = 'processed',
                                     error_msg: str = '') -> None:
        self._conn().execute(
            'UPDATE topup_webhook_events SET process_status=?,process_error=?,processed_at=? WHERE id=?',
            (status, error_msg[:400], self._ts(), webhook_event_id)
        )
        self._conn().commit()

    def list_topup_webhook_events(self, limit: int = 200) -> list:
        limit = max(1, min(500, int(limit)))
        return self._conn().execute(
            'SELECT * FROM topup_webhook_events ORDER BY id DESC LIMIT ?',
            (limit,)
        ).fetchall()

    def add_topup_reconciliation_action(self, order_id: int, actor_user_id: int, action: str,
                                        old_status: str, new_status: str, note: str = '') -> None:
        self._conn().execute(
            '''INSERT INTO topup_reconciliation_actions
               (order_id,actor_user_id,action,note,old_status,new_status,created_at)
               VALUES (?,?,?,?,?,?,?)''',
            (order_id, actor_user_id, action, note[:800], old_status, new_status, self._ts())
        )
        self._conn().commit()

    def list_topup_reconciliation_actions(self, order_id: int) -> list:
        return self._conn().execute(
            'SELECT * FROM topup_reconciliation_actions WHERE order_id=? ORDER BY id DESC',
            (order_id,)
        ).fetchall()

    def credit_topup_order(self, order_id: int, actor: str = 'system') -> tuple[bool, str]:
        c = self._conn()
        try:
            c.execute('BEGIN IMMEDIATE')
            order = c.execute('SELECT * FROM topup_orders WHERE id=?', (order_id,)).fetchone()
            if not order:
                c.execute('ROLLBACK')
                return False, 'Order not found.'
            if order['status'] == 'credited':
                c.execute('ROLLBACK')
                return False, 'Order already credited.'
            if order['status'] != 'confirmed':
                c.execute('ROLLBACK')
                return False, f'Order status {order["status"]} cannot be credited.'
            user = c.execute('SELECT id,username FROM users WHERE id=?', (order['user_id'],)).fetchone()
            if not user:
                c.execute('ROLLBACK')
                return False, 'User not found.'

            points = int(order['quoted_points'])
            c.execute('UPDATE users SET points = points + ? WHERE id = ?', (points, order['user_id']))
            bal_row = c.execute('SELECT points FROM users WHERE id=?', (order['user_id'],)).fetchone()
            balance = bal_row[0] if bal_row else 0
            c.execute(
                'INSERT INTO points_ledger (user_id,delta,balance_after,reason,ref_type,ref_id,created_at)'
                ' VALUES (?,?,?,?,?,?,?)',
                (order['user_id'], points, balance,
                 f'top-up credited (${order["amount_usd_cents"]/100:.2f})',
                 'topup', str(order_id), self._ts())
            )
            ledger_id = c.execute('SELECT last_insert_rowid()').fetchone()[0]
            now = self._ts()
            upd = c.execute(
                '''UPDATE topup_orders
                   SET status='credited',
                       status_reason='credited',
                       status_detail='Credited after confirmed payment',
                       credited_points=?,
                       credits_ledger_id=?,
                       confirmed_at=COALESCE(confirmed_at,?),
                       credited_at=?,
                       updated_at=?
                   WHERE id=? AND status='confirmed' ''',
                (points, ledger_id, now, now, now, order_id)
            )
            if upd.rowcount != 1:
                c.execute('ROLLBACK')
                latest = c.execute('SELECT status FROM topup_orders WHERE id=?', (order_id,)).fetchone()
                if latest and latest['status'] == 'credited':
                    return False, 'Order already credited.'
                return False, 'Order state changed during credit.'
            c.execute('COMMIT')
        except Exception:
            try:
                c.execute('ROLLBACK')
            except Exception:
                pass
            raise
        self.add_notification(
            order['user_id'],
            'topup_credited',
            'system',
            f'TOPUP:{order_id}',
            f'{points} pts awarded for ${order["amount_usd_cents"]/100:.2f}',
            0
        )
        self._log(actor, 'topup_credit', str(order_id),
                  f'user={user["username"]} points={points}')
        self.check_auto_promote(order['user_id'])
        return True, f'Credited {points} points.'

    def refund_topup_order(self, order_id: int, actor: str = 'system',
                           reason: str = 'provider_refund',
                           detail: str = '') -> tuple[bool, str]:
        """Reverse previously credited points for a refunded/reversed payment."""
        c = self._conn()
        try:
            c.execute('BEGIN IMMEDIATE')
            order = c.execute('SELECT * FROM topup_orders WHERE id=?', (order_id,)).fetchone()
            if not order:
                c.execute('ROLLBACK')
                return False, 'Order not found.'
            if order['status'] == 'refunded':
                c.execute('ROLLBACK')
                return False, 'Order already refunded.'
            if order['status'] != 'credited':
                c.execute('ROLLBACK')
                return False, f'Order status {order["status"]} cannot be refunded.'
            user = c.execute('SELECT id,username FROM users WHERE id=?', (order['user_id'],)).fetchone()
            if not user:
                c.execute('ROLLBACK')
                return False, 'User not found.'
            points = int(order['credited_points'] or 0 or order['quoted_points'])
            if points <= 0:
                c.execute('ROLLBACK')
                return False, 'No credited points to reverse.'

            c.execute('UPDATE users SET points = points - ? WHERE id = ?', (points, order['user_id']))
            bal_row = c.execute('SELECT points FROM users WHERE id=?', (order['user_id'],)).fetchone()
            balance = bal_row[0] if bal_row else 0
            c.execute(
                'INSERT INTO points_ledger (user_id,delta,balance_after,reason,ref_type,ref_id,created_at)'
                ' VALUES (?,?,?,?,?,?,?)',
                (order['user_id'], -points, balance,
                 f'top-up refunded (${order["amount_usd_cents"]/100:.2f})',
                 'topup_refund', str(order_id), self._ts())
            )
            now = self._ts()
            upd = c.execute(
                '''UPDATE topup_orders
                   SET status='refunded',
                       status_reason=?,
                       status_detail=?,
                       updated_at=?
                   WHERE id=? AND status='credited' ''',
                (reason[:120], (detail or 'Payment refunded by provider')[:400], now, order_id)
            )
            if upd.rowcount != 1:
                c.execute('ROLLBACK')
                latest = c.execute('SELECT status FROM topup_orders WHERE id=?', (order_id,)).fetchone()
                if latest and latest['status'] == 'refunded':
                    return False, 'Order already refunded.'
                return False, 'Order state changed during refund.'
            c.execute('COMMIT')
        except Exception:
            try:
                c.execute('ROLLBACK')
            except Exception:
                pass
            raise
        self.add_notification(
            order['user_id'],
            'topup_refunded',
            'system',
            f'TOPUP:{order_id}',
            f'{points} pts reversed due to payment refund (${order["amount_usd_cents"]/100:.2f})',
            0
        )
        if SUPER_USER:
            super_u = self.get_user(SUPER_USER)
            if super_u and int(super_u['id']) != int(order['user_id']):
                self.add_notification(
                    super_u['id'],
                    'topup_refunded',
                    'system',
                    f'TOPUP:{order_id}',
                    f'@{user["username"]} refunded (${order["amount_usd_cents"]/100:.2f}); reversed {points} pts',
                    0
                )
        self._log(actor, 'topup_refund', str(order_id),
                  f'user={user["username"]} points=-{points} reason={reason}')
        return True, f'Reversed {points} points due to refund.'

    def get_topup_stats(self) -> dict:
        c = self._conn()
        def _q(sql, *args):
            row = c.execute(sql, args).fetchone()
            return row[0] if row and row[0] is not None else 0
        credited_orders = _q("SELECT COUNT(*) FROM topup_orders WHERE status='credited'")
        pending_orders = _q("SELECT COUNT(*) FROM topup_orders WHERE status IN ('created','pending','confirmed')")
        exception_orders = _q("SELECT COUNT(*) FROM topup_orders WHERE status IN ('failed','expired','exception','refunded')")
        usd_credited_cents = _q("SELECT SUM(amount_usd_cents) FROM topup_orders WHERE status='credited'")
        points_credited = _q("SELECT SUM(credited_points) FROM topup_orders WHERE status='credited'")
        return {
            'credited_orders': credited_orders,
            'pending_orders': pending_orders,
            'exception_orders': exception_orders,
            'usd_credited_cents': usd_credited_cents,
            'points_credited': points_credited,
        }

    def reconcile_stale_topup_orders(self) -> int:
        """Reconcile stale orders:
        - created/pending -> exception
        - confirmed -> retry credit, else exception
        """
        cfg = self.get_topup_config()
        cutoff = (datetime.datetime.now() -
                  datetime.timedelta(minutes=cfg.get('pending_sla_minutes', 180))).isoformat()
        rows = self._conn().execute(
            "SELECT id,status FROM topup_orders WHERE status IN ('created','pending','confirmed') AND created_at < ?",
            (cutoff,)
        ).fetchall()
        count = 0
        for r in rows:
            if r['status'] == 'confirmed':
                try:
                    ok, msg = self.credit_topup_order(r['id'], actor='system')
                except Exception as e:
                    ok, msg = False, f'credit_exception:{e}'
                if ok:
                    count += 1
                    continue
                if 'already credited' in (msg or '').lower():
                    continue
                if self.update_topup_status(
                    r['id'], 'exception', actor='system',
                    reason='confirmed_uncredited_timeout',
                    detail=('Order exceeded pending SLA in confirmed state and auto-credit failed: '
                            + (msg or 'unknown'))
                ):
                    count += 1
                continue
            if self.update_topup_status(
                r['id'], 'exception', actor='system',
                reason='pending_timeout',
                detail='Order exceeded pending SLA window; review in admin reconciliation queue'
            ):
                count += 1
        return count

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

    def update_last_seen(self, uid: int) -> None:
        """Stamp last_seen for online presence tracking. Fire-and-forget."""
        try:
            now = datetime.datetime.now().isoformat(timespec='seconds')
            self._conn().execute('UPDATE users SET last_seen=? WHERE id=?', (now, uid))
            self._conn().commit()
        except Exception:
            pass

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

    def get_unique_recent_user_for_ip(self, ip: str, max_age_days: int):
        """Return a unique opted-in user row for IP if confidence is unambiguous."""
        days = max(1, min(365, int(max_age_days)))
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat(timespec='seconds')
        rows = self._conn().execute(
            '''SELECT DISTINCT u.id, u.username
               FROM users u
               JOIN login_history lh ON lh.user_id=u.id
               WHERE lh.ip_address=?
                 AND lh.logged_in_at>=?
                 AND u.is_disabled=0
                 AND COALESCE(u.link_torrent_activity, 1)=1''',
            (ip, cutoff)
        ).fetchall()
        if len(rows) != 1:
            return None
        return rows[0]

    def get_recent_unique_ip_user_map(self, max_age_days: int) -> dict[str, str]:
        """Return {ip: username} where each IP maps to exactly one eligible user."""
        days = max(1, min(365, int(max_age_days)))
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat(timespec='seconds')
        rows = self._conn().execute(
            '''SELECT lh.ip_address AS ip, MIN(u.username) AS username
               FROM login_history lh
               JOIN users u ON u.id=lh.user_id
               WHERE lh.logged_in_at>=?
                 AND u.is_disabled=0
                 AND COALESCE(u.link_torrent_activity, 1)=1
               GROUP BY lh.ip_address
               HAVING COUNT(DISTINCT u.id)=1''',
            (cutoff,)
        ).fetchall()
        return {r['ip']: r['username'] for r in rows}

    def get_torrents_by_hashes(self, info_hashes: list[str]) -> list:
        """Fetch registered torrents for a set of info hashes."""
        if not info_hashes:
            return []
        out = []
        # SQLite default max variables is commonly 999; chunk defensively.
        chunk = 500
        for i in range(0, len(info_hashes), chunk):
            part = [h.upper() for h in info_hashes[i:i + chunk] if h]
            if not part:
                continue
            placeholders = ','.join('?' for _ in part)
            out.extend(self._conn().execute(
                f'SELECT info_hash, name FROM torrents WHERE info_hash IN ({placeholders})',
                part
            ).fetchall())
        return out

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

    def change_password(self, username: str, new_password: str, actor: str,
                        keep_session_token: str = ''):
        ph, salt = _hash_password(new_password)
        c = self._conn()
        c.execute(
            'UPDATE users SET password_hash=?, salt=?, failed_attempts=0, is_locked=0, '
            'last_password_change=? WHERE username=?',
            (ph, salt, self._ts(), username)
        )
        # Revoke active sessions after a password change.
        # If keep_session_token is provided, preserve only that current session.
        if keep_session_token:
            c.execute(
                'DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username=?) '
                'AND token != ?',
                (username, keep_session_token)
            )
        else:
            c.execute(
                'DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username=?)',
                (username,)
            )
        c.commit()
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

    # ── Followers ─────────────────────────────────────────────

    def is_following(self, follower_user_id: int, followed_user_id: int) -> bool:
        if follower_user_id == followed_user_id:
            return False
        row = self._conn().execute(
            'SELECT 1 FROM user_follows WHERE follower_user_id=? AND followed_user_id=?',
            (follower_user_id, followed_user_id)
        ).fetchone()
        return row is not None

    def follow_user(self, follower_user_id: int, followed_user_id: int) -> tuple[bool, str]:
        if follower_user_id == followed_user_id:
            return False, 'You cannot follow yourself.'
        c = self._conn()
        follower = c.execute('SELECT id FROM users WHERE id=?', (follower_user_id,)).fetchone()
        followed = c.execute('SELECT id,is_disabled FROM users WHERE id=?', (followed_user_id,)).fetchone()
        if not follower or not followed:
            return False, 'User not found.'
        if followed['is_disabled']:
            return False, 'Cannot follow a disabled account.'
        try:
            c.execute(
                'INSERT INTO user_follows (follower_user_id,followed_user_id,created_at) VALUES (?,?,?)',
                (follower_user_id, followed_user_id, self._ts())
            )
            c.commit()
            return True, 'Now following.'
        except sqlite3.IntegrityError:
            return False, 'Already following.'

    def unfollow_user(self, follower_user_id: int, followed_user_id: int) -> tuple[bool, str]:
        c = self._conn()
        cur = c.execute(
            'DELETE FROM user_follows WHERE follower_user_id=? AND followed_user_id=?',
            (follower_user_id, followed_user_id)
        )
        c.commit()
        if cur.rowcount:
            return True, 'Unfollowed.'
        return False, 'Not currently following.'

    def count_followers(self, user_id: int) -> int:
        return int(self._conn().execute(
            'SELECT COUNT(*) FROM user_follows WHERE followed_user_id=?',
            (user_id,)
        ).fetchone()[0] or 0)

    def count_following(self, user_id: int) -> int:
        return int(self._conn().execute(
            'SELECT COUNT(*) FROM user_follows WHERE follower_user_id=?',
            (user_id,)
        ).fetchone()[0] or 0)

    def get_follow_counts(self, user_id: int) -> tuple[int, int]:
        return self.count_followers(user_id), self.count_following(user_id)

    def list_follower_user_ids(self, followed_user_id: int) -> list[int]:
        rows = self._conn().execute(
            'SELECT follower_user_id FROM user_follows WHERE followed_user_id=?',
            (followed_user_id,)
        ).fetchall()
        return [int(r['follower_user_id']) for r in rows]

    def list_followers(self, user_id: int, limit: int = 500) -> list:
        return self._conn().execute(
            'SELECT u.id,u.username,u.is_admin,u.is_standard,u.is_disabled,f.created_at AS followed_at '
            'FROM user_follows f JOIN users u ON u.id=f.follower_user_id '
            'WHERE f.followed_user_id=? '
            'ORDER BY f.id DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()

    def list_following(self, user_id: int, limit: int = 500) -> list:
        return self._conn().execute(
            'SELECT u.id,u.username,u.is_admin,u.is_standard,u.is_disabled,f.created_at AS followed_at '
            'FROM user_follows f JOIN users u ON u.id=f.followed_user_id '
            'WHERE f.follower_user_id=? '
            'ORDER BY f.id DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()

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
        self._conn().execute(
            'DELETE FROM user_follows WHERE follower_user_id IN (SELECT id FROM users WHERE username != ?)'
            ' OR followed_user_id IN (SELECT id FROM users WHERE username != ?)',
            (except_username, except_username)
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
        self._conn().execute(
            'DELETE FROM user_follows WHERE follower_user_id IN (SELECT id FROM users WHERE username=?)'
            ' OR followed_user_id IN (SELECT id FROM users WHERE username=?)',
            (username, username)
        )
        self._conn().execute('DELETE FROM users WHERE username=?', (username,))
        self._conn().commit()
        self._log(actor, 'delete_user', username)

    # ── Torrents ───────────────────────────────────────────────

    def register_torrent(self, ih: str, name: str, total_size: int,
                         user_id: int, username: str, meta: dict | None = None) -> bool:
        meta = meta or {}
        for attempt in range(10):
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
                if 'locked' in str(e).lower() and attempt < 9:
                    time.sleep(0.25 * (attempt + 1))
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
        # Notify opted-in non-basic users, excluding creator.
        recipients = c.execute(
            '''SELECT username FROM users
               WHERE is_disabled=0
                 AND COALESCE(bounty_alerts, 1)=1
                 AND username != ?
                 AND (is_standard=1 OR is_admin=1 OR username=?)''',
            (username, SUPER_USER)
        ).fetchall()
        for r in recipients:
            self._notify_bounty(r['username'], 'bounty_new', username, bid, description, 0)
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
            self.notify_followers_bounty_fulfilled(claimer, bounty_id, b['description'])
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

        popular = _rows(
            'SELECT u.username, COUNT(f.id) AS follower_count '
            'FROM users u LEFT JOIN user_follows f ON f.followed_user_id=u.id '
            'WHERE u.is_standard=1 OR u.is_admin=1 '
            'GROUP BY u.id ORDER BY follower_count DESC, u.username ASC LIMIT ?', top_n)

        return {
            'holders':       holders,
            'earners':       earners,
            'uploaders':     uploaders,
            'bounty_hunters':bounty_hunters,
            'streaks':       streaks,
            'chatty':        chatty,
            'popular':       popular,
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
        # Keep only the super account itself; wipe all runtime/user-generated data.
        c.execute('DELETE FROM users WHERE username != ?', (actor,))
        c.execute('DELETE FROM torrents')
        c.execute('DELETE FROM comments')
        c.execute('DELETE FROM notifications')
        c.execute('DELETE FROM invite_codes')
        c.execute('DELETE FROM points_ledger')
        c.execute('DELETE FROM bounties')
        c.execute('DELETE FROM bounty_contributions')
        c.execute('DELETE FROM bounty_votes')
        c.execute('DELETE FROM bounty_comments')
        c.execute('DELETE FROM direct_messages')
        c.execute('DELETE FROM dm_blocklist')
        c.execute('DELETE FROM ip_allowlist')
        c.execute('DELETE FROM login_history')
        c.execute('DELETE FROM user_follows')
        c.execute('DELETE FROM account_delete_challenges')
        c.execute('DELETE FROM topup_reconciliation_actions')
        c.execute('DELETE FROM topup_webhook_events')
        c.execute('DELETE FROM topup_orders')
        c.execute('DELETE FROM sessions WHERE user_id NOT IN (SELECT id FROM users)')
        # Reset mutable account state for remaining account(s).
        c.execute(
            '''UPDATE users
               SET is_locked=0,
                   is_disabled=0,
                   failed_attempts=0,
                   last_login=NULL,
                   login_count=0,
                   credits=0,
                   credits_awarded=0,
                   points=0,
                   login_streak=0,
                   longest_streak=0,
                   last_login_date=NULL,
                   comment_pts_date=NULL,
                   comment_pts_today=0,
                   last_seen=NULL'''
        )
        c.execute('DELETE FROM events')
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
        user = self.get_user_by_id(row['user_id'])
        if user is None:
            return None
        # Disabled/locked users must not keep using existing sessions.
        if user['is_disabled'] or user['is_locked']:
            self.delete_session(token)
            return None
        return user

    def has_active_session(self, user_id: int) -> bool:
        """True when user currently has any non-expired session."""
        now = datetime.datetime.now().isoformat(timespec='seconds')
        row = self._conn().execute(
            'SELECT 1 FROM sessions WHERE user_id=? AND expires_at>? LIMIT 1',
            (user_id, now)
        ).fetchone()
        return row is not None

    def delete_session(self, token: str):
        self._conn().execute('DELETE FROM sessions WHERE token=?', (token,))
        self._conn().commit()

    def delete_sessions_for_user(self, user_id: int):
        self._conn().execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
        self._conn().commit()

    def purge_expired_sessions(self):
        now = datetime.datetime.now().isoformat(timespec='seconds')
        self._conn().execute('DELETE FROM sessions WHERE expires_at<=?', (now,))
        self._conn().commit()

    # ── Self-delete challenges ───────────────────────────────

    def expire_account_delete_challenges(self) -> int:
        now = self._ts()
        c = self._conn()
        rows = c.execute(
            "SELECT id,user_id FROM account_delete_challenges "
            "WHERE status='challenged' AND expires_at<=?",
            (now,)
        ).fetchall()
        cur = c.execute(
            "UPDATE account_delete_challenges SET status='expired' "
            "WHERE status='challenged' AND expires_at<=?",
            (now,)
        )
        c.commit()
        for r in rows:
            self._log('system', 'account_delete_expired', str(r['user_id']),
                      f'challenge_id={r[0]}')
        return int(cur.rowcount or 0)

    def get_active_account_delete_challenge(self, user_id: int):
        self.expire_account_delete_challenges()
        now = self._ts()
        return self._conn().execute(
            "SELECT * FROM account_delete_challenges "
            "WHERE user_id=? AND status='challenged' AND expires_at>? "
            "ORDER BY id DESC LIMIT 1",
            (user_id, now)
        ).fetchone()

    def create_account_delete_challenge(self, user_id: int, actor: str,
                                        requested_ip: str, requested_user_agent: str,
                                        ttl_minutes: int = ACCOUNT_DELETE_CHALLENGE_TTL_MINUTES):
        ttl = max(1, min(30, int(ttl_minutes)))
        now_dt = datetime.datetime.now()
        now = now_dt.isoformat(timespec='seconds')
        expires_at = (now_dt + datetime.timedelta(minutes=ttl)).isoformat(timespec='seconds')
        c = self._conn()
        c.execute(
            "UPDATE account_delete_challenges SET status='canceled', canceled_at=? "
            "WHERE user_id=? AND status='challenged'",
            (now, user_id)
        )
        cur = c.execute(
            '''INSERT INTO account_delete_challenges
               (user_id,status,created_at,expires_at,requested_ip,requested_user_agent)
               VALUES (?,?,?,?,?,?)''',
            (user_id, 'challenged', now, expires_at, requested_ip[:64], requested_user_agent[:255])
        )
        c.commit()
        self._log(actor, 'account_delete_challenge_issued', str(user_id),
                  f'expires_at={expires_at} ip={requested_ip[:64]}')
        return c.execute('SELECT * FROM account_delete_challenges WHERE id=?', (cur.lastrowid,)).fetchone()

    def mark_account_delete_attempt(self, challenge_id: int) -> int:
        now = self._ts()
        c = self._conn()
        c.execute(
            'UPDATE account_delete_challenges '
            'SET attempt_count=attempt_count+1,last_attempt_at=? WHERE id=?',
            (now, challenge_id)
        )
        c.commit()
        row = c.execute('SELECT attempt_count FROM account_delete_challenges WHERE id=?', (challenge_id,)).fetchone()
        return int(row['attempt_count']) if row else 0

    def cancel_account_delete_challenge(self, user_id: int, actor: str, detail: str = '') -> bool:
        ch = self.get_active_account_delete_challenge(user_id)
        if not ch:
            return False
        now = self._ts()
        c = self._conn()
        c.execute(
            "UPDATE account_delete_challenges SET status='canceled', canceled_at=? WHERE id=?",
            (now, ch['id'])
        )
        c.commit()
        self._log(actor, 'account_delete_canceled', str(user_id), detail[:255])
        return True

    def self_delete_account(self, user_id: int, actor: str,
                            consumed_ip: str = '', consumed_user_agent: str = '',
                            challenge_id: int | None = None) -> tuple[bool, str]:
        user = self.get_user_by_id(user_id)
        if not user:
            return False, 'Account not found.'
        if user['username'] == SUPER_USER:
            return False, 'Super account cannot self-delete.'
        now = self._ts()
        c = self._conn()
        try:
            c.execute('BEGIN IMMEDIATE')
            if challenge_id:
                c.execute(
                    "UPDATE account_delete_challenges "
                    "SET status='completed',completed_at=?,consumed_ip=?,consumed_user_agent=? "
                    "WHERE id=?",
                    (now, consumed_ip[:64], consumed_user_agent[:255], challenge_id)
                )
            c.execute(
                "UPDATE torrents SET uploaded_by_id=NULL, uploaded_by_username='[deleted]' "
                "WHERE uploaded_by_id=? OR uploaded_by_username=?",
                (user_id, user['username'])
            )
            c.execute(
                'DELETE FROM user_follows WHERE follower_user_id=? OR followed_user_id=?',
                (user_id, user_id)
            )
            c.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            c.execute('DELETE FROM users WHERE id=?', (user_id,))
            c.commit()
        except Exception as e:
            c.rollback()
            return False, f'Account deletion failed: {e}'
        self._log(actor, 'account_deleted_self', user['username'],
                  f'ip={consumed_ip[:64]}')
        return True, 'Account deleted.'

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

    def notify_followed_user_new_follower(self, followed_user_id: int,
                                          follower_user_id: int,
                                          follower_username: str) -> None:
        self.add_notification(
            followed_user_id, 'follow_new_follower', follower_username,
            'FOLLOW:USER', 'started following you', follower_user_id
        )

    def notify_followers_torrent_upload(self, actor_user_id: int,
                                        actor_username: str,
                                        info_hash: str,
                                        torrent_name: str) -> int:
        follower_ids = self.list_follower_user_ids(actor_user_id)
        sent = 0
        for fid in follower_ids:
            if fid == actor_user_id:
                continue
            self.add_notification(
                fid, 'followed_upload', actor_username, info_hash, torrent_name, 0
            )
            sent += 1
        return sent

    def notify_followers_bounty_fulfilled(self, actor_username: str,
                                          bounty_id: int,
                                          description: str) -> int:
        actor = self.get_user(actor_username)
        if not actor:
            return 0
        follower_ids = self.list_follower_user_ids(actor['id'])
        sent = 0
        for fid in follower_ids:
            if fid == actor['id']:
                continue
            self._conn().execute(
                'INSERT INTO notifications (user_id,type,from_username,info_hash,torrent_name,'
                'comment_id,created_at,is_read) VALUES (?,?,?,?,?,?,?,0)',
                (fid, 'followed_bounty_fulfilled', actor_username,
                 f'BOUNTY:{bounty_id}', description[:120], 0, self._ts())
            )
            sent += 1
        if sent:
            self._conn().commit()
        return sent

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

def _fmt_elapsed_compact(start_iso: str, end_iso: str) -> str:
    """Format elapsed wall time as compact d/h/m string."""
    if not start_iso or not end_iso:
        return ''
    try:
        sdt = datetime.datetime.fromisoformat(start_iso)
        edt = datetime.datetime.fromisoformat(end_iso)
        total = int((edt - sdt).total_seconds())
        if total < 0:
            total = 0
        days, rem = divmod(total, 86400)
        hours, rem = divmod(rem, 3600)
        mins, _ = divmod(rem, 60)
        if days > 0:
            return f'{days}d {hours}h {mins}m'
        if hours > 0:
            return f'{hours}h {mins}m'
        return f'{mins}m'
    except Exception:
        return ''

def _bounty_speed_emoji(start_iso: str, end_iso: str) -> str:
    """Gamified speed badge for bounty completion time."""
    if not start_iso or not end_iso:
        return ''
    try:
        sdt = datetime.datetime.fromisoformat(start_iso)
        edt = datetime.datetime.fromisoformat(end_iso)
        total = int((edt - sdt).total_seconds())
        if total < 0:
            total = 0
        if total < 10 * 60:
            return '🚀'
        if total < 60 * 60:
            return '⚡'
        if total < 6 * 60 * 60:
            return '🔥'
        if total < 24 * 60 * 60:
            return '✅'
        return '🏁'
    except Exception:
        return ''

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



# ── In-memory typing presence store ─────────────────────────────────────────
# {thread_key: {'username': str, 'expires': float}}
# thread_key = "dm:{user_a}:{user_b}" (sorted alphabetically)
import threading as _threading
_TYPING_STORE: dict = {}
_TYPING_LOCK  = _threading.Lock()
_ONLINE_MINUTES  = 5   # active within N minutes = online
_RECENT_MINUTES  = 30  # active within N minutes = recently active


def _typing_key(u1: str, u2: str) -> str:
    return 'dm:' + ':'.join(sorted([u1, u2]))


def _set_typing(username: str, other: str) -> None:
    key = _typing_key(username, other)
    with _TYPING_LOCK:
        _TYPING_STORE[key] = {'username': username, 'expires': time.time() + 6}


def _is_typing(username: str, other: str) -> bool:
    """Return True if `username` is currently typing to `other`."""
    key = _typing_key(username, other)
    with _TYPING_LOCK:
        entry = _TYPING_STORE.get(key)
        if not entry:
            return False
        if entry['username'] != username:
            return False
        if time.time() > entry['expires']:
            del _TYPING_STORE[key]
            return False
        return True


def _online_status(user_row) -> str:
    """Return 'online', 'recent', or 'offline'.
    Online requires an active web session; recent/offline are derived from last_seen.
    Returns 'hidden' if user has disabled show_online."""
    if user_row is None:
        return 'offline'
    show = user_row['show_online'] if 'show_online' in user_row.keys() else 1
    if not show:
        return 'hidden'
    try:
        if REGISTRATION_DB and ('id' in user_row.keys()) and REGISTRATION_DB.has_active_session(user_row['id']):
            return 'online'
    except Exception:
        pass
    last = user_row['last_seen'] if 'last_seen' in user_row.keys() else None
    if not last:
        return 'offline'
    try:
        import datetime as _dt
        delta = _dt.datetime.now() - _dt.datetime.fromisoformat(last)
        mins = delta.total_seconds() / 60
        if mins <= _RECENT_MINUTES:
            return 'recent'
        return 'offline'
    except Exception:
        return 'offline'


def _online_dot_html(status: str, label: str = '') -> str:
    """Return a small colored presence dot with optional label."""
    if status == 'hidden':
        return ''
    color = {'online': 'var(--green)', 'recent': 'var(--accent)', 'offline': 'var(--border)'}.get(status, 'var(--border)')
    tip   = {'online': 'Online now', 'recent': 'Recently active', 'offline': 'Offline'}.get(status, '')
    dot   = (f'<span title="{tip}" style="display:inline-block;width:8px;height:8px;'
             f'border-radius:50%;background:{color};margin-right:4px;vertical-align:middle"></span>')
    if label:
        return dot + f'<span style="font-size:0.8rem;color:var(--muted)">{label}</span>'
    return dot

def _online_badge_html(status: str) -> str:
    """Return a compact presence badge for profile headers."""
    if status == 'hidden':
        return ''
    cfg = {
        'online':  ('Online', 'var(--green)', 'rgba(52,211,153,0.15)'),
        'recent':  ('Recently active', 'var(--accent)', 'rgba(245,166,35,0.16)'),
        'offline': ('Offline', 'var(--muted)', 'rgba(138,147,189,0.14)'),
    }
    label, color, bg = cfg.get(status, cfg['offline'])
    return (
        '<span style="display:inline-flex;align-items:center;gap:6px;'
        'padding:3px 9px;border-radius:6px;'
        f'border:1px solid {color};background:{bg};'
        f'color:{color};font-size:0.78rem;">'
        f'<span aria-hidden="true" style="width:7px;height:7px;border-radius:50%;background:{color};display:inline-block"></span>'
        f'{label}</span>'
    )


def _can_view_follow_visibility(viewer, target_user) -> bool:
    """Whether `viewer` can see `target_user` follower/following lists."""
    if viewer is None or target_user is None:
        return False
    if int(viewer['id']) == int(target_user['id']):
        return True
    if viewer['username'] == SUPER_USER or viewer['is_admin']:
        return True
    if 'allow_follow_visibility' not in target_user.keys():
        return True
    return bool(target_user['allow_follow_visibility'])

def _gravatar_enabled() -> bool:
    if not REGISTRATION_DB:
        return False
    return REGISTRATION_DB.get_setting('gravatar_enabled', '0') == '1'

def _gravatar_url(user_row, size: int = 48) -> str:
    if not _gravatar_enabled() or not user_row:
        return ''
    if ('gravatar_opt_in' in user_row.keys()) and (not user_row['gravatar_opt_in']):
        return ''
    gh = (user_row['gravatar_hash'] or '').strip().lower() if 'gravatar_hash' in user_row.keys() else ''
    if not re.fullmatch(r'[a-f0-9]{32}', gh):
        return ''
    return f'https://www.gravatar.com/avatar/{gh}?s={max(16, min(256, int(size)))}&d=identicon&r=g'

def _normalize_gravatar_identity(raw: str) -> tuple[str | None, str | None]:
    """Accept either an email or an MD5 hash; return (hash, error)."""
    text = (raw or '').strip()
    if not text:
        return None, None
    low = text.lower()
    if re.fullmatch(r'[a-f0-9]{32}', low):
        return low, None
    # Keep validation intentionally simple: something@something
    if re.fullmatch(r'[^@\s]+@[^@\s]+', text):
        return hashlib.md5(low.encode('utf-8')).hexdigest(), None
    return None, 'Invalid Gravatar value. Use email (name@domain) or a 32-char MD5 hash.'

def _avatar_html(user_row, size: int = 24) -> str:
    url = _gravatar_url(user_row, size=size)
    radius = '50%'
    if url:
        return (
            f'<img src="{url}" alt="" referrerpolicy="no-referrer" loading="lazy" '
            f'style="width:{size}px;height:{size}px;border-radius:{radius};object-fit:cover;'
            f'border:1px solid var(--border);background:var(--card2)">'
        )
    label = '?'
    if user_row and ('username' in user_row.keys()) and user_row['username']:
        label = _h(user_row['username'][0].upper())
    return (
        f'<span aria-hidden="true" '
        f'style="display:inline-flex;align-items:center;justify-content:center;'
        f'width:{size}px;height:{size}px;border-radius:{radius};border:1px solid var(--border);'
        f'background:var(--card2);color:var(--muted);font-family:var(--mono);'
        f'font-size:{max(10, int(size * 0.45))}px">{label}</span>'
    )

def _fmt_seen_ago(ts: float) -> str:
    """Compact relative time for recent peer activity."""
    try:
        delta = max(0, int(time.time() - float(ts)))
    except Exception:
        return ''
    if delta < 60:
        return 'just now'
    if delta < 3600:
        return f'{delta // 60}m ago'
    if delta < 86400:
        h, rem = divmod(delta, 3600)
        return f'{h}h {rem // 60}m ago'
    d, rem = divmod(delta, 86400)
    return f'{d}d {rem // 3600}h ago'

def _linked_swarm_members(info_hash: str) -> list[dict]:
    """Return uniquely linked active swarm members for a torrent."""
    if not REGISTRATION_DB:
        return []
    try:
        max_age_days = int(REGISTRATION_DB.get_setting('activity_link_max_login_age_days', '30'))
    except Exception:
        max_age_days = 30
    ip_rows = REGISTRY.get_active_ip_last_seen(info_hash.upper())
    by_user: dict[str, dict] = {}
    for ip, last_seen in ip_rows:
        u = REGISTRATION_DB.get_unique_recent_user_for_ip(ip, max_age_days)
        if not u:
            continue
        uname = u['username']
        prev = by_user.get(uname)
        if (not prev) or (last_seen > prev['last_seen']):
            by_user[uname] = {'username': uname, 'last_seen': last_seen, 'ip': ip}
    return sorted(by_user.values(), key=lambda m: m['last_seen'], reverse=True)

def _linked_active_torrents_for_username(username: str) -> list[dict]:
    """Return active registered torrents currently linked to one member."""
    if not REGISTRATION_DB or not username:
        return []
    try:
        max_age_days = int(REGISTRATION_DB.get_setting('activity_link_max_login_age_days', '30'))
    except Exception:
        max_age_days = 30
    ip_user = REGISTRATION_DB.get_recent_unique_ip_user_map(max_age_days)
    if not ip_user:
        return []
    snap = REGISTRY.snapshot_active_ips_by_hash()
    ih_last: dict[str, float] = {}
    for ih, ip_map in snap.items():
        for ip, last_seen in ip_map.items():
            if ip_user.get(ip) == username:
                prev = ih_last.get(ih, 0.0)
                if last_seen > prev:
                    ih_last[ih] = last_seen
                break
    if not ih_last:
        return []
    torrents = REGISTRATION_DB.get_torrents_by_hashes(list(ih_last.keys()))
    out = []
    for t in torrents:
        ih = t['info_hash']
        out.append({
            'info_hash': ih,
            'name': t['name'],
            'last_seen': ih_last.get(ih, 0.0),
        })
    return sorted(out, key=lambda x: x['last_seen'], reverse=True)


def _parse_iso_ts(ts: str) -> datetime.datetime | None:
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(ts)
    except Exception:
        return None


def _peer_refresh_remaining_seconds(torrent_row) -> int:
    """Cooldown based on last successful peer snapshot update."""
    if not torrent_row:
        return 0
    last = torrent_row['peer_last_updated'] if 'peer_last_updated' in torrent_row.keys() else None
    dt = _parse_iso_ts(last or '')
    if not dt:
        return 0
    elapsed = (datetime.datetime.now() - dt).total_seconds()
    return max(0, int(PEER_SCRAPE_MIN_INTERVAL_SECONDS - elapsed))


def _extract_peer_counts_from_query_json(payload: dict, info_hash: str) -> tuple[bool, dict]:
    """
    Return (ok, data).
    On success data: {'seeds': int, 'peers': int, 'downloaded': int|None}.
    """
    if not isinstance(payload, dict):
        return False, {'error': 'Query output was not a JSON object.'}
    torrents = payload.get('torrents')
    if not isinstance(torrents, list) or not torrents:
        return False, {'error': 'No torrent data returned from query output.'}
    ih_lower = info_hash.lower()
    match = None
    for row in torrents:
        if not isinstance(row, dict):
            continue
        row_ih = str(row.get('info_hash', '')).strip().lower()
        if row_ih == ih_lower:
            match = row
            break
    if match is None:
        return False, {'error': 'Query output did not include this torrent hash.'}
    try:
        seeds = int(match.get('complete', 0))
        peers = int(match.get('incomplete', 0))
    except Exception:
        return False, {'error': 'Query output had invalid complete/incomplete values.'}
    try:
        downloaded = int(match['downloaded']) if ('downloaded' in match and match.get('downloaded') is not None) else None
    except Exception:
        downloaded = None
    return True, {'seeds': max(0, seeds), 'peers': max(0, peers), 'downloaded': downloaded}


def _run_peer_query(info_hash: str) -> tuple[bool, dict]:
    """
    Run external tracker query command for one hash.
    Returns (ok, details). Never mutates DB.
    """
    if not REGISTRATION_DB:
        return False, {'error': 'Database unavailable.'}
    cfg = REGISTRATION_DB.get_peer_query_config()
    if not cfg.get('active'):
        return False, {'error': 'Peer query is not enabled/configured.'}
    tracker = cfg['tracker'].strip()
    tool = cfg['tool'].strip()
    args_template = cfg['args'].strip()
    if not (tracker and tool and args_template):
        return False, {'error': 'Peer query settings are incomplete.'}
    if not os.path.exists(tool):
        return False, {'error': f'Query tool not found: {tool}'}
    try:
        arg_tokens = shlex.split(args_template)
    except Exception as e:
        return False, {'error': f'Invalid query arguments: {e}'}
    attempts = max(1, int(cfg.get('retries', 3)))
    wait_sec = max(0, int(cfg.get('retry_wait_sec', 2)))
    last_error = 'Query failed.'
    for attempt in range(1, attempts + 1):
        cmd = [tool] + [tok.replace('{hash}', info_hash.upper()).replace('{tracker}', tracker) for tok in arg_tokens]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except Exception as e:
            last_error = f'Query execution failed: {e}'
            if attempt < attempts and wait_sec > 0:
                time.sleep(wait_sec)
            continue
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or '').strip()
            last_error = 'Query command returned non-zero exit status.'
            if detail:
                last_error += f' {detail[:180]}'
            if attempt < attempts and wait_sec > 0:
                time.sleep(wait_sec)
            continue
        raw = (proc.stdout or '').strip()
        if not raw:
            last_error = 'Query command returned empty output.'
            if attempt < attempts and wait_sec > 0:
                time.sleep(wait_sec)
            continue
        try:
            payload = json.loads(raw)
        except Exception as e:
            last_error = f'Query output was not valid JSON: {e}'
            if attempt < attempts and wait_sec > 0:
                time.sleep(wait_sec)
            continue
        ok_counts, data = _extract_peer_counts_from_query_json(payload, info_hash)
        if ok_counts:
            data['tracker'] = tracker
            return True, data
        last_error = data.get('error', 'No data in query output.')
        if attempt < attempts and wait_sec > 0:
            time.sleep(wait_sec)
    return False, {'error': last_error}


def _enqueue_peer_update(info_hash: str, actor: str = 'system', source: str = 'upload') -> bool:
    """Queue a peer snapshot refresh job for background processing."""
    global PEER_UPDATE_QUEUE
    if PEER_UPDATE_QUEUE is None:
        return False
    try:
        PEER_UPDATE_QUEUE.put_nowait((info_hash.upper(), actor, source))
        return True
    except Exception:
        return False


def _peer_update_worker():
    """Background worker that resolves queued peer snapshot jobs."""
    global PEER_UPDATE_QUEUE
    while True:
        job = PEER_UPDATE_QUEUE.get()
        try:
            if not job:
                continue
            ih, actor, source = job
            ok, details = _run_peer_query(ih)
            if not ok:
                log.debug('PEER queue update failed ih=%s source=%s err=%s',
                          ih, source, details.get('error', 'unknown'))
                continue
            REGISTRATION_DB.update_torrent_peer_snapshot(
                ih,
                details['seeds'],
                details['peers'],
                details.get('downloaded'),
                details.get('tracker', ''),
                actor
            )
            log.debug('PEER queue update success ih=%s source=%s seeds=%s peers=%s',
                      ih, source, details.get('seeds', 0), details.get('peers', 0))
        except Exception:
            log.exception('PEER queue worker unexpected error')
        finally:
            PEER_UPDATE_QUEUE.task_done()


def _start_peer_update_worker():
    """Initialize queue + one daemon worker for async peer updates."""
    global PEER_UPDATE_QUEUE
    if PEER_UPDATE_QUEUE is not None:
        return
    PEER_UPDATE_QUEUE = queue.Queue()
    t = threading.Thread(target=_peer_update_worker, daemon=True, name='peer-update-worker')
    t.start()
    log.info('Peer update background worker started')

def _render_profile_sharing_card(target_user) -> str:
    """Full-width profile card listing torrents currently shared by this member."""
    if not target_user:
        return ''
    if ('link_torrent_activity' in target_user.keys()) and (not target_user['link_torrent_activity']):
        return ''
    username = target_user['username']
    active = _linked_active_torrents_for_username(username)
    if not active:
        return ''
    rows = ''.join(
        '<tr>'
        f'<td><a href="/manage/torrent/{_h(t["info_hash"]).lower()}" class="user-link">{_h(t["name"])}</a></td>'
        f'<td class="hash">{_h(_fmt_seen_ago(t["last_seen"]))}</td>'
        '</tr>'
        for t in active
    )
    return (
        '<div class="card">'
        f'<div class="card-title">Currently sharing {len(active)} torrent{"s" if len(active) != 1 else ""}</div>'
        '<div class="table-wrap"><table class="torrent-table"><thead><tr>'
        '<th scope="col">Torrent</th>'
        '<th scope="col" style="width:180px">Last Activity</th>'
        '</tr></thead><tbody>'
        + rows +
        '</tbody></table></div>'
        '</div>'
    )


class ManageHandler(BaseHTTPRequestHandler):
    """Handles all /manage/* routes."""
    def _is_https(self) -> bool:
        return isinstance(self.connection, ssl.SSLSocket)

    def _redirect(self, location: str, code: int = 303):
        self.send_response(code)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _redirect_with_session(self, location: str, session_token: str, code: int = 303):
        """Redirect while refreshing auth cookies for a newly created session."""
        self.send_response(code)
        self._set_session_cookie(session_token)
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

    def _send_json(self, data: dict, code: int = 200):
        import json as _json
        body = _json.dumps(data).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
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
                # Update last_seen for online presence — lightweight, fire-and-forget
                if REGISTRATION_DB:
                    REGISTRATION_DB.update_last_seen(user['id'])
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
            # Lax allows top-level return navigations from payment providers.
            f'wksession={token}; Path=/; HttpOnly; SameSite=Lax; '
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

    def _drain_request_body(self, length: int) -> None:
        """Consume and discard request body bytes to keep the connection stable."""
        remaining = max(0, int(length))
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    def _get_upload_limits(self) -> tuple[int, int, int]:
        """Return (max_content_mb, max_files, max_file_mb) from settings with safe bounds."""
        def _as_int(key: str, default: str, lo: int, hi: int) -> int:
            try:
                v = int(REGISTRATION_DB.get_setting(key, default))
            except Exception:
                v = int(default)
            return max(lo, min(hi, v))
        max_content_mb = _as_int('upload_max_content_mb', '100', 1, 2048)
        max_files      = _as_int('upload_max_files', '1000', 1, 50000)
        max_file_mb    = _as_int('upload_max_file_mb', '10', 1, 1024)
        return max_content_mb, max_files, max_file_mb

    def log_message(self, fmt, *args):
        log.debug('MANAGE %s %s', self.address_string(), fmt % args)

    # ── Routing ──────────────────────────────────────────────

    def do_GET(self):
        if not self._require_https():
            return
        path = urllib.parse.urlparse(self.path).path.rstrip('/')

        if path in ('/manage', ''):
            user = self._get_session_user()
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            msg = urllib.parse.unquote(qs.get('msg', [''])[0])
            msg_type = qs.get('msg_type', ['error'])[0]
            if user:
                self._redirect('/manage/dashboard')
            else:
                self._send_html(_render_login(msg, msg_type=msg_type))
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
        elif path.startswith('/manage/user/') and path.endswith('/following'):
            username = path[len('/manage/user/'):-len('/following')].strip('/')
            self._get_user_following(username)
        elif path.startswith('/manage/user/'):
            self._get_public_profile(path[len('/manage/user/'):])
        elif path == '/manage/profile':
            self._get_profile()
        elif path == '/manage/account/delete/confirm':
            self._get_account_delete_confirm()
        elif path == '/manage/goodbye':
            self._send_html(_render_goodbye_page())
        elif path == '/manage/following':
            self._get_following()
        elif path == '/robots.txt':
            self._serve_robots()
        elif path == '/manage/search':
            self._get_search()
        elif path == '/manage/notifications':
            self._get_notifications()
        elif path == '/manage/notifications/preview':
            self._get_notifications_preview()
        elif path == '/manage/poll':
            self._get_global_poll()
        elif path == '/manage/messages':
            self._get_messages()
        elif path == '/manage/messages/poll':
            self._get_dm_poll()
        elif path.startswith('/manage/messages/'):
            self._get_message_thread(path[len('/manage/messages/'):])
        elif path == '/manage/bounty':
            self._get_bounty_board()
        elif path == '/manage/leaderboard':
            self._get_leaderboard()
        elif path == '/manage/topups':
            self._get_topups()
        elif path == '/manage/upload':
            self._redirect('/manage/dashboard')
        elif path == '/manage/topups/paypal/return':
            self._get_topups_paypal_return()
        elif path == '/manage/topups/paypal/cancel':
            self._get_topups_paypal_cancel()
        elif path.startswith('/manage/bounty/'):
            bid_str = path[len('/manage/bounty/'):]
            if bid_str.isdigit():
                self._get_bounty_detail(int(bid_str))
            else:
                self._send_html('<h1>Not Found</h1>', 404)
        elif path.startswith('/manage/torrent/lock/'):
            ih = path[len('/manage/torrent/lock/'):]
            self._redirect(f'/manage/torrent/{ih}')
        elif path.startswith('/manage/torrent/unlock/'):
            ih = path[len('/manage/torrent/unlock/'):]
            self._redirect(f'/manage/torrent/{ih}')
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
        if path == '/coinbase/webhook':
            self._post_coinbase_webhook()
            return
        if path == '/paypal/webhook':
            self._post_paypal_webhook()
            return

        # Upload body-size guard before CSRF parsing to avoid loading huge bodies into RAM.
        if path == '/manage/upload':
            max_content_mb, _, _ = self._get_upload_limits()
            max_content_bytes = max_content_mb * 1024 * 1024
            try:
                content_len = int(self.headers.get('Content-Length', '0'))
            except Exception:
                content_len = 0
            if content_len > max_content_bytes:
                # Keep UX consistent: show a normal dashboard error instead of a raw 413 page.
                # Drain the oversized body so clients do not see connection-reset errors.
                self._drain_request_body(content_len)
                user = self._get_session_user()
                if not user:
                    self._redirect('/manage')
                    return
                torrents = REGISTRATION_DB.list_torrents(user_id=user['id'])
                self._send_html(
                    _render_dashboard(
                        user,
                        torrents,
                        (f'Upload rejected: request size is over the configured '
                         f'limit ({max_content_mb} MB).'),
                        'error'
                    )
                )
                return

        # ── CSRF validation ──────────────────────────────
        # Login and signup have no session yet; everything else must carry
        # the CSRF token derived from whichever session token the browser used.
        # Browsers can hold multiple wksession cookies (stale + current); we try
        # all candidates so the valid one matches regardless of order.
        _no_csrf = ('/manage/login', '/manage/signup', '/manage', '/manage/messages/typing', '/coinbase/webhook', '/paypal/webhook')
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
        elif path == '/manage/account/delete/start':
            self._post_account_delete_start()
        elif path == '/manage/account/delete/confirm':
            self._post_account_delete_confirm()
        elif path == '/manage/account/delete/cancel':
            self._post_account_delete_cancel()
        elif path == '/manage/upload':
            self._post_upload()
        elif path == '/manage/delete-torrent':
            self._post_delete_torrent()
        elif path == '/manage/torrent/lock':
            self._post_toggle_comments_lock(True)
        elif path == '/manage/torrent/unlock':
            self._post_toggle_comments_lock(False)
        elif path == '/manage/torrent/update-peers':
            self._post_torrent_update_peers()
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
        elif path == '/manage/messages/typing':
            self._post_dm_typing()
        elif path == '/manage/messages/send':
            self._post_dm_send()
        elif path == '/manage/messages/reply':
            self._post_dm_reply()
        elif path == '/manage/messages/delete':
            self._post_dm_delete()
        elif path == '/manage/messages/delete-conversation':
            self._post_dm_delete_conversation()
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
        elif path == '/manage/follow':
            self._post_follow()
        elif path == '/manage/unfollow':
            self._post_unfollow()
        elif path == '/manage/topup/create':
            self._post_topup_create()
        elif path == '/manage/admin/topup/reconcile':
            self._post_topup_reconcile()
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
        client_ip = self.client_address[0]
        log.debug('LOGIN attempt user=%r ip=%s', username, client_ip)
        user = REGISTRATION_DB.authenticate(username, password)
        if user is None:
            log.debug('LOGIN failed user=%r', username)
            REGISTRATION_DB._log(username or '(unknown)', 'login_failed',
                                 client_ip)
            self._send_html(_render_login('Invalid credentials.'))
            return
        if not REGISTRATION_DB.is_ip_allowed(user['id'], client_ip):
            log.warning('LOGIN blocked by IP allowlist user=%r ip=%s', username, client_ip)
            REGISTRATION_DB._log(username, 'login_ip_blocked', client_ip)
            self._send_html(_render_login('Invalid credentials.'))
            return
        token = REGISTRATION_DB.create_session(user['id'])
        REGISTRATION_DB.record_login_ip(user['id'], client_ip)
        REGISTRATION_DB.daily_login_check(user['id'])
        REGISTRATION_DB._log(username, 'login', client_ip)
        delete_challenge = REGISTRATION_DB.get_active_account_delete_challenge(user['id'])
        login_redirect = '/manage/account/delete/confirm' if delete_challenge else '/manage/dashboard'
        log.debug('LOGIN success user=%r token=%s...', username, token[:8])
        self.send_response(303)
        try:
            self._set_session_cookie(token)
        except Exception as exc:
            log.error('LOGIN _set_session_cookie failed: %s', exc, exc_info=True)
            raise
        self.send_header('Location', login_redirect)
        self.send_header('Content-Length', '0')
        self.end_headers()
        log.debug('LOGIN 303 sent for user=%r location=%s', username, login_redirect)

    def _post_upload(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        max_content_mb, max_files, max_file_mb = self._get_upload_limits()
        max_file_bytes = max_file_mb * 1024 * 1024
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
        added = []
        added_with_hash = []
        skipped_duplicate = 0
        skipped_too_large = 0
        skipped_invalid   = 0
        skipped_over_max_files = 0
        skipped_db_locked = 0
        for idx, (fname, file_data) in enumerate(file_list):
            if idx >= max_files:
                skipped_over_max_files += 1
                continue
            if len(file_data) > max_file_bytes:
                skipped_too_large += 1
                continue
            try:
                ih, name, total_size, meta = parse_torrent(file_data)
            except Exception:
                skipped_invalid += 1
                continue
            try:
                ok = REGISTRATION_DB.register_torrent(ih, name, total_size, user['id'], user['username'], meta=meta)
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    skipped_db_locked += 1
                    log.warning('UPLOAD register skipped due DB lock ih=%s user=%s', ih, user['username'])
                    continue
                raise
            if ok:
                log.info('REGISTRATION torrent registered  ih=%s  name=%s  by=%s', ih, name, user['username'])
                REGISTRATION_DB.award_upload_points(user['id'], name, ih)
                REGISTRATION_DB.check_auto_promote(user['id'])
                added.append(name)
                added_with_hash.append((ih, name))
            else:
                skipped_duplicate += 1
        auto_peer_queued = 0
        auto_peer_not_queued = 0
        peer_cfg = REGISTRATION_DB.get_peer_query_config()
        if added_with_hash and peer_cfg.get('active') and peer_cfg.get('auto_on_upload'):
            cap = max(1, int(peer_cfg.get('auto_upload_cap', 5)))
            for ih, tname in added_with_hash[:cap]:
                if _enqueue_peer_update(ih, user['username'], 'upload'):
                    auto_peer_queued += 1
                else:
                    auto_peer_not_queued += 1
                    log.debug('UPLOAD auto peer queue failed ih=%s', ih)
        follower_notifs = 0
        for ih, tname in added_with_hash:
            follower_notifs += REGISTRATION_DB.notify_followers_torrent_upload(
                user['id'], user['username'], ih, tname
            )
        parts = []
        if added:
            parts.append(f'{len(added)} registered')
        if skipped_duplicate:
            parts.append(f'{skipped_duplicate} duplicates skipped')
        if skipped_too_large:
            parts.append(f'{skipped_too_large} skipped (file > {max_file_mb} MB)')
        if skipped_invalid:
            parts.append(f'{skipped_invalid} invalid torrent files skipped')
        if skipped_over_max_files:
            parts.append(f'{skipped_over_max_files} skipped (max files per upload is {max_files})')
        if skipped_db_locked:
            parts.append(f'{skipped_db_locked} skipped (temporary database lock)')
        if auto_peer_queued:
            parts.append(f'{auto_peer_queued} peer snapshots queued')
        over_cap = max(0, len(added_with_hash) - max(1, int(peer_cfg.get('auto_upload_cap', 5)))) if (added_with_hash and peer_cfg.get('active') and peer_cfg.get('auto_on_upload')) else 0
        if over_cap:
            parts.append(f'{over_cap} peer snapshots deferred (cap)')
        if auto_peer_not_queued:
            parts.append(f'{auto_peer_not_queued} peer snapshots queue failed')
        # Include a short preview of registered torrent names when practical.
        if added:
            preview = ', '.join(added[:8])
            if len(added) > 8:
                preview += ', ...'
            parts.append(f'registered: {preview}')
        msg = ' | '.join(parts) if parts else 'No files processed.'
        msg_type = 'success' if added else 'error'
        log.debug('UPLOAD result msg=%r msg_type=%r added=%d skipped=%d errors=%d',
                  msg[:80], msg_type, len(added),
                  skipped_duplicate + skipped_too_large + skipped_invalid + skipped_over_max_files,
                  skipped_invalid)
        if follower_notifs:
            log.debug('UPLOAD follower notifications sent=%d uploader=%s', follower_notifs, user['username'])
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
        raw_status = qs.get('status', [None])[0]
        if raw_status is None:
            filt = 'open'
        elif raw_status in ('', 'all'):
            filt = 'all'
        elif raw_status in ('open', 'pending', 'fulfilled', 'expired'):
            filt = raw_status
        else:
            filt = 'open'
        page = max(1, int(qs.get('page', ['1'])[0]) if qs.get('page', ['1'])[0].isdigit() else 1)
        per_page = 20
        status_filter = None if filt == 'all' else filt
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
                ih = str(n['info_hash'] or '')
                ih_up = ih.upper()
                if ih_up.startswith('TOPUP:'):
                    return self._redirect('/manage/topups')
                if ih_up.startswith('FOLLOW:'):
                    if int(n['comment_id'] or 0) > 0:
                        follower = REGISTRATION_DB.get_user_by_id(int(n['comment_id']))
                        if follower:
                            return self._redirect(f'/manage/user/{urllib.parse.quote(follower["username"])}')
                    return self._redirect('/manage/following')
                if ih_up.startswith('BOUNTY:'):
                    bid = ih.split(':', 1)[1] if ':' in ih else ''
                    if bid.isdigit():
                        return self._redirect(f'/manage/bounty/{bid}')
                    return self._redirect('/manage/bounty')
                anchor = f'#comment-{n["comment_id"]}' if int(n['comment_id'] or 0) > 0 else ''
                return self._redirect(f'/manage/torrent/{ih.lower()}{anchor}')
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

    def _post_toggle_comments_lock(self, lock: bool):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        ih = fields.get('info_hash', '').strip().upper()
        if not ih:
            return self._redirect('/manage/dashboard')
        if _user_role(user) not in ('super', 'admin'):
            return self._redirect(f'/manage/torrent/{ih.lower()}')
        t = REGISTRATION_DB.get_torrent(ih.upper())
        if not t: return self._redirect('/manage/dashboard')
        REGISTRATION_DB.set_comments_locked(ih, lock, user['username'])
        self._redirect(f'/manage/torrent/{ih.lower()}')

    def _post_torrent_update_peers(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        ih = fields.get('info_hash', '').strip().upper()
        if not ih:
            return self._redirect('/manage/dashboard')
        t = REGISTRATION_DB.get_torrent(ih)
        if not t:
            return self._redirect('/manage/dashboard')
        cfg = REGISTRATION_DB.get_peer_query_config()
        if not cfg.get('active'):
            q = urllib.parse.quote('Peer query is disabled or not fully configured.')
            return self._redirect(f'/manage/torrent/{ih.lower()}?msg={q}&msg_type=error')
        rem = _peer_refresh_remaining_seconds(t)
        if rem > 0:
            h = rem // 3600
            m = (rem % 3600) // 60
            q = urllib.parse.quote(f'Peer stats can be refreshed again in {h}h {m}m.')
            return self._redirect(f'/manage/torrent/{ih.lower()}?msg={q}&msg_type=error')
        ok, details = _run_peer_query(ih)
        if not ok:
            q = urllib.parse.quote('Peer stats update failed: ' + details.get('error', 'unknown error'))
            return self._redirect(f'/manage/torrent/{ih.lower()}?msg={q}&msg_type=error')
        REGISTRATION_DB.update_torrent_peer_snapshot(
            ih,
            details['seeds'],
            details['peers'],
            details.get('downloaded'),
            details.get('tracker', cfg.get('tracker', '')),
            user['username']
        )
        q = urllib.parse.quote(f'Peer stats updated: seeds={details["seeds"]}, peers={details["peers"]}.')
        return self._redirect(f'/manage/torrent/{ih.lower()}?msg={q}&msg_type=success')

    def _get_torrent_detail(self, ih: str):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        t = REGISTRATION_DB.get_torrent(ih.upper())
        if not t: return self._send_html('<h1>Torrent not found</h1>', 404)
        referer = self.headers.get('Referer', '')
        back = urllib.parse.urlparse(referer).path or '/manage/dashboard'
        if back.startswith('/manage/torrent'): back = '/manage/dashboard'
        if back == '/manage/upload': back = '/manage/dashboard'
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
        current_token = getattr(self, '_valid_token', '') or self._get_session_token()
        REGISTRATION_DB.change_password(
            user['username'], new, user['username'], keep_session_token=current_token
        )
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
        self._redirect('/manage/admin?tab=users')

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
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg      = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        self._send_html(_render_public_profile(viewer, target, torrents,
                                               page=page, total_pages=total_pages, total=total,
                                               msg=msg, msg_type=msg_type))

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
        topup_orders = REGISTRATION_DB.list_topup_orders(user_id=user['id'], limit=100)
        bounty_data = REGISTRATION_DB.list_bounties_by_user(user['username'])
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg      = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        self._send_html(_render_user_detail(user, user, torrents, history, is_super,
                                            allowlist=allowlist, is_own_profile=True,
                                            page=page, total_pages=total_pages,
                                            total=total, base_url='/manage/profile',
                                            ledger=ledger, bounty_data=bounty_data, topup_orders=topup_orders,
                                            msg=msg, msg_type=msg_type))

    def _get_account_delete_confirm(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        ch = REGISTRATION_DB.get_active_account_delete_challenge(user['id'])
        if not ch:
            q = urllib.parse.quote_plus('No active account deletion request. Start from your profile.')
            return self._redirect(f'/manage/profile?msg={q}&msg_type=error')
        expires_dt = _parse_iso_ts(ch['expires_at'] or '')
        remaining_sec = 0
        if expires_dt:
            remaining_sec = max(0, int((expires_dt - datetime.datetime.now()).total_seconds()))
        msg = urllib.parse.unquote(urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get('msg', [''])[0])
        msg_type = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get('msg_type', ['error'])[0]
        self._send_html(_render_account_delete_confirm_page(user, remaining_sec, msg=msg, msg_type=msg_type))

    def _post_account_delete_start(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        if user['username'] == SUPER_USER:
            return self._redirect('/manage/profile?msg=Super+account+cannot+self-delete.&msg_type=error')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        phrase = (fields.get('delete_phrase', '') or '').strip()
        if phrase != 'DELETE MY ACCOUNT':
            return self._redirect('/manage/profile?msg=Type+DELETE+MY+ACCOUNT+to+continue.&msg_type=error')
        challenge = REGISTRATION_DB.create_account_delete_challenge(
            user['id'],
            user['username'],
            self.client_address[0] if self.client_address else '',
            self.headers.get('User-Agent', '')
        )
        REGISTRATION_DB.delete_sessions_for_user(user['id'])
        REGISTRATION_DB._log(user['username'], 'account_delete_start', user['username'],
                             f'challenge_id={challenge["id"] if challenge else "?"}')
        self.send_response(303)
        self._clear_session_cookie()
        msg = urllib.parse.quote_plus(
            f'Account deletion started. Sign in again and complete within {ACCOUNT_DELETE_CHALLENGE_TTL_MINUTES} minutes.'
        )
        self.send_header('Location', f'/manage?msg={msg}&msg_type=success')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _post_account_delete_cancel(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        REGISTRATION_DB.cancel_account_delete_challenge(user['id'], user['username'], 'User canceled from confirm page')
        self._redirect('/manage/profile?msg=Account+deletion+canceled.&msg_type=success')

    def _post_account_delete_confirm(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        ch = REGISTRATION_DB.get_active_account_delete_challenge(user['id'])
        if not ch:
            q = urllib.parse.quote_plus('Deletion window expired. Start again from your profile.')
            return self._redirect(f'/manage/profile?msg={q}&msg_type=error')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        phrase = (fields.get('delete_phrase', '') or '').strip()
        password = fields.get('password', '')
        if phrase != 'DELETE MY ACCOUNT' or not _verify_password(password, user['password_hash'], user['salt']):
            attempts = REGISTRATION_DB.mark_account_delete_attempt(ch['id'])
            REGISTRATION_DB._log(user['username'], 'account_delete_confirm_failed', user['username'],
                                 f'challenge_id={ch["id"]} attempts={attempts}')
            if attempts >= 5:
                REGISTRATION_DB.cancel_account_delete_challenge(
                    user['id'], user['username'],
                    'Too many failed account deletion confirmation attempts'
                )
                self.send_response(303)
                self._clear_session_cookie()
                q = urllib.parse.quote_plus('Deletion confirmation canceled after too many failed attempts.')
                self.send_header('Location', f'/manage?msg={q}&msg_type=error')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            q = urllib.parse.quote_plus('Password or deletion phrase was incorrect.')
            return self._redirect(f'/manage/account/delete/confirm?msg={q}&msg_type=error')
        ok, detail = REGISTRATION_DB.self_delete_account(
            user['id'],
            user['username'],
            consumed_ip=self.client_address[0] if self.client_address else '',
            consumed_user_agent=self.headers.get('User-Agent', ''),
            challenge_id=ch['id']
        )
        if not ok:
            q = urllib.parse.quote_plus(detail)
            return self._redirect(f'/manage/account/delete/confirm?msg={q}&msg_type=error')
        self.send_response(303)
        self._clear_session_cookie()
        self.send_header('Location', '/manage/goodbye')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _get_following(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        followers = REGISTRATION_DB.list_followers(user['id'], limit=500)
        following = REGISTRATION_DB.list_following(user['id'], limit=500)
        viewer_following_ids = set(int(r['id']) for r in following)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        self._send_html(_render_following_page(
            user, user, followers, following,
            base_path='/manage/following',
            viewer_following_ids=viewer_following_ids,
            msg=msg, msg_type=msg_type
        ))

    def _get_user_following(self, username: str):
        viewer = self._get_session_user()
        if not viewer:
            return self._redirect('/manage')
        if _user_role(viewer) == 'basic':
            return self._redirect('/manage/dashboard')
        target = REGISTRATION_DB.get_user(username)
        if not target:
            return self._redirect('/manage/dashboard')
        if not _can_view_follow_visibility(viewer, target):
            q = urllib.parse.quote_plus('This member has hidden follower visibility.')
            return self._redirect(f'/manage/user/{urllib.parse.quote(target["username"])}?msg={q}&msg_type=error')
        followers = REGISTRATION_DB.list_followers(target['id'], limit=500)
        following = REGISTRATION_DB.list_following(target['id'], limit=500)
        viewer_following = REGISTRATION_DB.list_following(viewer['id'], limit=500)
        viewer_following_ids = set(int(r['id']) for r in viewer_following)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        base_path = f'/manage/user/{urllib.parse.quote(target["username"])}/following'
        self._send_html(_render_following_page(
            viewer, target, followers, following,
            base_path=base_path,
            viewer_following_ids=viewer_following_ids,
            msg=msg, msg_type=msg_type
        ))

    def _get_topups(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        if not REGISTRATION_DB.topup_enabled_for_user(user):
            return self._redirect('/manage/profile?msg=Top-ups+are+not+enabled+for+your+account.&msg_type=error')
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        msg = urllib.parse.unquote(qs.get('msg', [''])[0])
        msg_type = qs.get('msg_type', ['error'])[0]
        orders = REGISTRATION_DB.list_topup_orders(user_id=user['id'], limit=200)
        cfg = REGISTRATION_DB.get_topup_config()
        self._send_html(_render_topups_page(user, orders, cfg, msg=msg, msg_type=msg_type))

    def _build_manage_base_url(self) -> str:
        host = self.headers.get('Host', '').strip()
        if not host:
            host = 'localhost'
            if _MANAGE_HTTPS_PORT and _MANAGE_HTTPS_PORT != 443:
                host += f':{_MANAGE_HTTPS_PORT}'
        return f'https://{host}'

    def _get_topups_paypal_return(self):
        try:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            token = (qs.get('token', [''])[0] or '').strip()
            payer_id = (qs.get('PayerID', [''])[0] or '').strip()
            log.debug('PAYPAL return start token=%s payer_id=%s remote_ip=%s',
                      token[:24], payer_id[:24], self.client_address[0] if self.client_address else '?')
            if not token:
                return self._redirect('/manage/topups?msg=Missing+PayPal+token.&msg_type=error')
            order = REGISTRATION_DB.get_topup_order_by_provider_checkout_id(token)
            if not order:
                log.warning('PAYPAL return unknown_token token=%s', token[:24])
                return self._redirect('/manage/topups?msg=Top-up+order+not+found+for+PayPal+token.&msg_type=error')
            user = self._get_session_user()
            log.debug('PAYPAL return linked order_id=%s order_uuid=%s order_user_id=%s order_status=%s session_user=%s',
                      order['id'], str(order['order_uuid'])[:12], order['user_id'], order['status'],
                      user['username'] if user else '(none)')
            if user and int(order['user_id']) != int(user['id']) and not (user['is_admin'] or user['username'] == SUPER_USER):
                log.warning('PAYPAL return unauthorized order_id=%s session_user=%s', order['id'], user['username'])
                return self._redirect('/manage/topups?msg=Unauthorized+PayPal+return+context.&msg_type=error')
            # Build redirect path first; we may need to recreate the owner's session
            # when browser policy or provider flow drops auth cookies on return.
            def _return_to_topups(message: str, msg_type: str = 'success'):
                location = '/manage/topups?msg=' + urllib.parse.quote(message) + f'&msg_type={msg_type}'
                if user:
                    return self._redirect(location)
                owner = REGISTRATION_DB.get_user_by_id(order['user_id'])
                if owner and not owner['disabled']:
                    new_token = REGISTRATION_DB.create_session(owner['id'])
                    return self._redirect_with_session(location, new_token)
                return self._redirect('/manage')

            if order['status'] == 'credited':
                log.debug('PAYPAL return already_credited order_id=%s', order['id'])
                return _return_to_topups('Order already credited.')
            actor = user['username'] if user else 'paypal_return'
            ok, info = REGISTRATION_DB.capture_paypal_order(order['id'], actor=actor)
            if not ok:
                detail = info.get('message') or info.get('error') or 'PayPal capture failed'
                log.warning('PAYPAL return capture_failed order_id=%s token=%s detail=%r',
                            order['id'], token[:24], detail[:180] if isinstance(detail, str) else detail)
                q = urllib.parse.quote('PayPal return received but capture did not complete: ' + detail)
                return self._redirect(f'/manage/topups?msg={q}&msg_type=error')
            msg = 'PayPal payment has been confirmed.'
            if payer_id:
                msg += f' PayerID: {payer_id}'
            log.debug('PAYPAL return success order_id=%s token=%s payer_id=%s', order['id'], token[:24], payer_id[:24])
            return _return_to_topups(msg)
        except Exception as e:
            log.exception('PAYPAL return handler failed token=%r: %s', self.path, e)
            return self._redirect('/manage/topups?msg=PayPal+return+processing+failed.+Please+check+Top-up+Orders.&msg_type=error')

    def _get_topups_paypal_cancel(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        token = (qs.get('token', [''])[0] or '').strip()
        if token:
            order = REGISTRATION_DB.get_topup_order_by_provider_checkout_id(token)
            if order and int(order['user_id']) == int(user['id']) and order['status'] in ('created', 'pending'):
                REGISTRATION_DB.update_topup_status(order['id'], 'pending', actor=user['username'],
                                                    reason='user_cancelled_checkout',
                                                    detail='User cancelled PayPal checkout; can retry Pay Now link')
        return self._redirect('/manage/topups?msg=PayPal+checkout+was+cancelled.&msg_type=error')

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
        elif form_id == 'upload_limits':
            for key, default, lo, hi in [
                ('upload_max_content_mb', '100', 1, 2048),
                ('upload_max_files',      '1000', 1, 50000),
                ('upload_max_file_mb',    '10',  1, 1024),
            ]:
                try:
                    v = str(max(lo, min(hi, int(fields.get(key, default)))))
                except Exception:
                    v = default
                REGISTRATION_DB.set_setting(key, v, user['username'])
        elif form_id == 'peer_query_settings':
            enabled = '1' if fields.get('peer_query_enabled') == '1' else '0'
            tracker = fields.get('peer_query_tracker', '').strip()
            tool = fields.get('peer_query_tool', '').strip()
            args = fields.get('peer_query_args', '').strip()
            auto_on_upload = '1' if fields.get('peer_query_auto_on_upload') == '1' else '0'
            try:
                retries = str(max(1, min(10, int(fields.get('peer_query_retries', '3')))))
            except Exception:
                retries = '3'
            try:
                retry_wait = str(max(0, min(30, int(fields.get('peer_query_retry_wait_sec', '2')))))
            except Exception:
                retry_wait = '2'
            try:
                auto_cap = str(max(1, min(50, int(fields.get('peer_query_auto_upload_cap', '5')))))
            except Exception:
                auto_cap = '5'
            if tool and not os.path.exists(tool):
                q = urllib.parse.quote_plus(f'Peer query tool not found: {tool}')
                return self._redirect(f'/manage/admin?tab=trackers&msg={q}&msg_type=error')
            if enabled == '1':
                if not (tracker and tool and args):
                    return self._redirect('/manage/admin?tab=trackers&msg=Fill+all+peer+query+fields+before+enabling.&msg_type=error')
                if ('{hash}' not in args) or ('{tracker}' not in args):
                    return self._redirect('/manage/admin?tab=trackers&msg=Query+arguments+must+contain+%7Bhash%7D+and+%7Btracker%7D.&msg_type=error')
                if 'json' not in args.lower():
                    return self._redirect('/manage/admin?tab=trackers&msg=Query+arguments+must+request+JSON+output.&msg_type=error')
            REGISTRATION_DB.set_setting('peer_query_enabled', enabled, user['username'])
            REGISTRATION_DB.set_setting('peer_query_tracker', tracker, user['username'])
            REGISTRATION_DB.set_setting('peer_query_tool', tool, user['username'])
            REGISTRATION_DB.set_setting('peer_query_args', args, user['username'])
            REGISTRATION_DB.set_setting('peer_query_retries', retries, user['username'])
            REGISTRATION_DB.set_setting('peer_query_retry_wait_sec', retry_wait, user['username'])
            REGISTRATION_DB.set_setting('peer_query_auto_on_upload', auto_on_upload, user['username'])
            REGISTRATION_DB.set_setting('peer_query_auto_upload_cap', auto_cap, user['username'])
            return self._redirect('/manage/admin?tab=trackers&msg=Peer+query+settings+saved&msg_type=success')
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
        elif form_id == 'gravatar_settings':
            val = '1' if fields.get('gravatar_enabled') == '1' else '0'
            REGISTRATION_DB.set_setting('gravatar_enabled', val, user['username'])
        elif form_id == 'topup_settings':
            # PayPal webhook verification policy:
            # enforce=1 -> fail closed and require active env webhook ID when PayPal enabled
            # enforce=0 -> allow open mode (insecure), still logs warnings on each webhook
            _pp_enabled = fields.get('topup_paypal_enabled', '')
            if _pp_enabled not in ('0', '1'):
                _pp_enabled = '0'
            _pp_enforce = fields.get('topup_paypal_webhook_enforce', '')
            if _pp_enforce not in ('0', '1'):
                _pp_enforce = '1'
            _pp_env = fields.get('topup_paypal_env', 'sandbox')
            if _pp_env not in ('sandbox', 'live'):
                _pp_env = 'sandbox'
            _pp_wh_sbx = fields.get('topup_paypal_webhook_id_sandbox', '')[:500]
            _pp_wh_live = fields.get('topup_paypal_webhook_id_live', '')[:500]
            if _pp_enabled == '1' and _pp_enforce == '1':
                _active_wh = _pp_wh_sbx if _pp_env == 'sandbox' else _pp_wh_live
                if not (_active_wh or '').strip():
                    log.warning('TOPUP settings rejected: paypal enabled without webhook id env=%s actor=%s',
                                _pp_env, user['username'])
                    return self._redirect('/manage/admin?tab=topups&msg=PayPal+webhook+ID+is+required+for+the+active+environment+when+PayPal+is+enabled.&msg_type=error')

            enabled = '1' if fields.get('topup_enabled') == '1' else '0'
            REGISTRATION_DB.set_setting('topup_enabled', enabled, user['username'])
            rollout = fields.get('topup_rollout_mode', 'admin_only')
            if rollout not in ('admin_only', 'all_users'):
                rollout = 'admin_only'
            REGISTRATION_DB.set_setting('topup_rollout_mode', rollout, user['username'])
            provider = fields.get('topup_provider', 'coinbase') or 'coinbase'
            if provider not in ('coinbase', 'paypal'):
                provider = 'coinbase'
            coinbase_enabled = fields.get('topup_coinbase_enabled', '')
            if coinbase_enabled not in ('0', '1'):
                coinbase_enabled = '1'
            REGISTRATION_DB.set_setting('topup_coinbase_enabled', coinbase_enabled, user['username'])
            REGISTRATION_DB.set_setting('topup_provider', provider[:32], user['username'])
            env = fields.get('topup_coinbase_env', 'sandbox')
            if env not in ('sandbox', 'live'):
                env = 'sandbox'
            REGISTRATION_DB.set_setting('topup_coinbase_env', env, user['username'])
            cb_key_sandbox = fields.get('topup_coinbase_api_key_sandbox', '')[:500]
            cb_key_live = fields.get('topup_coinbase_api_key_live', '')[:500]
            cb_secret_sandbox = fields.get('topup_coinbase_webhook_secret_sandbox', '')[:500]
            cb_secret_live = fields.get('topup_coinbase_webhook_secret_live', '')[:500]
            REGISTRATION_DB.set_setting('topup_coinbase_api_key_sandbox', cb_key_sandbox, user['username'])
            REGISTRATION_DB.set_setting('topup_coinbase_api_key_live', cb_key_live, user['username'])
            REGISTRATION_DB.set_setting('topup_coinbase_webhook_secret_sandbox', cb_secret_sandbox, user['username'])
            REGISTRATION_DB.set_setting('topup_coinbase_webhook_secret_live', cb_secret_live, user['username'])
            # Legacy single-value keys mirror active env value for backward compatibility.
            REGISTRATION_DB.set_setting('topup_coinbase_api_key',
                                        cb_key_sandbox if env == 'sandbox' else cb_key_live,
                                        user['username'])
            REGISTRATION_DB.set_setting('topup_coinbase_webhook_secret',
                                        cb_secret_sandbox if env == 'sandbox' else cb_secret_live,
                                        user['username'])
            REGISTRATION_DB.set_setting('topup_coinbase_create_url',
                                        fields.get('topup_coinbase_create_url',
                                                   'https://api.commerce.coinbase.com/charges')[:500],
                                        user['username'])
            try:
                req_timeout = str(max(3, min(120, int(
                    fields.get('topup_provider_request_timeout_sec',
                               fields.get('topup_coinbase_request_timeout_sec', '15'))
                ))))
            except Exception:
                req_timeout = '15'
            REGISTRATION_DB.set_setting('topup_provider_request_timeout_sec', req_timeout, user['username'])
            REGISTRATION_DB.set_setting('topup_coinbase_request_timeout_sec', req_timeout, user['username'])
            auto_redirect = '1' if fields.get('topup_auto_redirect_checkout') == '1' else '0'
            REGISTRATION_DB.set_setting('topup_auto_redirect_checkout', auto_redirect, user['username'])
            try:
                pending_sla = str(max(5, min(10080, int(fields.get('topup_pending_sla_minutes', '180')))))
            except Exception:
                pending_sla = '180'
            REGISTRATION_DB.set_setting('topup_pending_sla_minutes', pending_sla, user['username'])
            paypal_enabled = fields.get('topup_paypal_enabled', '')
            if paypal_enabled not in ('0', '1'):
                paypal_enabled = '0'
            REGISTRATION_DB.set_setting('topup_paypal_enabled', paypal_enabled, user['username'])
            paypal_webhook_enforce = fields.get('topup_paypal_webhook_enforce', '')
            if paypal_webhook_enforce not in ('0', '1'):
                paypal_webhook_enforce = '1'
            REGISTRATION_DB.set_setting('topup_paypal_webhook_enforce', paypal_webhook_enforce, user['username'])
            paypal_env = fields.get('topup_paypal_env', 'sandbox')
            if paypal_env not in ('sandbox', 'live'):
                paypal_env = 'sandbox'
            REGISTRATION_DB.set_setting('topup_paypal_env', paypal_env, user['username'])
            pp_client_id_sandbox = fields.get('topup_paypal_client_id_sandbox', '')[:500]
            pp_client_id_live = fields.get('topup_paypal_client_id_live', '')[:500]
            pp_client_secret_sandbox = fields.get('topup_paypal_client_secret_sandbox', '')[:500]
            pp_client_secret_live = fields.get('topup_paypal_client_secret_live', '')[:500]
            pp_webhook_id_sandbox = fields.get('topup_paypal_webhook_id_sandbox', '')[:500]
            pp_webhook_id_live = fields.get('topup_paypal_webhook_id_live', '')[:500]
            REGISTRATION_DB.set_setting('topup_paypal_client_id_sandbox', pp_client_id_sandbox, user['username'])
            REGISTRATION_DB.set_setting('topup_paypal_client_id_live', pp_client_id_live, user['username'])
            REGISTRATION_DB.set_setting('topup_paypal_client_secret_sandbox', pp_client_secret_sandbox, user['username'])
            REGISTRATION_DB.set_setting('topup_paypal_client_secret_live', pp_client_secret_live, user['username'])
            REGISTRATION_DB.set_setting('topup_paypal_webhook_id_sandbox', pp_webhook_id_sandbox, user['username'])
            REGISTRATION_DB.set_setting('topup_paypal_webhook_id_live', pp_webhook_id_live, user['username'])
            # Legacy single-value keys mirror active env value for backward compatibility.
            REGISTRATION_DB.set_setting('topup_paypal_client_id',
                                        pp_client_id_sandbox if paypal_env == 'sandbox' else pp_client_id_live,
                                        user['username'])
            REGISTRATION_DB.set_setting('topup_paypal_client_secret',
                                        pp_client_secret_sandbox if paypal_env == 'sandbox' else pp_client_secret_live,
                                        user['username'])
            REGISTRATION_DB.set_setting('topup_paypal_webhook_id',
                                        pp_webhook_id_sandbox if paypal_env == 'sandbox' else pp_webhook_id_live,
                                        user['username'])
            try:
                base_rate = str(max(1, min(100000, int(fields.get('topup_base_rate_pts_per_usd', '200')))))
            except Exception:
                base_rate = '200'
            REGISTRATION_DB.set_setting('topup_base_rate_pts_per_usd', base_rate, user['username'])
            raw_amounts = fields.get('topup_fixed_amounts', '5,10,25,50,100')
            amounts = []
            for part in raw_amounts.split(','):
                part = part.strip()
                if not part:
                    continue
                try:
                    amounts.append(max(1, min(100000, int(part))))
                except Exception:
                    continue
            if not amounts:
                amounts = [5, 10, 25, 50, 100]
            amounts = sorted(set(amounts))
            REGISTRATION_DB.set_setting('topup_fixed_amounts_json', json.dumps(amounts), user['username'])
            raw_bands = fields.get('topup_multiplier_bands', '5:1.00,10:1.25,25:1.40,50:1.55,100:1.75')
            bands = []
            for part in raw_bands.split(','):
                part = part.strip()
                if ':' not in part:
                    continue
                left, right = part.split(':', 1)
                try:
                    min_usd = max(1, min(100000, int(left.strip())))
                    mult = float(right.strip())
                    bp = int(mult * 10000)
                    bp = max(1000, min(100000, bp))
                except Exception:
                    continue
                bands.append({'min_usd': min_usd, 'multiplier_bp': bp})
            if not bands:
                bands = [{'min_usd': 5, 'multiplier_bp': 10000}]
            bands.sort(key=lambda x: x['min_usd'])
            REGISTRATION_DB.set_setting('topup_multiplier_bands_json', json.dumps(bands), user['username'])
        self._redirect('/manage/admin?tab=economy' if form_id in ('points_earn','points_spend','bounty_settings','leaderboard_settings','admin_grant_settings','dm_settings')
                       else ('/manage/admin?tab=topups' if form_id == 'topup_settings' else '/manage/admin'))

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
            bounty = REGISTRATION_DB.get_bounty(bounty_id)
            if bounty:
                _deliver_bounty_comment_notifications(
                    cid, bounty_id, bounty['description'], user['username'], text
                )
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

    def _post_follow(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target_username = fields.get('username', '').strip()
        referer = fields.get('referer', '').strip()
        target = REGISTRATION_DB.get_user(target_username) if target_username else None
        if not target:
            return self._redirect('/manage/following?msg=User+not+found.&msg_type=error')
        ok, msg = REGISTRATION_DB.follow_user(user['id'], target['id'])
        if ok:
            REGISTRATION_DB._log(user['username'], 'follow_user', target['username'])
            REGISTRATION_DB.notify_followed_user_new_follower(
                target['id'], user['id'], user['username']
            )
        dest = referer if referer.startswith('/manage/') else f'/manage/user/{urllib.parse.quote(target["username"])}'
        glue = '&' if '?' in dest else '?'
        self._redirect(f'{dest}{glue}msg={urllib.parse.quote(msg)}&msg_type={"success" if ok else "error"}')

    def _post_unfollow(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        target_username = fields.get('username', '').strip()
        referer = fields.get('referer', '').strip()
        target = REGISTRATION_DB.get_user(target_username) if target_username else None
        if not target:
            return self._redirect('/manage/following?msg=User+not+found.&msg_type=error')
        ok, msg = REGISTRATION_DB.unfollow_user(user['id'], target['id'])
        if ok:
            REGISTRATION_DB._log(user['username'], 'unfollow_user', target['username'])
        dest = referer if referer.startswith('/manage/') else '/manage/following'
        glue = '&' if '?' in dest else '?'
        self._redirect(f'{dest}{glue}msg={urllib.parse.quote(msg)}&msg_type={"success" if ok else "error"}')

    def _post_topup_create(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        if not REGISTRATION_DB.topup_enabled_for_user(user):
            return self._redirect('/manage/profile?msg=Top-ups+are+disabled.&msg_type=error')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        try:
            amount_usd = int(fields.get('amount_usd', '0'))
        except Exception:
            amount_usd = 0
        selected_provider = (fields.get('provider', '') or '').strip().lower()
        cfg = REGISTRATION_DB.get_topup_config()
        if amount_usd not in cfg['fixed_amounts_usd']:
            return self._redirect('/manage/topups?msg=Invalid+top-up+amount.&msg_type=error')
        provider = selected_provider or cfg.get('provider', 'coinbase')
        if provider not in cfg.get('providers', ['coinbase']):
            return self._redirect('/manage/topups?msg=Selected+payment+processor+is+not+available.&msg_type=error')
        order = REGISTRATION_DB.create_topup_order(
            user['id'], amount_usd, actor=user['username'], provider=provider
        )
        if not order:
            return self._redirect('/manage/topups?msg=Unable+to+create+order.&msg_type=error')
        if provider == 'paypal':
            base = self._build_manage_base_url()
            return_url = f'{base}/manage/topups/paypal/return'
            cancel_url = f'{base}/manage/topups/paypal/cancel'
            ok, info = REGISTRATION_DB.create_paypal_checkout_for_order(
                order['id'], user, return_url=return_url, cancel_url=cancel_url,
                actor=user['username']
            )
            if not ok:
                if info.get('error') == 'missing_paypal_credentials':
                    REGISTRATION_DB.update_topup_status(
                        order['id'], 'pending', actor=user['username'],
                        reason='awaiting_manual_payment',
                        detail='PayPal credentials are not configured; manual/admin flow required'
                    )
                    q = urllib.parse.quote('Order created in pending state. PayPal auto-checkout is not configured yet.')
                    return self._redirect(f'/manage/topups?msg={q}&msg_type=success')
                REGISTRATION_DB.update_topup_status(
                    order['id'], 'exception', actor=user['username'],
                    reason='checkout_create_failed',
                    detail=(info.get('message') or info.get('error') or 'Unable to create PayPal checkout')
                )
                q = urllib.parse.quote('Order created but PayPal checkout failed: ' + (info.get('message') or info.get('error') or 'unknown'))
                return self._redirect(f'/manage/topups?msg={q}&msg_type=error')
            approve_url = info.get('checkout_url', '')
            if approve_url:
                self.send_response(303)
                self.send_header('Location', approve_url)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            return self._redirect('/manage/topups?msg=PayPal+order+created.+Use+Pay+Now+to+continue.&msg_type=success')
        ok, info = REGISTRATION_DB.create_coinbase_checkout_for_order(
            order['id'], user, actor=user['username']
        )
        if not ok:
            if info.get('error') in ('missing_api_key', 'missing_create_url'):
                REGISTRATION_DB.update_topup_status(
                    order['id'], 'pending', actor=user['username'],
                    reason='awaiting_manual_payment',
                    detail='Checkout not auto-created (provider credentials/URL not configured); admin/manual flow required'
                )
                q = urllib.parse.quote('Order created in pending state. Coinbase auto-checkout is not configured yet.')
                return self._redirect(f'/manage/topups?msg={q}&msg_type=success')
            # Keep order visible for reconciliation and troubleshooting.
            REGISTRATION_DB.update_topup_status(
                order['id'], 'exception', actor=user['username'],
                reason='checkout_create_failed',
                detail=(info.get('message') or info.get('error') or 'Unable to create Coinbase checkout')
            )
            q = urllib.parse.quote('Order created but checkout failed: ' + (info.get('message') or info.get('error') or 'unknown'))
            return self._redirect(f'/manage/topups?msg={q}&msg_type=error')
        checkout_url = info.get('checkout_url', '')
        if cfg.get('auto_redirect_checkout') and checkout_url:
            self.send_response(303)
            self.send_header('Location', checkout_url)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self._redirect('/manage/topups?msg=Top-up+order+created.+Proceed+to+Coinbase+checkout.&msg_type=success')

    def _post_topup_reconcile(self):
        user = self._get_session_user()
        if not user:
            return self._redirect('/manage')
        is_super = user['username'] == SUPER_USER
        if not (user['is_admin'] or is_super):
            return self._redirect('/manage/dashboard')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        try:
            order_id = int(fields.get('order_id', '0'))
        except Exception:
            order_id = 0
        action = fields.get('action', '').strip()
        note = fields.get('note', '').strip()
        if order_id <= 0:
            return self._redirect('/manage/admin?tab=topups&msg=Invalid+order+id.&msg_type=error')
        order = REGISTRATION_DB.get_topup_order(order_id)
        if not order:
            return self._redirect('/manage/admin?tab=topups&msg=Order+not+found.&msg_type=error')
        old_status = order['status']
        if old_status == 'credited':
            return self._redirect('/manage/admin?tab=topups&msg=Credited+orders+are+final+and+cannot+be+changed.&msg_type=error')
        if action == 'mark_confirmed':
            if old_status not in ('created', 'pending'):
                return self._redirect('/manage/admin?tab=topups&msg=Confirm+is+only+allowed+from+created+or+pending.&msg_type=error')
            ok = REGISTRATION_DB.update_topup_status(order_id, 'confirmed', actor=user['username'],
                                                     reason='admin_confirmed', detail=note or 'Marked confirmed by admin')
            new_status = 'confirmed'
        elif action == 'mark_failed':
            if old_status not in ('created', 'pending', 'confirmed'):
                return self._redirect('/manage/admin?tab=topups&msg=Failed+is+only+allowed+from+created%2C+pending%2C+or+confirmed.&msg_type=error')
            ok = REGISTRATION_DB.update_topup_status(order_id, 'failed', actor=user['username'],
                                                     reason='admin_failed', detail=note or 'Marked failed by admin')
            new_status = 'failed'
        elif action == 'mark_expired':
            if old_status not in ('created', 'pending', 'confirmed'):
                return self._redirect('/manage/admin?tab=topups&msg=Expired+is+only+allowed+from+created%2C+pending%2C+or+confirmed.&msg_type=error')
            ok = REGISTRATION_DB.update_topup_status(order_id, 'expired', actor=user['username'],
                                                     reason='admin_expired', detail=note or 'Marked expired by admin')
            new_status = 'expired'
        elif action == 'mark_exception':
            if old_status not in ('created', 'pending', 'confirmed'):
                return self._redirect('/manage/admin?tab=topups&msg=Exception+is+only+allowed+from+created%2C+pending%2C+or+confirmed.&msg_type=error')
            ok = REGISTRATION_DB.update_topup_status(order_id, 'exception', actor=user['username'],
                                                     reason='admin_exception', detail=note or 'Marked exception by admin')
            new_status = 'exception'
        elif action == 'mark_credited':
            if old_status != 'confirmed':
                return self._redirect('/manage/admin?tab=topups&msg=Credit+is+only+allowed+from+confirmed.&msg_type=error')
            ok, msg = REGISTRATION_DB.credit_topup_order(order_id, actor=user['username'])
            if ok:
                new_status = 'credited'
            else:
                return self._redirect('/manage/admin?tab=topups&msg=' + urllib.parse.quote(msg) + '&msg_type=error')
        else:
            return self._redirect('/manage/admin?tab=topups&msg=Unknown+action.&msg_type=error')
        if not ok:
            return self._redirect('/manage/admin?tab=topups&msg=Unable+to+update+order.&msg_type=error')
        actor_id = user['id']
        REGISTRATION_DB.add_topup_reconciliation_action(
            order_id, actor_id, action, old_status, new_status, note
        )
        REGISTRATION_DB._log(user['username'], 'topup_reconcile', str(order_id), f'{action} old={old_status} new={new_status}')
        self._redirect('/manage/admin?tab=topups&msg=Top-up+order+updated.&msg_type=success')

    def _post_coinbase_webhook(self):
        """Coinbase webhook ingestion endpoint."""
        body = self._read_body()
        cfg = REGISTRATION_DB.get_topup_config() if REGISTRATION_DB else {}
        secret = cfg.get('coinbase_webhook_secret', '') if cfg else ''
        sig = (self.headers.get('X-CC-Webhook-Signature')
               or self.headers.get('X-Coinbase-Signature')
               or self.headers.get('X-Hook0-Signature')
               or self.headers.get('x-cc-webhook-signature')
               or '')
        signature_valid = _verify_coinbase_signature(secret, body, sig)
        try:
            payload = json.loads(body.decode('utf-8', errors='replace') or '{}')
        except Exception:
            payload = {}
        refs = _coinbase_extract_refs(payload)
        event_type = refs['event_type']
        event_id = refs['event_id']
        if event_id:
            existing_event = REGISTRATION_DB.get_topup_webhook_event('coinbase', event_id)
            if existing_event and existing_event['process_status'] in ('processed', 'ignored'):
                return self._send_json({'ok': True, 'duplicate': True})
        linked_order = None
        if refs['order_uuid']:
            linked_order = REGISTRATION_DB.get_topup_order_by_uuid(refs['order_uuid'])
        if not linked_order and refs['order_id'].isdigit():
            linked_order = REGISTRATION_DB.get_topup_order(int(refs['order_id']))
        if not linked_order and refs['checkout_id']:
            linked_order = REGISTRATION_DB.get_topup_order_by_provider_checkout_id(refs['checkout_id'])
        if not linked_order and refs['charge_id']:
            linked_order = REGISTRATION_DB.get_topup_order_by_provider_charge_id(refs['charge_id'])
        if not linked_order and refs['hosted_url']:
            linked_order = REGISTRATION_DB.get_topup_order_by_provider_reference(refs['hosted_url'])
        linked_order_id = linked_order['id'] if linked_order else None
        wh_id = REGISTRATION_DB.record_topup_webhook_event(
            provider='coinbase',
            event_type=event_type[:120],
            payload_json=body.decode('utf-8', errors='replace'),
            headers_json=json.dumps({
                'x-cc-webhook-signature': self.headers.get('X-CC-Webhook-Signature', ''),
                'x-coinbase-signature': self.headers.get('X-Coinbase-Signature', ''),
                'x-hook0-signature': self.headers.get('X-Hook0-Signature', ''),
            }),
            signature_valid=signature_valid,
            event_id=event_id[:120],
            linked_order_id=linked_order_id,
            idempotency_key=(event_id or refs['order_uuid'] or refs['checkout_id'] or secrets.token_hex(8))
        )
        if secret and not signature_valid:
            REGISTRATION_DB.mark_topup_webhook_processed(wh_id, status='ignored', error_msg='invalid signature')
            return self._send_json({'ok': False, 'error': 'invalid signature'}, 400)
        if linked_order_id:
            text_blob = json.dumps(payload).lower()
            try:
                if refs['checkout_id'] or refs['charge_id'] or refs['hosted_url']:
                    REGISTRATION_DB.set_topup_provider_refs(
                        linked_order_id,
                        provider_checkout_id=refs['checkout_id'] or (linked_order['provider_checkout_id'] if linked_order else ''),
                        provider_charge_id=refs['charge_id'] or (linked_order['provider_charge_id'] if linked_order else ''),
                        provider_reference=refs['hosted_url'] or (linked_order['provider_reference'] if linked_order else ''),
                        actor='coinbase_webhook',
                    )
                if ('confirmed' in event_type.lower() or 'completed' in event_type.lower()
                        or '"status":"confirmed"' in text_blob
                        or '"status":"completed"' in text_blob
                        or '"status":"success"' in text_blob):
                    REGISTRATION_DB.update_topup_status(
                        linked_order_id, 'confirmed', actor='coinbase_webhook',
                        reason='provider_confirmed', detail=f'Webhook {event_type}'
                    )
                    REGISTRATION_DB.credit_topup_order(linked_order_id, actor='coinbase_webhook')
                elif ('failed' in event_type.lower() or 'expired' in event_type.lower()
                      or '"status":"failed"' in text_blob or '"status":"expired"' in text_blob):
                    target = 'failed' if 'failed' in event_type.lower() or '"status":"failed"' in text_blob else 'expired'
                    REGISTRATION_DB.update_topup_status(
                        linked_order_id, target, actor='coinbase_webhook',
                        reason=f'provider_{target}', detail=f'Webhook {event_type}'
                    )
                else:
                    REGISTRATION_DB.update_topup_status(
                        linked_order_id, 'pending', actor='coinbase_webhook',
                        reason='provider_pending', detail=f'Webhook {event_type}'
                    )
                REGISTRATION_DB._conn().execute(
                    'UPDATE topup_orders SET last_webhook_at=?, updated_at=? WHERE id=?',
                    (REGISTRATION_DB._ts(), REGISTRATION_DB._ts(), linked_order_id)
                )
                REGISTRATION_DB._conn().commit()
            except Exception as exc:
                REGISTRATION_DB.mark_topup_webhook_processed(wh_id, status='error', error_msg=str(exc))
                return self._send_json({'ok': False}, 500)
        REGISTRATION_DB.mark_topup_webhook_processed(wh_id, status='processed', error_msg='')
        return self._send_json({'ok': True})

    def _post_paypal_webhook(self):
        """PayPal webhook ingestion endpoint."""
        body = self._read_body()
        try:
            payload = json.loads(body.decode('utf-8', errors='replace') or '{}')
        except Exception:
            payload = {}
        sig_ok, sig_detail = REGISTRATION_DB.verify_paypal_webhook_signature(payload, self.headers)
        refs = _paypal_extract_refs(payload)
        event_type = refs['event_type']
        event_id = refs['event_id']
        log.debug('PAYPAL webhook recv event_type=%s event_id=%s checkout_id=%s capture_id=%s order_uuid=%s sig_ok=%s sig_detail=%s',
                  event_type[:80], event_id[:40], refs['checkout_id'][:24], refs['capture_id'][:24],
                  refs['order_uuid'][:12], int(bool(sig_ok)), str(sig_detail)[:80])
        if event_id:
            existing_event = REGISTRATION_DB.get_topup_webhook_event('paypal', event_id)
            if existing_event and existing_event['process_status'] in ('processed', 'ignored'):
                log.debug('PAYPAL webhook duplicate event_id=%s status=%s', event_id[:40], existing_event['process_status'])
                return self._send_json({'ok': True, 'duplicate': True})
        linked_order = None
        if refs['order_uuid']:
            linked_order = REGISTRATION_DB.get_topup_order_by_uuid(refs['order_uuid'])
        if not linked_order and refs['checkout_id']:
            linked_order = REGISTRATION_DB.get_topup_order_by_provider_checkout_id(refs['checkout_id'])
        if not linked_order and refs['capture_id']:
            linked_order = REGISTRATION_DB.get_topup_order_by_provider_charge_id(refs['capture_id'])
        linked_order_id = linked_order['id'] if linked_order else None
        log.debug('PAYPAL webhook linked event_id=%s linked_order_id=%s', event_id[:40], linked_order_id or 0)
        wh_id = REGISTRATION_DB.record_topup_webhook_event(
            provider='paypal',
            event_type=event_type[:120],
            payload_json=body.decode('utf-8', errors='replace'),
            headers_json=json.dumps({
                'paypal-transmission-id': self.headers.get('paypal-transmission-id', ''),
                'paypal-transmission-sig': self.headers.get('paypal-transmission-sig', ''),
                'paypal-cert-url': self.headers.get('paypal-cert-url', ''),
                'paypal-auth-algo': self.headers.get('paypal-auth-algo', ''),
            }),
            signature_valid=1 if sig_ok else 0,
            event_id=event_id[:120],
            linked_order_id=linked_order_id,
            idempotency_key=(event_id or refs['order_uuid'] or refs['checkout_id'] or secrets.token_hex(8))
        )
        if not sig_ok:
            log.warning('PAYPAL webhook ignored invalid_signature event_id=%s detail=%s',
                        event_id[:40], str(sig_detail)[:120])
            REGISTRATION_DB.mark_topup_webhook_processed(wh_id, status='ignored', error_msg=f'invalid signature: {sig_detail}')
            return self._send_json({'ok': False, 'error': 'invalid signature'}, 400)
        if linked_order_id:
            try:
                current = REGISTRATION_DB.get_topup_order(linked_order_id)
                current_status = (current['status'] if current else '')
                if event_type in ('PAYMENT.CAPTURE.REFUNDED', 'PAYMENT.CAPTURE.REVERSED'):
                    ok_refund, refund_msg = REGISTRATION_DB.refund_topup_order(
                        linked_order_id,
                        actor='paypal_webhook',
                        reason='provider_refund',
                        detail=f'Webhook {event_type}'
                    )
                    if ok_refund:
                        log.debug('PAYPAL webhook refunded order_id=%s event_type=%s event_id=%s',
                                  linked_order_id, event_type[:80], event_id[:40])
                    else:
                        log.debug('PAYPAL webhook refund_noop order_id=%s event_type=%s event_id=%s detail=%s',
                                  linked_order_id, event_type[:80], event_id[:40], str(refund_msg)[:120])
                elif current_status == 'credited':
                    log.debug('PAYPAL webhook already_credited_skip order_id=%s event_type=%s event_id=%s',
                              linked_order_id, event_type[:80], event_id[:40])
                elif event_type in ('PAYMENT.CAPTURE.COMPLETED', 'CHECKOUT.ORDER.APPROVED'):
                    REGISTRATION_DB.set_topup_provider_refs(
                        linked_order_id,
                        provider_checkout_id=refs['checkout_id'] or (linked_order['provider_checkout_id'] if linked_order else ''),
                        provider_charge_id=refs['capture_id'] or (linked_order['provider_charge_id'] if linked_order else ''),
                        provider_reference=(linked_order['provider_reference'] if linked_order else ''),
                        actor='paypal_webhook',
                    )
                    REGISTRATION_DB.update_topup_status(
                        linked_order_id, 'confirmed', actor='paypal_webhook',
                        reason='provider_confirmed', detail=f'Webhook {event_type}'
                    )
                    ok_credit, credit_msg = REGISTRATION_DB.credit_topup_order(linked_order_id, actor='paypal_webhook')
                    if ok_credit:
                        log.debug('PAYPAL webhook confirmed+credited order_id=%s event_type=%s event_id=%s',
                                  linked_order_id, event_type[:80], event_id[:40])
                    else:
                        log.debug('PAYPAL webhook confirmed_but_not_credited order_id=%s event_type=%s event_id=%s detail=%s',
                                  linked_order_id, event_type[:80], event_id[:40], str(credit_msg)[:120])
                elif event_type in ('PAYMENT.CAPTURE.DENIED', 'CHECKOUT.ORDER.CANCELLED'):
                    REGISTRATION_DB.update_topup_status(
                        linked_order_id, 'failed', actor='paypal_webhook',
                        reason='provider_failed', detail=f'Webhook {event_type}'
                    )
                    log.debug('PAYPAL webhook marked_failed order_id=%s event_type=%s event_id=%s',
                              linked_order_id, event_type[:80], event_id[:40])
                REGISTRATION_DB._conn().execute(
                    'UPDATE topup_orders SET last_webhook_at=?, updated_at=? WHERE id=?',
                    (REGISTRATION_DB._ts(), REGISTRATION_DB._ts(), linked_order_id)
                )
                REGISTRATION_DB._conn().commit()
            except Exception as exc:
                log.exception('PAYPAL webhook processing_error wh_id=%s order_id=%s event_id=%s err=%s',
                              wh_id, linked_order_id, event_id[:40], exc)
                REGISTRATION_DB.mark_topup_webhook_processed(wh_id, status='error', error_msg=str(exc))
                return self._send_json({'ok': False}, 500)
        else:
            log.debug('PAYPAL webhook no_link event_id=%s event_type=%s', event_id[:40], event_type[:80])
        REGISTRATION_DB.mark_topup_webhook_processed(wh_id, status='processed', error_msg='')
        log.debug('PAYPAL webhook processed wh_id=%s event_id=%s', wh_id, event_id[:40])
        return self._send_json({'ok': True})

    # ── DM Handlers ─────────────────────────────────────────

    def _get_notifications_preview(self):
        """Return top-5 unread notifications as JSON for live dropdown refresh."""
        user = self._get_session_user()
        if not user:
            return self._send_json({'error': 'auth'}, 401)
        items = REGISTRATION_DB.get_unread_notifications(user['id'], 5) if REGISTRATION_DB else []
        out = []
        for n in items:
            is_bounty = str(n['info_hash']).upper().startswith('BOUNTY:')
            is_topup = str(n['info_hash']).upper().startswith('TOPUP:')
            is_follow = str(n['info_hash']).upper().startswith('FOLLOW:')
            if is_bounty:
                bid   = str(n['info_hash']).split(':',1)[1]
                ntype = n['type']
                icons = {
                    'bounty_new':             ('📣', 'has posted a bounty for'),
                    'bounty_mention':         ('@',  'mentioned you in bounty'),
                    'bounty_claimed':         ('🎯', 'claimed your bounty'),
                    'bounty_rejected':        ('✗',  'rejected your claim on'),
                    'bounty_fulfilled':       ('✅', 'has accepted your bounty for'),
                    'bounty_contribution':    ('➕', 'added points to your bounty'),
                    'bounty_expired':         ('⏰', 'bounty expired:'),
                    'bounty_uploader_payout': ('💰', 'fulfilled a bounty using your upload:'),
                    'followed_bounty_fulfilled': ('✅', 'fulfilled a bounty:'),
                }
                icon, label = icons.get(ntype, ('🔔', 'bounty update on'))
                anchor = f'#bcmt-{n["comment_id"]}' if (ntype == 'bounty_mention' and n['comment_id']) else ''
                url = f'/manage/bounty/{bid}{anchor}'
            elif is_topup:
                oid = str(n['info_hash']).split(':', 1)[1]
                oid_disp = oid
                if oid.isdigit() and REGISTRATION_DB:
                    try:
                        seq = REGISTRATION_DB.get_topup_user_sequence(user['id'], int(oid))
                        if seq > 0:
                            oid_disp = str(seq)
                    except Exception:
                        pass
                icon = '💳'
                label = (f'top-up #{oid_disp} refunded'
                         if n['type'] == 'topup_refunded'
                         else f'top-up #{oid_disp} credited')
                url = '/manage/topups'
            elif is_follow:
                icon = '👥'
                label = 'is now following you!'
                follow_uid = int(n['comment_id'] or 0)
                url = '/manage/following'
                if follow_uid > 0 and REGISTRATION_DB:
                    fu = REGISTRATION_DB.get_user_by_id(follow_uid)
                    if fu:
                        url = f'/manage/user/{urllib.parse.quote(fu["username"])}'
            else:
                if n['type'] == 'followed_upload':
                    icon = '📦'
                    label = 'uploaded a new torrent'
                    url = f'/manage/torrent/{n["info_hash"].lower()}'
                else:
                    icon  = '💬' if n['type'] == 'reply' else '@'
                    label = 'replied to your comment' if n['type'] == 'reply' else 'mentioned you'
                    anchor = f'#comment-{n["comment_id"]}' if int(n['comment_id'] or 0) > 0 else ''
                    url = f'/manage/torrent/{n["info_hash"].lower()}{anchor}'
            out.append({
                'id':       n['id'],
                'icon':     icon,
                'label':    label,
                'from':     n['from_username'],
                'torrent':  (n['torrent_name'] or '')[:40],
                'ts':       (n['created_at'] or '')[:16].replace('T', ' '),
                'url':      url,
            })
        return self._send_json({'items': out})

    def _get_global_poll(self):
        """Lightweight background poll for nav badge counts. Called every 30s by all pages."""
        user = self._get_session_user()
        if not user:
            return self._send_json({'error': 'auth'}, 401)
        notifs = REGISTRATION_DB.get_unread_count(user['id']) if REGISTRATION_DB else 0
        msgs   = REGISTRATION_DB.get_unread_dm_count(user['username']) if REGISTRATION_DB else 0
        return self._send_json({'notifs': notifs, 'msgs': msgs})

    def _get_dm_poll(self):
        """Lightweight JSON poll: returns new messages and presence info for a thread."""
        user = self._get_session_user()
        if not user:
            return self._send_json({'error': 'auth'}, 401)
        if _user_role(user) == 'basic':
            return self._send_json({'error': 'forbidden'}, 403)
        qs         = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        since_id   = int(qs.get('since_id', ['0'])[0])
        other_user = qs.get('other', [''])[0]
        uname      = user['username']

        # Fetch only new messages in this conversation since since_id
        conv_id   = int(qs.get('conv_id', ['0'])[0])
        new_msgs  = []
        if conv_id and REGISTRATION_DB:
            rows = REGISTRATION_DB._conn().execute(
                '''SELECT id, sender, recipient, subject, body, sent_at, is_broadcast
                   FROM direct_messages
                   WHERE id > ? AND conversation_id=?
                   AND (
                       (sender=? AND del_by_sender=0)
                       OR (recipient=? AND del_by_recip=0)
                   )
                   ORDER BY id ASC''',
                (since_id, conv_id, uname, uname)
            ).fetchall()
            for m in rows:
                new_msgs.append({
                    'id':           m['id'],
                    'sender':       m['sender'],
                    'recipient':    m['recipient'],
                    'subject':      m['subject'] or '',
                    'body':         m['body'],
                    'sent_at':      (m['sent_at'] or '')[:16].replace('T', ' '),
                    'is_broadcast': m['is_broadcast'],
                    'is_mine':      m['sender'] == uname,
                })
            # Mark newly arrived incoming messages as read
            if new_msgs:
                REGISTRATION_DB._conn().execute(
                    '''UPDATE direct_messages SET read_at=?
                       WHERE conversation_id=? AND recipient=? AND read_at IS NULL''',
                    (datetime.datetime.now().isoformat(timespec='seconds'), conv_id, uname)
                )
                REGISTRATION_DB._conn().commit()

        # Presence
        other_online  = False
        other_status  = 'offline'
        other_typing  = False
        if other_user and REGISTRATION_DB:
            ou = REGISTRATION_DB.get_user(other_user)
            other_status = _online_status(ou)
            # Respect show_online — only reveal to others if they allow it
            other_online = (other_status == 'online')
            other_typing = _is_typing(other_user, uname)

        return self._send_json({
            'messages':     new_msgs,
            'other_typing': other_typing,
            'other_online': other_online,
            'other_status': other_status,
        })

    def _post_dm_typing(self):
        """Receive typing heartbeat — store in memory, no DB write."""
        user = self._get_session_user()
        if not user:
            return self._send_json({'ok': False}, 401)
        fields = urllib.parse.parse_qs(self._read_body().decode('utf-8', errors='replace'))
        other  = fields.get('other', [''])[0].strip()
        if other:
            _set_typing(user['username'], other)
        return self._send_json({'ok': True})

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

    def _get_message_thread(self, conv_id_str: str):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        role = _user_role(user)
        if role == 'basic': return self._redirect('/manage/dashboard')
        msg_id_str = conv_id_str  # keep variable name for rest of handler
        if not msg_id_str.isdigit():
            return self._redirect('/manage/messages')
        msg_id = int(msg_id_str)
        thread = REGISTRATION_DB.get_dm_thread(msg_id, user['username'])
        if not thread:
            return self._redirect('/manage/messages')
        uname = user['username']
        if not any(m['sender'] == uname or m['recipient'] == uname for m in thread):
            return self._redirect('/manage/messages')
        # Mark entire conversation read in one shot
        REGISTRATION_DB.mark_dm_read(msg_id, uname)
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
        # Inherit conversation_id from parent so reply stays in same thread
        conv_id = orig['conversation_id'] if 'conversation_id' in orig.keys() and orig['conversation_id'] else orig['id']
        REGISTRATION_DB.send_dm(uname, recipient, subject, text,
                                reply_to_id=int(reply_to), conversation_id=conv_id)
        # Redirect to the conversation root so URL stays stable
        self._redirect(f'/manage/messages/{conv_id}?msg=Reply+sent&msg_type=success')

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

    def _post_dm_delete_conversation(self):
        user = self._get_session_user()
        if not user: return self._redirect('/manage')
        body = self._read_body()
        fields, _ = _parse_multipart(self.headers, body)
        conv_id = fields.get('conversation_id', '').strip()
        if not conv_id.isdigit():
            return self._redirect('/manage/messages')
        uname = user['username']
        # Verify user is a participant before deleting
        c = REGISTRATION_DB._conn()
        is_participant = c.execute(
            '''SELECT 1 FROM direct_messages
               WHERE conversation_id=? AND (sender=? OR recipient=?) LIMIT 1''',
            (int(conv_id), uname, uname)
        ).fetchone()
        if not is_participant:
            return self._redirect('/manage/messages')
        REGISTRATION_DB.delete_dm_conversation(int(conv_id), uname)
        REGISTRATION_DB._log(uname, 'dm_delete_conversation', uname,
                             f'conversation_id={conv_id}')
        self._redirect('/manage/messages?msg=Conversation+deleted&msg_type=success')
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
        allow       = fields.get('allow_dms',   '0') == '1'
        full_privacy_submit = fields.get('form_scope', '') == 'profile_privacy'
        if full_privacy_submit:
            show_online = fields.get('show_online', '0') == '1'
            bounty_alerts = fields.get('bounty_alerts', '0') == '1'
            link_torrent_activity = fields.get('link_torrent_activity', '0') == '1'
            allow_follow_visibility = fields.get('allow_follow_visibility', '0') == '1'
            gravatar_opt_in = fields.get('gravatar_opt_in', '0') == '1'
            gravatar_identity = fields.get('gravatar_identity',
                                           fields.get('gravatar_email', '')).strip()
        else:
            show_online = ('show_online' not in user.keys() or user['show_online'])
            bounty_alerts = ('bounty_alerts' not in user.keys() or user['bounty_alerts'])
            link_torrent_activity = ('link_torrent_activity' not in user.keys() or user['link_torrent_activity'])
            allow_follow_visibility = ('allow_follow_visibility' not in user.keys() or user['allow_follow_visibility'])
            gravatar_opt_in = ('gravatar_opt_in' in user.keys() and user['gravatar_opt_in'])
            gravatar_identity = ''
        REGISTRATION_DB.dm_toggle_setting(user['id'], allow)
        c = REGISTRATION_DB._conn()
        if full_privacy_submit and _gravatar_enabled():
            gravatar_hash = (user['gravatar_hash'] if 'gravatar_hash' in user.keys() else None)
            if gravatar_opt_in and gravatar_identity:
                parsed_hash, gravatar_err = _normalize_gravatar_identity(gravatar_identity)
                if gravatar_err:
                    msg = urllib.parse.quote_plus(gravatar_err)
                    return self._redirect(f'/manage/profile?msg={msg}&msg_type=error')
                gravatar_hash = parsed_hash
            c.execute(
                '''UPDATE users
                   SET show_online=?, bounty_alerts=?, link_torrent_activity=?,
                       allow_follow_visibility=?, gravatar_opt_in=?, gravatar_hash=?
                   WHERE id=?''',
                (1 if show_online else 0,
                 1 if bounty_alerts else 0,
                 1 if link_torrent_activity else 0,
                 1 if allow_follow_visibility else 0,
                 1 if gravatar_opt_in else 0,
                 gravatar_hash if gravatar_opt_in else None,
                 user['id'])
            )
        else:
            c.execute(
                '''UPDATE users
                   SET show_online=?, bounty_alerts=?, link_torrent_activity=?,
                       allow_follow_visibility=?
                   WHERE id=?''',
                (1 if show_online else 0,
                 1 if bounty_alerts else 0,
                 1 if link_torrent_activity else 0,
                 1 if allow_follow_visibility else 0,
                 user['id'])
            )
        c.commit()
        if full_privacy_submit:
            self._redirect('/manage/profile?msg=Profile+settings+saved&msg_type=success')
        else:
            self._redirect('/manage/messages?msg=DM+settings+saved&msg_type=success')

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
        topup_orders = REGISTRATION_DB.list_topup_orders(user_id=target['id'], limit=100)
        base_url  = f'/manage/admin/user/{username}'
        self._send_html(_render_user_detail(viewer, target, torrents, history, is_super,
                                            allowlist=allowlist,
                                            page=page, total_pages=total_pages,
                                            total=total, base_url=base_url,
                                            topup_orders=topup_orders))

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

    def handle_error(self, request, client_address):
        exc_type = sys.exc_info()[0]
        if exc_type in _BENIGN_SOCKET_EXC:
            log.debug('WEB connection reset from %s', client_address[0])
            return
        super().handle_error(request, client_address)


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
        if path.startswith('/manage') or path in ('/coinbase/webhook', '/paypal/webhook'):
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

    def handle_error(self, request, client_address):
        exc_type = sys.exc_info()[0]
        if exc_type in _BENIGN_SOCKET_EXC:
            log.debug('WEB connection reset from %s', client_address[0])
            return
        super().handle_error(request, client_address)


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
  @keyframes notif-glow {
    0%   { filter: drop-shadow(0 0 0px transparent); }
    20%  { filter: drop-shadow(0 0 6px var(--accent)); }
    40%  { filter: drop-shadow(0 0 1px transparent); }
    60%  { filter: drop-shadow(0 0 6px var(--accent)); }
    80%  { filter: drop-shadow(0 0 1px transparent); }
    100% { filter: drop-shadow(0 0 0px transparent); }
  }
  .notif-glow { animation: notif-glow 1.4s ease-in-out; }
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
  /* ── Themed scrollbars ── */
  #dm-bubbles { scrollbar-width:thin; scrollbar-color:var(--accent) var(--card2); }
  #dm-bubbles::-webkit-scrollbar { width:5px; }
  #dm-bubbles::-webkit-scrollbar-track { background:var(--card2); border-radius:3px; }
  #dm-bubbles::-webkit-scrollbar-thumb { background:var(--accent); border-radius:3px; }
  #dm-bubbles::-webkit-scrollbar-thumb:hover { background:var(--text); }
  .notif-dropdown { scrollbar-width:thin; scrollbar-color:var(--accent) var(--card2); }
  .notif-dropdown::-webkit-scrollbar { width:4px; }
  .notif-dropdown::-webkit-scrollbar-track { background:transparent; }
  .notif-dropdown::-webkit-scrollbar-thumb { background:var(--accent); border-radius:2px; }
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
    var prev = document.activeElement;
    var o = document.createElement('div');
    o.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:9999;display:flex;align-items:center;justify-content:center';
    o.setAttribute('role','alertdialog');
    o.setAttribute('aria-modal','true');
    o.setAttribute('aria-labelledby','_ca_title');
    o.setAttribute('aria-describedby','_ca_body');
    o.innerHTML = '<div style="background:var(--card);border:1px solid var(--border);border-radius:12px;padding:28px 32px;max-width:560px;width:92%;text-align:center">'
      + '<div id="_ca_title" style="font-family:var(--mono);font-size:0.68rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--muted);margin-bottom:12px">Confirm Action</div>'
      + '<div id="_ca_body" style="font-size:0.92rem;margin-bottom:24px;line-height:1.5;color:var(--text);word-break:break-word;overflow-wrap:anywhere">' + msg + '</div>'
      + '<div style="display:flex;gap:12px;justify-content:center">'
      + '<button id="_ca_no" class="btn">Cancel</button>'
      + '<button id="_ca_yes" class="btn btn-danger">Confirm</button>'
      + '</div></div>';
    document.body.appendChild(o);
    var noBtn = document.getElementById('_ca_no');
    var yesBtn = document.getElementById('_ca_yes');
    function _close(ok){
      if (o.parentNode) o.parentNode.removeChild(o);
      if (prev && prev.focus) prev.focus();
      resolve(ok);
    }
    noBtn.onclick  = function(){ _close(false); };
    yesBtn.onclick = function(){ _close(true); };
    yesBtn.focus();
    o.addEventListener('keydown', function(e){
      if (e.key === 'Escape') {
        e.preventDefault();
        _close(false);
        return;
      }
      if (e.key === 'Tab') {
        var focusables = [noBtn, yesBtn];
        var idx = focusables.indexOf(document.activeElement);
        if (idx < 0) idx = 0;
        if (e.shiftKey) idx = (idx + focusables.length - 1) % focusables.length;
        else idx = (idx + 1) % focusables.length;
        e.preventDefault();
        focusables[idx].focus();
      }
    });
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
function _submitFormWithCsrf(form){
  if (!form) return;
  if (form.requestSubmit){
    form.requestSubmit();
    return;
  }
  _injectCsrf(form);
  form.submit();
}
function _bindEnterToSendComments(){
  var selectors = [
    'form[action="/manage/comment/post"] textarea[name="body"]',
    'form[action="/manage/bounty/comment"] textarea[name="body"]'
  ];
  selectors.forEach(function(sel){
    document.querySelectorAll(sel).forEach(function(ta){
      if (ta.dataset.enterSendBound === '1') return;
      ta.dataset.enterSendBound = '1';
      ta.addEventListener('keydown', function(e){
        // Match DM behavior: Enter sends, Shift+Enter inserts newline.
        if (e.key === 'Enter' && !e.shiftKey){
          // Ignore IME composition and modified-enter shortcuts.
          if (e.isComposing || e.ctrlKey || e.metaKey || e.altKey) return;
          e.preventDefault();
          if (!ta.value || !ta.value.trim()) return;
          _submitFormWithCsrf(ta.closest('form'));
        }
      });
    });
  });
}
function _bindFormLabels(){
  var i = 0;
  document.querySelectorAll('.form-group label:not([for])').forEach(function(label){
    var wrap = label.closest('.form-group');
    if (!wrap) return;
    var ctrl = wrap.querySelector('input, textarea, select');
    if (!ctrl) return;
    if (!ctrl.id) {
      i += 1;
      ctrl.id = 'auto-field-' + i;
    }
    label.setAttribute('for', ctrl.id);
  });
}
document.addEventListener('DOMContentLoaded', _bindEnterToSendComments);
document.addEventListener('DOMContentLoaded', _bindFormLabels);
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
  var btn = document.getElementById('nav-bell');
  var d = document.getElementById('notif-dropdown');
  if (!d) return;
  var opening = !d.classList.contains('open');
  d.classList.toggle('open');
  if (btn) btn.setAttribute('aria-expanded', opening ? 'true' : 'false');
  if (!opening) return;
  // Fetch fresh notifications every time the dropdown opens
  var body = d.querySelector('.notif-dropdown-body');
  fetch('/manage/notifications/preview', {credentials:'same-origin'})
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(data){
      if (!body) return;
      if (!data || !data.items || !data.items.length) {
        body.innerHTML = '<div class="notif-empty">No unread notifications</div>';
        return;
      }
      var html = '';
      data.items.forEach(function(n){
        var tname = n.torrent.length >= 40 ? n.torrent + '...' : n.torrent;
        html += '<button class="notif-item" onclick="readNotif(' + n.id + ',&#39;' + n.url + '&#39;)">'
              + '<div class="notif-item-type">' + n.icon + ' <strong>' + _esc(n.from) + '</strong> ' + _esc(n.label) + '</div>'
              + '<div class="notif-item-text"><em>' + _esc(tname) + '</em></div>'
              + '<div class="notif-item-ts">' + _esc(n.ts) + '</div>'
              + '</button>';
      });
      body.innerHTML = html;
    })
    .catch(function(){
      if (body) body.innerHTML = '<div class="notif-empty">Could not load notifications</div>';
    });
}
function _esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
document.addEventListener('click', function() {
  var btn = document.getElementById('nav-bell');
  var d = document.getElementById('notif-dropdown');
  if (d) d.classList.remove('open');
  if (btn) btn.setAttribute('aria-expanded', 'false');
});
document.addEventListener('keydown', function(e){
  if (e.key !== 'Escape') return;
  var btn = document.getElementById('nav-bell');
  var d = document.getElementById('notif-dropdown');
  if (!d || !d.classList.contains('open')) return;
  d.classList.remove('open');
  if (btn) {
    btn.setAttribute('aria-expanded', 'false');
    btn.focus();
  }
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
// ── Global background poll: updates nav bell + mail badges every 30s ─────────
(function(){
  var _prevNotifs = -1;
  var _prevMsgs   = -1;

  function _glowEl(el) {
    if (!el) return;
    el.classList.remove('notif-glow');
    // Force reflow so re-adding the class restarts the animation
    void el.offsetWidth;
    el.classList.add('notif-glow');
    el.addEventListener('animationend', function(){ el.classList.remove('notif-glow'); }, {once:true});
  }

  function _updateBell(count) {
    var btn = document.getElementById('nav-bell');
    if (!btn) return;
    var badge = btn.querySelector('.notif-count');
    if (count > 0) {
      btn.classList.remove('notif-bell-inactive');
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'notif-count';
        btn.appendChild(badge);
      }
      badge.textContent = count;
    } else {
      btn.classList.add('notif-bell-inactive');
      if (badge) badge.remove();
    }
  }

  function _updateMail(count) {
    var btn = document.getElementById('nav-mail');
    if (!btn) return;
    var badge = btn.querySelector('.notif-count');
    if (count > 0) {
      btn.classList.remove('notif-bell-inactive');
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'notif-count';
        btn.appendChild(badge);
      }
      badge.textContent = count;
    } else {
      btn.classList.add('notif-bell-inactive');
      if (badge) badge.remove();
    }
  }

  function doPoll() {
    if (document.visibilityState !== 'visible') return;
    fetch('/manage/poll', {credentials: 'same-origin'})
      .then(function(r){ return r.ok ? r.json() : null; })
      .then(function(d){
        if (!d) return;
        // Glow if count increased since last check
        if (_prevNotifs >= 0 && d.notifs > _prevNotifs)
          _glowEl(document.getElementById('nav-bell'));
        if (_prevMsgs >= 0 && d.msgs > _prevMsgs)
          _glowEl(document.getElementById('nav-mail'));
        _updateBell(d.notifs);
        _updateMail(d.msgs);
        _prevNotifs = d.notifs;
        _prevMsgs   = d.msgs;
      })
      .catch(function(){});
  }

  // Seed initial values from what the server rendered so first poll doesn't false-glow
  document.addEventListener('DOMContentLoaded', function(){
    var bell = document.getElementById('nav-bell');
    var mail = document.getElementById('nav-mail');
    if (bell) {
      var bc = bell.querySelector('.notif-count');
      _prevNotifs = bc ? parseInt(bc.textContent, 10) : 0;
    }
    if (mail) {
      var mc = mail.querySelector('.notif-count');
      _prevMsgs = mc ? parseInt(mc.textContent, 10) : 0;
    }
  });

  setInterval(doPoll, 30000);
  document.addEventListener('visibilitychange', function(){
    if (document.visibilityState === 'visible') doPoll();
  });
})();
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
            is_topup = str(n['info_hash']).upper().startswith('TOPUP:')
            is_follow = str(n['info_hash']).upper().startswith('FOLLOW:')
            if is_bounty:
                bid = str(n['info_hash']).split(':',1)[1]
                ntype = n['type']
                icon, label = {
                    'bounty_new':              ('📣', 'has posted a bounty for'),
                    'bounty_mention':          ('@',  'mentioned you in bounty'),
                    'bounty_claimed':          ('🎯', 'claimed your bounty'),
                    'bounty_rejected':         ('✗',  'rejected your claim on'),
                    'bounty_fulfilled':        ('✅', 'has accepted your bounty for'),
                    'bounty_contribution':     ('➕', 'added points to your bounty'),
                    'bounty_expired':          ('⏰', 'bounty expired:'),
                    'bounty_uploader_payout':  ('💰', 'fulfilled a bounty using your upload:'),
                    'followed_bounty_fulfilled': ('✅', 'fulfilled a bounty:'),
                }.get(ntype, ('🔔', 'bounty update on'))
                tname_h = _h(n['torrent_name'][:40] + ('…' if len(n['torrent_name']) > 40 else ''))
                from_h  = _h(n['from_username'])
                ts_h    = _h((n['created_at'] or '')[:16].replace('T', ' '))
                n_id    = n['id']
                anchor  = f'#bcmt-{n["comment_id"]}' if (ntype == 'bounty_mention' and n['comment_id']) else ''
                dropdown_items += (
                    f'<button class="notif-item" '
                    f'onclick="readNotif({n_id},\'/manage/bounty/{bid}{anchor}\')"'
                    f' aria-label="bounty notification from {from_h}">'
                    f'<div class="notif-item-type">{icon} <strong>{from_h}</strong> {label}</div>'
                    f'<div class="notif-item-text"><em>{tname_h}</em></div>'
                    f'<div class="notif-item-ts">{ts_h}</div>'
                    f'</button>'
                )
            elif is_topup:
                from_h = _h(n['from_username'])
                ts_h = _h((n['created_at'] or '')[:16].replace('T', ' '))
                n_id = n['id']
                tname_h = _h(n['torrent_name'][:60] + ('…' if len(n['torrent_name']) > 60 else ''))
                topup_label = 'top-up refunded' if n['type'] == 'topup_refunded' else 'top-up credited'
                dropdown_items += (
                    f'<button class="notif-item" '
                    f'onclick="readNotif({n_id},\'/manage/topups\')"'
                    f' aria-label="top-up notification">'
                    f'<div class="notif-item-type">💳 <strong>{from_h}</strong> {topup_label}</div>'
                    f'<div class="notif-item-text"><em>{tname_h}</em></div>'
                    f'<div class="notif-item-ts">{ts_h}</div>'
                    f'</button>'
                )
            elif is_follow:
                from_h = _h(n['from_username'])
                ts_h = _h((n['created_at'] or '')[:16].replace('T', ' '))
                n_id = n['id']
                target_url = '/manage/following'
                follow_uid = int(n['comment_id'] or 0)
                if follow_uid > 0 and REGISTRATION_DB:
                    fu = REGISTRATION_DB.get_user_by_id(follow_uid)
                    if fu:
                        target_url = f'/manage/user/{urllib.parse.quote(fu["username"])}'
                dropdown_items += (
                    f'<button class="notif-item" '
                    f'onclick="readNotif({n_id},\'{target_url}\')"'
                    f' aria-label="follow notification from {from_h}">'
                    f'<div class="notif-item-type">👥 <strong>{from_h}</strong> is now following you!</div>'
                    f'<div class="notif-item-text"><em>{_h(n["torrent_name"] or "")}</em></div>'
                    f'<div class="notif-item-ts">{ts_h}</div>'
                    f'</button>'
                )
            else:
                tname_h = _h(n['torrent_name'][:40] + ('…' if len(n['torrent_name']) > 40 else ''))
                from_h = _h(n['from_username'])
                ts_h = _h((n['created_at'] or '')[:16].replace('T', ' '))
                n_id   = n['id']
                n_hash = n['info_hash'].lower()
                if n['type'] == 'followed_upload':
                    dropdown_items += (
                        f'<button class="notif-item" '
                        f'onclick="readNotif({n_id},\'/manage/torrent/{n_hash}\')"'
                        f' aria-label="new upload by {from_h}">'
                        f'<div class="notif-item-type">📦 <strong>{from_h}</strong> uploaded a new torrent</div>'
                        f'<div class="notif-item-text"><em>{tname_h}</em></div>'
                        f'<div class="notif-item-ts">{ts_h}</div>'
                        f'</button>'
                    )
                else:
                    icon = '💬' if n['type'] == 'reply' else '@'
                    label = 'replied to your comment' if n['type'] == 'reply' else 'mentioned you'
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
            f'<button id="nav-bell" class="{bell_cls}" onclick="toggleNotifDropdown(event)" aria-label="Notifications" aria-haspopup="true" aria-controls="notif-dropdown" aria-expanded="false">'
            f'🔔{badge_html}</button>'
            f'<div class="notif-dropdown" id="notif-dropdown">'
            f'<div class="notif-dropdown-header">'
            f'<span class="notif-dropdown-title">Notifications</span>'
            f'</div>'
            f'<div class="notif-dropdown-body">{dropdown_items}</div>'
            f'<div class="notif-footer"><a href="/manage/notifications">View all notifications</a></div>'
            f'</div></div>'
        )
        unread_dm = REGISTRATION_DB.get_unread_dm_count(user['username']) if REGISTRATION_DB else 0
        dm_badge  = f'<span class="notif-count">{unread_dm}</span>' if unread_dm else ''
        dm_cls    = 'notif-bell-btn' if unread_dm else 'notif-bell-btn notif-bell-inactive'
        mail_html = (f'<a id="nav-mail" href="/manage/messages" class="{dm_cls}" '
                     f'style="text-decoration:none" aria-label="Messages">'
                     f'📬{dm_badge}</a>') if role != 'basic' else ''
        nav_avatar = _avatar_html(user, 22)
        nav = (f'<a href="/manage/profile" class="nav-user" style="text-decoration:none;display:inline-flex;align-items:center;gap:8px">'
               f'{nav_avatar}<span class="nav-username">{_h(user["username"])}</span> '
               f'<span class="badge badge-{role}">{role_label}</span></a>'
               + mail_html + bell_html +
               f'<a href="/manage/logout" class="btn btn-sm">Logout</a>')
        center_nav = (
            '<a href="/manage/dashboard" class="nav-btn">🖥 Dashboard</a>'
            '<a href="/manage/search" class="nav-btn">🔍 Search</a>'
            '<a href="/manage/following" class="nav-btn">👥 Following</a>'
            + ('' if role == 'basic' else
               '<a href="/manage/bounty" class="nav-btn">🎯 Bounties</a>'
               '<a href="/manage/leaderboard" class="nav-btn">🏆 Leaderboard</a>')
            + (f'<a href="/manage/topups" class="nav-btn">💳 Top-ups</a>'
               if REGISTRATION_DB and REGISTRATION_DB.topup_enabled_for_user(user) else '')
        )
    else:
        nav = ''
        center_nav = ''

    alert = ''
    if msg:
        cls = 'alert-error' if msg_type == 'error' else 'alert-success'
        prefix = '⚠️ ' if msg_type == 'error' else '✅ '
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


def _render_login(msg: str = '', msg_type: str = 'error') -> str:
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
    return _manage_page('Login', body, msg=msg, msg_type=msg_type)


def _render_account_delete_confirm_page(user, remaining_sec: int,
                                        msg: str = '', msg_type: str = 'error') -> str:
    mins = max(0, int(remaining_sec // 60))
    secs = max(0, int(remaining_sec % 60))
    timer = f'{mins}m {secs}s'
    countdown_js = (
        '<script>'
        '(function(){'
        f'var remain={max(0, int(remaining_sec))};'
        'var el=document.getElementById("delete-expire-timer");'
        'if(!el)return;'
        'function tick(){'
        'if(remain<0)remain=0;'
        'var m=Math.floor(remain/60);'
        'var s=remain%60;'
        'el.textContent=m+"m "+s+"s";'
        'if(remain===0){return;}'
        'remain-=1;'
        'setTimeout(tick,1000);'
        '}'
        'tick();'
        '})();'
        '</script>'
    )
    body = (
        '<div style="max-width:560px;margin:40px auto">'
        '<div class="page-title">Confirm Account Deletion</div>'
        '<div class="page-sub">Final step - this action is irreversible.</div>'
        '<div class="card">'
        '<div style="padding:10px 12px;background:var(--danger)22;border:1px solid var(--danger);'
        'border-radius:8px;color:var(--danger);margin-bottom:14px;font-size:0.9rem">'
        'You must complete this confirmation before the deletion challenge expires.'
        f' Time remaining: <strong id="delete-expire-timer">{timer}</strong>.'
        '</div>'
        '<form method="POST" action="/manage/account/delete/confirm" style="display:flex;flex-direction:column;gap:12px">'
        '<div class="form-group">'
        '<label>Re-enter Password</label>'
        '<input type="password" name="password" autocomplete="current-password" required>'
        '</div>'
        '<div class="form-group">'
        '<label>Type exactly: DELETE MY ACCOUNT</label>'
        '<input type="text" name="delete_phrase" autocomplete="off" required placeholder="DELETE MY ACCOUNT">'
        '</div>'
        '<div style="display:flex;gap:8px;flex-wrap:wrap">'
        '<button type="submit" class="btn btn-danger" '
        'onclick="return confirm(\'Last chance: your account will be permanently deleted. Continue?\')">Delete Permanently</button>'
        '</form>'
        '<form method="POST" action="/manage/account/delete/cancel" style="display:inline">'
        '<button type="submit" class="btn btn-sm">Cancel</button>'
        '</form>'
        '</div>'
        '</div>'
        + countdown_js +
        '</div>'
    )
    return _manage_page('Confirm Deletion', body, user=user, msg=msg, msg_type=msg_type)


def _render_goodbye_page() -> str:
    body = (
        '<div style="max-width:560px;margin:60px auto">'
        '<div class="page-title">Goodbye</div>'
        '<div class="card">'
        '<p style="margin-bottom:10px">Your account has been deleted.</p>'
        '<p style="color:var(--muted);margin-bottom:18px">If this was not expected, contact the operator.</p>'
        '<a href="/manage" class="btn btn-primary">Return to Sign In</a>'
        '</div>'
        '</div>'
    )
    return _manage_page('Goodbye', body)


def _fmt_size(b: int) -> str:
    """Human-friendly file size."""
    if b == 0: return '--'
    if b < 1024: return f'{b} B'
    if b < 1024**2: return f'{b/1024:.1f} KB'
    if b < 1024**3: return f'{b/1024**2:.1f} MB'
    return f'{b/1024**3:.2f} GB'


def _torrent_header(show_owner: bool = False, hide_info_hash: bool = False) -> str:
    if hide_info_hash:
        if show_owner:
            # 5 cols: 58+12+8+10+12 = 100%
            return (
                '<tr>'
                '<th scope="col" style="width:58%">Name</th>'
                '<th scope="col" style="width:12%">Owner</th>'
                '<th scope="col" style="width:8%;white-space:nowrap">Size</th>'
                '<th scope="col" style="width:10%;white-space:nowrap">Registered</th>'
                '<th scope="col" style="width:12%;min-width:100px">Action</th>'
                '</tr>'
            )
        # 4 cols: 72+8+8+12 = 100%
        return (
            '<tr>'
            '<th scope="col" style="width:72%">Name</th>'
            '<th scope="col" style="width:8%;white-space:nowrap">Size</th>'
            '<th scope="col" style="width:8%;white-space:nowrap">Registered</th>'
            '<th scope="col" style="width:12%;min-width:100px">Action</th>'
            '</tr>'
        )
    if show_owner:
        # 6 cols: 39+21+10+8+10+12 = 100%
        return (
            '<tr>'
            '<th scope="col" style="width:39%">Name</th>'
            '<th scope="col" style="width:21%">Info Hash</th>'
            '<th scope="col" style="width:10%">Owner</th>'
            '<th scope="col" style="width:8%;white-space:nowrap">Size</th>'
            '<th scope="col" style="width:10%;white-space:nowrap">Registered</th>'
            '<th scope="col" style="width:12%;min-width:100px">Action</th>'
            '</tr>'
        )
    # 5 cols: 44+28+8+8+12 = 100%
    return (
        '<tr>'
        '<th scope="col" style="width:44%">Name</th>'
        '<th scope="col" style="width:28%">Info Hash</th>'
        '<th scope="col" style="width:8%;white-space:nowrap">Size</th>'
        '<th scope="col" style="width:8%;white-space:nowrap">Registered</th>'
        '<th scope="col" style="width:12%;min-width:100px">Action</th>'
        '</tr>'
    )


def _torrent_row(t, viewer_role: str, viewer_id: int,
                 show_owner: bool = False, show_delete: bool = True,
                 hide_info_hash: bool = False) -> str:
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

    info_hash_td = '' if hide_info_hash else f'<td class="hash" style="word-break:break-all">{ih}</td>'
    return (
        f'<tr data-name="{name_lower}">'
        f'<td style="word-break:break-word;overflow-wrap:anywhere"><a href="/manage/torrent/{ih}" class="user-link">{name_esc}</a></td>'
        f'{info_hash_td}'
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
        _torrent_row(t, srole, user['id'], show_owner=is_admin, show_delete=False,
                     hide_info_hash=True)
        for t in torrents
    )
    if not t_rows:
        cols = 5 if is_admin else 4
        t_rows = f'<tr><td colspan="{cols}" class="empty">No results found</td></tr>'

    q_enc = urllib.parse.quote(query)
    pagination = _pagination_html(page, total_pages, f'/manage/search?q={q_enc}')

    body = f'''
  <div class="page-title">🔍 Search Torrents</div>
  <div class="page-sub"><a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a></div>
  <div class="card" style="margin-bottom:0">
    <form method="GET" action="/manage/search" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
      <div class="form-group" style="flex:1;margin:0;min-width:240px">
        <label for="search-q">Search by name or info hash</label>
        <input id="search-q" type="text" name="q" value="{query}" placeholder="Enter name or hash..." autofocus
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
      {_torrent_header(show_owner=is_admin, hide_info_hash=True)}
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
        _torrent_row(t, viewer_role, user['id'], show_owner=is_standard, show_delete=is_super,
                     hide_info_hash=True)
        for t in torrents
    )
    if not torrent_rows:
        cols = 5 if is_standard else 4
        torrent_rows = f'<tr><td colspan="{cols}" class="empty">No torrents registered yet</td></tr>'

    admin_link = (
        '<a href="/manage/admin" class="dash-nav-btn">&#9881;&#65039; Admin Panel</a>'
        if is_admin else '')
    search_link = '<a href="/manage/search" class="dash-nav-btn">&#128269; Search</a>'
    try:
        max_content_mb = int(REGISTRATION_DB.get_setting('upload_max_content_mb', '100')) if REGISTRATION_DB else 100
    except Exception:
        max_content_mb = 100
    try:
        max_files = int(REGISTRATION_DB.get_setting('upload_max_files', '1000')) if REGISTRATION_DB else 1000
    except Exception:
        max_files = 1000
    try:
        max_file_mb = int(REGISTRATION_DB.get_setting('upload_max_file_mb', '10')) if REGISTRATION_DB else 10
    except Exception:
        max_file_mb = 10
    upload_limits_hint = (f'Limits: {max_content_mb} MB/request \u2022 '
                          f'{max_files} files/upload \u2022 '
                          f'{max_file_mb} MB/file')

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
          <label for="dash-upload-torrent">Torrent File (.torrent)</label>
          <input id="dash-upload-torrent" type="file" name="torrent" accept=".torrent" multiple required>
          <div style="color:var(--muted);font-size:0.82rem;margin-top:6px">{upload_limits_hint}</div>
        </div>
        <div style="display:flex;align-items:flex-start;padding-top:32px">
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
      {_torrent_header(is_standard, hide_info_hash=True)}
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
    upload_max_content_mb = settings.get('upload_max_content_mb', '100')
    upload_max_files = settings.get('upload_max_files', '1000')
    upload_max_file_mb = settings.get('upload_max_file_mb', '10')
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
      <div class="card">
        <div class="card-title">Upload Limits</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Configure request and file limits for torrent uploads. Requests over the
          content-size limit are rejected with HTTP 413. Files beyond the per-upload
          cap are skipped, and valid files before the cap are still processed.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="upload_limits">
          <div class="form-group">
            <label>Max request size (MB)</label>
            <input type="number" name="upload_max_content_mb" value="{upload_max_content_mb}"
                   min="1" max="2048" style="width:120px">
          </div>
          <div class="form-group">
            <label>Max files per upload</label>
            <input type="number" name="upload_max_files" value="{upload_max_files}"
                   min="1" max="50000" style="width:120px">
          </div>
          <div class="form-group">
            <label>Max file size (MB)</label>
            <input type="number" name="upload_max_file_mb" value="{upload_max_file_mb}"
                   min="1" max="1024" style="width:120px">
          </div>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">Gravatar Integration</div>
        <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
          Allows members to opt in to Gravatar avatars. The tracker stores only an MD5
          hash value provided from the profile form, never the raw email address.
        </p>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="gravatar_settings">
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:16px">
            <input type="checkbox" name="gravatar_enabled" value="1" {'checked' if settings.get('gravatar_enabled','0')=='1' else ''}> Enable Gravatar avatars
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

    # ── Top-up admin HTML ────────────────────────────────────
    _topup_cfg = REGISTRATION_DB.get_topup_config() if REGISTRATION_DB else {}
    _topup_stats = REGISTRATION_DB.get_topup_stats() if REGISTRATION_DB else {}
    _topup_orders = REGISTRATION_DB.list_topup_orders(limit=200) if REGISTRATION_DB else []
    _topup_hooks = REGISTRATION_DB.list_topup_webhook_events(limit=200) if REGISTRATION_DB else []
    _topup_rows = ''
    for o in _topup_orders:
        _u = REGISTRATION_DB.get_user_by_id(o['user_id']) if REGISTRATION_DB else None
        _uname = _h(_u['username']) if _u else f'user-{o["user_id"]}'
        _user_cell = (f'<a href="/manage/user/{_uname}" class="user-link">{_uname}</a>'
                      if _u else f'<span class="hash">{_uname}</span>')
        _status = _h(o['status'])
        _badge_color = {
            'credited': 'var(--green)',
            'confirmed': 'var(--accent)',
            'pending': 'var(--muted)',
            'created': 'var(--muted)',
            'expired': 'var(--danger)',
            'failed': 'var(--danger)',
            'exception': 'var(--danger)',
        }.get(o['status'], 'var(--muted)')
        _status_badge = (f'<span style="display:inline-block;padding:2px 8px;border:1px solid {_badge_color};'
                         f'color:{_badge_color};font-size:0.7rem;font-family:var(--mono)">{_status.upper()}</span>')
        _actions = (
            f'<form method="POST" action="/manage/admin/topup/reconcile" style="display:inline">'
            f'<input type="hidden" name="order_id" value="{o["id"]}">'
            f'<input type="hidden" name="action" value="mark_confirmed">'
            f'<button class="btn btn-sm">Confirm</button></form>'
            f'<form method="POST" action="/manage/admin/topup/reconcile" style="display:inline">'
            f'<input type="hidden" name="order_id" value="{o["id"]}">'
            f'<input type="hidden" name="action" value="mark_credited">'
            f'<button class="btn btn-sm btn-green">Credit</button></form>'
            f'<form method="POST" action="/manage/admin/topup/reconcile" style="display:inline">'
            f'<input type="hidden" name="order_id" value="{o["id"]}">'
            f'<input type="hidden" name="action" value="mark_exception">'
            f'<button class="btn btn-sm btn-danger">Exception</button></form>'
        )
        _topup_rows += (
            f'<tr id="topup-order-{o["id"]}">'
            f'<td class="hash">#{o["id"]}</td>'
            f'<td class="hash">{_h((o["provider"] or "").upper() or "COINBASE")}</td>'
            f'<td>{_user_cell}</td>'
            f'<td>${o["amount_usd_cents"]/100:.2f}</td>'
            f'<td style="color:var(--accent)">{o["quoted_points"]} pts</td>'
            f'<td>{_status_badge}</td>'
            f'<td class="hash">{(o["updated_at"] or "")[:16].replace("T"," ")}</td>'
            f'<td><div class="actions">{_actions}</div></td>'
            '</tr>'
        )
    if not _topup_rows:
        _topup_rows = '<tr><td colspan="8" class="empty">No top-up orders yet</td></tr>'
    _hook_rows = ''
    for h in _topup_hooks:
        _hook_rows += (
            '<tr>'
            f'<td class="hash">#{h["id"]}</td>'
            f'<td class="hash">{_h((h["received_at"] or "")[:16].replace("T"," "))}</td>'
            f'<td>{_h(h["event_type"])}</td>'
            f'<td>{_h(h["event_id"] or "-")}</td>'
            f'<td>{_h(h["process_status"])}</td>'
            f'<td class="hash">{_h(str(h["linked_order_id"] or ""))}</td>'
            '</tr>'
        )
    if not _hook_rows:
        _hook_rows = '<tr><td colspan="6" class="empty">No webhook events recorded</td></tr>'
    _topup_fixed_csv = ', '.join(str(v) for v in _topup_cfg.get('fixed_amounts_usd', [5, 10, 25, 50, 100]))
    _topup_bands_csv = ', '.join(
        f'{b["min_usd"]}:{b["multiplier_bp"]/10000:.2f}'
        for b in _topup_cfg.get('multiplier_bands', [{'min_usd': 5, 'multiplier_bp': 10000}])
    )
    topups_html = f'''
    <div class="card" style="margin-bottom:16px">
      <div class="card-title">Top-up Overview</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px">
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.3rem;font-weight:700;color:var(--green)">{_topup_stats.get("credited_orders",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Credited Orders</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.3rem;font-weight:700;color:var(--accent)">{_topup_stats.get("pending_orders",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Pending/Confirmed</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.3rem;font-weight:700;color:var(--danger)">{_topup_stats.get("exception_orders",0)}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Exceptions</div>
        </div>
        <div style="background:var(--card2);padding:12px;border-radius:8px;text-align:center">
          <div style="font-size:1.3rem;font-weight:700;color:var(--text)">${_topup_stats.get("usd_credited_cents",0)/100:.2f}</div>
          <div style="font-size:0.78rem;color:var(--muted)">Credited USD</div>
        </div>
      </div>
    </div>
    <div class="two-col">
      <div class="card">
        <div class="card-title">Top-up Settings</div>
        <form method="POST" action="/manage/admin/save-settings">
          <input type="hidden" name="form_id" value="topup_settings">
          <div class="form-group">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input type="checkbox" name="topup_enabled" value="1" {'checked' if _topup_cfg.get('enabled') else ''}> Enable top-up system
            </label>
          </div>
          <div class="form-group"><label>Rollout mode</label>
            <select name="topup_rollout_mode" style="width:100%;padding:8px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text)">
              <option value="admin_only" {'selected' if _topup_cfg.get('rollout_mode') == 'admin_only' else ''}>Admin only (staging)</option>
              <option value="all_users" {'selected' if _topup_cfg.get('rollout_mode') == 'all_users' else ''}>All users</option>
            </select>
          </div>
          <div class="form-group"><label>Default Processor</label>
            <select name="topup_provider" style="width:100%;padding:8px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text)">
              <option value="coinbase" {'selected' if _topup_cfg.get('provider','coinbase') == 'coinbase' else ''}>coinbase</option>
              <option value="paypal" {'selected' if _topup_cfg.get('provider','coinbase') == 'paypal' else ''}>paypal</option>
            </select></div>
          <div class="card-title" style="margin-top:10px">Coinbase</div>
          <div class="form-group"><label>Coinbase processor</label>
            <div style="display:flex;gap:14px;flex-wrap:wrap">
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
                <input type="radio" name="topup_coinbase_enabled" value="1" {'checked' if _topup_cfg.get('coinbase_enabled') else ''}> Enabled
              </label>
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
                <input type="radio" name="topup_coinbase_enabled" value="0" {'checked' if not _topup_cfg.get('coinbase_enabled') else ''}> Disabled
              </label>
            </div>
          </div>
          <div class="form-group"><label>Coinbase environment</label>
            <select name="topup_coinbase_env" style="width:100%;padding:8px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text)">
              <option value="sandbox" {'selected' if _topup_cfg.get('coinbase_env') == 'sandbox' else ''}>sandbox</option>
              <option value="live" {'selected' if _topup_cfg.get('coinbase_env') == 'live' else ''}>live</option>
            </select></div>
          <div class="form-group"><label>Coinbase API key (sandbox)</label>
            <input type="text" name="topup_coinbase_api_key_sandbox" value="{_h(_topup_cfg.get('coinbase_api_key_sandbox',''))}" placeholder="sandbox API key"></div>
          <div class="form-group"><label>Coinbase webhook secret (sandbox)</label>
            <input type="text" name="topup_coinbase_webhook_secret_sandbox" value="{_h(_topup_cfg.get('coinbase_webhook_secret_sandbox',''))}" placeholder="sandbox webhook secret"></div>
          <div class="form-group"><label>Coinbase API key (live)</label>
            <input type="text" name="topup_coinbase_api_key_live" value="{_h(_topup_cfg.get('coinbase_api_key_live',''))}" placeholder="live API key"></div>
          <div class="form-group"><label>Coinbase webhook secret (live)</label>
            <input type="text" name="topup_coinbase_webhook_secret_live" value="{_h(_topup_cfg.get('coinbase_webhook_secret_live',''))}" placeholder="live webhook secret"></div>
          <div class="form-group"><label>Coinbase create endpoint URL</label>
            <input type="text" name="topup_coinbase_create_url" value="{_h(_topup_cfg.get('coinbase_create_url',''))}" placeholder="https://api.commerce.coinbase.com/charges"></div>
          <div class="form-group">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input type="checkbox" name="topup_auto_redirect_checkout" value="1" {'checked' if _topup_cfg.get('auto_redirect_checkout') else ''}> Auto-redirect user to Coinbase after order creation
            </label>
          </div>
          <div class="card-title" style="margin-top:10px">PayPal</div>
          <p style="color:var(--muted);font-size:0.78rem;margin:0 0 10px">Webhook verification can be enforced (recommended) or disabled (insecure open mode). If enforced and PayPal is enabled, webhook ID is required for the active PayPal environment.</p>
          <div class="form-group"><label>PayPal processor</label>
            <div style="display:flex;gap:14px;flex-wrap:wrap">
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
                <input type="radio" name="topup_paypal_enabled" value="1" {'checked' if _topup_cfg.get('paypal_enabled') else ''}> Enabled
              </label>
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
                <input type="radio" name="topup_paypal_enabled" value="0" {'checked' if not _topup_cfg.get('paypal_enabled') else ''}> Disabled
              </label>
            </div>
          </div>
          <div class="form-group"><label>PayPal webhook verification</label>
            <div style="display:flex;gap:14px;flex-wrap:wrap">
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
                <input type="radio" name="topup_paypal_webhook_enforce" value="1" {'checked' if _topup_cfg.get('paypal_webhook_enforce', True) else ''}> Enforce (Recommended)
              </label>
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
                <input type="radio" name="topup_paypal_webhook_enforce" value="0" {'checked' if not _topup_cfg.get('paypal_webhook_enforce', True) else ''}> Allow unsigned (Insecure)
              </label>
            </div>
          </div>
          <div class="form-group"><label>PayPal environment</label>
            <select name="topup_paypal_env" style="width:100%;padding:8px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text)">
              <option value="sandbox" {'selected' if _topup_cfg.get('paypal_env') == 'sandbox' else ''}>sandbox</option>
              <option value="live" {'selected' if _topup_cfg.get('paypal_env') == 'live' else ''}>live</option>
            </select></div>
          <div class="form-group"><label>PayPal client id (sandbox)</label>
            <input type="text" name="topup_paypal_client_id_sandbox" value="{_h(_topup_cfg.get('paypal_client_id_sandbox',''))}" placeholder="PayPal sandbox client id"></div>
          <div class="form-group"><label>PayPal client secret (sandbox)</label>
            <input type="text" name="topup_paypal_client_secret_sandbox" value="{_h(_topup_cfg.get('paypal_client_secret_sandbox',''))}" placeholder="PayPal sandbox client secret"></div>
          <div class="form-group"><label>PayPal webhook id (sandbox)</label>
            <input type="text" name="topup_paypal_webhook_id_sandbox" value="{_h(_topup_cfg.get('paypal_webhook_id_sandbox',''))}" placeholder="sandbox webhook id"></div>
          <div class="form-group"><label>PayPal client id (live)</label>
            <input type="text" name="topup_paypal_client_id_live" value="{_h(_topup_cfg.get('paypal_client_id_live',''))}" placeholder="PayPal live client id"></div>
          <div class="form-group"><label>PayPal client secret (live)</label>
            <input type="text" name="topup_paypal_client_secret_live" value="{_h(_topup_cfg.get('paypal_client_secret_live',''))}" placeholder="PayPal live client secret"></div>
          <div class="form-group"><label>PayPal webhook id (live)</label>
            <input type="text" name="topup_paypal_webhook_id_live" value="{_h(_topup_cfg.get('paypal_webhook_id_live',''))}" placeholder="live webhook id"></div>
          <div style="display:flex;gap:12px;flex-wrap:wrap">
            <div class="form-group"><label>API timeout (sec)</label>
              <input type="number" min="3" max="120" name="topup_provider_request_timeout_sec" value="{_topup_cfg.get('provider_request_timeout_sec',15)}" style="width:100px"></div>
            <div class="form-group"><label>Pending SLA (minutes)</label>
              <input type="number" min="5" max="10080" name="topup_pending_sla_minutes" value="{_topup_cfg.get('pending_sla_minutes',180)}" style="width:120px"></div>
          </div>
          <div class="form-group"><label>Base rate (points per USD)</label>
            <input type="number" min="1" max="100000" name="topup_base_rate_pts_per_usd" value="{_topup_cfg.get('base_rate_pts_per_usd',200)}" style="width:140px"></div>
          <div class="form-group"><label>Fixed amounts (USD, comma-separated)</label>
            <input type="text" name="topup_fixed_amounts" value="{_h(_topup_fixed_csv)}"></div>
          <div class="form-group"><label>Multiplier bands (min:multiplier, comma-separated)</label>
            <input type="text" name="topup_multiplier_bands" value="{_h(_topup_bands_csv)}" placeholder="5:1.00,10:1.25"></div>
          <button type="submit" class="btn btn-primary">Save Top-up Settings</button>
        </form>
      </div>
      <div class="card">
        <div class="card-title">Quote Preview</div>
        <table>
          <tr><th scope="col">Amount</th><th scope="col">Multiplier</th><th scope="col">Quoted Points</th></tr>
          {''.join(f'<tr><td>${amt}</td><td>{REGISTRATION_DB.quote_topup_points(amt)["multiplier_bp"]/10000:.2f}x</td><td style="color:var(--accent)">{REGISTRATION_DB.quote_topup_points(amt)["quoted_points"]}</td></tr>' for amt in _topup_cfg.get("fixed_amounts_usd",[5,10,25,50,100]))}
        </table>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Top-up Orders</div>
      <div class="table-wrap"><table>
        <tr><th scope="col">Order</th><th scope="col">Processor</th><th scope="col">User</th><th scope="col">Amount</th><th scope="col">Quoted</th><th scope="col">Status</th><th scope="col">Updated</th><th scope="col">Actions</th></tr>
        {_topup_rows}
      </table></div>
    </div>
    <div class="card">
      <div class="card-title">Webhook Events</div>
      <div class="table-wrap"><table>
        <tr><th scope="col">ID</th><th scope="col">Received</th><th scope="col">Type</th><th scope="col">Event ID</th><th scope="col">Process</th><th scope="col">Order</th></tr>
        {_hook_rows}
      </table></div>
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
        elif 'bounty' in action or 'points' in action or 'spend' in action or 'topup' in action:
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
    _tab_topups    = ('<button class="tab" onclick="showTab(\'topups\',this)">Top-ups</button>'
                      if is_super else '')
    _tab_invites   = ('<button class="tab" onclick="showTab(\'invites\',this)">Invites</button>'
                      if (is_super or user['is_admin']) else '')
    _tab_danger    = ('<button class="tab tab-danger" onclick="showTab(\'danger\',this)"'
                      '>Danger</button>'
                      if is_super else '')
    _tab_names = ['torrents','users','adduser','trackers','settings','database','economy','topups','invites','danger','events']
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

    _peer_enabled = settings.get('peer_query_enabled', '0') == '1'
    _peer_tracker = _h(settings.get('peer_query_tracker', 'http://tracker.opentrackr.org:1337/announce'))
    _peer_tool = _h(settings.get('peer_query_tool', '/opt/tracker/tracker_query.py'))
    _peer_args = _h(settings.get('peer_query_args', '-o json -s -r -H {hash} -t {tracker}'))
    _peer_retries = _h(settings.get('peer_query_retries', '3'))
    _peer_wait = _h(settings.get('peer_query_retry_wait_sec', '2'))
    _peer_auto_upload = settings.get('peer_query_auto_on_upload', '0') == '1'
    _peer_auto_cap = _h(settings.get('peer_query_auto_upload_cap', '5'))
    _peer_disabled_attr = '' if is_super else 'disabled'
    _peer_save_cta = ('<button type="submit" class="btn btn-primary">Save Peer Query Settings</button>'
                      if is_super else
                      '<div style="font-size:0.82rem;color:var(--muted)">Only superuser can change these settings.</div>')
    peer_query_card = f'''
    <div class="card">
      <div class="card-title">Torrent Seeds/Peers Query</div>
      <p style="font-size:0.88rem;color:var(--muted);margin-bottom:16px">
        Configure a command that returns JSON peer stats for a torrent hash. Updates are manual per torrent and
        allowed once every 3 hours.
      </p>
      <form method="POST" action="/manage/admin/save-settings">
        <input type="hidden" name="form_id" value="peer_query_settings">
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:12px">
          <input type="checkbox" name="peer_query_enabled" value="1" {'checked' if _peer_enabled else ''} {_peer_disabled_attr}>
          Enable seeds/peers query updates
        </label>
        <div class="form-group">
          <label>Scrape Input (announce URL)</label>
          <input type="text" name="peer_query_tracker" value="{_peer_tracker}"
                 placeholder="http://tracker.opentrackr.org:1337/announce" {_peer_disabled_attr}>
        </div>
        <div class="form-group">
          <label>Tracker Query Tool Path</label>
          <input type="text" name="peer_query_tool" value="{_peer_tool}"
                 placeholder="/opt/tracker/tracker_query.py" {_peer_disabled_attr}>
        </div>
        <div class="form-group">
          <label>Tracker Query Arguments</label>
          <input type="text" name="peer_query_args" value="{_peer_args}"
                 placeholder="-o json -s -r -H {{hash}} -t {{tracker}}" {_peer_disabled_attr}>
          <div style="color:var(--muted);font-size:0.8rem;margin-top:6px">
            Example: -o json -s -r -H {{hash}} -t {{tracker}}
          </div>
        </div>
        <div style="display:flex;gap:12px;flex-wrap:wrap">
          <div class="form-group" style="min-width:160px">
            <label>Retry Attempts</label>
            <input type="number" name="peer_query_retries" value="{_peer_retries}" min="1" max="10" {_peer_disabled_attr}>
          </div>
          <div class="form-group" style="min-width:160px">
            <label>Retry Wait (sec)</label>
            <input type="number" name="peer_query_retry_wait_sec" value="{_peer_wait}" min="0" max="30" {_peer_disabled_attr}>
          </div>
          <div class="form-group" style="min-width:180px">
            <label>Auto update cap per upload</label>
            <input type="number" name="peer_query_auto_upload_cap" value="{_peer_auto_cap}" min="1" max="50" {_peer_disabled_attr}>
          </div>
        </div>
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:12px">
          <input type="checkbox" name="peer_query_auto_on_upload" value="1" {'checked' if _peer_auto_upload else ''} {_peer_disabled_attr}>
          Auto-run peer updates on successful uploads (up to cap)
        </label>
        <div style="font-size:0.8rem;color:var(--muted);margin:6px 0 14px 0">
          Saving fails if the tool path does not exist. Enabling requires all fields plus both placeholders: {{hash}}, {{tracker}}.
        </div>
        {_peer_save_cta}
      </form>
    </div>'''

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
    {_tab_topups}
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
    {peer_query_card}
  </div>

  {'<div class="panel" id="panel-settings">' + settings_html + '</div>' if is_super else ''}
  {'<div class="panel" id="panel-database">' + database_html + '</div>' if is_super else ''}
  {'<div class="panel" id="panel-economy">' + economy_html + '</div>' if is_super else ''}
  {'<div class="panel" id="panel-topups">' + topups_html + '</div>' if is_super else ''}
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
            <input type="text" name="eactor" value="{_h(eactor)}" placeholder="e.g. thomas"
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
            <input type="text" name="etarget" value="{_h(etarget)}" placeholder="e.g. patrick"
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

def _deliver_bounty_comment_notifications(comment_id: int, bounty_id: int,
                                          bounty_desc: str, uname: str, text: str):
    """Send @mention notifications for bounty comments."""
    if not REGISTRATION_DB:
        return
    mentioned = set(_MENTION_RE.findall(text))
    poster = REGISTRATION_DB.get_user(uname)
    poster_id = poster['id'] if poster else -1
    for mname in mentioned:
        if mname == uname:
            continue
        muser = REGISTRATION_DB.get_user(mname)
        if muser and muser['id'] != poster_id and not muser['is_disabled']:
            REGISTRATION_DB._notify_bounty(
                mname, 'bounty_mention', uname, bounty_id, bounty_desc, comment_id
            )

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
        unread_count = m['unread_count'] if 'unread_count' in m.keys() else 0
        msg_count    = m['msg_count']    if 'msg_count'    in m.keys() else 1
        is_unread    = unread_count > 0 and mode == 'inbox'
        last_ts      = (m['last_activity'] if 'last_activity' in m.keys() else None) or (m['sent_at'] if 'sent_at' in m.keys() else '') or ''
        other   = m['sender'] if mode == 'inbox' else m['recipient']
        subj    = _h(((m['subject'] if 'subject' in m.keys() else '') or '')[:60] or '(no subject)')
        ts      = _h(last_ts[:16].replace('T', ' '))
        bold    = 'font-weight:700;' if is_unread else ''
        conv_id = m['conversation_id'] if 'conversation_id' in m.keys() and m['conversation_id'] else m['id']
        badge   = (f'<span style="background:var(--accent);color:#000;font-size:0.65rem;'
                   f'padding:1px 5px;border-radius:3px;margin-left:6px">{unread_count} NEW</span>') if is_unread else ''
        count_badge = (f'<span style="color:var(--muted);font-size:0.75rem;margin-left:6px">[{msg_count}]</span>') if msg_count > 1 else ''
        bcast   = ('<span style="background:var(--blue);color:#fff;font-size:0.65rem;'
                   'padding:1px 5px;border-radius:3px;margin-left:4px">BROADCAST</span>') if (m['is_broadcast'] if 'is_broadcast' in m.keys() else 0) else ''
        trash = (
            f'<form method="POST" action="/manage/messages/delete-conversation"'
            f' style="display:inline"'
            f' data-confirm="Delete this conversation? This cannot be undone.">'
            f'<input type="hidden" name="conversation_id" value="{conv_id}">'
            f'<button type="submit" class="btn btn-sm"'
            f' style="background:transparent;border:none;color:var(--muted);padding:4px 6px;'
            f'cursor:pointer;font-size:1rem;line-height:1" title="Delete conversation"'
            f' onmouseover="this.style.color=\'var(--danger)\'" onmouseout="this.style.color=\'var(--muted)\'">'
            f'&#x1F5D1;</button></form>'
        )
        return (f'<tr>'
                f'<td style="{bold}padding:8px 10px;cursor:pointer" onclick="location.href=\'/manage/messages/{conv_id}\'">{_h(other)}{bcast}</td>'
                f'<td style="{bold}padding:8px 10px;cursor:pointer" onclick="location.href=\'/manage/messages/{conv_id}\'">{subj}{count_badge}{badge}</td>'
                f'<td style="padding:8px 10px;color:var(--muted);white-space:nowrap;cursor:pointer" onclick="location.href=\'/manage/messages/{conv_id}\'">{ts}</td>'
                f'<td style="padding:4px 6px;text-align:right;white-space:nowrap">{trash}</td>'
                f'</tr>')

    inbox_rows = (''.join(_row(m, 'inbox') for m in inbox)
                  or '<tr><td colspan="4" style="padding:20px;text-align:center;'
                     'color:var(--muted)">No messages</td></tr>')
    sent_rows  = (''.join(_row(m, 'sent') for m in sent)
                  or '<tr><td colspan="4" style="padding:20px;text-align:center;'
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
                f'<th style="padding:8px 10px"></th>'
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
        f'<input type="hidden" name="form_scope" value="messages_quick">'
        
        f'<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.9rem">'
        f'<input type="checkbox" name="allow_dms" value="1" {allow_checked} onchange="_submitFormWithCsrf(this.form)">'
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
    # ── Compute presence now so profile_link dot renders correctly on first load ──
    other_user_row  = REGISTRATION_DB.get_user(other_party) if (other_party and REGISTRATION_DB) else None
    presence_status = _online_status(other_user_row)
    presence_dot    = _online_dot_html(presence_status)
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
                    f'<button class="btn btn-sm btn-danger">'
                    f'&#x1F6AB; Block {opu}</button></form>')

    profile_link = ''
    if other_party:
        opu = _h(other_party)
        dot_html = (f'<span id="dm-presence-dot" title="{{}}" '
                    f'style="display:inline-block;width:8px;height:8px;border-radius:50%;'
                    f'background:{{}};vertical-align:middle;margin-right:4px"></span>')
        # Set initial color based on current presence
        init_color = {'online':'var(--green)','recent':'var(--accent)','offline':'var(--border)','hidden':''}.get(presence_status, 'var(--border)')
        init_tip   = {'online':'Online now','recent':'Recently active','offline':'Offline','hidden':''}.get(presence_status, '')
        init_dot   = (f'<span id="dm-presence-dot" title="{init_tip}" '
                      f'style="display:{"none" if presence_status == "hidden" else "inline-block"};'
                      f'width:8px;height:8px;border-radius:50%;background:{init_color};'
                      f'vertical-align:middle;margin-right:4px"></span>') if presence_status != 'hidden' else ''
        profile_link = (f' &nbsp;&#183;&nbsp; '
                        f'<a href="/manage/user/{opu}" class="btn btn-sm" '
                        f'style="text-decoration:none">{init_dot}👤 {opu}\'s Profile</a>')

    msg_html = ''
    if msg:
        clr = 'var(--green)' if msg_type == 'success' else 'var(--red)'
        msg_html = (f'<div style="background:{clr}22;border:1px solid {clr};color:{clr};'
                    f'padding:10px 14px;border-radius:6px;margin:12px 0">{_h(msg)}</div>')

    # ── Build JS for live polling ─────────────────────────────────
    last_id    = thread[-1]['id'] if thread else 0
    conv_id_js = thread[0]['conversation_id'] if thread and thread[0]['conversation_id'] else (thread[0]['id'] if thread else 0)
    opu_js     = _h(other_party) if other_party else ''
    uname_js   = _h(uname)
    poll_js = f'''<script>
(function(){{
  var sinceId = {last_id};
  var convId  = {conv_id_js};
  var otherUser = '{opu_js}';
  var myUser = '{uname_js}';
  var pollTimer = null;
  var typingTimer = null;
  var isTyping = false;

  function _esc(s){{
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }}

  function appendBubble(m){{
    var wrap = document.getElementById('dm-bubbles');
    if (!wrap) return;
    var align  = m.is_mine ? 'flex-end' : 'flex-start';
    var bg     = m.is_mine ? 'var(--accent)22' : 'var(--card2)';
    var border = m.is_mine ? 'var(--accent)' : 'var(--border)';
    var subj   = m.subject ? '<div style="font-size:0.82rem;color:var(--muted);margin-bottom:4px">'+_esc(m.subject)+'</div>' : '';
    var bcast  = m.is_broadcast ? ' <span style="background:var(--blue);color:#fff;font-size:0.65rem;padding:1px 5px;border-radius:3px">BROADCAST</span>' : '';
    var html   = '<div style="display:flex;justify-content:'+align+';margin-bottom:12px">'
               + '<div style="max-width:75%;background:'+bg+';border:1px solid '+border+';border-radius:10px;padding:10px 14px">'
               + '<div style="font-size:0.75rem;color:var(--muted);margin-bottom:4px">'
               + '<strong>'+_esc(m.sender)+'</strong> &#x2192; <strong>'+_esc(m.recipient)+'</strong>'+bcast+' &middot; '+_esc(m.sent_at)
               + '</div>'
               + subj
               + '<div style="white-space:pre-wrap;word-break:break-word">'+_esc(m.body)+'</div>'
               + '</div></div>';
    wrap.insertAdjacentHTML('beforeend', html);
    wrap.scrollTop = wrap.scrollHeight;
  }}

  function updatePresence(status){{
    var dot = document.getElementById('dm-presence-dot');
    if (!dot) return;
    var colors = {{online:'var(--green)', recent:'var(--accent)', offline:'var(--border)'}};
    var tips   = {{online:'Online now', recent:'Recently active', offline:'Offline'}};
    if (status === 'hidden'){{ dot.style.display='none'; return; }}
    dot.style.background = colors[status] || 'var(--border)';
    dot.title = tips[status] || '';
    dot.style.display = 'inline-block';
  }}

  function updateTyping(isTyping){{
    var el = document.getElementById('dm-typing');
    if (!el) return;
    el.style.display = isTyping ? 'block' : 'none';
  }}

  function doPoll(){{
    if (document.visibilityState !== 'visible') return;
    fetch('/manage/messages/poll?since_id=' + sinceId + '&conv_id=' + convId + '&other=' + encodeURIComponent(otherUser))
      .then(function(r){{ return r.json(); }})
      .then(function(d){{
        if (d.messages && d.messages.length){{
          d.messages.forEach(function(m){{ appendBubble(m); }});
          sinceId = d.messages[d.messages.length-1].id;
          // update reply_to hidden input
          var ri = document.querySelector('input[name="reply_to_id"]');
          if (ri) ri.value = sinceId;
        }}
        updatePresence(d.other_status || 'offline');
        updateTyping(d.other_typing || false);
      }})
      .catch(function(){{}});
  }}

  function sendTyping(){{
    var fd = new FormData();
    fd.append('other', otherUser);
    fetch('/manage/messages/typing', {{method:'POST', body: new URLSearchParams({{other: otherUser}})}});
    isTyping = false;
  }}

  function onKeyDown(){{
    if (!isTyping){{
      isTyping = true;
      sendTyping();
    }}
    clearTimeout(typingTimer);
    typingTimer = setTimeout(function(){{ isTyping=false; }}, 4000);
  }}

  // Start polling
  pollTimer = setInterval(doPoll, 4000);

  // Pause/resume on visibility
  document.addEventListener('visibilitychange', function(){{
    if (document.visibilityState === 'visible'){{
      doPoll(); // immediate catch-up
    }}
  }});

  // Wire up typing listener when DOM ready
  document.addEventListener('DOMContentLoaded', function(){{
    var ta = document.querySelector('textarea[name="body"]');
    if (ta) {{
      ta.addEventListener('keydown', onKeyDown);
      ta.addEventListener('keydown', function(e) {{
        // Enter sends, Shift+Enter inserts newline
        if (e.key === 'Enter' && !e.shiftKey) {{
          e.preventDefault();
          var form = ta.closest('form');
          if (form && ta.value.trim()) {{
            // requestSubmit fires the submit event (triggering CSRF injection)
            // form.submit() bypasses it — don't use that
            if (form.requestSubmit) {{
              form.requestSubmit();
            }} else {{
              // Fallback: inject CSRF manually then submit
              var m = document.cookie.match(/wkcsrf=([^;]+)/);
              if (m) {{
                var csrf = form.querySelector('input[name="_csrf"]');
                if (!csrf) {{
                  csrf = document.createElement('input');
                  csrf.type = 'hidden'; csrf.name = '_csrf';
                  form.appendChild(csrf);
                }}
                csrf.value = m[1];
              }}
              form.submit();
            }}
          }}
        }}
      }});
    }}
    // Scroll bubbles to bottom on load
    var wrap = document.getElementById('dm-bubbles');
    if (wrap) wrap.scrollTop = wrap.scrollHeight;
  }});
}})();
</script>'''

    body = (
        f'<div class="page-title">📬 Conversation</div>'
        f'<div class="page-sub" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">'
        f'<a href="/manage/messages" style="color:var(--muted);text-decoration:none">&#10094; Messages</a>'
        f'{profile_link}'
        f'{block_html}</div>'
        f'{msg_html}'
        f'<div id="dm-bubbles" style="margin-top:16px;max-height:60vh;overflow-y:auto;scroll-behavior:smooth;padding-right:10px">{bubbles}</div>'
        f'<div id="dm-typing" style="display:none;color:var(--muted);font-size:0.82rem;'
        f'font-style:italic;padding:4px 0 8px 4px">{_h(other_party) if other_party else ""} is typing...</div>'
        f'{reply_html}'
        f'{poll_js}')
    return _manage_page('📬 Conversation', body, user=viewer)


def _render_notifications_page(viewer) -> str:
    if not REGISTRATION_DB:
        return _manage_page('Notifications', '<p>Unavailable</p>', user=viewer)
    notifs = REGISTRATION_DB.get_all_notifications(viewer['id'])
    unread_count = sum(1 for n in notifs if not n['is_read'])

    rows = ''
    for n in notifs:
        is_bounty = str(n['info_hash']).upper().startswith('BOUNTY:')
        is_topup = str(n['info_hash']).upper().startswith('TOPUP:')
        is_follow = str(n['info_hash']).upper().startswith('FOLLOW:')
        ts_h = _h((n['created_at'] or '')[:16].replace('T', ' '))
        from_h = _h(n['from_username'])
        tname_h = _h(n['torrent_name'])
        unread_cls = '' if n['is_read'] else ' unread'
        n_id = n['id']

        if is_bounty:
            bid = str(n['info_hash']).split(':',1)[1]
            ntype = n['type']
            icon, label = {
                'bounty_new':              ('📣', 'has posted a bounty for'),
                'bounty_mention':          ('@',  'mentioned you in bounty'),
                'bounty_claimed':          ('🎯', 'claimed your bounty'),
                'bounty_rejected':         ('✗',  'rejected your claim on'),
                'bounty_fulfilled':        ('✅', 'has accepted your bounty for'),
                'bounty_contribution':     ('➕', 'added points to your bounty'),
                'bounty_expired':          ('⏰', 'bounty expired:'),
                'bounty_uploader_payout':  ('💰', 'fulfilled a bounty using your upload:'),
                'followed_bounty_fulfilled': ('✅', 'fulfilled a bounty:'),
            }.get(ntype, ('🔔', 'bounty update on'))
            anchor = f'#bcmt-{n["comment_id"]}' if (ntype == 'bounty_mention' and n['comment_id']) else ''
            url = f'/manage/bounty/{bid}{anchor}'
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
        elif is_topup:
            oid = str(n['info_hash']).split(':', 1)[1]
            oid_disp = oid
            if oid.isdigit() and REGISTRATION_DB:
                try:
                    seq = REGISTRATION_DB.get_topup_user_sequence(viewer['id'], int(oid))
                    if seq > 0:
                        oid_disp = str(seq)
                except Exception:
                    pass
            url = '/manage/topups'
            read_js = f"readNotif({n_id},'{url}')"
            topup_action = 'refunded' if n['type'] == 'topup_refunded' else 'credited'
            rows += (
                f'<div class="notif-page-item{unread_cls}">'
                f'<div>'
                f'<div style="font-size:0.9rem"><span style="margin-right:6px">💳</span>'
                f'<a href="/manage/user/{from_h}" class="user-link">{from_h}</a>'
                f' {topup_action} top-up #{oid_disp}: '
                f'<a href="{url}" onclick="event.preventDefault();{read_js}" style="color:var(--accent);text-decoration:none">{tname_h}</a></div>'
                f'<div class="notif-page-meta">{ts_h}</div>'
                f'</div>'
                f'<button class="btn btn-sm" style="white-space:nowrap" onclick="{read_js}">View →</button>'
                f'</div>'
            )
        elif is_follow:
            target_url = '/manage/following'
            follow_uid = int(n['comment_id'] or 0)
            if follow_uid > 0 and REGISTRATION_DB:
                fu = REGISTRATION_DB.get_user_by_id(follow_uid)
                if fu:
                    target_url = f'/manage/user/{urllib.parse.quote(fu["username"])}'
            read_js = f"readNotif({n_id},'{target_url}')"
            rows += (
                f'<div class="notif-page-item{unread_cls}">'
                f'<div>'
                f'<div style="font-size:0.9rem"><span style="margin-right:6px">👥</span>'
                f'<a href="{target_url}" class="user-link">{from_h}</a>'
                f' is now following you!</div>'
                f'<div class="notif-page-meta">{ts_h}</div>'
                f'</div>'
                f'<button class="btn btn-sm" style="white-space:nowrap" onclick="{read_js}">View →</button>'
                f'</div>'
            )
        else:
            if n['type'] == 'followed_upload':
                url = f'/manage/torrent/{n["info_hash"].lower()}'
                read_js = f"readNotif({n_id},'{url}')"
                rows += (
                    f'<div class="notif-page-item{unread_cls}">'
                    f'<div>'
                    f'<div style="font-size:0.9rem"><span style="margin-right:6px">📦</span>'
                    f'<a href="/manage/user/{from_h}" class="user-link">{from_h}</a>'
                    f' uploaded a new torrent: '
                    f'<a href="{url}" onclick="event.preventDefault();{read_js}" style="color:var(--accent);text-decoration:none">{tname_h}</a></div>'
                    f'<div class="notif-page-meta">{ts_h}</div>'
                    f'</div>'
                    f'<button class="btn btn-sm" style="white-space:nowrap" onclick="{read_js}" aria-label="View notification from {from_h}">View →</button>'
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
    swarm_members = _linked_swarm_members(ih)
    peer_seeders = t['peer_seeders'] if ('peer_seeders' in t.keys() and t['peer_seeders'] is not None) else None
    peer_leechers = t['peer_leechers'] if ('peer_leechers' in t.keys() and t['peer_leechers'] is not None) else None
    peer_downloaded = t['peer_downloaded'] if ('peer_downloaded' in t.keys() and t['peer_downloaded'] is not None) else None
    peer_last_updated = t['peer_last_updated'] if ('peer_last_updated' in t.keys()) else ''
    peer_last_tracker = t['peer_last_tracker'] if ('peer_last_tracker' in t.keys() and t['peer_last_tracker']) else ''
    peer_cfg = REGISTRATION_DB.get_peer_query_config() if REGISTRATION_DB else {'active': False}
    peer_update_btn = ''
    if peer_cfg.get('active'):
        rem = _peer_refresh_remaining_seconds(t)
        if rem > 0:
            h = rem // 3600
            m = (rem % 3600) // 60
            peer_update_btn = (
                f'<button type="button" class="btn btn-green" disabled '
                f'style="opacity:0.95;cursor:not-allowed" '
                f'title="Available in {h}h {m}m">'
                f'Refresh Seeds/Peers ({h}h {m}m)</button>'
            )
        else:
            peer_update_btn = (
                f'<form method="POST" action="/manage/torrent/update-peers" style="display:inline">'
                f'<input type="hidden" name="info_hash" value="{ih}">'
                f'<button type="submit" class="btn btn-green">Refresh Seeds/Peers</button>'
                f'</form>'
            )

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
            lock_btn = (
                f'<form method="POST" action="/manage/torrent/unlock" style="display:inline">'
                f'<input type="hidden" name="info_hash" value="{ih}">'
                f'<button type="submit" class="btn btn-sm"'
                f' aria-label="Unlock comments for this torrent">&#x1F513; Unlock Comments</button>'
                f'</form>'
            )
        else:
            lock_btn = (
                f'<form method="POST" action="/manage/torrent/lock" style="display:inline">'
                f'<input type="hidden" name="info_hash" value="{ih}">'
                f'<button type="submit" class="btn btn-sm btn-danger"'
                f' aria-label="Lock comments for this torrent">&#x1F512; Lock Comments</button>'
                f'</form>'
            )
        tname_esc = t['name'].replace('"', '&quot;').replace("'", '&#39;')
        del_comments_btn = (
            f'<form method="POST" action="/manage/comment/delete-all" style="display:inline"'
            f' data-confirm="Delete ALL comments on {tname_esc}? This cannot be undone.">'
            f'<input type="hidden" name="info_hash" value="{ih}">'
            f'<button type="submit" class="btn btn-sm btn-danger"'
            f' aria-label="Delete all comments on this torrent">&#x1F5D1; Delete All Comments</button>'
            f'</form>'
        )

    swarm_card = ''
    if swarm_members:
        member_rows = ''.join(
            '<tr>'
            f'<td><a href="/manage/user/{_h(m["username"])}" class="user-link">{_h(m["username"])}</a></td>'
            f'<td class="hash">{_h(_fmt_seen_ago(m["last_seen"]))}</td>'
            '</tr>'
            for m in swarm_members
        )
        swarm_card = (
            '<div class="card">'
            '<div class="card-title">Members Currently Sharing This Torrent</div>'
            f'<div style="color:var(--muted);font-size:0.82rem;margin-bottom:12px">{len(swarm_members)} member{"s" if len(swarm_members) != 1 else ""} currently sharing</div>'
            '<div class="table-wrap"><table style="min-width:unset"><thead><tr>'
            '<th scope="col" style="width:60%">Member</th>'
            '<th scope="col" style="width:40%">Last Activity</th>'
            '</tr></thead><tbody>'
            + member_rows +
            '</tbody></table></div>'
            '</div>'
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
        <colgroup>
          <col style="width:28%">
          <col style="width:72%">
        </colgroup>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">NAME</td>
            <td style="word-break:break-word;overflow-wrap:anywhere">{t["name"]}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">INFO HASH</td>
            <td class="hash" style="word-break:break-all;font-size:0.82rem">
              <button type="button" onclick="copyHash(this,'{ih}')" title="Click to copy"
                      aria-label="Copy info hash"
                      style="cursor:pointer;border:none;background:none;padding:0;color:inherit;font:inherit;border-bottom:1px dashed var(--muted)">{ih}</button>
            </td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">TYPE</td>
            <td>{mf}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">TOTAL SIZE</td>
            <td>{_fmt_size(t["total_size"] if "total_size" in t.keys() else 0)}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">PIECE SIZE</td>
            <td>{pl_str}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">PIECE COUNT</td>
            <td>{pc:,}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">PRIVATE</td>
            <td>{priv}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">REGISTERED BY</td>
            <td><a href="/manage/user/{t["uploaded_by_username"]}" class="user-link">{t["uploaded_by_username"]}</a></td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">REGISTERED AT</td>
            <td class="hash">{t["registered_at"][:16].replace("T", " ")}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">SEEDERS</td>
            <td>{'--' if peer_seeders is None else int(peer_seeders)}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">PEERS</td>
            <td>{'--' if peer_leechers is None else int(peer_leechers)}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">DOWNLOADS</td>
            <td>{'--' if peer_downloaded is None else int(peer_downloaded)}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">LAST PEER UPDATE</td>
            <td class="hash">{(peer_last_updated or '--')[:16].replace("T", " ")}</td></tr>
        <tr><td style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;white-space:nowrap">PEER SOURCE</td>
            <td class="hash" style="word-break:break-all">{_h(peer_last_tracker) if peer_last_tracker else '--'}</td></tr>
      </table>
    </div>
    <div class="card">
      <div class="card-title">Actions</div>
      <div style="display:flex;flex-direction:column;gap:12px;align-items:flex-start">
        <button class="btn btn-primary" onclick="copyMagnet(this,{repr(magnet)})">&#x1F9F2; Copy Magnet Link</button>
        {peer_update_btn}
        {del_btn}
        {lock_btn}
        {del_comments_btn}
      </div>
    </div>
  </div>

  {swarm_card}

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
                            page: int = 1, total_pages: int = 1, total: int = 0,
                            msg: str = '', msg_type: str = 'error') -> str:
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
    status_badge = _online_badge_html(_online_status(target_user))
    followers_count, following_count = REGISTRATION_DB.get_follow_counts(target_user['id']) if REGISTRATION_DB else (0, 0)
    is_following = (REGISTRATION_DB.is_following(viewer['id'], target_user['id'])
                    if (REGISTRATION_DB and not is_own) else False)
    can_view_follow_lists = _can_view_follow_visibility(viewer, target_user)
    follow_lists_url = (f'/manage/user/{urllib.parse.quote(uname)}/following'
                        if not is_own else '/manage/following')
    if is_own or can_view_follow_lists:
        followers_value = f'<a href="{follow_lists_url}" class="user-link">{followers_count}</a>'
        following_value = f'<a href="{follow_lists_url}" class="user-link">{following_count}</a>'
    else:
        followers_value = '<span class="hash" title="This member has hidden follower visibility">Private</span>'
        following_value = '<span class="hash" title="This member has hidden follower visibility">Private</span>'

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
    sharing_card = _render_profile_sharing_card(target_user)

    avatar_html = _avatar_html(target_user, 34)
    follow_btn = ''
    if not is_own:
        if is_following:
            follow_btn = (
                '<form method="POST" action="/manage/unfollow" style="display:inline">'
                f'<input type="hidden" name="username" value="{uname_h}">'
                f'<input type="hidden" name="referer" value="/manage/user/{uname_h}">'
                '<button class="btn btn-sm" onmouseover="this.textContent=\'❌ Unfollow\'" '
                'onmouseout="this.textContent=\'✅ Following\'">✅ Following</button>'
                '</form>'
            )
        else:
            follow_btn = (
                '<form method="POST" action="/manage/follow" style="display:inline">'
                f'<input type="hidden" name="username" value="{uname_h}">'
                f'<input type="hidden" name="referer" value="/manage/user/{uname_h}">'
                '<button class="btn btn-sm btn-green">Follow</button>'
                '</form>'
            )
    body = f'''
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap">
    {avatar_html}
    <div class="page-title">{uname_h}</div>
    {role_badge}
  </div>
  <div class="page-sub" style="margin-bottom:20px">
    Public profile
    &nbsp;&#183;&nbsp; <a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a>
    {admin_link}
    {'&nbsp;&#183;&nbsp; <a href="/manage/messages?to=' + uname_h + '" class="btn btn-sm">📬 Send DM</a>' if (not is_own and vrole != 'basic' and REGISTRATION_DB and REGISTRATION_DB.get_setting('dm_enabled','1') == '1' and not target_user['is_disabled']) else ''}
    {'&nbsp;&#183;&nbsp; ' + follow_btn if follow_btn else ''}
  </div>

  <div class="card" style="max-width:400px">
    <div style="display:flex;align-items:center;margin-bottom:12px">
      <div class="card-title" style="margin:0">Account</div>
    </div>
    <table style="min-width:unset">
      {_pub_row('Status', status_badge if status_badge else '--')}
      {_pub_row('Member Since', joined)}
      {_pub_row('Points', f'<span style="color:{pts_color};font-weight:bold">{pts_val}</span>'
                          + (f' <span style="color:var(--muted);font-size:0.8rem">🔥 {streak}-day streak</span>'
                             if streak > 1 else ''))}
      {_pub_row('Torrents', str(total))}
      {_pub_row('Followers', followers_value)}
      {_pub_row('Following', following_value)}
    </table>
  </div>

  {sharing_card}

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

    return _manage_page(uname_h, body, user=viewer, msg=msg, msg_type=msg_type)


def _render_user_detail(viewer, target_user, torrents, login_history, is_super,
                        allowlist=None, is_own_profile=False,
                        page: int = 1, total_pages: int = 1, total: int = 0, base_url: str = '',
                        ledger=None, bounty_data=None, topup_orders=None,
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
    sharing_card = _render_profile_sharing_card(target_user)

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
    followers_count, following_count = REGISTRATION_DB.get_follow_counts(target_user['id']) if REGISTRATION_DB else (0, 0)
    is_following = (REGISTRATION_DB.is_following(viewer['id'], target_user['id'])
                    if (REGISTRATION_DB and not is_own_profile) else False)
    can_view_follow_lists = _can_view_follow_visibility(viewer, target_user)
    follow_lists_url = (f'/manage/user/{urllib.parse.quote(uname)}/following'
                        if not is_own_profile else '/manage/following')
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
        + row('Followers',      (f'<a href="{follow_lists_url}" class="user-link">{followers_count}</a>'
                                 if (is_own_profile or can_view_follow_lists)
                                 else '<span class="hash" title="This member has hidden follower visibility">Private</span>'))
        + row('Following',      (f'<a href="{follow_lists_url}" class="user-link">{following_count}</a>'
                                 if (is_own_profile or can_view_follow_lists)
                                 else '<span class="hash" title="This member has hidden follower visibility">Private</span>'))
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
            + 'var old=f.querySelector(\'input[name="selected_ips"]\');if(old){old.remove();}'
            + 'var h=document.createElement("input");h.type="hidden";h.name="selected_ips";h.value=ips;f.appendChild(h);'
            + 'if(!f.querySelector(\'input[name="_csrf"]\')){'
            + 'var m=document.cookie.match(/(?:^|;[ \\t]*)wkcsrf=([^;]+)/);'
            + 'var c=document.createElement("input");c.type="hidden";c.name="_csrf";c.value=(m?m[1]:"");f.appendChild(c);}'
            + 'f.submit();}'
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
        gravatar_on = _gravatar_enabled()
        gravatar_checked = ('checked' if ('gravatar_opt_in' in viewer.keys() and viewer['gravatar_opt_in']) else '')
        gravatar_section = ''
        if gravatar_on:
            gravatar_section = (
                '<div style="margin-top:8px;padding-top:10px;border-top:1px solid var(--border)">'
                '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.9rem">'
                f'<input type="checkbox" name="gravatar_opt_in" value="1" {gravatar_checked}> '
                'Use Gravatar avatar'
                '</label>'
                '<label style="display:block;margin-top:8px;font-size:0.84rem;color:var(--muted)">'
                'Gravatar email or MD5 hash (optional)'
                '<input type="text" name="gravatar_identity" autocomplete="off" '
                'placeholder="you@example.com or 4fca794da0cf08804f99048d3c8b39c1" '
                'style="margin-top:6px;width:100%;padding:8px;background:var(--card2);'
                'border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:0.84rem">'
                '</label>'
                '<div style="margin-top:6px;font-size:0.76rem;color:var(--muted)">'
                'Tip: you can hash your email with MD5 and paste the hash directly.'
                '</div>'
                '<div style="margin-top:8px;font-size:0.78rem;color:var(--muted)" '
                'title="Privacy note: your raw email is not stored. We keep only the MD5 hash. Hashes can still be correlated or guessed for predictable emails, and avatar fetches contact a third-party service (Gravatar).">'
                'Privacy note: hash-only storage, possible hash correlation risk, and third-party Gravatar fetches.'
                '</div>'
                '</div>'
            )
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
            '&nbsp; <a href="/manage/following" class="btn btn-sm">Followers</a>'
            '</div>'
            '</div>'
            '<div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--border)">'
            '<div style="font-size:0.85rem;color:var(--muted);margin-bottom:8px">Messaging &amp; Privacy</div>'
            '<form method="POST" action="/manage/messages/toggle-dms" style="display:flex;flex-direction:column;gap:10px">'
            '<input type="hidden" name="form_scope" value="profile_privacy">'
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.9rem">'
            '<input type="checkbox" name="allow_dms" value="1" '
            + ('checked' if ('allow_dms' in viewer.keys() and viewer['allow_dms']) else '')
            + '> Allow others to send me DMs</label>'
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.9rem">'
            '<input type="checkbox" name="show_online" value="1" '
            + ('checked' if ('show_online' not in viewer.keys() or viewer['show_online']) else '')
            + '> Show my online status to others</label>'
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.9rem">'
            '<input type="checkbox" name="bounty_alerts" value="1" '
            + ('checked' if ('bounty_alerts' not in viewer.keys() or viewer['bounty_alerts']) else '')
            + '> Bounty alerts (new bounty notifications)</label>'
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.9rem">'
            '<input type="checkbox" name="link_torrent_activity" value="1" '
            + ('checked' if ('link_torrent_activity' not in viewer.keys() or viewer['link_torrent_activity']) else '')
            + '> Allow linking my torrent swarm activity</label>'
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.9rem">'
            '<input type="checkbox" name="allow_follow_visibility" value="1" '
            + ('checked' if ('allow_follow_visibility' not in viewer.keys() or viewer['allow_follow_visibility']) else '')
            + '> Allow others to view my followers and following</label>'
            + gravatar_section
            + '<div><button type="submit" class="btn btn-sm">Save</button></div>'
            + '</form>'
            + '</div>'
            + '<div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--border)">'
            + '<div style="font-size:0.85rem;color:var(--danger);margin-bottom:8px">Danger Zone</div>'
            + ('<div style="font-size:0.82rem;color:var(--muted);margin-bottom:8px">'
               f'Self-delete is a multi-step process. You will be logged out and must return within {ACCOUNT_DELETE_CHALLENGE_TTL_MINUTES} minutes.'
               '</div>' if viewer['username'] != SUPER_USER else
               '<div style="font-size:0.82rem;color:var(--muted);margin-bottom:8px">'
               'Super account cannot self-delete.</div>')
            + ('' if viewer['username'] == SUPER_USER else
               '<form method="POST" action="/manage/account/delete/start" '
               'onsubmit="return confirm(\'Final warning: this starts account deletion and logs you out. Continue?\')" '
               'style="display:flex;flex-direction:column;gap:8px">'
               '<label style="font-size:0.8rem;color:var(--muted)">Type DELETE MY ACCOUNT</label>'
               '<input type="text" name="delete_phrase" autocomplete="off" required '
               'placeholder="DELETE MY ACCOUNT" '
               'style="padding:8px;background:var(--card2);border:1px solid var(--border);border-radius:6px;'
               'color:var(--text);font-family:var(--mono);font-size:0.82rem">'
               '<div><button type="submit" class="btn btn-sm btn-danger">Delete My Account</button></div>'
               '</form>')
            + '</div>'
            + '</div></div>'
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
    follow_btn = ''
    if not is_own_profile:
        if is_following:
            follow_btn = (
                f' &nbsp;&#183;&nbsp; <form method="POST" action="/manage/unfollow" style="display:inline">'
                f'<input type="hidden" name="username" value="{uname_h}">'
                f'<input type="hidden" name="referer" value="/manage/admin/user/{uname_h}">'
                f'<button class="btn btn-sm" onmouseover="this.textContent=\'❌ Unfollow\'" '
                f'onmouseout="this.textContent=\'✅ Following\'">✅ Following</button></form>'
            )
        else:
            follow_btn = (
                f' &nbsp;&#183;&nbsp; <form method="POST" action="/manage/follow" style="display:inline">'
                f'<input type="hidden" name="username" value="{uname_h}">'
                f'<input type="hidden" name="referer" value="/manage/admin/user/{uname_h}">'
                f'<button class="btn btn-sm btn-green">Follow</button></form>'
            )

    avatar_html = _avatar_html(target_user, 34)
    show_topup_section = is_own_profile or _user_role(viewer) in ('admin', 'super')
    focus_topup_id = None
    if (not is_own_profile) and (topup_orders or []):
        try:
            focus_topup_id = int((topup_orders or [])[0]['id'])
        except Exception:
            focus_topup_id = None
    topup_section = _render_topup_history_section(
        target_user, topup_orders or [], force_show=show_topup_section,
        admin_context=(not is_own_profile and _user_role(viewer) in ('admin', 'super')),
        focus_order_id=focus_topup_id
    )
    body = (
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap">'
        + avatar_html
        + '<div class="page-title">' + uname_h + '</div>'
        + role_badge + status_badges
        + '</div>'
        + '<div class="page-sub" style="margin-bottom:20px">'
        + ('Your profile' if is_own_profile else 'User profile')
        + nav_links
        + dm_btn + follow_btn + '</div>'
        + '<div style="display:flex;flex-direction:column;gap:24px">'
        + '<div class="two-col">'
        + '<div class="card"><div class="card-title">Account Details</div>'
        + '<table style="min-width:unset">' + info_rows + '</table></div>'
        + actions_card
        + '</div>'
        + topup_section
        + _render_points_section(viewer, target_user, is_own_profile, ledger, bounty_data, part='rest')
        + ip_html
        + delete_all_html
        + sharing_card
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



def _render_topup_history_section(user, orders: list, force_show: bool = False,
                                  admin_context: bool = False,
                                  focus_order_id: int | None = None) -> str:
    if not REGISTRATION_DB:
        return ''
    if REGISTRATION_DB.get_setting('topup_enabled', '0') != '1':
        return ''
    if not force_show and not REGISTRATION_DB.topup_enabled_for_user(user):
        return ''
    user_seq = {}
    for idx, o in enumerate(sorted(orders, key=lambda r: int(r['id']))):
        user_seq[int(o['id'])] = idx + 1
    rows = ''
    for o in orders[:50]:
        status = _h(o['status'])
        color = {
            'credited': 'var(--green)',
            'confirmed': 'var(--accent)',
            'pending': 'var(--muted)',
            'created': 'var(--muted)',
            'expired': 'var(--danger)',
            'failed': 'var(--danger)',
            'exception': 'var(--danger)',
            'refunded': 'var(--danger)',
        }.get(o['status'], 'var(--muted)')
        rows += (
            '<tr>'
            f'<td class="hash">#{user_seq.get(int(o["id"]), 0)}</td>'
            f'<td>${o["amount_usd_cents"]/100:.2f}</td>'
            f'<td style="color:var(--accent)">{o["quoted_points"]}</td>'
            f'<td style="color:{color};font-family:var(--mono);font-size:0.76rem">{status.upper()}</td>'
            f'<td class="hash">{(o["updated_at"] or "")[:16].replace("T"," ")}</td>'
            '</tr>'
        )
    if not rows:
        rows = '<tr><td colspan="5" class="empty">No top-up orders yet</td></tr>'
    open_link = '/manage/topups'
    if admin_context:
        if focus_order_id:
            open_link = f'/manage/admin?tab=topups#topup-order-{focus_order_id}'
        else:
            open_link = '/manage/admin?tab=topups'
    return (
        '<div class="card">'
        '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px">'
        '<div class="card-title" style="margin:0">Top-up Orders</div>'
        f'<a href="{open_link}" class="btn btn-sm">Open Top-ups</a>'
        '</div>'
        '<div class="table-wrap"><table>'
        '<tr><th scope="col">Order</th><th scope="col">Amount</th><th scope="col">Quoted</th><th scope="col">Status</th><th scope="col">Updated</th></tr>'
        + rows +
        '</table></div></div>'
    )


def _render_following_page(viewer, target_user, followers: list, following: list,
                           base_path: str = '/manage/following',
                           viewer_following_ids=None,
                           msg: str = '', msg_type: str = 'error') -> str:
    if viewer_following_ids is None:
        viewer_following_ids = set(int(r['id']) for r in following)
    else:
        viewer_following_ids = set(int(i) for i in viewer_following_ids)
    is_own = int(viewer['id']) == int(target_user['id'])
    target_uname = _h(target_user['username'])
    viewer_id = int(viewer['id'])

    def _follow_action(r, prefer_follow_back: bool = False) -> str:
        rid = int(r['id'])
        uname = _h(r['username'])
        if rid == viewer_id:
            return '<span class="hash" style="font-size:0.78rem">You</span>'
        if rid in viewer_following_ids:
            return (
                '<form method="POST" action="/manage/unfollow" style="display:inline">'
                f'<input type="hidden" name="username" value="{uname}">'
                f'<input type="hidden" name="referer" value="{_h(base_path)}">'
                '<button class="btn btn-sm" onmouseover="this.textContent=\'❌ Unfollow\'" '
                'onmouseout="this.textContent=\'✅ Following\'">✅ Following</button>'
                '</form>'
            )
        follow_label = 'Follow back' if (is_own and prefer_follow_back) else 'Follow'
        return (
            '<form method="POST" action="/manage/follow" style="display:inline">'
            f'<input type="hidden" name="username" value="{uname}">'
            f'<input type="hidden" name="referer" value="{_h(base_path)}">'
            f'<button class="btn btn-sm btn-green">{follow_label}</button>'
            '</form>'
        )

    def _role_badge_row(u) -> str:
        role = 'basic'
        if u['username'] == SUPER_USER:
            role = 'super'
        elif u['is_admin']:
            role = 'admin'
        elif u['is_standard']:
            role = 'standard'
        return f'<span class="badge badge-{role}">{role.upper()}</span>'

    def _followers_rows() -> str:
        out = ''
        for r in followers:
            uname = _h(r['username'])
            urole = _role_badge_row(r)
            since = _h((r['followed_at'] or '')[:16].replace('T', ' '))
            action = _follow_action(r, prefer_follow_back=True)
            out += (
                '<tr>'
                f'<td><a href="/manage/user/{uname}" class="user-link">{uname}</a></td>'
                f'<td>{urole}</td>'
                f'<td class="hash">{since}</td>'
                f'<td>{action}</td>'
                '</tr>'
            )
        if not out:
            out = '<tr><td colspan="4" class="empty">No followers yet</td></tr>'
        return out

    def _following_rows() -> str:
        out = ''
        for r in following:
            uname = _h(r['username'])
            urole = _role_badge_row(r)
            since = _h((r['followed_at'] or '')[:16].replace('T', ' '))
            action = _follow_action(r, prefer_follow_back=False)
            out += (
                '<tr>'
                f'<td><a href="/manage/user/{uname}" class="user-link">{uname}</a></td>'
                f'<td>{urole}</td>'
                f'<td class="hash">{since}</td>'
                f'<td>{action}</td>'
                '</tr>'
            )
        if not out:
            out = '<tr><td colspan="4" class="empty">You are not following anyone yet</td></tr>'
        return out

    page_title = 'Followers' if is_own else f'{target_uname} Followers'
    back_url = '/manage/profile' if is_own else f'/manage/user/{urllib.parse.quote(target_user["username"])}'
    back_label = 'Profile' if is_own else f'{target_uname} profile'
    body = (
        f'<div class="page-title">{page_title}</div>'
        f'<div class="page-sub"><a href="{back_url}" style="color:var(--muted);text-decoration:none">&#10094; {back_label}</a></div>'
        '<div class="two-col">'
        '<div class="card">'
        f'<div class="card-title">Followers ({len(followers)})</div>'
        '<div class="table-wrap"><table>'
        '<tr><th scope="col">Member</th><th scope="col">Role</th><th scope="col">Since</th><th scope="col">Action</th></tr>'
        + _followers_rows() +
        '</table></div></div>'
        '<div class="card">'
        f'<div class="card-title">Following ({len(following)})</div>'
        '<div class="table-wrap"><table>'
        '<tr><th scope="col">Member</th><th scope="col">Role</th><th scope="col">Since</th><th scope="col">Action</th></tr>'
        + _following_rows() +
        '</table></div></div>'
        '</div>'
    )
    return _manage_page(page_title, body, user=viewer, msg=_h(msg), msg_type=msg_type)


def _render_topups_page(user, orders: list, cfg: dict, msg: str = '', msg_type: str = 'error') -> str:
    default_provider = cfg.get('provider', 'coinbase')
    provider_options = cfg.get('providers', ['coinbase'])
    if default_provider not in provider_options:
        default_provider = provider_options[0] if provider_options else 'coinbase'
    provider_control_html = ''
    if len(provider_options) <= 1:
        only = (provider_options[0] if provider_options else default_provider).upper()
        provider_control_html = (
            '<div class="form-group" style="margin:0">'
            '<label>Payment Processor</label>'
            f'<div class="hash" style="padding:8px 10px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text);min-width:120px;text-align:center">{_h(only)}</div>'
            f'<input type="hidden" name="provider" value="{_h((provider_options[0] if provider_options else default_provider))}">'
            '</div>'
        )
    else:
        provider_control_html = (
            '<div class="form-group" style="margin:0">'
            '<label>Payment Processor</label>'
            '<select name="provider" id="topup-provider" style="padding:8px;background:var(--card2);border:1px solid var(--border);border-radius:6px;color:var(--text)">'
            + ''.join(
                f'<option value="{_h(p)}" {"selected" if p == default_provider else ""}>{_h(p.upper())}</option>'
                for p in provider_options
            )
            + '</select></div>'
        )
    amount_buttons = ''
    for amt in cfg.get('fixed_amounts_usd', [5, 10, 25, 50, 100]):
        q = REGISTRATION_DB.quote_topup_points(amt) if REGISTRATION_DB else {'quoted_points': 0}
        amount_buttons += (
            f'<button type="button" class="btn btn-primary" style="margin-right:8px;margin-bottom:8px" '
            f'onclick="submitTopupOrder({amt})">${amt} → {q["quoted_points"]} pts</button>'
        )
    user_seq = {}
    for idx, o in enumerate(sorted(orders, key=lambda r: int(r['id']))):
        user_seq[int(o['id'])] = idx + 1
    rows = ''
    for o in orders:
        status = _h(o['status'])
        color = {
            'credited': 'var(--green)',
            'confirmed': 'var(--accent)',
            'pending': 'var(--muted)',
            'created': 'var(--muted)',
            'expired': 'var(--danger)',
            'failed': 'var(--danger)',
            'exception': 'var(--danger)',
            'refunded': 'var(--danger)',
        }.get(o['status'], 'var(--muted)')
        action_html = ''
        if o['status'] in ('created', 'pending') and o['provider_reference']:
            safe_url = _h(o['provider_reference'])
            action_html = f'<a href="{safe_url}" target="_blank" rel="noopener" class="btn btn-sm">Pay Now</a>'
        rows += (
            '<tr>'
            f'<td class="hash">#{user_seq.get(int(o["id"]), 0)}</td>'
            f'<td class="hash">{_h((o["provider"] or "").upper() or "COINBASE")}</td>'
            f'<td class="hash">{_h(o["order_uuid"][:10])}...</td>'
            f'<td>${o["amount_usd_cents"]/100:.2f}</td>'
            f'<td style="color:var(--accent)">{o["quoted_points"]} pts</td>'
            f'<td style="color:{color};font-family:var(--mono);font-size:0.76rem">{status.upper()}</td>'
            f'<td class="hash">{(o["updated_at"] or "")[:16].replace("T"," ")}</td>'
            f'<td style="font-size:0.8rem;color:var(--muted)">{_h(o["status_detail"] or "")}'
            + ('' if not action_html else f'<div style="margin-top:6px">{action_html}</div>')
            + '</td>'
            '</tr>'
        )
    if not rows:
        rows = '<tr><td colspan="8" class="empty">No top-up orders yet</td></tr>'
    body = (
        '<div class="page-title">Top-ups</div>'
        '<div class="page-sub"><a href="/manage/dashboard" style="color:var(--muted);text-decoration:none">&#10094; Dashboard</a></div>'
        '<div class="card">'
        '<div class="card-title">Purchase Points</div>'
        '<p style="color:var(--muted);font-size:0.86rem;margin-bottom:12px">Credits are issued only after confirmed payment. This may take time.</p>'
        '<form id="topup-create-form" method="POST" action="/manage/topup/create" style="margin-bottom:12px;display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">'
        '<input type="hidden" name="amount_usd" id="topup-amount-usd" value="">'
        + provider_control_html
        + '</form>'
        '<div style="display:flex;flex-wrap:wrap;align-items:center">' + amount_buttons + '</div>'
        '<script>function submitTopupOrder(amt){var f=document.getElementById("topup-create-form");var a=document.getElementById("topup-amount-usd");if(!f||!a)return;a.value=String(amt);if(typeof _submitFormWithCsrf==="function"){_submitFormWithCsrf(f);}else{f.submit();}}</script>'
        '</div>'
        '<div class="card">'
        '<div class="card-title">Order History</div>'
        '<div class="table-wrap"><table>'
        '<tr><th scope="col">Order</th><th scope="col">Processor</th><th scope="col">Reference</th><th scope="col">Amount</th><th scope="col">Quoted</th><th scope="col">Status</th><th scope="col">Updated</th><th scope="col">Detail</th></tr>'
        + rows +
        '</table></div>'
        '</div>'
    )
    return _manage_page('Top-ups', body, user=user, msg=msg, msg_type=msg_type)


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
        if part == 'rest':
            return ''
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
        _start_peer_update_worker()
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
                try:
                    expired = REGISTRATION_DB.expire_account_delete_challenges()
                    if expired:
                        log.info('account delete reconcile: expired %d challenge(s)', expired)
                except Exception as _e:
                    log.warning('expire_account_delete_challenges failed (non-fatal): %s', _e)
                try:
                    stale = REGISTRATION_DB.reconcile_stale_topup_orders()
                    if stale:
                        log.info('topup stale reconcile: reconciled %d stale order(s)', stale)
                except Exception as _e:
                    log.warning('reconcile_stale_topup_orders failed (non-fatal): %s', _e)
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
    """Render leaderboard categories."""
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
    cols_popular  = [('Followers',    'follower_count', count('followers'))]

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
    card_popular   = _card("Most Followed",    "👥", data["popular"],        cols_popular,
                           "Most followed members in the community.")

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
      {card_popular}
    </div>'''

    return _manage_page('Leaderboard', body, user=viewer)


def _render_bounty_board(viewer, bounties: list, total: int, page: int, total_pages: int,
                          sort: str = 'points', status: str = 'open',
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
        + _stat_link('all',       'All')
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
        desc  = _h(b['description'][:120] + ('…' if len(b['description']) > 120 else ''))
        badge = _bounty_status_badge(b['status'])
        pts_disp = f'<span style="color:var(--accent);font-weight:700">{b["total_escrow"]} pts</span>'
        by    = _h(b['created_by'])
        exp   = _h((b['expires_at'] or '')[:10])
        ff    = _h(b['fulfilled_by'] or '')
        rows += (
            f'<tr>'
            f'<td style="word-break:break-word;overflow-wrap:anywhere;line-height:1.45">'
            f'<a href="/manage/bounty/{bid}" style="color:var(--text)">{desc}</a></td>'
            f'<td style="text-align:center;white-space:nowrap">{pts_disp}</td>'
            f'<td style="text-align:center;white-space:nowrap">{badge}</td>'
            f'<td class="hash" style="white-space:nowrap"><a href="/manage/user/{by}" class="user-link">{by}</a></td>'
            f'<td class="hash" style="white-space:nowrap">{ff if ff else "—"}</td>'
            f'<td class="hash" style="white-space:nowrap">{exp}</td>'
            f'<td style="white-space:nowrap"><a href="/manage/bounty/{bid}" class="btn btn-sm">View →</a></td>'
            f'</tr>'
        )
    if not rows:
        rows = '<tr><td colspan="7" class="empty">No bounties found</td></tr>'

    table = f'''<div class="table-wrap"><table class="torrent-table" style="width:100%;table-layout:fixed;min-width:0">
      <colgroup>
        <col>
        <col style="width:96px">
        <col style="width:120px">
        <col style="width:116px">
        <col style="width:116px">
        <col style="width:110px">
        <col style="width:92px">
      </colgroup>
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
        elapsed = _fmt_elapsed_compact(bounty['created_at'] or '', bounty['fulfilled_at'] or '')
        speed_emoji = _bounty_speed_emoji(bounty['created_at'] or '', bounty['fulfilled_at'] or '')
        elapsed_html = (f'<div style="color:var(--green);font-weight:700;margin:0 0 8px 0">'
                        f'BOUNTY FULFILLED in {elapsed} {speed_emoji}</div>') if elapsed else ''

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
      {elapsed_html}
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
        bd_h = _render_comment_body(c['body'])
        at_h = _h((c['created_at'] or '')[:16])
        comment_rows += f'''
      <div id="bcmt-{c['id']}" style="padding:12px 0;border-top:1px solid var(--border)">
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
