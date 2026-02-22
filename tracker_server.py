#!/usr/bin/env python3
from __future__ import annotations
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

import argparse
import datetime
import gzip
import ipaddress
import json
import logging
import os
import random
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

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
                # Only increment downloaded counter once per peer — same peer
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
# HTTP Handler
# ─────────────────────────────────────────────────────────────

class TrackerHTTPHandler(BaseHTTPRequestHandler):
    """Handles HTTP(S) announce and scrape GET requests."""

    # Suppress default access logs; we use our own
    def log_message(self, fmt, *args):
        log.info('%s %s %s', self.client_address[0],
                 self.command, self.path.split('?')[0])

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

        if not ih_list:
            if not ALLOW_FULL_SCRAPE:
                log.debug('HTTP SCRAPE  full scrape denied from=%s', self.client_address[0])
                self._send_bencode(200, {b'failure reason': b'full scrape not allowed'})
                return
            # Full scrape allowed — return all known torrents
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

def generate_stats_html(snap: dict, web_config: dict) -> str:
    uptime_str   = _fmt_uptime(snap['uptime'])
    torrents     = snap['torrents']
    live_peers   = snap['live_peers']

    a   = snap['all']
    tod = snap['today']
    yes = snap.get('yesterday', {})

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
          <div class="section-title">Hourly Activity — {yes.get('date','')}</div>
          <div class="chart">{yes_hourly_bars}</div>
        </div>'''
    else:
        yes_panel = '<div class="panel" id="panel-yesterday"><div class="no-data">No data for yesterday yet — check back after midnight.</div></div>'

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
      <div class="brag-card"><strong>gzip Compression</strong>Automatic compression when clients advertise support — only applied when it actually saves bytes</div>
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


class IPv6HTTPServer(HTTPServer):
    """HTTPServer variant that binds an AF_INET6 socket.
    IPV6_V6ONLY=1 ensures this socket handles only IPv6 traffic, allowing
    the paired IPv4 socket to coexist on the same port (required on Linux).
    """
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def start_http_server(host: str, port: int, ssl_ctx=None, label='HTTP'):
    server = HTTPServer((host, port), TrackerHTTPHandler)
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


class IPv6RedirectServer(HTTPServer):
    """IPv6 variant of the HTTP→HTTPS redirect server."""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def start_redirect_server(host: str, port: int, target_host: str):
    RedirectHandler.redirect_host = target_host
    if ':' in host or host == '::':
        server = IPv6RedirectServer((host, port, 0, 0), RedirectHandler)
        log.info('HTTP→HTTPS redirect listening on [%s]:%d (IPv6)', host or '::', port)
    else:
        server = HTTPServer((host, port), RedirectHandler)
        log.info('HTTP→HTTPS redirect listening on %s:%d', host or '0.0.0.0', port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server



# ─────────────────────────────────────────────────────────────
# Stats web server
# ─────────────────────────────────────────────────────────────

WEB_CONFIG: dict = {}   # populated at startup by main()


class StatsWebHandler(BaseHTTPRequestHandler):
    """Serves the stats page at / and nothing else."""

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == '/' or path == '':
            snap = STATS.snapshot()
            html = generate_stats_html(snap, WEB_CONFIG)
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
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '9')
            self.end_headers()
            self.wfile.write(b'Not Found')

    def log_message(self, fmt, *args):
        log.debug('WEB %s %s', self.address_string(), fmt % args)


class IPv6StatsWebServer(HTTPServer):
    """IPv6 variant of the stats web server."""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def start_web_server(host: str, port: int, ssl_ctx=None, label='WEB'):
    server = HTTPServer((host, port), StatsWebHandler)
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


def main():
    global DEFAULT_INTERVAL, DEFAULT_MIN_INTERVAL, PEER_TTL, MAX_PEERS_PER_REPLY, DEFAULT_TRACKER_ID, MAX_SCRAPE_HASHES, ALLOW_FULL_SCRAPE

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

    if not servers and not args.udp_port:
        print('Error: all listeners disabled.', file=sys.stderr)
        sys.exit(1)

    log.info('Tracker running. Press Ctrl-C to stop.')

    # ── Stats loop ───────────────────────────────────────────
    try:
        while True:
            time.sleep(60)
            STATS.check_rollover()
            hashes = REGISTRY.all_hashes()
            total_peers = sum(
                len(REGISTRY._torrents.get(h, {})) for h in hashes
            )
            log.info('Stats: %d torrents  %d peers', len(hashes), total_peers)
    except KeyboardInterrupt:
        log.info('Shutting down.')
        for s in servers:
            s.shutdown()


if __name__ == '__main__':
    main()
