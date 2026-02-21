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
            sock.sendto(resp_header + udp_peers, addr)
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

    if not servers and not args.udp_port:
        print('Error: all listeners disabled.', file=sys.stderr)
        sys.exit(1)

    log.info('Tracker running. Press Ctrl-C to stop.')

    # ── Stats loop ───────────────────────────────────────────
    try:
        while True:
            time.sleep(60)
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
