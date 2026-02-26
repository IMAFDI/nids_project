"""
NIDS — Network Scanner Module
Discovers devices on the local subnet via ARP scanning,
resolves hostnames, identifies MAC vendors, and tracks
per-device traffic statistics in real time.
"""

import os
import re
import csv
import time
import socket
import logging
import threading
import ipaddress
from collections import defaultdict
from datetime import datetime

from scapy.all import ARP, Ether, srp, IP, TCP, UDP, ICMP, conf

logger = logging.getLogger('NIDS.NetworkScanner')

# Path to IEEE OUI CSV file (downloaded on first use)
OUI_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        'config', 'oui.csv')

# ---------------------------------------------------------------------------
# MAC Vendor lookup (IEEE OUI)
# ---------------------------------------------------------------------------

_oui_table: dict = {}
_oui_loaded = False
_oui_lock   = threading.Lock()


def _load_oui():
    """Load OUI table from local CSV (mac,vendor format)."""
    global _oui_loaded
    with _oui_lock:
        if _oui_loaded:
            return
        if not os.path.exists(OUI_FILE):
            logger.debug("OUI file not found — vendor lookup disabled.")
            _oui_loaded = True
            return
        try:
            with open(OUI_FILE, newline='', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        oui = row[0].strip().upper().replace('-', ':').replace('.', ':')
                        _oui_table[oui[:8]] = row[1].strip()
            logger.info(f"OUI table loaded: {len(_oui_table)} entries.")
        except Exception as e:
            logger.warning(f"Could not load OUI table: {e}")
        _oui_loaded = True


def get_vendor(mac: str) -> str:
    """Return manufacturer name for a MAC address, or 'Unknown'."""
    _load_oui()
    if not mac or mac == 'N/A':
        return 'Unknown'
    oui = mac.upper()[:8]
    return _oui_table.get(oui, 'Unknown')


def download_oui(force=False):
    """
    Download the IEEE OUI CSV from the internet and save to OUI_FILE.
    Only needed once — run manually if vendor lookup shows 'Unknown'.
    """
    if os.path.exists(OUI_FILE) and not force:
        logger.info("OUI file already exists. Use force=True to re-download.")
        return
    import urllib.request
    url = 'https://maclookup.app/downloads/csv-database/get-db?t=22-08-19&h=d1'
    logger.info(f"Downloading OUI database from {url} ...")
    try:
        urllib.request.urlretrieve(url, OUI_FILE)
        logger.info(f"OUI database saved to {OUI_FILE}")
        global _oui_loaded
        _oui_loaded = False
        _oui_table.clear()
        _load_oui()
    except Exception as e:
        logger.error(f"Failed to download OUI database: {e}")


# ---------------------------------------------------------------------------
# Device data model
# ---------------------------------------------------------------------------

class Device:
    __slots__ = [
        'ip', 'mac', 'hostname', 'vendor',
        'first_seen', 'last_seen',
        'bytes_sent', 'bytes_recv',
        'pkts_sent', 'pkts_recv',
        'protocols', 'alert_count', 'is_gateway',
    ]

    def __init__(self, ip, mac='N/A'):
        self.ip          = ip
        self.mac         = mac.upper() if mac else 'N/A'
        self.hostname    = ''
        self.vendor      = get_vendor(mac)
        self.first_seen  = datetime.utcnow().isoformat()
        self.last_seen   = self.first_seen
        self.bytes_sent  = 0
        self.bytes_recv  = 0
        self.pkts_sent   = 0
        self.pkts_recv   = 0
        self.protocols   = set()
        self.alert_count = 0
        self.is_gateway  = False

    def to_dict(self):
        return {
            'ip':          self.ip,
            'mac':         self.mac,
            'hostname':    self.hostname or self.ip,
            'vendor':      self.vendor,
            'first_seen':  self.first_seen,
            'last_seen':   self.last_seen,
            'bytes_sent':  self.bytes_sent,
            'bytes_recv':  self.bytes_recv,
            'pkts_sent':   self.pkts_sent,
            'pkts_recv':   self.pkts_recv,
            'protocols':   list(self.protocols),
            'alert_count': self.alert_count,
            'is_gateway':  self.is_gateway,
        }


# ---------------------------------------------------------------------------
# Network Scanner
# ---------------------------------------------------------------------------

PROTO_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


class NetworkScanner:
    """
    Maintains a live map of devices on the local subnet.

    Usage:
        scanner = NetworkScanner(interface='en0')
        scanner.start()          # starts background ARP scan + traffic tracking
        scanner.get_devices()    # returns list of Device dicts
        scanner.stop()
    """

    def __init__(self, interface=None, scan_interval=30, local_ip=None):
        self.interface     = interface or str(conf.iface)
        self.scan_interval = scan_interval
        self.local_ip      = local_ip or self._get_local_ip()
        self.subnet        = self._guess_subnet(self.local_ip)
        self.gateway_ip    = self._guess_gateway()

        self._devices: dict[str, Device] = {}   # ip -> Device
        self._lock    = threading.Lock()
        self._stop    = threading.Event()
        self._threads: list[threading.Thread] = []

        logger.info(
            f"NetworkScanner initialised — interface={self.interface}, "
            f"local_ip={self.local_ip}, subnet={self.subnet}, "
            f"gateway={self.gateway_ip}"
        )

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def _guess_subnet(self, local_ip):
        """Guess /24 subnet from local IP."""
        try:
            parts = local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return '192.168.1.0/24'

    def _guess_gateway(self):
        """Guess gateway as x.x.x.1"""
        try:
            parts = self.local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except Exception:
            return ''

    def _resolve_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ''

    # ------------------------------------------------------------------ #
    # ARP Scanning                                                         #
    # ------------------------------------------------------------------ #

    def _arp_scan(self):
        """Send ARP requests to entire subnet, collect responses."""
        try:
            logger.debug(f"ARP scanning {self.subnet} ...")
            arp  = ARP(pdst=self.subnet)
            ether = Ether(dst='ff:ff:ff:ff:ff:ff')
            answered, _ = srp(ether / arp, iface=self.interface,
                               timeout=3, verbose=False)
            found = {}
            for sent, received in answered:
                ip  = received.psrc
                mac = received.hwsrc
                found[ip] = mac
            logger.debug(f"ARP scan found {len(found)} host(s).")
            return found
        except Exception as e:
            logger.warning(f"ARP scan error: {e}")
            return {}

    def _scan_loop(self):
        """Background thread: periodic ARP scan."""
        while not self._stop.is_set():
            hosts = self._arp_scan()
            now   = datetime.utcnow().isoformat()

            with self._lock:
                for ip, mac in hosts.items():
                    if ip not in self._devices:
                        dev = Device(ip, mac)
                        dev.hostname   = self._resolve_hostname(ip)
                        dev.is_gateway = (ip == self.gateway_ip)
                        self._devices[ip] = dev
                        logger.info(
                            f"New device discovered: {ip} "
                            f"({dev.hostname or 'unknown'}) "
                            f"[{mac}] {dev.vendor}"
                        )
                    else:
                        dev = self._devices[ip]
                        dev.last_seen = now
                        if dev.mac == 'N/A' and mac:
                            dev.mac    = mac.upper()
                            dev.vendor = get_vendor(mac)

            self._stop.wait(self.scan_interval)

    # ------------------------------------------------------------------ #
    # Per-packet traffic tracking                                          #
    # ------------------------------------------------------------------ #

    def update_traffic(self, packet):
        """
        Call this for every captured packet to track per-device stats.
        Designed to be used as a Scapy prn callback or called from NIDS.
        """
        if not packet.haslayer(IP):
            return

        ip       = packet[IP]
        src      = ip.src
        dst      = ip.dst
        pkt_len  = len(packet)
        proto    = ip.proto
        proto_name = PROTO_NAMES.get(proto, str(proto))
        now      = datetime.utcnow().isoformat()

        with self._lock:
            # Source device — bytes_sent
            if src not in self._devices:
                self._devices[src] = Device(src)
                self._devices[src].hostname = self._resolve_hostname(src)
            self._devices[src].bytes_sent += pkt_len
            self._devices[src].pkts_sent  += 1
            self._devices[src].last_seen   = now
            self._devices[src].protocols.add(proto_name)

            # Destination device — bytes_recv (only local IPs)
            if dst not in self._devices:
                self._devices[dst] = Device(dst)
                self._devices[dst].hostname = self._resolve_hostname(dst)
            self._devices[dst].bytes_recv += pkt_len
            self._devices[dst].pkts_recv  += 1
            self._devices[dst].last_seen   = now

    def increment_alert(self, ip: str):
        """Increment the alert counter for a device."""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].alert_count += 1

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def start(self):
        """Start background ARP scanning thread."""
        t = threading.Thread(target=self._scan_loop, daemon=True, name='ARPScanner')
        t.start()
        self._threads.append(t)
        logger.info("Network scanner started.")

    def stop(self):
        """Stop all background threads."""
        self._stop.set()
        logger.info("Network scanner stopped.")

    def get_devices(self) -> list:
        """Return list of device dicts, sorted by last_seen descending."""
        with self._lock:
            devs = [d.to_dict() for d in self._devices.values()]
        devs.sort(key=lambda d: d['last_seen'], reverse=True)
        return devs

    def get_device(self, ip: str) -> dict:
        """Return a single device dict by IP."""
        with self._lock:
            d = self._devices.get(ip)
            return d.to_dict() if d else None

    def get_stats(self) -> dict:
        """Return summary stats for the Devices tab."""
        with self._lock:
            devs = list(self._devices.values())
        return {
            'total_devices':  len(devs),
            'active_devices': sum(1 for d in devs if d.bytes_sent > 0 or d.bytes_recv > 0),
            'total_bytes':    sum(d.bytes_sent + d.bytes_recv for d in devs),
            'alerted_devices': sum(1 for d in devs if d.alert_count > 0),
            'subnet':         self.subnet,
            'gateway':        self.gateway_ip,
            'local_ip':       self.local_ip,
        }


def fmt_bytes(n: int) -> str:
    """Human-readable byte size."""
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
