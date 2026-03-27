"""
NIDS — Threat Intelligence Engine
=================================
Queries multiple threat intelligence sources:
  - AbuseIPDB API (free tier) for IP reputation
  - Local blocklists (config/blocklists/*.txt — one IP/CIDR per line)
  - Redis cache with in-memory TTL fallback

Results are cached. Auto-escalates severity if IP is found in threat feeds.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import urllib.request
import urllib.error

logger = logging.getLogger("NIDS.ThreatIntel")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ThreatIntelResult:
    """Result of a threat intel lookup."""
    ip: str
    score: int | None  # 0-100 abuse score
    source: str
    is_malicious: bool
    country_code: str | None = None
    isp: str | None = None
    domain: str | None = None
    cached: bool = False
    raw_data: dict | None = None


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

class TTLCache:
    """
    Simple in-memory TTL cache for threat intel results.
    Thread-safe.
    """

    def __init__(self, ttl_seconds: int = 3600):
        self._cache: dict[str, tuple[ThreatIntelResult, float]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def get(self, key: str) -> ThreatIntelResult | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            result, expires_at = entry
            if time.time() > expires_at:
                del self._cache[key]
                return None
            result.cached = True
            return result

    def set(self, key: str, result: ThreatIntelResult) -> None:
        with self._lock:
            expires_at = time.time() + self._ttl
            self._cache[key] = (result, expires_at)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# ---------------------------------------------------------------------------
# Blocklist loader
# ---------------------------------------------------------------------------

class BlocklistLoader:
    """Loads IP blocklists from files in config/blocklists/."""

    def __init__(self, blocklist_dir: Path):
        self.blocklist_dir = blocklist_dir
        self._blocklist: set[str] = set()
        self._subnets: list = []
        self._last_load: float = 0
        self._lock = threading.Lock()

    def load(self) -> None:
        """Load all blocklist files."""
        self._blocklist.clear()
        self._subnets.clear()

        if not self.blocklist_dir.exists():
            logger.debug(f"Blocklist directory not found: {self.blocklist_dir}")
            return

        for filepath in self.blocklist_dir.glob("*.txt"):
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        self._add_entry(line)
            except Exception as e:
                logger.warning(f"Failed to load blocklist {filepath}: {e}")

        self._last_load = time.time()
        logger.info(
            f"Blocklists loaded from {self.blocklist_dir}: "
            f"{len(self._blocklist)} IPs, {len(self._subnets)} CIDRs."
        )

    def _add_entry(self, entry: str) -> None:
        entry = entry.strip()
        if "/" in entry:
            try:
                self._subnets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass
        else:
            try:
                ipaddress.ip_address(entry)
                self._blocklist.add(entry)
            except ValueError:
                pass

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is in any blocklist."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip in self._blocklist:
                return True
            for subnet in self._subnets:
                if ip_obj in subnet:
                    return True
        except ValueError:
            pass
        return False

    def get_blocked_entries(self) -> list[dict]:
        """Return all blocked entries as dicts."""
        result = []
        for ip in sorted(self._blocklist):
            result.append({"ip": ip, "type": "ip"})
        for subnet in sorted(self._subnets, key=lambda s: str(s)):
            result.append({"ip": str(subnet), "type": "cidr"})
        return result


# ---------------------------------------------------------------------------
# AbuseIPDB API client
# ---------------------------------------------------------------------------

class AbuseIPDBClient:
    """Client for the AbuseIPDB API (free tier — 1 req/sec limit)."""

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"
    MAX_SEVERITY = 100

    def __init__(self, api_key: str, check_interval_seconds: int = 1):
        self.api_key = api_key
        self.check_interval = check_interval_seconds
        self._last_request: float = 0
        self._lock = threading.Lock()

    def _rate_limit(self) -> None:
        """Enforce 1 request per second."""
        with self._lock:
            elapsed = time.time() - self._last_request
            if elapsed < self.check_interval:
                time.sleep(self.check_interval - elapsed)
            self._last_request = time.time()

    def check_ip(self, ip: str) -> dict[str, Any] | None:
        """
        Query AbuseIPDB for an IP address.
        Returns a dict with abuse score and metadata, or None on error.
        """
        if not self.api_key:
            return None

        self._rate_limit()

        try:
            url = f"{self.BASE_URL}?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(
                url,
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read())
                    return data.get("data")
                logger.warning(f"AbuseIPDB returned status {resp.status} for {ip}")
                return None

        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("AbuseIPDB rate limit hit.")
            else:
                logger.warning(f"AbuseIPDB HTTP error for {ip}: {e.code}")
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")

        return None


# ---------------------------------------------------------------------------
# GeoIP helper
# ---------------------------------------------------------------------------

_geo_reader = None


def _get_geo_reader():
    global _geo_reader
    if _geo_reader is not None:
        return _geo_reader
    try:
        import geoip2.database
        for db_path in [
            "/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
            "/usr/share/GeoIP/GeoLite2-Country.mmdb",
            Path(__file__).parent.parent / "config" / "GeoLite2-Country.mmdb",
        ]:
            if Path(db_path).exists():
                _geo_reader = geoip2.database.Reader(str(db_path))
                logger.info(f"GeoIP database loaded from {db_path}")
                return _geo_reader
    except ImportError:
        logger.debug("geoip2 not installed — country lookup disabled.")
    except Exception as e:
        logger.debug(f"GeoIP database not available: {e}")
    return None


def _get_country_code(ip: str) -> str | None:
    reader = _get_geo_reader()
    if reader is None:
        return None
    try:
        response = reader.country(ip)
        return response.country.iso_code
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ThreatIntelEngine
# ---------------------------------------------------------------------------

class ThreatIntelEngine:
    """
    Unified threat intelligence engine combining AbuseIPDB and local blocklists.
    Results are cached (Redis if available, in-memory TTL fallback).
    """

    def __init__(
        self,
        abuseipdb_api_key: str = "",
        blocklist_dir: Path | None = None,
        cache_ttl_seconds: int = 3600,
        escalation_threshold: int = 50,
    ):
        self.abuseipdb = AbuseIPDBClient(abuseipdb_api_key) if abuseipdb_api_key else None
        self.blocklist = BlocklistLoader(blocklist_dir or Path("config/blocklists"))
        self.cache = TTLCache(ttl_seconds=cache_ttl_seconds)
        self.escalation_threshold = escalation_threshold
        self._redis_client = None
        self._redis_available = False

        # Try to connect to Redis
        self._try_redis()

    def _try_redis(self) -> None:
        """Attempt to connect to Redis for caching."""
        try:
            import redis
            host = os.environ.get("REDIS_HOST", "localhost")
            port = int(os.environ.get("REDIS_PORT", "6379"))
            self._redis_client = redis.Redis(host=host, port=port, decode_responses=True)
            self._redis_client.ping()
            self._redis_available = True
            logger.info("Threat intel Redis cache connected.")
        except Exception:
            self._redis_client = None
            self._redis_available = False
            logger.debug("Redis not available — using in-memory TTL cache.")

    def _redis_key(self, ip: str) -> str:
        return f"threat_intel:{ip}"

    def _redis_get(self, ip: str) -> ThreatIntelResult | None:
        if not self._redis_available:
            return None
        try:
            data = self._redis_client.get(self._redis_key(ip))
            if data:
                obj = json.loads(data)
                return ThreatIntelResult(**obj)
        except Exception:
            pass
        return None

    def _redis_set(self, result: ThreatIntelResult, ttl: int) -> None:
        if not self._redis_available:
            return
        try:
            import json as json_mod
            data = json_mod.dumps({
                "ip": result.ip,
                "score": result.score,
                "source": result.source,
                "is_malicious": result.is_malicious,
                "country_code": result.country_code,
                "isp": result.isp,
                "domain": result.domain,
                "cached": result.cached,
                "raw_data": result.raw_data,
            })
            self._redis_client.setex(self._redis_key(result.ip), ttl, data)
        except Exception:
            pass

    def start(self) -> None:
        """Load blocklists on startup."""
        self.blocklist.load()

    def reload_blocklists(self) -> None:
        """Reload blocklists from disk."""
        self.blocklist.load()

    def check_ip(self, ip: str) -> ThreatIntelResult:
        """
        Perform a full threat intel lookup on an IP address.
        Checks cache first, then blocklists, then AbuseIPDB.
        """
        # Check cache first
        cached = self.cache.get(ip)
        if cached:
            return cached

        redis_result = self._redis_get(ip)
        if redis_result:
            self.cache.set(ip, redis_result)
            return redis_result

        # Check blocklists
        if self.blocklist.is_blocked(ip):
            result = ThreatIntelResult(
                ip=ip,
                score=100,
                source="blocklist",
                is_malicious=True,
                country_code=_get_country_code(ip),
            )
            self.cache.set(ip, result)
            self._redis_set(result, 3600)
            return result

        # Check AbuseIPDB
        if self.abuseipdb:
            data = self.abuseipdb.check_ip(ip)
            if data:
                score = data.get("abuseConfidenceScore", 0)
                is_malicious = score >= self.escalation_threshold
                country = data.get("countryCode")
                if not country:
                    country = _get_country_code(ip)
                result = ThreatIntelResult(
                    ip=ip,
                    score=score,
                    source="abuseipdb",
                    is_malicious=is_malicious,
                    country_code=country,
                    isp=data.get("isp"),
                    domain=data.get("domain"),
                    raw_data=data,
                )
                self.cache.set(ip, result)
                self._redis_set(result, 3600)
                return result

        # No threat found
        result = ThreatIntelResult(
            ip=ip,
            score=0,
            source="none",
            is_malicious=False,
            country_code=_get_country_code(ip),
        )
        self.cache.set(ip, result)
        self._redis_set(result, 1800)
        return result

    def should_escalate(self, ip: str, current_severity: str) -> tuple[bool, int]:
        """
        Check if severity should be escalated based on threat intel.
        Returns (should_escalate, new_score).
        """
        result = self.check_ip(ip)
        if result.is_malicious and result.score and result.score > self.escalation_threshold:
            return True, result.score
        return False, 0

    def get_blocklist(self) -> list[dict]:
        """Return all current blocklist entries."""
        return self.blocklist.get_blocked_entries()

    def add_to_blocklist(self, entry: str, source: str = "manual") -> bool:
        """Add an IP or CIDR to the blocklist file."""
        blocklist_file = self.blocklist_dir / "manual_blocklist.txt"
        try:
            with open(blocklist_file, "a") as f:
                f.write(f"{entry}\n")
            self.blocklist.load()
            return True
        except Exception as e:
            logger.error(f"Failed to add {entry} to blocklist: {e}")
            return False

    def remove_from_blocklist(self, entry: str) -> bool:
        """Remove an IP or CIDR from the blocklist."""
        blocklist_file = self.blocklist_dir / "manual_blocklist.txt"
        if not blocklist_file.exists():
            return False
        try:
            with open(blocklist_file) as f:
                lines = [l.strip() for l in f if l.strip() != entry]
            with open(blocklist_file, "w") as f:
                f.write("\n".join(lines) + "\n")
            self.blocklist.load()
            return True
        except Exception as e:
            logger.error(f"Failed to remove {entry} from blocklist: {e}")
            return False


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
_engine: ThreatIntelEngine | None = None


def get_threat_intel_engine() -> ThreatIntelEngine:
    global _engine
    if _engine is None:
        from config.settings import get_settings
        s = get_settings()
        _engine = ThreatIntelEngine(
            abuseipdb_api_key=s.threat_intel.abuseipdb_api_key,
            blocklist_dir=s.threat_intel.blocklist_dir,
            cache_ttl_seconds=s.threat_intel.cache_ttl_seconds,
            escalation_threshold=s.threat_intel.abuseipdb_check_severity,
        )
    return _engine


import os
