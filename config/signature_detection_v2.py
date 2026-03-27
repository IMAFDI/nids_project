"""
NIDS — Signature Detection Engine v2
====================================
Extended, stateful signature detector with support for multiple rule types:
  - SIGNATURE   : Protocol, IP, port, TCP flags, threshold/time window
  - RATE_LIMIT  : Trigger if X packets/sec from same IP
  - PAYLOAD_MATCH: Regex match on packet payload
  - GEO_BLOCK   : Block traffic from specific countries (requires GeoIP2)
  - WHITELIST   : Always-pass rules for trusted IPs/subnets

Rules are loaded from both rules.json (file) AND the database (live CRUD).
"""

from __future__ import annotations

import json
import re
import time
import logging
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from scapy.all import IP, TCP, UDP, ICMP, Raw

logger = logging.getLogger("NIDS.SignatureDetection")

# Protocol number map
PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}

# Rule types
RULE_TYPE_SIGNATURE = "SIGNATURE"
RULE_TYPE_RATE_LIMIT = "RATE_LIMIT"
RULE_TYPE_PAYLOAD_MATCH = "PAYLOAD_MATCH"
RULE_TYPE_GEO_BLOCK = "GEO_BLOCK"
RULE_TYPE_WHITELIST = "WHITELIST"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    """A detection rule loaded from rules.json or the database."""
    id: int | str
    name: str
    rule_type: str
    enabled: bool = True
    version: int = 1
    priority: str = "MEDIUM"  # LOW | MEDIUM | HIGH | CRITICAL
    criteria: dict = field(default_factory=dict)
    description: str = ""
    # State for rate limiting
    _counters: dict = field(default_factory=lambda: defaultdict(list))
    _last_reset: float = field(default_factory=time.time)

    def reset_counters(self) -> None:
        """Reset all counters for this rule."""
        self._counters.clear()
        self._last_reset = time.time()


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
        db_path = "/usr/local/share/GeoIP/GeoLite2-Country.mmdb"
        if not os.path.exists(db_path):
            db_path = os.path.join(os.path.dirname(__file__), "..", "config", "GeoLite2-Country.mmdb")
        if os.path.exists(db_path):
            _geo_reader = geoip2.database.Reader(db_path)
            logger.info(f"GeoIP database loaded from {db_path}")
        else:
            logger.warning("GeoIP database not found — GEO_BLOCK rules will be skipped.")
    except ImportError:
        logger.warning("geoip2 package not installed — GEO_BLOCK rules will be skipped.")
    except Exception as e:
        logger.warning(f"Failed to load GeoIP database: {e}")
    return _geo_reader


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
# IP/subnet matching
# ---------------------------------------------------------------------------

def _ip_matches(pattern: str, ip: str) -> bool:
    """Match an IP against a pattern (exact, CIDR, or 'any')."""
    if pattern == "any":
        return True
    if "/" in pattern:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
    return pattern == ip


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def load_rules_from_file(rule_file: str) -> list[dict]:
    """Load rules from a JSON file."""
    try:
        with open(rule_file, "r") as f:
            data = json.load(f)
        rules = data.get("rules", [])
        logger.info(f"Loaded {len(rules)} signature rule(s) from '{rule_file}'.")
        return rules
    except FileNotFoundError:
        logger.error(f"Rules file not found: {rule_file}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse rules file: {e}")
        return []


def _json_rule_to_rule(rule_json: dict) -> Rule:
    """Convert a JSON rule dict to a Rule dataclass."""
    return Rule(
        id=rule_json["id"],
        name=rule_json.get("name", rule_json.get("description", "")),
        rule_type=rule_json.get("rule_type", RULE_TYPE_SIGNATURE),
        enabled=rule_json.get("enabled", True),
        version=rule_json.get("version", 1),
        priority=rule_json.get("priority", "MEDIUM"),
        criteria={
            "protocol": rule_json.get("protocol", "any"),
            "src_ip": rule_json.get("src_ip", "any"),
            "dst_ip": rule_json.get("dst_ip", "any"),
            "src_port": rule_json.get("src_port", "any"),
            "dst_port": rule_json.get("dst_port", "any"),
            "flags": rule_json.get("flags"),
            "type": rule_json.get("type"),
            "threshold": rule_json.get("threshold", 1),
            "time_window": rule_json.get("time_window", 60),
            "rate_per_second": rule_json.get("rate_per_second"),
            "payload_regex": rule_json.get("payload_regex"),
            "countries": rule_json.get("countries", []),
        },
        description=rule_json.get("description", ""),
    )


# ---------------------------------------------------------------------------
# SignatureDetector
# ---------------------------------------------------------------------------

class SignatureDetector:
    """
    Stateful, extensible signature detector supporting multiple rule types.
    """

    def __init__(self, rules: list[dict] | None = None):
        self._rules: dict[int | str, Rule] = {}
        self._whitelist: set[str] = set()
        self._whitelist_subnets: list = []
        self._rate_tracker: dict[str, list[float]] = defaultdict(list)

        if rules:
            for r in rules:
                self.add_rule(r)

    def add_rule(self, rule_json: dict) -> None:
        """Add or replace a rule."""
        r = _json_rule_to_rule(rule_json)
        self._rules[r.id] = r
        logger.debug(f"Rule {r.id} ({r.rule_type}): {r.name} added/updated.")

    def remove_rule(self, rule_id: int | str) -> None:
        """Remove a rule by ID."""
        if rule_id in self._rules:
            del self._rules[rule_id]

    def get_rule(self, rule_id: int | str) -> Rule | None:
        return self._rules.get(rule_id)

    def get_rules(self) -> list[Rule]:
        return list(self._rules.values())

    def set_whitelist(self, ips: set[str]) -> None:
        """Set the whitelist of trusted IPs/subnets."""
        self._whitelist = ips
        self._whitelist_subnets = [
            ipaddress.ip_network(ip, strict=False)
            for ip in ips
            if "/" in ip
        ]
        trusted_ips = [ip for ip in ips if "/" not in ip]
        logger.info(f"Whitelist updated: {len(trusted_ips)} IPs, {len(self._whitelist_subnets)} subnets.")

    def _is_whitelisted(self, ip: str) -> bool:
        if ip in self._whitelist:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
            for subnet in self._whitelist_subnets:
                if ip_obj in subnet:
                    return True
        except ValueError:
            pass
        return False

    def _prune_window(self, key: tuple, window: float) -> list:
        """Return only timestamps within the window."""
        now = time.time()
        return [t for t in self._rate_tracker[key] if now - t <= window]

    def _check_rate_limit(self, ip: str, rate_per_second: int, window: float = 1.0) -> bool:
        """
        Check if an IP has exceeded the rate limit.
        Returns True if the limit is EXCEEDED (should alert).
        """
        key = ip
        self._rate_tracker[key] = self._prune_window(key, window)
        count = len(self._rate_tracker[key])
        if count >= rate_per_second:
            return True  # Limit exceeded
        self._rate_tracker[key].append(time.time())
        return False

    # ------------------------------------------------------------------ #
    # Evaluation
    # ------------------------------------------------------------------ #

    def _match_ip(self, rule_val: str, packet_val: str) -> bool:
        return rule_val == "any" or _ip_matches(rule_val, packet_val)

    def _match_port(self, rule_val: Any, packet_val: Any) -> bool:
        if rule_val == "any":
            return True
        try:
            return int(rule_val) == int(packet_val)
        except (ValueError, TypeError):
            return False

    def _check_flags(self, rule_flags: str | None, packet) -> bool:
        if not rule_flags or not packet.haslayer(TCP):
            return True
        flag_map = {
            "SYN": 0x02, "ACK": 0x10, "FIN": 0x01,
            "RST": 0x04, "PSH": 0x08, "URG": 0x20,
        }
        required = 0
        for f in rule_flags.split(","):
            required |= flag_map.get(f.strip().upper(), 0)
        return bool(packet[TCP].flags & required)

    def _check_payload_regex(self, pattern: str | None, packet) -> bool:
        if not pattern:
            return True
        if not packet.haslayer(Raw):
            return False
        try:
            payload = bytes(packet[Raw].load)
            return bool(re.search(pattern, payload, re.IGNORECASE | re.DOTALL))
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            return False

    def _evaluate_signature_rule(self, rule: Rule, packet, ip) -> list[dict]:
        """Evaluate a SIGNATURE type rule."""
        crit = rule.criteria
        src_ip = ip.src
        dst_ip = ip.dst
        proto_str = crit.get("protocol", "any").lower()

        if proto_str != "any":
            expected = PROTO_MAP.get(proto_str)
            if expected is None or ip.proto != expected:
                return []

        if not self._match_ip(crit.get("src_ip", "any"), src_ip):
            return []
        if not self._match_ip(crit.get("dst_ip", "any"), dst_ip):
            return []

        src_port = dst_port = None
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if not self._match_port(crit.get("src_port", "any"), src_port):
            return []
        if not self._match_port(crit.get("dst_port", "any"), dst_port):
            return []

        if proto_str == "tcp" and not self._check_flags(crit.get("flags"), packet):
            return []

        if proto_str == "icmp" and packet.haslayer(ICMP):
            icmp_type = crit.get("type")
            if icmp_type == "echo-request" and packet[ICMP].type != 8:
                return []
            elif icmp_type == "echo-reply" and packet[ICMP].type != 0:
                return []

        # Threshold / time-window
        threshold = crit.get("threshold", 1)
        window = crit.get("time_window", 60)
        key = (rule.id, src_ip)
        self._rate_tracker[key] = self._prune_window(key, window)
        self._rate_tracker[key].append(time.time())
        count = len(self._rate_tracker[key])

        if count >= threshold:
            return [{
                "rule_id": rule.id,
                "rule_name": rule.name,
                "rule_type": rule.rule_type,
                "priority": rule.priority,
                "description": rule.description or rule.name,
                "protocol": proto_str,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "count": count,
                "threshold": threshold,
                "window": window,
            }]
        return []

    def _evaluate_rate_limit_rule(self, rule: Rule, packet, ip) -> list[dict]:
        """Evaluate a RATE_LIMIT type rule."""
        if not packet.haslayer(IP):
            return []
        src_ip = ip.src
        rate = rule.criteria.get("rate_per_second", 100)
        window = rule.criteria.get("time_window", 1)
        protocol = rule.criteria.get("protocol", "any").lower()

        if protocol != "any":
            proto_num = PROTO_MAP.get(protocol)
            if proto_num and ip.proto != proto_num:
                return []

        exceeded = self._check_rate_limit(src_ip, rate, window)
        if exceeded:
            return [{
                "rule_id": rule.id,
                "rule_name": rule.name,
                "rule_type": rule.rule_type,
                "priority": rule.priority,
                "description": rule.description or f"Rate limit exceeded: {rate} pkt/s",
                "protocol": PROTO_MAP.get(ip.proto, ip.proto),
                "src_ip": src_ip,
                "dst_ip": ip.dst,
                "count": len(self._rate_tracker.get(src_ip, [])),
                "threshold": rate,
                "window": window,
            }]
        return []

    def _evaluate_payload_match_rule(self, rule: Rule, packet, ip) -> list[dict]:
        """Evaluate a PAYLOAD_MATCH type rule."""
        if not packet.haslayer(Raw):
            return []
        pattern = rule.criteria.get("payload_regex")
        if not pattern:
            return []
        if not self._check_payload_regex(pattern, packet):
            return []

        return [{
            "rule_id": rule.id,
            "rule_name": rule.name,
            "rule_type": rule.rule_type,
            "priority": rule.priority,
            "description": rule.description or f"Payload matched: {pattern}",
            "protocol": PROTO_MAP.get(ip.proto, ip.proto),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "count": 1,
            "threshold": 1,
            "window": 0,
        }]

    def _evaluate_geo_block_rule(self, rule: Rule, packet, ip) -> list[dict]:
        """Evaluate a GEO_BLOCK type rule."""
        countries = rule.criteria.get("countries", [])
        if not countries:
            return []
        country = _get_country_code(ip.src)
        if country and country.upper() in [c.upper() for c in countries]:
            return [{
                "rule_id": rule.id,
                "rule_name": rule.name,
                "rule_type": rule.rule_type,
                "priority": rule.priority,
                "description": rule.description or f"Traffic blocked from country: {country}",
                "protocol": PROTO_MAP.get(ip.proto, ip.proto),
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "count": 1,
                "threshold": 1,
                "window": 0,
                "country_code": country,
            }]
        return []

    def _evaluate_whitelist_rule(self, rule: Rule, packet, ip) -> list[dict]:
        """WHITELIST rules always pass — they mark IPs as trusted."""
        return []

    def evaluate(self, packet) -> list[dict]:
        """
        Evaluate a packet against all enabled rules.

        Returns:
            list[dict]: All matched rule events.
        """
        matches = []

        if not packet.haslayer(IP):
            return matches

        ip = packet[IP]
        src_ip = ip.src

        # Skip whitelisted IPs first
        if self._is_whitelisted(src_ip):
            return matches

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            try:
                if rule.rule_type == RULE_TYPE_SIGNATURE:
                    matches.extend(self._evaluate_signature_rule(rule, packet, ip))
                elif rule.rule_type == RULE_TYPE_RATE_LIMIT:
                    matches.extend(self._evaluate_rate_limit_rule(rule, packet, ip))
                elif rule.rule_type == RULE_TYPE_PAYLOAD_MATCH:
                    matches.extend(self._evaluate_payload_match_rule(rule, packet, ip))
                elif rule.rule_type == RULE_TYPE_GEO_BLOCK:
                    matches.extend(self._evaluate_geo_block_rule(rule, packet, ip))
                elif rule.rule_type == RULE_TYPE_WHITELIST:
                    matches.extend(self._evaluate_whitelist_rule(rule, packet, ip))
            except Exception as e:
                logger.warning(f"Error evaluating rule {rule.id}: {e}")

        return matches


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def create_detector(rules: list[dict]) -> SignatureDetector:
    """Create a configured SignatureDetector from a list of rule dicts."""
    return SignatureDetector(rules=rules)


import os
