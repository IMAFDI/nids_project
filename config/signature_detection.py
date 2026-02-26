import json
import time
import logging
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP

logger = logging.getLogger('NIDS.SignatureDetection')

# Protocol number map
PROTO_MAP = {'tcp': 6, 'udp': 17, 'icmp': 1}


def load_rules(rule_file):
    """Load signature rules from a JSON file."""
    try:
        with open(rule_file, 'r') as f:
            data = json.load(f)
        rules = data.get('rules', [])
        logger.info(f"Loaded {len(rules)} signature rule(s) from '{rule_file}'.")
        return rules
    except FileNotFoundError:
        logger.error(f"Rules file not found: {rule_file}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse rules file: {e}")
        return []


class SignatureDetector:
    """
    Stateful signature detector that evaluates full rule attributes:
    protocol, src/dst IP, src/dst port, TCP flags, threshold, and time window.
    """

    def __init__(self, rules):
        self.rules = rules
        # Counters keyed by (rule_id, src_ip): list of timestamps
        self._counters = defaultdict(list)

    def _match_ip(self, rule_val, packet_val):
        """Match IP field — 'any' is a wildcard."""
        return rule_val == 'any' or rule_val == packet_val

    def _match_port(self, rule_val, packet_val):
        """Match port field — 'any' is a wildcard."""
        if rule_val == 'any':
            return True
        try:
            return int(rule_val) == packet_val
        except (ValueError, TypeError):
            return False

    def _check_flags(self, rule_flags, packet):
        """Check TCP flags — e.g. rule_flags='SYN' means SYN must be set."""
        if not rule_flags or not packet.haslayer(TCP):
            return True
        flag_map = {
            'SYN': 0x02, 'ACK': 0x10, 'FIN': 0x01,
            'RST': 0x04, 'PSH': 0x08, 'URG': 0x20,
        }
        required = 0
        for f in rule_flags.split(','):
            required |= flag_map.get(f.strip().upper(), 0)
        return bool(packet[TCP].flags & required)

    def _prune_window(self, key, window):
        """Remove timestamps outside the current time window."""
        now = time.time()
        self._counters[key] = [
            t for t in self._counters[key] if now - t <= window
        ]

    def evaluate(self, packet):
        """
        Evaluate a single packet against all rules.

        Returns:
            list[dict]: List of matched rules with metadata.
        """
        matches = []

        if not packet.haslayer(IP):
            return matches

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto_num = ip.proto

        for rule in self.rules:
            rule_id = rule.get('id')
            proto_str = rule.get('protocol', 'any').lower()

            # --- Protocol check ---
            if proto_str != 'any':
                expected_proto = PROTO_MAP.get(proto_str)
                if expected_proto is None or proto_num != expected_proto:
                    continue

            # --- IP checks ---
            if not self._match_ip(rule.get('src_ip', 'any'), src_ip):
                continue
            if not self._match_ip(rule.get('dst_ip', 'any'), dst_ip):
                continue

            # --- Port checks ---
            src_port = None
            dst_port = None
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            if not self._match_port(rule.get('src_port', 'any'), src_port):
                continue
            if not self._match_port(rule.get('dst_port', 'any'), dst_port):
                continue

            # --- TCP flags check ---
            if proto_str == 'tcp' and not self._check_flags(rule.get('flags'), packet):
                continue

            # --- ICMP type check ---
            if proto_str == 'icmp' and packet.haslayer(ICMP):
                icmp_type = rule.get('type')
                if icmp_type == 'echo-request' and packet[ICMP].type != 8:
                    continue
                elif icmp_type == 'echo-reply' and packet[ICMP].type != 0:
                    continue

            # --- Threshold / time-window check ---
            threshold = rule.get('threshold', 1)
            window = rule.get('time_window', 60)
            key = (rule_id, src_ip)

            self._prune_window(key, window)
            self._counters[key].append(time.time())
            count = len(self._counters[key])

            if count >= threshold:
                match_info = {
                    'rule_id': rule_id,
                    'description': rule.get('description', ''),
                    'protocol': proto_str,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'count': count,
                    'threshold': threshold,
                    'window': window,
                }
                logger.warning(
                    f"Signature match — Rule {rule_id}: "
                    f"{rule.get('description')} | "
                    f"src={src_ip} count={count}/{threshold} in {window}s"
                )
                matches.append(match_info)

        return matches


def detect_signatures(packets, rules):
    """
    Convenience function: evaluate a list of packets against rules.

    Returns:
        list[dict]: All matched rule events.
    """
    detector = SignatureDetector(rules)
    all_matches = []
    for pkt in packets:
        matches = detector.evaluate(pkt)
        all_matches.extend(matches)
    return all_matches
