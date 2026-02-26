"""
NIDS — Network Intrusion Detection System
Entry point: python config/main.py  (or use the CLI: python config/cli.py start)
"""

import os
import sys
import logging
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'config'))

from logging_alerting import (setup_logging, log_intrusion, alert_intrusion,
                               log_event, SEVERITY_LOW, SEVERITY_MEDIUM,
                               SEVERITY_HIGH, SEVERITY_CRITICAL)
from packet_capture import (capture_packets, capture_live_forever,
                             list_interfaces, get_default_interface, stop_capture)
from signature_detection import load_rules, detect_signatures, SignatureDetector
from anomaly_detection import (load_model, load_anomaly_thresholds,
                                perform_anomaly_detection)
from database import init_db, log_intrusion_event, log_system_event
from notifications import send_notification
from network_scanner import NetworkScanner

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
RULES_FILE      = os.path.join(BASE_DIR, 'config', 'rules.json')
THRESHOLDS_FILE = os.path.join(BASE_DIR, 'config', 'anomaly_thresholds.json')
MODEL_PATH      = os.path.join(BASE_DIR, 'models', 'anomaly_model.joblib')
LOG_DIR         = os.path.join(BASE_DIR, 'logs')

# Whitelist of known-safe IPs (won't trigger anomaly alerts)
WHITELIST_FILE  = os.path.join(BASE_DIR, 'config', 'whitelist.json')


def _load_whitelist():
    import json
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE) as f:
                return set(json.load(f).get('ips', []))
        except Exception:
            pass
    return set()


def _sig_severity(match):
    ratio = match['count'] / max(match['threshold'], 1)
    if ratio >= 5:   return SEVERITY_CRITICAL
    elif ratio >= 2: return SEVERITY_HIGH
    elif ratio >= 1: return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _handle_sig_match(match, sse_push=None):
    sev = _sig_severity(match)
    msg = (f"Signature alert — {match['description']} | "
           f"src={match['src_ip']} dst={match['dst_ip']} "
           f"count={match['count']}/{match['threshold']}")
    log_intrusion(msg, severity=sev)
    alert_intrusion(msg, severity=sev)
    details = {
        'src_ip': match['src_ip'], 'dst_ip': match['dst_ip'],
        'protocol': match['protocol'], 'description': match['description'],
        'rule_id': match['rule_id'], 'count': match['count'],
        'threshold': match['threshold'],
    }
    log_intrusion_event('signature', sev, msg, details=details)
    send_notification(sev, msg, details=details)
    if sse_push:
        sse_push({**details, 'severity': sev, 'event_type': 'signature',
                  'raw_message': msg})


def _handle_anomaly(anomaly, sse_push=None):
    sev = SEVERITY_HIGH
    msg = (f"Anomaly detected | src={anomaly['src_ip']} "
           f"dst={anomaly['dst_ip']} proto={anomaly['protocol']} "
           f"len={anomaly['packet_length']}")
    log_intrusion(msg, severity=sev)
    alert_intrusion(msg, severity=sev)
    details = {
        'src_ip': anomaly['src_ip'], 'dst_ip': anomaly['dst_ip'],
        'protocol': str(anomaly['protocol']),
        'packet_length': anomaly['packet_length'],
        'tcp_flags': anomaly['tcp_flags'], 'ttl': anomaly['ttl'],
        'description': msg,
    }
    log_intrusion_event('anomaly', sev, msg, details=details)
    send_notification(sev, msg, details=details)
    if sse_push:
        sse_push({**details, 'severity': sev, 'event_type': 'anomaly',
                  'raw_message': msg})


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run_nids(interface=None, packet_count=200, timeout=60,
             packet_filter=None, live=False, dashboard=False,
             dashboard_port=5000):
    """
    Main NIDS orchestration function.

    Args:
        interface      : Network interface (None = auto-detect).
        packet_count   : Packets per batch (0 = unlimited, batch mode only).
        timeout        : Capture timeout per batch in seconds.
        packet_filter  : BPF filter string.
        live           : If True, run indefinitely processing each packet in real-time.
        dashboard      : If True, start the web dashboard in a background thread.
        dashboard_port : Port for the web dashboard.
    """
    # ------------------------------------------------------------------
    # 1. Logging + DB
    # ------------------------------------------------------------------
    setup_logging(log_file=os.path.join(LOG_DIR, 'nids.log'), level=logging.INFO)
    logger = logging.getLogger('NIDS')
    logger.info("=" * 60)
    logger.info("NIDS starting up")
    logger.info("=" * 60)

    init_db()
    log_system_event('INFO', 'NIDS started')

    # ------------------------------------------------------------------
    # 2. Optional web dashboard (background thread)
    # ------------------------------------------------------------------
    sse_push = None
    if dashboard:
        try:
            from dashboard import run_dashboard, push_sse_event, set_scanner
            sse_push = push_sse_event
            t = threading.Thread(
                target=run_dashboard,
                kwargs={'host': '127.0.0.1', 'port': dashboard_port},
                daemon=True,
            )
            t.start()
            logger.info(f"Web dashboard → http://localhost:{dashboard_port}")
        except ImportError as e:
            logger.warning(f"Dashboard unavailable (install flask): {e}")
            set_scanner = None
    else:
        set_scanner = None

    # ------------------------------------------------------------------
    # 3. Load detection config
    # ------------------------------------------------------------------
    rules      = load_rules(RULES_FILE)
    thresholds = load_anomaly_thresholds(THRESHOLDS_FILE)
    model      = load_model(MODEL_PATH)
    whitelist  = _load_whitelist()

    if not rules:
        logger.warning("No signature rules loaded — signature detection disabled.")
    if model is None:
        logger.warning("No ML model loaded — anomaly detection disabled.")
    if whitelist:
        logger.info(f"IP whitelist loaded: {len(whitelist)} entries.")

    # ------------------------------------------------------------------
    # 3b. Start network scanner
    # ------------------------------------------------------------------
    scanner = NetworkScanner(interface=interface if interface else get_default_interface())
    scanner.start()
    if set_scanner:
        set_scanner(scanner)
    logger.info(f"Network scanner active — subnet={scanner.subnet}")

    # ------------------------------------------------------------------
    # 4. Resolve interface
    # ------------------------------------------------------------------
    if interface is None:
        interface = get_default_interface()
        logger.info(f"Auto-selected interface: {interface}")

    sig_detector = SignatureDetector(rules) if rules else None

    # ------------------------------------------------------------------
    # 5a. LIVE MODE — runs indefinitely until Ctrl+C / SIGTERM
    # ------------------------------------------------------------------
    if live:
        logger.info("Running in LIVE mode — press Ctrl+C to stop.")

        def _process_packet(pkt):
            # Track per-device traffic
            scanner.update_traffic(pkt)

            # Signature detection
            if sig_detector:
                for match in sig_detector.evaluate(pkt):
                    if match['src_ip'] not in whitelist:
                        _handle_sig_match(match, sse_push=sse_push)
                        scanner.increment_alert(match['src_ip'])

            # Anomaly detection
            if model:
                anomalies = perform_anomaly_detection([pkt], model, thresholds)
                for anomaly in anomalies:
                    if anomaly['src_ip'] not in whitelist:
                        _handle_anomaly(anomaly, sse_push=sse_push)
                        scanner.increment_alert(anomaly['src_ip'])

        # This blocks until Ctrl+C / SIGTERM — automatically restarts
        # the sniffer every 10 s so it never silently stops
        capture_live_forever(
            interface=interface,
            packet_filter=packet_filter,
            callback=_process_packet,
            batch_timeout=10,
        )

    # ------------------------------------------------------------------
    # 5b. BATCH MODE — capture N packets then analyse
    # ------------------------------------------------------------------
    else:
        logger.info("Running in BATCH mode.")
        packets = capture_packets(
            interface=interface,
            count=packet_count,
            timeout=timeout,
            packet_filter=packet_filter,
        )

        if not packets:
            logger.warning("No packets captured.")
            log_system_event('WARNING', 'No packets captured in batch')
            return

        logger.info(f"Analysing {len(packets)} packets ...")

        sig_alerts = []
        if sig_detector:
            sig_alerts = detect_signatures(packets, rules)
            logger.info(f"Signature detection: {len(sig_alerts)} alert(s).")
            for match in sig_alerts:
                if match['src_ip'] not in whitelist:
                    _handle_sig_match(match, sse_push=sse_push)

        anomaly_alerts = []
        if model:
            anomaly_alerts = perform_anomaly_detection(packets, model, thresholds)
            logger.info(f"Anomaly detection: {len(anomaly_alerts)} alert(s).")
            for anomaly in anomaly_alerts:
                if anomaly['src_ip'] not in whitelist:
                    _handle_anomaly(anomaly, sse_push=sse_push)

        total = len(sig_alerts) + len(anomaly_alerts)
        summary = (f"Batch complete — {total} threat(s) detected "
                   f"({len(sig_alerts)} signature, {len(anomaly_alerts)} anomaly) "
                   f"from {len(packets)} packets.")
        if total == 0:
            logger.info("✔  No threats detected in this batch.")
        else:
            logger.warning(f"⚠  {summary}")
        log_system_event('INFO', summary)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='NIDS — Network Intrusion Detection System')
    parser.add_argument('-i', '--interface', default=None,
                        help='Network interface (default: auto)')
    parser.add_argument('-c', '--count', type=int, default=200,
                        help='Packets per batch (default: 200, batch mode only)')
    parser.add_argument('-t', '--timeout', type=int, default=60,
                        help='Batch capture timeout seconds (default: 60)')
    parser.add_argument('-f', '--filter', dest='bpf_filter', default=None,
                        help="BPF filter e.g. 'tcp' or 'not arp'")
    parser.add_argument('--live', action='store_true',
                        help='Run indefinitely in real-time mode')
    parser.add_argument('--dashboard', action='store_true',
                        help='Launch web dashboard alongside NIDS')
    parser.add_argument('--dashboard-port', type=int, default=5000,
                        help='Dashboard port (default: 5000)')
    parser.add_argument('--list-interfaces', action='store_true',
                        help='Print available interfaces and exit')
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    run_nids(
        interface=args.interface,
        packet_count=args.count,
        timeout=args.timeout,
        packet_filter=args.bpf_filter,
        live=args.live,
        dashboard=args.dashboard,
        dashboard_port=args.dashboard_port,
    )
