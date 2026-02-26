"""
NIDS — Network Intrusion Detection System
Entry point: python config/main.py  (or use the CLI: python config/cli.py start)
"""

import os
import sys
import logging
import threading

# Make sure imports work whether launched from repo root or config/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'config'))

from logging_alerting import (setup_logging, log_intrusion, alert_intrusion,
                               log_event, SEVERITY_LOW, SEVERITY_MEDIUM,
                               SEVERITY_HIGH, SEVERITY_CRITICAL)
from packet_capture import capture_packets, list_interfaces, get_default_interface
from signature_detection import load_rules, detect_signatures, SignatureDetector
from anomaly_detection import (load_model, load_anomaly_thresholds,
                                perform_anomaly_detection, extract_features)
from database import init_db, log_intrusion_event, log_system_event
from notifications import send_notification

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
RULES_FILE      = os.path.join(BASE_DIR, 'config', 'rules.json')
THRESHOLDS_FILE = os.path.join(BASE_DIR, 'config', 'anomaly_thresholds.json')
MODEL_PATH      = os.path.join(BASE_DIR, 'models', 'anomaly_model.joblib')
LOG_DIR         = os.path.join(BASE_DIR, 'logs')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig_severity(match):
    """Map signature match count ratio to a severity level."""
    ratio = match['count'] / max(match['threshold'], 1)
    if ratio >= 5:
        return SEVERITY_CRITICAL
    elif ratio >= 2:
        return SEVERITY_HIGH
    elif ratio >= 1:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _handle_sig_match(match, sse_push=None):
    """Log, alert, persist and notify a signature detection match."""
    sev = _sig_severity(match)
    msg = (f"Signature alert — {match['description']} | "
           f"src={match['src_ip']} dst={match['dst_ip']} "
           f"count={match['count']}/{match['threshold']}")
    log_intrusion(msg, severity=sev)
    alert_intrusion(msg, severity=sev)

    details = {
        'src_ip':      match['src_ip'],
        'dst_ip':      match['dst_ip'],
        'protocol':    match['protocol'],
        'description': match['description'],
        'rule_id':     match['rule_id'],
        'count':       match['count'],
        'threshold':   match['threshold'],
    }
    log_intrusion_event('signature', sev, msg, details=details)
    send_notification(sev, msg, details=details)

    if sse_push:
        sse_push({**details, 'severity': sev, 'event_type': 'signature',
                  'raw_message': msg})


def _handle_anomaly(anomaly, sse_push=None):
    """Log, alert, persist and notify an anomaly detection result."""
    sev = SEVERITY_HIGH
    msg = (f"Anomaly detected | src={anomaly['src_ip']} "
           f"dst={anomaly['dst_ip']} proto={anomaly['protocol']} "
           f"len={anomaly['packet_length']}")
    log_intrusion(msg, severity=sev)
    alert_intrusion(msg, severity=sev)

    details = {
        'src_ip':        anomaly['src_ip'],
        'dst_ip':        anomaly['dst_ip'],
        'protocol':      str(anomaly['protocol']),
        'packet_length': anomaly['packet_length'],
        'tcp_flags':     anomaly['tcp_flags'],
        'ttl':           anomaly['ttl'],
        'description':   msg,
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
        interface      : Network interface to sniff on (None = auto-detect).
        packet_count   : Number of packets to capture per batch (0 = unlimited).
        timeout        : Capture timeout in seconds.
        packet_filter  : BPF filter string e.g. 'tcp', 'not arp'.
        live           : If True, process each packet in real-time.
        dashboard      : If True, start the web dashboard in a background thread.
        dashboard_port : Port for the web dashboard (default 5000).
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
    # 2. Optional web dashboard
    # ------------------------------------------------------------------
    sse_push = None
    if dashboard:
        try:
            from dashboard import run_dashboard, push_sse_event
            sse_push = push_sse_event
            t = threading.Thread(
                target=run_dashboard,
                kwargs={'port': dashboard_port},
                daemon=True,
            )
            t.start()
            logger.info(f"Web dashboard available at http://localhost:{dashboard_port}")
        except ImportError as e:
            logger.warning(f"Dashboard unavailable (install flask): {e}")

    # ------------------------------------------------------------------
    # 3. Load detection config
    # ------------------------------------------------------------------
    rules      = load_rules(RULES_FILE)
    thresholds = load_anomaly_thresholds(THRESHOLDS_FILE)
    model      = load_model(MODEL_PATH)

    if not rules:
        logger.warning("No signature rules loaded — signature detection disabled.")
    if model is None:
        logger.warning("No ML model loaded — anomaly detection disabled.")

    # ------------------------------------------------------------------
    # 4. Resolve interface
    # ------------------------------------------------------------------
    if interface is None:
        interface = get_default_interface()
        logger.info(f"Auto-selected interface: {interface}")

    # ------------------------------------------------------------------
    # 5. Packet capture + detection
    # ------------------------------------------------------------------
    sig_detector = SignatureDetector(rules) if rules else None

    if live:
        logger.info("Running in LIVE (real-time) mode.")

        def _process_packet(pkt):
            if sig_detector:
                for match in sig_detector.evaluate(pkt):
                    _handle_sig_match(match, sse_push=sse_push)
            if model:
                for anomaly in perform_anomaly_detection([pkt], model, thresholds):
                    _handle_anomaly(anomaly, sse_push=sse_push)

        capture_packets(
            interface=interface,
            count=packet_count,
            timeout=timeout,
            packet_filter=packet_filter,
            callback=_process_packet,
        )

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
                _handle_sig_match(match, sse_push=sse_push)

        anomaly_alerts = []
        if model:
            anomaly_alerts = perform_anomaly_detection(packets, model, thresholds)
            logger.info(f"Anomaly detection: {len(anomaly_alerts)} alert(s).")
            for anomaly in anomaly_alerts:
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
                        help='Network interface to capture on (default: auto)')
    parser.add_argument('-c', '--count', type=int, default=200,
                        help='Number of packets to capture per batch (default: 200)')
    parser.add_argument('-t', '--timeout', type=int, default=60,
                        help='Capture timeout in seconds (default: 60)')
    parser.add_argument('-f', '--filter', dest='bpf_filter', default=None,
                        help="BPF capture filter e.g. 'tcp' or 'not arp'")
    parser.add_argument('--live', action='store_true',
                        help='Enable real-time per-packet processing mode')
    parser.add_argument('--dashboard', action='store_true',
                        help='Launch the web dashboard alongside the NIDS')
    parser.add_argument('--dashboard-port', type=int, default=5000,
                        help='Port for the web dashboard (default: 5000)')
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
