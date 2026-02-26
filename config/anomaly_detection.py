import os
import logging
import numpy as np
import joblib
from scapy.all import IP, TCP, UDP, ICMP

logger = logging.getLogger('NIDS.AnomalyDetection')

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'anomaly_model.joblib')


def load_model(model_path=None):
    """Load the pre-trained anomaly detection model."""
    path = model_path or MODEL_PATH
    if not os.path.exists(path):
        logger.error(
            f"Model file not found: '{path}'. "
            "Run 'python models/train_model.py' to train the model first."
        )
        return None
    try:
        model = joblib.load(path)
        logger.info(f"Anomaly detection model loaded from '{path}'.")
        return model
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return None


def load_anomaly_thresholds(threshold_file=None):
    """Load anomaly thresholds from JSON config."""
    import json
    if threshold_file is None:
        threshold_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'config', 'anomaly_thresholds.json'
        )
    try:
        with open(threshold_file, 'r') as f:
            thresholds = json.load(f)
        logger.info(f"Anomaly thresholds loaded from '{threshold_file}'.")
        return thresholds
    except FileNotFoundError:
        logger.warning(f"Threshold file not found: '{threshold_file}'. Using defaults.")
        return {}
    except Exception as e:
        logger.error(f"Failed to load thresholds: {e}")
        return {}


def extract_features(packet):
    """
    Extract network-level numerical features from a Scapy packet.

    Features (must match training features in train_model.py):
        0: packet_length       — total packet size in bytes
        1: protocol            — IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.)
        2: src_port            — source port (0 if not TCP/UDP)
        3: dst_port            — destination port (0 if not TCP/UDP)
        4: tcp_flags           — TCP flags as integer (0 if not TCP)
        5: icmp_type           — ICMP type (0 if not ICMP)
        6: payload_length      — length of the transport-layer payload in bytes
        7: is_fragmented       — 1 if IP fragment, else 0
        8: ttl                 — IP Time-To-Live value
        9: header_length       — IP header length in bytes

    Returns:
        np.ndarray of shape (1, 10), or None if packet has no IP layer.
    """
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    packet_length  = len(packet)
    protocol       = ip.proto
    ttl            = ip.ttl
    header_length  = ip.ihl * 4
    is_fragmented  = 1 if (ip.flags.MF or ip.frag > 0) else 0

    src_port = dst_port = tcp_flags = 0
    icmp_type = 0
    payload_length = 0

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port       = tcp.sport
        dst_port       = tcp.dport
        tcp_flags      = int(tcp.flags)
        payload_length = len(tcp.payload)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port       = udp.sport
        dst_port       = udp.dport
        payload_length = len(udp.payload)
    elif packet.haslayer(ICMP):
        icmp_type      = packet[ICMP].type
        payload_length = len(packet[ICMP].payload)

    features = np.array([[
        packet_length,
        protocol,
        src_port,
        dst_port,
        tcp_flags,
        icmp_type,
        payload_length,
        is_fragmented,
        ttl,
        header_length,
    ]], dtype=np.float64)

    return features


def perform_anomaly_detection(packets, model, thresholds=None):
    """
    Run anomaly detection on a list of packets using the pre-trained model.

    Args:
        packets   : list of Scapy packets
        model     : loaded sklearn model (must support .predict())
        thresholds: dict of thresholds from anomaly_thresholds.json (informational)

    Returns:
        list[dict]: Anomalous packet records with features and prediction.
    """
    if model is None:
        logger.error("No model loaded — skipping anomaly detection.")
        return []

    anomalies = []
    for pkt in packets:
        features = extract_features(pkt)
        if features is None:
            continue  # skip non-IP packets

        try:
            prediction = model.predict(features)  # 1 = normal, -1 = anomaly
        except Exception as e:
            logger.debug(f"Prediction error on packet: {e}")
            continue

        if prediction[0] == -1:
            record = {
                'src_ip':         pkt[IP].src,
                'dst_ip':         pkt[IP].dst,
                'protocol':       pkt[IP].proto,
                'packet_length':  int(features[0][0]),
                'tcp_flags':      int(features[0][4]),
                'ttl':            int(features[0][8]),
            }
            logger.warning(
                f"Anomaly detected | src={record['src_ip']} "
                f"dst={record['dst_ip']} proto={record['protocol']} "
                f"len={record['packet_length']}"
            )
            anomalies.append(record)

    if len(packets) > 1:
        # Only log summary for batch mode (not per-packet in live mode)
        logger.info(
            f"Anomaly detection complete: {len(anomalies)} anomal{'y' if len(anomalies)==1 else 'ies'} "
            f"found in {len(packets)} packets."
        )
    else:
        logger.debug(
            f"Anomaly detection complete: {len(anomalies)} anomal{'y' if len(anomalies)==1 else 'ies'} "
            f"found in 1 packet."
        )
    return anomalies
