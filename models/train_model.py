"""
Train an Isolation Forest anomaly detection model on synthetic network traffic data.

Features used (must stay in sync with config/anomaly_detection.py::extract_features):
    0: packet_length
    1: protocol            (6=TCP, 17=UDP, 1=ICMP)
    2: src_port
    3: dst_port
    4: tcp_flags
    5: icmp_type
    6: payload_length
    7: is_fragmented
    8: ttl
    9: header_length

The script generates realistic synthetic normal traffic + injects attack-pattern
anomalies, trains an IsolationForest, and saves the model to models/anomaly_model.joblib.
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

RANDOM_SEED = 42
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'anomaly_model.joblib')
CSV_PATH   = os.path.join(os.path.dirname(__file__), 'anomaly_detection_data.csv')

np.random.seed(RANDOM_SEED)

# ---------------------------------------------------------------------------
# 1. Generate synthetic normal network traffic
#    Covers realistic macOS/Linux traffic patterns seen in the wild:
#    HTTPS (TLS), HTTP, DNS, SSH keepalives, iCloud, GitHub, Azure, AWS, etc.
# ---------------------------------------------------------------------------
N_NORMAL = 12000

# --- HTTPS / TLS traffic (dominant on modern machines) ---
# Typical TLS record sizes: 66 (ACK), 74 (SYN-ACK), ~1490 (data), ~90-200 (handshake)
n_https = N_NORMAL // 3
https_lengths = np.concatenate([
    np.full(n_https // 5, 54),    # bare ACK
    np.full(n_https // 5, 66),    # ACK with timestamp option
    np.full(n_https // 5, 74),    # SYN-ACK
    np.random.randint(80, 300, n_https // 5),   # TLS handshake
    np.random.randint(800, 1514, n_https - 4 * (n_https // 5)),  # TLS data
])
np.random.shuffle(https_lengths)
https_traffic = pd.DataFrame({
    'packet_length':  https_lengths,
    'protocol':       np.full(n_https, 6),
    'src_port':       np.random.randint(1024, 65535, n_https),
    'dst_port':       np.random.choice([443, 8443], n_https),
    'tcp_flags':      np.random.choice([0x02, 0x10, 0x18, 0x11, 0x12], n_https,
                                       p=[0.1, 0.5, 0.2, 0.1, 0.1]),
    'icmp_type':      np.zeros(n_https, dtype=int),
    'payload_length': np.clip(https_lengths - 40, 0, 1460),
    'is_fragmented':  np.zeros(n_https, dtype=int),
    'ttl':            np.random.choice([49, 51, 52, 54, 55, 56, 57, 58, 60,
                                        64, 115, 117, 118, 119, 120, 128], n_https),
    'header_length':  np.full(n_https, 20),
    'target_column':  np.zeros(n_https, dtype=int),
})

# --- HTTP traffic ---
n_http = N_NORMAL // 6
http_lengths = np.concatenate([
    np.random.randint(40, 200, n_http // 2),
    np.random.randint(200, 1514, n_http - n_http // 2),
])
http_traffic = pd.DataFrame({
    'packet_length':  http_lengths,
    'protocol':       np.full(n_http, 6),
    'src_port':       np.random.randint(1024, 65535, n_http),
    'dst_port':       np.random.choice([80, 8080, 8000], n_http),
    'tcp_flags':      np.random.choice([0x02, 0x10, 0.18, 0x11], n_http),
    'icmp_type':      np.zeros(n_http, dtype=int),
    'payload_length': np.clip(http_lengths - 40, 0, 1460),
    'is_fragmented':  np.zeros(n_http, dtype=int),
    'ttl':            np.random.choice([64, 128, 255, 56, 57, 58], n_http),
    'header_length':  np.full(n_http, 20),
    'target_column':  np.zeros(n_http, dtype=int),
})

# --- DNS traffic ---
n_dns = N_NORMAL // 8
dns_traffic = pd.DataFrame({
    'packet_length':  np.random.randint(60, 512, n_dns),
    'protocol':       np.full(n_dns, 17),
    'src_port':       np.random.randint(1024, 65535, n_dns),
    'dst_port':       np.full(n_dns, 53),
    'tcp_flags':      np.zeros(n_dns, dtype=int),
    'icmp_type':      np.zeros(n_dns, dtype=int),
    'payload_length': np.random.randint(20, 470, n_dns),
    'is_fragmented':  np.zeros(n_dns, dtype=int),
    'ttl':            np.random.choice([64, 128], n_dns),
    'header_length':  np.full(n_dns, 20),
    'target_column':  np.zeros(n_dns, dtype=int),
})

# --- SSH keepalive / interactive ---
n_ssh = N_NORMAL // 8
ssh_lengths = np.random.choice([66, 90, 114, 130, 162, 184, 258], n_ssh)
ssh_traffic = pd.DataFrame({
    'packet_length':  ssh_lengths,
    'protocol':       np.full(n_ssh, 6),
    'src_port':       np.random.randint(1024, 65535, n_ssh),
    'dst_port':       np.full(n_ssh, 22),
    'tcp_flags':      np.random.choice([0x10, 0x18], n_ssh),
    'icmp_type':      np.zeros(n_ssh, dtype=int),
    'payload_length': np.clip(ssh_lengths - 40, 0, 1460),
    'is_fragmented':  np.zeros(n_ssh, dtype=int),
    'ttl':            np.random.choice([64, 128], n_ssh),
    'header_length':  np.full(n_ssh, 20),
    'target_column':  np.zeros(n_ssh, dtype=int),
})

# --- Remaining generic normal traffic ---
n_rest = N_NORMAL - n_https - n_http - n_dns - n_ssh
rest_lengths = np.random.randint(40, 1514, n_rest)
rest_traffic = pd.DataFrame({
    'packet_length':  rest_lengths,
    'protocol':       np.random.choice([6, 17, 1], n_rest, p=[0.7, 0.25, 0.05]),
    'src_port':       np.random.randint(1024, 65535, n_rest),
    'dst_port':       np.random.choice([80, 443, 53, 22, 8080, 3306, 5432], n_rest),
    'tcp_flags':      np.random.choice([0x02, 0x10, 0x18, 0x11, 0x00], n_rest),
    'icmp_type':      np.zeros(n_rest, dtype=int),
    'payload_length': np.clip(rest_lengths - 40, 0, 1460),
    'is_fragmented':  np.random.choice([0, 1], n_rest, p=[0.99, 0.01]),
    'ttl':            np.random.choice([64, 128, 255, 56, 60], n_rest),
    'header_length':  np.full(n_rest, 20),
    'target_column':  np.zeros(n_rest, dtype=int),
})

normal = pd.concat([https_traffic, http_traffic, dns_traffic, ssh_traffic, rest_traffic],
                   ignore_index=True)

# ---------------------------------------------------------------------------
# 2. Generate anomalous / attack traffic
# ---------------------------------------------------------------------------
N_ATTACK = 2000

# TCP SYN flood — many SYN packets, small payload, same dst_port
syn_flood = pd.DataFrame({
    'packet_length':  np.random.randint(40, 60, N_ATTACK // 4),
    'protocol':       np.full(N_ATTACK // 4, 6),
    'src_port':       np.random.randint(1024, 65535, N_ATTACK // 4),
    'dst_port':       np.full(N_ATTACK // 4, 80),
    'tcp_flags':      np.full(N_ATTACK // 4, 0x02),  # SYN
    'icmp_type':      np.zeros(N_ATTACK // 4, dtype=int),
    'payload_length': np.zeros(N_ATTACK // 4, dtype=int),
    'is_fragmented':  np.zeros(N_ATTACK // 4, dtype=int),
    'ttl':            np.random.randint(1, 30, N_ATTACK // 4),
    'header_length':  np.full(N_ATTACK // 4, 20),
    'target_column':  np.ones(N_ATTACK // 4, dtype=int),
})

# UDP flood — large payloads, high-rate
udp_flood = pd.DataFrame({
    'packet_length':  np.random.randint(1000, 1500, N_ATTACK // 4),
    'protocol':       np.full(N_ATTACK // 4, 17),
    'src_port':       np.random.randint(1024, 65535, N_ATTACK // 4),
    'dst_port':       np.random.randint(1, 1024, N_ATTACK // 4),
    'tcp_flags':      np.zeros(N_ATTACK // 4, dtype=int),
    'icmp_type':      np.zeros(N_ATTACK // 4, dtype=int),
    'payload_length': np.random.randint(950, 1460, N_ATTACK // 4),
    'is_fragmented':  np.random.choice([0, 1], N_ATTACK // 4, p=[0.5, 0.5]),
    'ttl':            np.random.randint(1, 10, N_ATTACK // 4),
    'header_length':  np.full(N_ATTACK // 4, 20),
    'target_column':  np.ones(N_ATTACK // 4, dtype=int),
})

# ICMP flood
icmp_flood = pd.DataFrame({
    'packet_length':  np.random.randint(28, 100, N_ATTACK // 4),
    'protocol':       np.full(N_ATTACK // 4, 1),
    'src_port':       np.zeros(N_ATTACK // 4, dtype=int),
    'dst_port':       np.zeros(N_ATTACK // 4, dtype=int),
    'tcp_flags':      np.zeros(N_ATTACK // 4, dtype=int),
    'icmp_type':      np.full(N_ATTACK // 4, 8),   # echo request
    'payload_length': np.random.randint(0, 56, N_ATTACK // 4),
    'is_fragmented':  np.zeros(N_ATTACK // 4, dtype=int),
    'ttl':            np.random.randint(1, 20, N_ATTACK // 4),
    'header_length':  np.full(N_ATTACK // 4, 20),
    'target_column':  np.ones(N_ATTACK // 4, dtype=int),
})

# Port scan — many different dst_ports, tiny packets
port_scan = pd.DataFrame({
    'packet_length':  np.random.randint(40, 60, N_ATTACK // 4),
    'protocol':       np.full(N_ATTACK // 4, 6),
    'src_port':       np.random.randint(1024, 65535, N_ATTACK // 4),
    'dst_port':       np.random.randint(1, 65535, N_ATTACK // 4),
    'tcp_flags':      np.full(N_ATTACK // 4, 0x02),  # SYN
    'icmp_type':      np.zeros(N_ATTACK // 4, dtype=int),
    'payload_length': np.zeros(N_ATTACK // 4, dtype=int),
    'is_fragmented':  np.zeros(N_ATTACK // 4, dtype=int),
    'ttl':            np.full(N_ATTACK // 4, 64),
    'header_length':  np.full(N_ATTACK // 4, 20),
    'target_column':  np.ones(N_ATTACK // 4, dtype=int),
})

# ---------------------------------------------------------------------------
# 3. Combine, shuffle, save CSV
# ---------------------------------------------------------------------------
data = pd.concat([normal, syn_flood, udp_flood, icmp_flood, port_scan],
                 ignore_index=True)
data = data.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
data.to_csv(CSV_PATH, index=False)
print(f"Dataset saved → {CSV_PATH}  ({len(data)} rows)")

FEATURE_COLS = [
    'packet_length', 'protocol', 'src_port', 'dst_port',
    'tcp_flags', 'icmp_type', 'payload_length',
    'is_fragmented', 'ttl', 'header_length',
]

X = data[FEATURE_COLS].values
y = data['target_column'].values   # 0=normal, 1=attack  (used only for evaluation)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
)

# ---------------------------------------------------------------------------
# 4. Train Isolation Forest
#    contamination = fraction of anomalies expected in data
# ---------------------------------------------------------------------------
contamination = float(np.sum(y == 1)) / len(y)
# Cap contamination: even if attacks are ~14% of data, tell the model
# to only flag the most extreme outliers to keep false positives low.
contamination_capped = min(contamination, 0.08)
print(f"Training IsolationForest  [true_contamination={contamination:.3f}, "
      f"model_contamination={contamination_capped:.3f}] ...")

model = IsolationForest(
    n_estimators=300,
    contamination=contamination_capped,
    max_samples=512,
    random_state=RANDOM_SEED,
    n_jobs=-1,
)
model.fit(X_train)

# ---------------------------------------------------------------------------
# 5. Evaluate  (IsolationForest: 1=normal, -1=anomaly → remap to 0/1)
# ---------------------------------------------------------------------------
y_pred_raw = model.predict(X_test)
y_pred = np.where(y_pred_raw == -1, 1, 0)

print("\n=== Evaluation on held-out test set ===")
print(classification_report(y_test, y_pred, target_names=['normal', 'attack']))

# ---------------------------------------------------------------------------
# 6. Save model
# ---------------------------------------------------------------------------
joblib.dump(model, MODEL_PATH)
print(f"\nModel saved → {MODEL_PATH}")
