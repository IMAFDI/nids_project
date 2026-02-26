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
# ---------------------------------------------------------------------------
N_NORMAL = 8000

normal = pd.DataFrame({
    'packet_length':  np.random.randint(40, 1500, N_NORMAL),
    'protocol':       np.random.choice([6, 17, 1], N_NORMAL, p=[0.7, 0.25, 0.05]),
    'src_port':       np.random.randint(1024, 65535, N_NORMAL),
    'dst_port':       np.random.choice([80, 443, 53, 22, 8080, 3306], N_NORMAL),
    'tcp_flags':      np.random.choice([0x02, 0x10, 0x18, 0x11, 0x00], N_NORMAL),  # SYN,ACK,PSH-ACK,FIN-ACK,none
    'icmp_type':      np.zeros(N_NORMAL, dtype=int),
    'payload_length': np.random.randint(0, 1460, N_NORMAL),
    'is_fragmented':  np.random.choice([0, 1], N_NORMAL, p=[0.98, 0.02]),
    'ttl':            np.random.choice([64, 128, 255], N_NORMAL),
    'header_length':  np.full(N_NORMAL, 20),
    'target_column':  np.zeros(N_NORMAL, dtype=int),   # 0 = normal
})

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
print(f"Training IsolationForest  [contamination={contamination:.3f}] ...")

model = IsolationForest(
    n_estimators=200,
    contamination=contamination,
    max_samples='auto',
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
