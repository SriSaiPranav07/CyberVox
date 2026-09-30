"""
Model Training & Validation Pipeline for SIH 2026.
Trains Random Forest Classifier & Isolation Forest on balanced benchmark network flow distributions.
Generates metrics: Precision, Recall, F1, Confusion Matrix, and saves serialized model artifacts.
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support

def generate_training_data(n_samples: int = 12000) -> pd.DataFrame:
    """
    Generates realistic network flow training data modeled after CIC-IDS2017 & CTU-13 distributions.
    Covers: BENIGN, DDoS_SYN_FLOOD, DDoS_UDP_FLOOD, C2_BEACONING, DGA_DOMAIN, DNS_TUNNELLING, PORT_SCAN, DATA_EXFILTRATION.
    """
    np.random.seed(42)
    per_class = n_samples // 8
    data = []

    # 1. BENIGN Traffic
    for _ in range(per_class):
        dur = np.random.exponential(1.5) + 0.05
        pkts = np.random.randint(2, 35)
        bytes_cnt = pkts * np.random.randint(64, 1200)
        bps = (bytes_cnt * 8.0) / dur
        pps = pkts / dur
        avg_pkt = bytes_cnt / pkts
        syn_ratio = np.random.uniform(0.05, 0.2)
        udp_ratio = 1.0 if np.random.rand() > 0.7 else 0.0
        dns_len = np.random.randint(8, 20) if np.random.rand() > 0.5 else 0
        dns_ent = np.random.uniform(1.5, 2.8) if dns_len > 0 else 0.0
        data.append([dur, pkts, bytes_cnt, bps, pps, avg_pkt, syn_ratio, udp_ratio, dns_len, dns_ent, "BENIGN"])

    # 2. DDoS_SYN_FLOOD
    for _ in range(per_class):
        dur = np.random.uniform(0.01, 0.5)
        pkts = np.random.randint(150, 1000)
        bytes_cnt = pkts * np.random.randint(40, 70) # small SYN packets
        bps = (bytes_cnt * 8.0) / dur
        pps = pkts / dur
        avg_pkt = bytes_cnt / pkts
        syn_ratio = np.random.uniform(0.90, 1.0)
        udp_ratio = 0.0
        dns_len = 0
        dns_ent = 0.0
        data.append([dur, pkts, bytes_cnt, bps, pps, avg_pkt, syn_ratio, udp_ratio, dns_len, dns_ent, "DDoS_SYN_FLOOD"])

    # 3. DDoS_UDP_FLOOD
    for _ in range(per_class):
        dur = np.random.uniform(0.01, 0.5)
        pkts = np.random.randint(200, 1200)
        bytes_cnt = pkts * np.random.randint(500, 1400)
        bps = (bytes_cnt * 8.0) / dur
        pps = pkts / dur
        avg_pkt = bytes_cnt / pkts
        syn_ratio = 0.0
        udp_ratio = 1.0
        dns_len = 0
        dns_ent = 0.0
        data.append([dur, pkts, bytes_cnt, bps, pps, avg_pkt, syn_ratio, udp_ratio, dns_len, dns_ent, "DDoS_UDP_FLOOD"])

    # 4. C2_BEACONING
    for _ in range(per_class):
        dur = np.random.uniform(0.02, 0.1)
        pkts = np.random.randint(1, 4)
        bytes_cnt = pkts * np.random.randint(64, 180)
        bps = (bytes_cnt * 8.0) / dur
        pps = pkts / dur
        avg_pkt = bytes_cnt / pkts
        syn_ratio = 0.33
        udp_ratio = 0.0
        dns_len = 0
        dns_ent = 0.0
        data.append([dur, pkts, bytes_cnt, bps, pps, avg_pkt, syn_ratio, udp_ratio, dns_len, dns_ent, "C2_BEACONING"])

    # 5. DGA_DOMAIN
    for _ in range(per_class):
        dur = np.random.uniform(0.01, 0.1)
        pkts = 2
        bytes_cnt = 180
        bps = (bytes_cnt * 8.0) / dur
        pps = pkts / dur
        avg_pkt = 90.0
        syn_ratio = 0.0
        udp_ratio = 1.0
        dns_len = np.random.randint(18, 38)
        dns_ent = np.random.uniform(3.7, 4.8) # High DGA entropy
        data.append([dur, pkts, bytes_cnt, bps, pps, avg_pkt, syn_ratio, udp_ratio, dns_len, dns_ent, "DGA_DOMAIN"])

    # 6. DNS_TUNNELLING
    for _ in range(per_class):
        dur = np.random.uniform(0.05, 0.3)
        pkts = np.random.randint(4, 15)
        bytes_cnt = pkts * np.random.randint(300, 600)
        bps = (bytes_cnt * 8.0) / dur
        pps = pkts / dur
        avg_pkt = bytes_cnt / pkts
        syn_ratio = 0.0
        udp_ratio = 1.0
        dns_len = np.random.randint(35, 65)
        dns_ent = np.random.uniform(4.0, 5.2) # High tunnel entropy + deep length
        data.append([dur, pkts, bytes_cnt, bps, pps, avg_pkt, syn_ratio, udp_ratio, dns_len, dns_ent, "DNS_TUNNELLING"])

    # 7. PORT_SCAN
    for _ in range(per_class):
        dur = np.random.uniform(0.005, 0.05)
        pkts = 1
        bytes_cnt = 44
        bps = (bytes_cnt * 8.0) / dur
        pps = pkts / dur
        avg_pkt = 44.0
        syn_ratio = 1.0
        udp_ratio = 0.0
        dns_len = 0
        dns_ent = 0.0
        data.append([dur, pkts, bytes_cnt, bps, pps, avg_pkt, syn_ratio, udp_ratio, dns_len, dns_ent, "PORT_SCAN"])

    # 8. DATA_EXFILTRATION
    for _ in range(per_class):
        dur = np.random.uniform(5.0, 30.0)
        pkts = np.random.randint(500, 4000)
        bytes_cnt = pkts * np.random.randint(1100, 1480) # High outbound payload
        bps = (bytes_cnt * 8.0) / dur
        pps = pkts / dur
        avg_pkt = bytes_cnt / pkts
        syn_ratio = 0.01
        udp_ratio = 0.0
        dns_len = 0
        dns_ent = 0.0
        data.append([dur, pkts, bytes_cnt, bps, pps, avg_pkt, syn_ratio, udp_ratio, dns_len, dns_ent, "DATA_EXFILTRATION"])

    columns = [
        "duration_sec", "packet_count", "byte_count", "bytes_per_sec", 
        "packets_per_sec", "avg_packet_size", "syn_ratio", "udp_ratio", 
        "dns_query_len", "dns_entropy", "label"
    ]
    return pd.DataFrame(data, columns=columns)

def train_and_save():
    print("==================================================")
    print("SIH 2026: Training Hybrid AI/ML Threat Detection Engine")
    print("==================================================")
    
    df = generate_training_data(n_samples=2400)
    X = df.drop(columns=["label"]).values
    y = df["label"].values
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    
    # 1. Train Random Forest Multi-class Classifier
    print("\n[1/3] Training Supervised Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=1)
    rf.fit(X_train, y_train)
    
    y_pred = rf.predict(X_test)
    print("\n--- Model Validation Report ---")
    print(classification_report(y_test, y_pred, digits=4))
    
    # 2. Train Isolation Forest (Trained on Benign to detect Outliers)
    print("[2/3] Training Unsupervised Isolation Forest Anomaly Detector...")
    X_benign = X_train[y_train == "BENIGN"]
    iforest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    iforest.fit(X_benign)
    
    # 3. Save Artifacts
    output_dir = os.path.join(os.path.dirname(__file__), "saved_models")
    os.makedirs(output_dir, exist_ok=True)
    
    rf_path = os.path.join(output_dir, "random_forest_threat_model.pkl")
    iforest_path = os.path.join(output_dir, "isolation_forest_anomaly.pkl")
    
    with open(rf_path, "wb") as f:
        pickle.dump(rf, f)
    with open(iforest_path, "wb") as f:
        pickle.dump(iforest, f)
        
    print(f"\n[3/3] Models successfully serialized to: {output_dir}")
    print(f"  - Random Forest: {rf_path}")
    print(f"  - Isolation Forest: {iforest_path}")
    print("==================================================")

if __name__ == "__main__":
    train_and_save()
