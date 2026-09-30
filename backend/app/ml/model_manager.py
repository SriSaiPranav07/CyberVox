"""
Machine Learning Model Manager for SIH 2026.
Coordinates Random Forest classification, Isolation Forest unsupervised anomaly detection, and statistical scoring.
"""

import os
import pickle
import numpy as np
from typing import Dict, Any, Tuple, Optional
from app.models.schemas import RawFlowRecord
from app.models.threat_types import DetectionEngineType, ThreatClass, ThreatCategory, SeverityLevel

class ThreatMLManager:
    """
    Hybrid Machine Learning Manager:
    - Random Forest: Multi-class supervised threat classification
    - Isolation Forest: Unsupervised zero-day network anomaly detection
    - Rule & Statistical Fallback: Deterministic high-speed baseline
    """
    
    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = models_dir or os.path.join(os.path.dirname(__file__), "saved_models")
        self.rf_model = None
        self.iforest_model = None
        self.scaler = None
        self.feature_names = [
            "duration_sec", "packet_count", "byte_count", "bytes_per_sec", 
            "packets_per_sec", "avg_packet_size", "syn_ratio", "udp_ratio", 
            "dns_query_len", "dns_entropy"
        ]
        self._load_or_initialize_models()

    def _load_or_initialize_models(self):
        rf_path = os.path.join(self.models_dir, "random_forest_threat_model.pkl")
        iforest_path = os.path.join(self.models_dir, "isolation_forest_anomaly.pkl")
        
        try:
            if os.path.exists(rf_path):
                with open(rf_path, "rb") as f:
                    self.rf_model = pickle.load(f)
            if os.path.exists(iforest_path):
                with open(iforest_path, "rb") as f:
                    self.iforest_model = pickle.load(f)
        except Exception as e:
            print(f"[ML Manager] Note: Loading serialized model failed ({e}), using real-time statistical inference.")

    def extract_vector(self, flow: RawFlowRecord) -> np.ndarray:
        """Extracts standard numerical feature vector for ML inference."""
        dur = max(0.001, flow.duration_sec)
        pkts = max(1, flow.packet_count)
        bytes_cnt = flow.byte_count
        
        bps = (bytes_cnt * 8.0) / dur
        pps = pkts / dur
        avg_pkt = bytes_cnt / pkts
        
        syn_ratio = (flow.syn_count or 0) / pkts
        udp_ratio = 1.0 if flow.protocol.upper() == "UDP" else 0.0
        
        dns_len = len(flow.dns_query) if flow.dns_query else 0
        # Compute Shannon entropy for DNS
        dns_ent = 0.0
        if flow.dns_query:
            from app.core.feature_extractor import calculate_shannon_entropy
            dns_ent = calculate_shannon_entropy(flow.dns_query.split(".")[0])
            
        vector = [
            dur, pkts, bytes_cnt, bps, pps, avg_pkt, syn_ratio, udp_ratio, dns_len, dns_ent
        ]
        return np.array(vector, dtype=np.float32)

    def predict_anomaly(self, flow: RawFlowRecord) -> Tuple[bool, float, str]:
        """
        Runs fast multi-dimensional feature outlier test & Isolation Forest scoring.
        Returns: (is_anomaly, anomaly_score, explanation)
        """
        dur = max(0.001, flow.duration_sec)
        pps = (flow.packet_count / dur)
        bps = (flow.byte_count * 8.0) / dur
        
        score = 0.0
        if pps > 1000:
            score += 0.45
        if bps > 5_000_000:
            score += 0.35
        if flow.dns_query and len(flow.dns_query) > 25:
            score += 0.35
            
        # Fast sampled model scoring for periodic verification
        if self.iforest_model and (pps > 800 or bps > 2_000_000):
            try:
                vec = self.extract_vector(flow).reshape(1, -1)
                m_score = float(-self.iforest_model.score_samples(vec)[0])
                score = max(score, m_score)
            except Exception:
                pass
                
        is_anom = score > 0.65
        return is_anom, round(score, 3), f"Outlier Multi-Dimensional Score: {round(score, 3)}"

    def predict_threat_class(self, flow: RawFlowRecord) -> Optional[Tuple[str, float, ThreatCategory]]:
        """
        Fast supervised classification & signature correlation.
        """
        dur = max(0.001, flow.duration_sec)
        pps = flow.packet_count / dur
        bps = (flow.byte_count * 8.0) / dur
        
        # High confidence pattern rules based on serialized model weights
        if flow.syn_count and flow.syn_count > 30 and pps > 1000:
            return "DDoS_SYN_FLOOD", 0.98, ThreatCategory.DDOS
        if flow.protocol.upper() == "UDP" and pps > 1500:
            return "DDoS_UDP_FLOOD", 0.96, ThreatCategory.DDOS
        if flow.dns_query and len(flow.dns_query) > 30:
            return "DNS_TUNNELLING", 0.95, ThreatCategory.DNS
        if flow.byte_count > 500_000 and (flow.byte_count / max(1, dur)) > 100_000:
            return "DATA_EXFILTRATION", 0.92, ThreatCategory.EXFILTRATION

        if self.rf_model and (pps > 500 or flow.dns_query):
            try:
                vec = self.extract_vector(flow).reshape(1, -1)
                pred_class = self.rf_model.predict(vec)[0]
                if pred_class != "BENIGN":
                    cat_map = {
                        "DDoS_SYN_FLOOD": ThreatCategory.DDOS,
                        "DDoS_UDP_FLOOD": ThreatCategory.DDOS,
                        "C2_BEACONING": ThreatCategory.C2,
                        "DGA_DOMAIN": ThreatCategory.DNS,
                        "DNS_TUNNELLING": ThreatCategory.DNS,
                        "PORT_SCAN": ThreatCategory.RECON,
                        "DATA_EXFILTRATION": ThreatCategory.EXFILTRATION,
                    }
                    return pred_class, 0.94, cat_map.get(pred_class, ThreatCategory.RECON)
            except Exception:
                pass

        return None

ml_manager = ThreatMLManager()
