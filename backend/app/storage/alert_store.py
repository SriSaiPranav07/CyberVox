"""
Persistent & In-Memory Alert and Flow Storage for SIH 2026.
Provides low-latency indexed querying, severity filtering, and JSON export.
"""

import sqlite3
import json
import os
from collections import deque
from typing import List, Optional, Dict, Any
from app.models.schemas import Alert, ThreatStats, ThreatCategoryInfo
from app.config import settings

class AlertStore:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(settings.DATA_DIR, "alerts.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.memory_alerts: deque[Alert] = deque(maxlen=settings.MAX_ALERTS_CACHE)
        self.stats = self._init_default_stats()
        self._init_db()

    def _init_default_stats(self) -> ThreatStats:
        cat_map = {
            "DDOS": ThreatCategoryInfo(
                category_id="DDOS",
                name="Volumetric / Protocol DDoS",
                count=0,
                status="IDLE",
                method="Statistical Velocity + ML Ensemble"
            ),
            "C2": ThreatCategoryInfo(
                category_id="C2",
                name="Botnet C2 Beaconing",
                count=0,
                status="IDLE",
                method="IAT Jitter CV & FFT Periodicity"
            ),
            "DNS": ThreatCategoryInfo(
                category_id="DNS",
                name="DGA & DNS Tunnelling",
                count=0,
                status="IDLE",
                method="Shannon Entropy & N-Gram Perplexity"
            ),
            "ENCRYPTED": ThreatCategoryInfo(
                category_id="ENCRYPTED",
                name="Encrypted Traffic (Metadata)",
                count=0,
                status="IDLE",
                method="JA3/JA4 Hashes & Packet Dispersion (No Decryption)"
            ),
            "RECON": ThreatCategoryInfo(
                category_id="RECON",
                name="Reconnaissance & Scanning",
                count=0,
                status="IDLE",
                method="Fan-Out Cardinality & Rate Analysis"
            ),
            "EXFILTRATION": ThreatCategoryInfo(
                category_id="EXFILTRATION",
                name="Potential Data Exfiltration",
                count=0,
                status="IDLE",
                method="Asymmetric Byte Ratio & Egress Baseline"
            ),
        }
        return ThreatStats(
            ddos_count=0,
            c2_count=0,
            dns_count=0,
            encrypted_count=0,
            recon_count=0,
            exfil_count=0,
            total_threats=0,
            category_details=cat_map,
            severity_breakdown={"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        )

    def _init_db(self):
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = NORMAL")
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT,
                timestamp TEXT,
                threat_category TEXT,
                threat_class TEXT,
                severity TEXT,
                confidence REAL,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                evidence TEXT,
                explanation TEXT,
                detection_engine TEXT,
                processing_latency_ms REAL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_class ON alerts(threat_class)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)")
        self.conn.commit()

    def add_alert(self, alert: Alert):
        """Adds alert to memory ring buffer and persistent database."""
        self.memory_alerts.appendleft(alert)
        
        # Update statistics & category details
        cat = alert.threat_category
        cat_str = cat.value if hasattr(cat, "value") else str(cat)
        sev_key = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        
        matched_cat_key = "RECON"
        if "DDOS" in cat_str or "DDOS" in alert.threat_class:
            self.stats.ddos_count += 1
            matched_cat_key = "DDOS"
        elif "C2" in cat_str or "C2" in alert.threat_class:
            self.stats.c2_count += 1
            matched_cat_key = "C2"
        elif "DNS" in cat_str or "DGA" in alert.threat_class or "DNS" in alert.threat_class:
            self.stats.dns_count += 1
            matched_cat_key = "DNS"
        elif "ENCRYPTED" in cat_str or "TLS" in alert.threat_class:
            self.stats.encrypted_count += 1
            matched_cat_key = "ENCRYPTED"
        elif "RECON" in cat_str or "SCAN" in alert.threat_class:
            self.stats.recon_count += 1
            matched_cat_key = "RECON"
        elif "EXFILTRATION" in cat_str or "EXFILTRATION" in alert.threat_class:
            self.stats.exfil_count += 1
            matched_cat_key = "EXFILTRATION"
            
        self.stats.total_threats += 1
        if sev_key in self.stats.severity_breakdown:
            self.stats.severity_breakdown[sev_key] += 1

        # Update dynamic category detail card
        if matched_cat_key in self.stats.category_details:
            detail = self.stats.category_details[matched_cat_key]
            detail.count += 1
            detail.status = "THREAT_DETECTED"
            detail.latest_threat = alert.threat_class
            detail.latest_severity = sev_key
            detail.latest_confidence = alert.confidence
            detail.latest_timestamp = alert.timestamp

        # Save to persistent SQLite
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (
                    flow_id, timestamp, threat_category, threat_class, severity,
                    confidence, source_ip, destination_ip, source_port, destination_port,
                    protocol, evidence, explanation, detection_engine, processing_latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.flow_id,
                alert.timestamp,
                cat_str,
                alert.threat_class,
                sev_key,
                alert.confidence,
                alert.source_ip,
                alert.destination_ip,
                alert.source_port,
                alert.destination_port,
                alert.protocol,
                json.dumps(alert.evidence),
                alert.explanation,
                alert.detection_engine.value if hasattr(alert.detection_engine, "value") else str(alert.detection_engine),
                alert.processing_latency_ms
            ))
            self.conn.commit()
        except Exception:
            pass

    def get_alerts(self, limit: int = 100, severity: Optional[str] = None, category: Optional[str] = None) -> List[Alert]:
        alerts = list(self.memory_alerts)
        if severity and severity.upper() != "ALL":
            alerts = [a for a in alerts if (a.severity.value if hasattr(a.severity, "value") else str(a.severity)) == severity.upper()]
        if category and category.upper() != "ALL":
            alerts = [a for a in alerts if category.upper() in (a.threat_category.value if hasattr(a.threat_category, "value") else str(a.threat_category)) or category.upper() in a.threat_class]
        return alerts[:limit]

    def get_stats(self) -> ThreatStats:
        return self.stats

    def clear(self):
        self.memory_alerts.clear()
        self.stats = self._init_default_stats()
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.cursor().execute("DELETE FROM alerts")
                conn.commit()
        except Exception:
            pass

alert_store = AlertStore()
