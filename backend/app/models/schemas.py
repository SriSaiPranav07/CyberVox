"""
Standardized Data & Alert Schemas for SIH 2026.
Strict adherence to Section 12 (Alert Schema), Section 13 (Confidence), Section 14 (Severity).
"""

from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from app.models.threat_types import ThreatClass, SeverityLevel, DetectionEngineType, ThreatCategory

def get_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class TrafficMode(str):
    PCAP_REPLAY = "PCAP_REPLAY"
    SYNTHETIC_DEMO = "SYNTHETIC_DEMO"
    PASSIVE_LIVE_FEED = "PASSIVE_LIVE_FEED"

class RawFlowRecord(BaseModel):
    flow_id: str
    timestamp: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str = "TCP"
    packet_count: int = 1
    byte_count: int = 64
    duration_sec: float = 0.01
    
    # Optional metadata fields (Strictly Read-Only Metadata)
    tcp_flags: Optional[List[str]] = None
    syn_count: Optional[int] = 0
    ack_count: Optional[int] = 0
    rst_count: Optional[int] = 0
    fin_count: Optional[int] = 0
    
    # DNS Metadata (No Active Resolution)
    dns_query: Optional[str] = None
    dns_record_type: Optional[str] = None
    dns_query_len: Optional[int] = 0
    
    # Encrypted TLS / QUIC Metadata (No Payload Decryption)
    tls_version: Optional[str] = None
    ja3_hash: Optional[str] = None
    ja4_hash: Optional[str] = None
    cipher_suite: Optional[str] = None
    sni: Optional[str] = None
    packet_sizes: Optional[List[int]] = None
    inter_arrival_times: Optional[List[float]] = None

class EvidenceDetail(BaseModel):
    feature_name: str
    observed_value: Any
    baseline_value: Optional[Any] = None
    threshold_value: Optional[Any] = None
    deviation_pct: Optional[float] = None
    unit: Optional[str] = ""
    interpretation: str

class Alert(BaseModel):
    timestamp: str = Field(description="ISO-8601 UTC timestamp")
    flow_id: str
    threat_category: ThreatCategory
    threat_class: str
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0, description="Strength of evidence (0.00 - 1.00)")
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    evidence: Dict[str, Any]
    evidence_details: Optional[List[EvidenceDetail]] = None
    explanation: str
    detection_engine: DetectionEngineType = DetectionEngineType.HYBRID_ENSEMBLE
    processing_latency_ms: float = 0.0

class EntityStat(BaseModel):
    key: str
    count: int
    bytes: int = 0

class SubsystemHealth(BaseModel):
    name: str
    status: str # "Active", "Healthy", "Ready", "Operational", "Connected"
    indicator: str = "ok" # "ok", "warning", "error"
    details: str

class StreamingMetrics(BaseModel):
    timestamp: str
    traffic_mode: str = "SYNTHETIC_DEMO" # PCAP_REPLAY, SYNTHETIC_DEMO, PASSIVE_LIVE_FEED
    flows_per_sec: float = 0.0
    packets_per_sec: float = 0.0
    mbps: float = 0.0
    total_processed_flows: int = 0
    total_processed_packets: int = 0
    total_processed_bytes: int = 0
    total_alerts_generated: int = 0
    avg_processing_latency_ms: float = 0.0
    p95_processing_latency_ms: float = 0.0
    p99_processing_latency_ms: float = 0.0
    active_sources_count: int = 0
    active_destinations_count: int = 0
    top_sources: List[EntityStat] = []
    top_destinations: List[EntityStat] = []
    top_ports: List[EntityStat] = []
    subsystem_health: List[SubsystemHealth] = []
    enclave_status: Dict[str, str]

class ThreatCategoryInfo(BaseModel):
    category_id: str
    name: str
    count: int = 0
    status: str = "IDLE" # "IDLE", "ANALYZING", "THREAT_DETECTED"
    latest_threat: Optional[str] = None
    latest_severity: Optional[str] = None
    latest_confidence: Optional[float] = None
    latest_timestamp: Optional[str] = None
    method: str = "Statistical + ML"

class ThreatStats(BaseModel):
    ddos_count: int = 0
    c2_count: int = 0
    dns_count: int = 0
    encrypted_count: int = 0
    recon_count: int = 0
    exfil_count: int = 0
    total_threats: int = 0
    category_details: Dict[str, ThreatCategoryInfo] = {}
    severity_breakdown: Dict[str, int] = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

class BenchmarkRequest(BaseModel):
    total_flows: int = 10000
    target_rate: int = 2000
    threat_ratio: float = 0.15
    dataset_name: str = "Synthetic Enterprise Trace"
    traffic_type: str = "Mixed L3/L4/DNS/TLS Flows"

class BenchmarkResult(BaseModel):
    test_id: str
    timestamp: str
    dataset_name: str = "Synthetic Enterprise Trace"
    traffic_type: str = "Mixed L3/L4/DNS/TLS Flows"
    total_flows_processed: int
    duration_sec: float
    actual_flows_per_sec: float
    actual_packets_per_sec: float
    actual_mbps: float
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    ml_inference_time_total_ms: float
    feature_extraction_time_total_ms: float
    memory_usage_mb: float
    cpu_usage_pct: float = 4.2
    alerts_generated: int
    enclave_integrity_verified: bool = True

class ReplayRequest(BaseModel):
    dataset_name: str = "synthetic_enterprise_traffic"
    speed_multiplier: float = 1.0
    threat_scenarios: Optional[List[str]] = None
    traffic_mode: str = "SYNTHETIC_DEMO"
    loop: bool = False

class ReplayStatus(BaseModel):
    is_active: bool
    is_paused: bool
    dataset_name: str
    traffic_mode: str = "SYNTHETIC_DEMO"
    total_records: int
    processed_records: int
    processed_packets: int = 0
    current_rate_fps: float
    alerts_generated: int
    elapsed_time_sec: float
    speed_multiplier: float
