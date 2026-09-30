"""
SIH 2026 - Passive Network Threat Detection System Configuration
One-Way Air-Gapped Intelligence Enclave Enforcement
"""

import os
from pydantic import BaseModel

class EnclaveSecurityPolicy:
    """
    Non-negotiable Enclave Security Invariants:
    Strictly enforce read-only passive intelligence architecture.
    Zero return-path, zero active probing, zero inline modification, zero payload decryption.
    """
    PASSIVE_MODE: bool = True
    READ_ONLY_INGEST: bool = True
    RETURN_PATH_ENABLED: bool = False
    ACTIVE_PROBING_ENABLED: bool = False
    PAYLOAD_DECRYPTION_ENABLED: bool = False
    INLINE_MITIGATION_ENABLED: bool = False
    SOCKET_CONNECT_ALLOWED: bool = False

    @classmethod
    def get_security_status(cls) -> dict:
        return {
            "passive_monitoring": "ACTIVE",
            "read_only_ingest": "ACTIVE",
            "return_path": "NONE (PHYSICAL/LOGICAL ONE-WAY AIRGAP)",
            "payload_decryption": "DISABLED (METADATA ONLY)",
            "active_probing": "DISABLED",
            "inline_mitigation": "DISABLED",
            "enclave_integrity": "SECURE",
        }

class DetectionThresholds(BaseModel):

    # Volumetric DDoS
    syn_flood_rate_threshold: float = 1200.0        # pkts/sec
    udp_flood_rate_threshold: float = 2000.0        # pkts/sec
    amplification_ratio_threshold: float = 15.0     # response/request byte ratio
    source_entropy_flood_min: float = 0.85          # high source diversity
    destination_concentration_min: float = 0.80     # targeted host concentration

    # Botnet C2 Beaconing
    c2_min_occurrences: int = 6                     # minimum periodic events
    c2_iat_jitter_max: float = 0.15                 # coefficient of variation threshold for beaconing
    c2_periodicity_confidence_min: float = 0.75     # autocorrelation peak threshold

    # DGA & DNS Tunnelling
    dga_entropy_threshold: float = 3.65             # Shannon entropy threshold for domains
    dga_length_threshold: int = 24                  # Domain length threshold
    dns_tunnel_byte_rate_threshold: float = 500.0   # DNS bytes/sec
    dns_subdomain_depth_max: int = 4                # Subdomain depth

    # Encrypted Traffic (Metadata Only - No Decryption)
    tls_packet_size_burst_threshold: int = 1400     # byte threshold
    tls_suspicious_ja3_hashes: list[str] = [
        "e7d705a3286e19ea42f587b344ee6865",        # TrickBot JA3
        "6734f37431670b3ab4292b8f60f29984",        # Cobalt Strike JA3
        "51c64c77e60f39ac3e179af7b3e55104",        # Metasploit HTTPS JA3
        "72a589da586844d7f0818ce684948eea",        # AsyncRAT JA3
        "3b5074b1b082c616ec018d85fb80385d",        # Emotet JA3
    ]

    # Reconnaissance / Scanning
    recon_unique_ports_threshold: int = 15          # Vertical scan (same IP, many ports)
    recon_unique_hosts_threshold: int = 15          # Horizontal scan (many IPs, same port)
    recon_scan_rate_threshold: float = 25.0         # attempts/sec

    # Data Exfiltration
    exfil_byte_ratio_threshold: float = 8.0         # Outbound / Inbound ratio
    exfil_min_outbound_bytes: int = 500_000         # 500 KB minimum
    exfil_duration_min_sec: float = 5.0

class Settings:
    APP_NAME: str = "Passive Network Threat Intelligence Enclave"
    VERSION: str = "2.0.0-SIH2026"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DEBUG: bool = False
    
    # Streaming window intervals (seconds)
    WINDOW_INTERVALS: list[int] = [1, 5, 30, 60]
    DEFAULT_WINDOW_SEC: int = 5
    
    # Maximum alerts stored in memory ring buffer
    MAX_ALERTS_CACHE: int = 5000
    
    # Path settings
    DATA_DIR: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
    MODELS_DIR: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml", "saved_models"))
    
    # Thresholds
    THRESHOLDS: DetectionThresholds = DetectionThresholds()
    SECURITY: EnclaveSecurityPolicy = EnclaveSecurityPolicy()

settings = Settings()
