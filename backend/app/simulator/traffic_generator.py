"""
Safe Synthetic Flow Generator for SIH 2026.
Produces realistic metadata/flow streams for passive analysis without contacting or attacking real systems.
"""

import random
import time
from typing import Dict, Any, List
from app.config import settings

ENTERPRISE_INTERNAL_IPS = [
    "10.0.1.15", "10.0.1.42", "10.0.1.88", "10.0.2.10", "10.0.2.55", 
    "192.168.1.100", "192.168.1.105", "192.168.1.210", "172.16.0.5", "172.16.0.12"
]

EXTERNAL_SAFE_SERVERS = [
    "142.250.190.46", "151.101.1.140", "104.244.42.1", "13.107.42.14", "20.112.52.29"
]

BENIGN_DOMAINS = [
    "api.internal.corp", "updates.microsoft.com", "github.com", "portal.office.com", 
    "aws.amazon.com", "analytics.google.com", "cdn.cloudflare.net"
]

DGA_CHARS = "abcdefghijklmnopqrstuvwxyz"

class SyntheticTrafficGenerator:
    """
    Generates realistic metadata flows for normal operations and threat demonstration scenarios.
    """

    @staticmethod
    def generate_benign_flow() -> Dict[str, Any]:
        """Produces typical internal-to-external enterprise HTTP/HTTPS/DNS traffic."""
        src_ip = random.choice(ENTERPRISE_INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_SAFE_SERVERS)
        src_port = random.randint(30000, 65000)
        dst_port = random.choice([80, 443, 8080, 53, 8443])
        protocol = "UDP" if dst_port == 53 else "TCP"
        
        pkts = random.randint(2, 25)
        bytes_cnt = pkts * random.randint(64, 1100)
        dur = random.uniform(0.01, 1.5)
        
        dns_q = None
        dns_type = None
        ja3 = None
        tls_ver = None
        
        if dst_port == 53:
            dns_q = random.choice(BENIGN_DOMAINS)
            dns_type = "A"
        elif dst_port in [443, 8443]:
            tls_ver = "TLSv1.3"
            ja3 = "b32309a26951912be7dba376398abcde" # Benign standard Chrome browser JA3

        return {
            "flow_id": f"benign-{random.randint(10000, 99999)}",
            "timestamp": time.time(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_count": pkts,
            "byte_count": bytes_cnt,
            "duration_sec": dur,
            "syn_count": 1 if protocol == "TCP" else 0,
            "dns_query": dns_q,
            "dns_record_type": dns_type,
            "tls_version": tls_ver,
            "ja3_hash": ja3,
            "packet_sizes": [random.randint(64, 1200) for _ in range(min(pkts, 5))]
        }

    @staticmethod
    def generate_ddos_syn_burst(target_ip: str = "10.0.1.15", count: int = 50) -> List[Dict[str, Any]]:
        """Generates a high-rate SYN flood burst targeting a single host."""
        burst = []
        now = time.time()
        for i in range(count):
            spoofed_src = f"198.51.100.{random.randint(1, 254)}"
            burst.append({
                "flow_id": f"syn-flood-{i}-{random.randint(1000,9999)}",
                "timestamp": now + (i * 0.0005),
                "source_ip": spoofed_src,
                "destination_ip": target_ip,
                "source_port": random.randint(1024, 65000),
                "destination_port": 80,
                "protocol": "TCP",
                "packet_count": random.randint(20, 50),
                "byte_count": random.randint(1200, 3000),
                "duration_sec": 0.01,
                "syn_count": random.randint(20, 50),
                "packet_sizes": [60, 60, 60, 60]
            })
        return burst

    @staticmethod
    def generate_c2_beacon(src_ip: str = "10.0.1.42", c2_ip: str = "185.220.101.5", count: int = 7, interval_sec: float = 2.0) -> List[Dict[str, Any]]:
        """Generates periodic beaconing pattern with low jitter."""
        flows = []
        base_time = time.time() - (count * interval_sec)
        for i in range(count):
            jitter = random.uniform(-0.05, 0.05) # Tiny robotic jitter
            flows.append({
                "flow_id": f"c2-beacon-{i}",
                "timestamp": base_time + (i * interval_sec) + jitter,
                "source_ip": src_ip,
                "destination_ip": c2_ip,
                "source_port": 49821,
                "destination_port": 443,
                "protocol": "TCP",
                "packet_count": 3,
                "byte_count": 180,
                "duration_sec": 0.05,
                "syn_count": 1,
                "tls_version": "TLSv1.2",
                "ja3_hash": "6734f37431670b3ab4292b8f60f29984", # Cobalt Strike JA3 signature
                "packet_sizes": [60, 60, 60]
            })
        return flows

    @staticmethod
    def generate_dga_flow(src_ip: str = "10.0.2.10") -> Dict[str, Any]:
        """Generates algorithmic high-entropy pseudo-random domain query."""
        dga_len = random.randint(18, 30)
        random_label = "".join(random.choice(DGA_CHARS) for _ in range(dga_len))
        domain = f"{random_label}.biz"
        return {
            "flow_id": f"dga-{random.randint(1000,9999)}",
            "timestamp": time.time(),
            "source_ip": src_ip,
            "destination_ip": "8.8.8.8",
            "source_port": random.randint(30000, 60000),
            "destination_port": 53,
            "protocol": "UDP",
            "packet_count": 2,
            "byte_count": 120,
            "duration_sec": 0.02,
            "dns_query": domain,
            "dns_record_type": "A"
        }

    @staticmethod
    def generate_dns_tunnel_flow(src_ip: str = "10.0.2.55") -> Dict[str, Any]:
        """Generates DNS data tunnelling chunk flow with high entropy hex payload."""
        hex_chunk = "".join(random.choice("0123456789abcdef") for _ in range(36))
        domain = f"{hex_chunk}.stage2.exfil-c2.net"
        return {
            "flow_id": f"tunnel-{random.randint(1000,9999)}",
            "timestamp": time.time(),
            "source_ip": src_ip,
            "destination_ip": "1.1.1.1",
            "source_port": random.randint(30000, 60000),
            "destination_port": 53,
            "protocol": "UDP",
            "packet_count": 5,
            "byte_count": 540,
            "duration_sec": 0.05,
            "dns_query": domain,
            "dns_record_type": "TXT"
        }

    @staticmethod
    def generate_port_scan_burst(src_ip: str = "192.168.1.210", target_ip: str = "10.0.1.88", num_ports: int = 25) -> List[Dict[str, Any]]:
        """Generates vertical port sweep probing."""
        burst = []
        now = time.time()
        for i in range(num_ports):
            port = 20 + i
            burst.append({
                "flow_id": f"scan-{i}-{random.randint(1000,9999)}",
                "timestamp": now + (i * 0.01),
                "source_ip": src_ip,
                "destination_ip": target_ip,
                "source_port": 45100,
                "destination_port": port,
                "protocol": "TCP",
                "packet_count": 1,
                "byte_count": 44,
                "duration_sec": 0.001,
                "syn_count": 1
            })
        return burst

    @staticmethod
    def generate_data_exfiltration_flow(src_ip: str = "10.0.1.15", dst_ip: str = "203.0.113.88") -> Dict[str, Any]:
        """Generates high outbound payload transfer with severe byte asymmetry."""
        outbound_bytes = random.randint(1_500_000, 4_500_000)
        return {
            "flow_id": f"exfil-{random.randint(1000,9999)}",
            "timestamp": time.time(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": 52140,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": int(outbound_bytes / 1400),
            "byte_count": outbound_bytes,
            "duration_sec": 8.5,
            "syn_count": 1,
            "tls_version": "TLSv1.3",
            "packet_sizes": [1400] * 10
        }
